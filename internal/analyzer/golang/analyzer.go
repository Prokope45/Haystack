package golang

import (
	"bytes"
	"context"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/flow"
)

var secretKeyRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|passwd|password|private[_-]?key)`)

// GoAnalyzer implements the analyzer.Analyzer interface for Go source files.
type GoAnalyzer struct {
	directives map[string]analyzer.AnalysisDirectives
}

func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{}
}

func (ga *GoAnalyzer) SetDirectives(directives map[string]analyzer.AnalysisDirectives) {
	ga.directives = directives
}

func (ga *GoAnalyzer) Language() string {
	return "go"
}

func (ga *GoAnalyzer) Supports(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".go"
}

func (ga *GoAnalyzer) Analyze(ctx context.Context, source []byte, filePath string) ([]analyzer.Evidence, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, source, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var evidences []analyzer.Evidence
	baseNameSanitized := sanitizeIdentifier(filepath.Base(filePath))

	// Inspect each function declaration
	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		funcName := fn.Name.Name
		maxDepth := 0
		mode := "deep"
		var matchedDirectives *analyzer.AnalysisDirectives

		if len(ga.directives) > 0 {
			// Find directive for this function
			for key, d := range ga.directives {
				if strings.Contains(key, baseNameSanitized) && strings.Contains(key, funcName) {
					dCopy := d
					matchedDirectives = &dCopy
					break
				}
			}

			if matchedDirectives != nil {
				if !matchedDirectives.Analyze {
					// Function's candidates were skipped by policy
					continue
				}
				mode = matchedDirectives.Mode
				maxDepth = matchedDirectives.MaxDepth
			}
		}

		ft := flow.NewBoundedFlowTracker(maxDepth)

		// Track function parameters if they are HTTP handlers or general inputs
		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				typeStr := exprToString(field.Type)
				if strings.Contains(typeStr, "http.Request") {
					for _, name := range field.Names {
						// Marker for request object
						ft.IntroduceSource(name.Name, analyzer.Source{
							Type:   analyzer.SourceHTTPInput,
							Name:   name.Name,
							Line:   fset.Position(name.Pos()).Line,
							Column: fset.Position(name.Pos()).Column,
							Detail: "HTTP Request parameter",
						})
					}
				}
			}
		}

		var funcEvidences []analyzer.Evidence

		// Walk through statements in the function body
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				return true
			}

			switch stmt := n.(type) {
			case *ast.AssignStmt:
				ga.handleAssignStmt(stmt, fset, ft, filePath, &funcEvidences)

			case *ast.ExprStmt:
				if call, ok := stmt.X.(*ast.CallExpr); ok {
					ga.handleCallExpr(call, fset, ft, filePath, &funcEvidences)
				}
			}

			return true
		})

		for i := range funcEvidences {
			if matchedDirectives != nil {
				funcEvidences[i].CandidateID = matchedDirectives.CandidateID
				funcEvidences[i].Mode = mode
			} else {
				funcEvidences[i].Mode = "deep"
			}
		}

		evidences = append(evidences, funcEvidences...)
	}

	return evidences, nil
}

func sanitizeIdentifier(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func (ga *GoAnalyzer) handleAssignStmt(
	stmt *ast.AssignStmt,
	fset *token.FileSet,
	ft *flow.FlowTracker,
	filePath string,
	evidences *[]analyzer.Evidence,
) {
	for i, rhs := range stmt.Rhs {
		var lhsName string
		if i < len(stmt.Lhs) {
			lhsName = exprToString(stmt.Lhs[i])
		}

		// 1. Check if RHS is a Source
		if src, ok := MatchSource(rhs, fset); ok {
			if lhsName != "" {
				ft.IntroduceSource(lhsName, *src)
			}
			continue
		}

		// 2. Check if RHS is a Sink (e.g. out, err := exec.Command(...).Output())
		if call, ok := rhs.(*ast.CallExpr); ok {
			ga.handleCallExpr(call, fset, ft, filePath, evidences)
		}

		// 3. Check for Hardcoded Secret pattern in assignment
		if lhsName != "" && secretKeyRegex.MatchString(lhsName) {
			if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				val := strings.Trim(lit.Value, `"'` + "`")
				if len(val) >= 6 && !strings.Contains(val, " ") && !strings.Contains(val, "%") {
					pos := fset.Position(stmt.Pos())
					*evidences = append(*evidences, analyzer.Evidence{
						File:     filePath,
						Line:     pos.Line,
						Column:   pos.Column,
						Language: "go",
						Source: analyzer.Source{
							Type:   analyzer.SourceHardcoded,
							Name:   lhsName,
							Line:   pos.Line,
							Column: pos.Column,
							Detail: "Hardcoded secret string assigned to variable",
						},
						Sink: analyzer.Sink{
							Type:   analyzer.SinkShell, // Hardcoded credential sink marker
							Name:   lhsName,
							Line:   pos.Line,
							Column: pos.Column,
							Detail: "Secret in source code",
						},
						FlowSteps: []string{
							"Hardcoded secret literal assigned to " + lhsName,
						},
						Code: exprToString(stmt),
					})
				}
			}
		}

		// 4. Check for Taint Propagation (BinaryExpr, Sprintf, CallExpr)
		if lhsName != "" {
			vars := extractVariables(rhs)
			if node, isTainted := ft.IsTainted(vars...); isTainted {
				opType := "assignment"
				switch rhs.(type) {
				case *ast.BinaryExpr:
					opType = "concatenation"
				case *ast.CallExpr:
					if strings.Contains(exprToString(rhs), "Sprintf") {
						opType = "format_string"
					} else {
						opType = "function_call"
					}
				}

				pos := fset.Position(stmt.Pos())
				ft.Propagate(lhsName, []string{node.VarName}, analyzer.Operation{
					Type:   opType,
					Detail: exprToString(rhs),
					Line:   pos.Line,
				})
			}
		}
	}
}

func (ga *GoAnalyzer) handleCallExpr(
	call *ast.CallExpr,
	fset *token.FileSet,
	ft *flow.FlowTracker,
	filePath string,
	evidences *[]analyzer.Evidence,
) {
	// Recursively check if receiver or arguments contain nested calls
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if innerCall, ok := sel.X.(*ast.CallExpr); ok {
			ga.handleCallExpr(innerCall, fset, ft, filePath, evidences)
		}
	}
	for _, arg := range call.Args {
		if innerCall, ok := arg.(*ast.CallExpr); ok {
			ga.handleCallExpr(innerCall, fset, ft, filePath, evidences)
		}
	}

	sink, argsToCheck, ok := MatchSink(call, fset)
	if !ok {
		return
	}

	// Check if any argument is tainted or is directly a source
	for _, arg := range argsToCheck {
		// Case A: Argument is directly a source call
		if src, isSrc := MatchSource(arg, fset); isSrc {
			*evidences = append(*evidences, analyzer.Evidence{
				File:     filePath,
				Line:     sink.Line,
				Column:   sink.Column,
				Language: "go",
				Source:   *src,
				Sink:     *sink,
				FlowSteps: []string{
					"source: " + src.Name,
					"sink: " + sink.Name,
				},
				Code: renderNode(fset, call),
			})
			return
		}

		// Case B: Argument uses tainted variable(s)
		vars := extractVariables(arg)
		if taintedNode, isTainted := ft.IsTainted(vars...); isTainted {
			ev := ft.BuildEvidence(filePath, *sink, taintedNode, renderNode(fset, call))
			ev.Language = "go"
			*evidences = append(*evidences, ev)
			return
		}
	}
}

// Helper: converts AST Expr to clean string representation
func exprToString(node ast.Node) string {
	return renderNode(token.NewFileSet(), node)
}

// Helper: formats node using the provided FileSet
func renderNode(fset *token.FileSet, node ast.Node) string {
	if node == nil {
		return ""
	}
	if fset == nil {
		fset = token.NewFileSet()
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}

// Helper: extracts variable identifiers used in an expression
func extractVariables(expr ast.Expr) []string {
	var vars []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			vars = append(vars, id.Name)
		}
		return true
	})
	return vars
}
