package golang

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"regexp"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/flow"
)

var secretKeyRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|passwd|password|private[_-]?key)`)

// functionAnalysis owns the tracker and evidence collected for one function body.
type functionAnalysis struct {
	fset        *token.FileSet
	filePath    string
	flowTracker *flow.FlowTracker
	evidences   []analyzer.Evidence
}

// analyze walks one function body and dispatches local assignments and expression calls.
func (scope *functionAnalysis) analyze(body *ast.BlockStmt) {
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			scope.handleAssignStmt(stmt)
		case *ast.ExprStmt:
			if call, ok := stmt.X.(*ast.CallExpr); ok {
				scope.handleCallExpr(call)
			}
		}
		return true
	})
}

// handleAssignStmt introduces sources, checks nested sinks and secrets, then propagates taint.
func (scope *functionAnalysis) handleAssignStmt(stmt *ast.AssignStmt) {
	for i, rhs := range stmt.Rhs {
		var lhsName string
		if i < len(stmt.Lhs) {
			lhsName = exprToString(stmt.Lhs[i])
		}

		if scope.introduceSource(lhsName, rhs) {
			continue
		}

		if call, ok := rhs.(*ast.CallExpr); ok {
			scope.handleCallExpr(call)
		}
		scope.recordHardcodedSecret(stmt, lhsName, rhs)
		scope.propagateAssignment(stmt, lhsName, rhs)
	}
}

// introduceSource seeds the local tracker when rhs is recognized as an input source.
func (scope *functionAnalysis) introduceSource(lhsName string, rhs ast.Expr) bool {
	source, ok := MatchSource(rhs, scope.fset)
	if !ok {
		return false
	}
	if lhsName != "" {
		scope.flowTracker.IntroduceSource(lhsName, *source)
	}
	return true
}

// recordHardcodedSecret emits evidence for qualifying string literals assigned to secret-like names.
func (scope *functionAnalysis) recordHardcodedSecret(stmt *ast.AssignStmt, lhsName string, rhs ast.Expr) {
	if lhsName == "" || !secretKeyRegex.MatchString(lhsName) {
		return
	}
	literal, ok := rhs.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return
	}
	value := strings.Trim(literal.Value, "'\"`")
	if len(value) < 6 || strings.Contains(value, " ") || strings.Contains(value, "%") {
		return
	}
	position := scope.fset.Position(stmt.Pos())
	scope.evidences = append(scope.evidences, analyzer.Evidence{
		File:     scope.filePath,
		Line:     position.Line,
		Column:   position.Column,
		Language: "go",
		Source: analyzer.Source{
			Type: analyzer.SourceHardcoded, Name: lhsName,
			Line: position.Line, Column: position.Column,
			Detail: "Hardcoded secret string assigned to variable",
		},
		Sink: analyzer.Sink{
			Type: analyzer.SinkShell, // Hardcoded credential sink marker
			Name: lhsName, Line: position.Line, Column: position.Column,
			Detail: "Secret in source code",
		},
		FlowSteps: []string{"Hardcoded secret literal assigned to " + lhsName},
		Code:      exprToString(stmt),
	})
}

// propagateAssignment carries tracked taint to lhs and labels the assignment operation.
func (scope *functionAnalysis) propagateAssignment(stmt *ast.AssignStmt, lhsName string, rhs ast.Expr) {
	if lhsName == "" {
		return
	}
	variables := extractVariables(rhs)
	if node, isTainted := scope.flowTracker.IsTainted(variables...); isTainted {
		operationType := "assignment"
		switch rhs.(type) {
		case *ast.BinaryExpr:
			operationType = "concatenation"
		case *ast.CallExpr:
			if strings.Contains(exprToString(rhs), "Sprintf") {
				operationType = "format_string"
			} else {
				operationType = "function_call"
			}
		}

		position := scope.fset.Position(stmt.Pos())
		scope.flowTracker.Propagate(lhsName, []string{node.VarName}, analyzer.Operation{
			Type: operationType, Detail: exprToString(rhs), Line: position.Line,
		})
	}
}

// handleCallExpr visits nested calls and records evidence when a sink argument is tainted.
func (scope *functionAnalysis) handleCallExpr(call *ast.CallExpr) {
	// Recursively check if receiver or arguments contain nested calls.
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if innerCall, ok := sel.X.(*ast.CallExpr); ok {
			scope.handleCallExpr(innerCall)
		}
	}
	for _, arg := range call.Args {
		if innerCall, ok := arg.(*ast.CallExpr); ok {
			scope.handleCallExpr(innerCall)
		}
	}

	sink, argsToCheck, ok := MatchSink(call, scope.fset)
	if !ok {
		return
	}

	for _, arg := range argsToCheck {
		if src, isSource := MatchSource(arg, scope.fset); isSource {
			scope.recordDirectSourceFlow(call, *sink, *src)
			return
		}

		variables := extractVariables(arg)
		if taintedNode, isTainted := scope.flowTracker.IsTainted(variables...); isTainted {
			scope.recordTaintedFlow(call, *sink, taintedNode)
			return
		}
	}
}

// recordDirectSourceFlow emits evidence when a sink argument is itself a recognized source.
func (scope *functionAnalysis) recordDirectSourceFlow(call *ast.CallExpr, sink analyzer.Sink, source analyzer.Source) {
	scope.evidences = append(scope.evidences, analyzer.Evidence{
		File: scope.filePath, Line: sink.Line, Column: sink.Column, Language: "go",
		Source: source, Sink: sink,
		FlowSteps: []string{"source: " + source.Name, "sink: " + sink.Name},
		Code:      renderNode(scope.fset, call),
	})
}

// recordTaintedFlow builds sink evidence from an existing local taint-tracker node.
func (scope *functionAnalysis) recordTaintedFlow(call *ast.CallExpr, sink analyzer.Sink, source *flow.TaintNode) {
	evidence := scope.flowTracker.BuildEvidence(scope.filePath, sink, source, renderNode(scope.fset, call))
	evidence.Language = "go"
	scope.evidences = append(scope.evidences, evidence)
}

// exprToString formats an AST node using a temporary file set.
func exprToString(node ast.Node) string {
	return renderNode(token.NewFileSet(), node)
}

// renderNode formats an AST node with the supplied file set for evidence details.
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

// extractVariables returns identifiers encountered while walking an expression.
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
