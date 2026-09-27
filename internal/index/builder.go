package index

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/analyzer/golang"
)

// Indexer builds a ProgramIndex from source files and contents.
type Indexer struct {
	index *ProgramIndex
}

// NewIndexer creates an Indexer targeting a fresh ProgramIndex.
func NewIndexer() *Indexer {
	return &Indexer{
		index: NewProgramIndex(),
	}
}

// Index returns the accumulated ProgramIndex.
func (b *Indexer) Index() *ProgramIndex {
	return b.index
}

// IndexFile parses and indexes a single source file content.
func (b *Indexer) IndexFile(filePath string, relPath string, content []byte) error {
	ext := strings.ToLower(filepath.Ext(filePath))
	lang := "unknown"

	switch ext {
	case ".go":
		lang = "go"
		b.index.Files = append(b.index.Files, FileInfo{
			Path:     filePath,
			RelPath:  relPath,
			Language: lang,
			Size:     int64(len(content)),
		})
		return b.indexGo(filePath, relPath, content)

	case ".py":
		lang = "python"
		b.index.Files = append(b.index.Files, FileInfo{
			Path:     filePath,
			RelPath:  relPath,
			Language: lang,
			Size:     int64(len(content)),
		})
		return b.indexPython(filePath, relPath, content)

	default:
		return nil
	}
}

func (b *Indexer) indexGo(filePath string, relPath string, content []byte) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("go parser error in %s: %w", filePath, err)
	}

	displayFile := relPath
	if displayFile == "" {
		displayFile = filePath
	}

	// 1. Imports
	for _, imp := range node.Imports {
		pathVal := strings.Trim(imp.Path.Value, `"`)
		b.index.Imports = append(b.index.Imports, ImportInfo{
			File: displayFile,
			Path: pathVal,
		})
	}

	// 2. Declarations (Functions / Methods)
	for _, decl := range node.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		fnName := fn.Name.Name
		startPos := fset.Position(fn.Pos())
		endPos := fset.Position(fn.End())

		var params []string
		isHandler := false

		if fn.Type.Params != nil {
			for _, field := range fn.Type.Params.List {
				typeStr := renderASTNode(fset, field.Type)
				if strings.Contains(typeStr, "http.Request") {
					isHandler = true
					for _, name := range field.Names {
						params = append(params, name.Name)
						// HTTP handler parameter is a source
						pos := fset.Position(name.Pos())
						b.index.Sources = append(b.index.Sources, SourceInfo{
							File:     displayFile,
							Function: fnName,
							Source: analyzer.Source{
								Type:   analyzer.SourceHTTPInput,
								Name:   name.Name,
								Line:   pos.Line,
								Column: pos.Column,
								Detail: "HTTP Request handler parameter",
							},
						})
					}
				} else {
					for _, name := range field.Names {
						params = append(params, name.Name)
					}
				}
			}
		}

		b.index.Functions = append(b.index.Functions, FunctionInfo{
			File:       displayFile,
			Name:       fnName,
			StartLine:  startPos.Line,
			EndLine:    endPos.Line,
			Parameters: params,
			IsHandler:  isHandler,
		})

		// Walk function body to detect calls, sources, and sinks
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n == nil {
				return true
			}

			switch stmt := n.(type) {
			case *ast.AssignStmt:
				for _, rhs := range stmt.Rhs {
					if src, isSrc := golang.MatchSource(rhs, fset); isSrc {
						b.index.Sources = append(b.index.Sources, SourceInfo{
							File:     displayFile,
							Function: fnName,
							Source:   *src,
						})
					}
				}

			case *ast.CallExpr:
				callName := renderASTNode(fset, stmt.Fun)
				pos := fset.Position(stmt.Pos())

				b.index.Calls = append(b.index.Calls, CallInfo{
					File:     displayFile,
					Function: fnName,
					Caller:   fnName,
					Callee:   callName,
					Line:     pos.Line,
					Column:   pos.Column,
				})

				// Check if call is a source
				if src, isSrc := golang.MatchSource(stmt, fset); isSrc {
					b.index.Sources = append(b.index.Sources, SourceInfo{
						File:     displayFile,
						Function: fnName,
						Source:   *src,
					})
				}

				// Check if call is a sink
				if sink, _, isSink := golang.MatchSink(stmt, fset); isSink {
					b.index.Sinks = append(b.index.Sinks, SinkInfo{
						File:     displayFile,
						Function: fnName,
						Sink:     *sink,
					})
				}

			case *ast.Ident:
				pos := fset.Position(stmt.Pos())
				b.index.References = append(b.index.References, ReferenceInfo{
					File:     displayFile,
					Function: fnName,
					Name:     stmt.Name,
					Line:     pos.Line,
				})
			}

			return true
		})
	}

	return nil
}

var (
	pyDefRegex    = regexp.MustCompile(`(?m)^\s*def\s+([a-zA-Z0-9_]+)\s*\((.*?)\):`)
	pyImportRegex = regexp.MustCompile(`(?m)^\s*(?:import\s+([a-zA-Z0-9_., ]+)|from\s+([a-zA-Z0-9_.]+)\s+import)`)
)

func (b *Indexer) indexPython(filePath string, relPath string, content []byte) error {
	displayFile := relPath
	if displayFile == "" {
		displayFile = filePath
	}

	lines := strings.Split(string(content), "\n")
	currentFunc := "global"

	for lineIdx, line := range lines {
		lineNum := lineIdx + 1
		trimmed := strings.TrimSpace(line)

		// 1. Function definitions
		if matches := pyDefRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentFunc = matches[1]
			rawParams := matches[2]
			var params []string
			if rawParams != "" {
				for _, p := range strings.Split(rawParams, ",") {
					params = append(params, strings.TrimSpace(p))
				}
			}

			b.index.Functions = append(b.index.Functions, FunctionInfo{
				File:       displayFile,
				Name:       currentFunc,
				StartLine:  lineNum,
				EndLine:    lineNum,
				Parameters: params,
				IsHandler:  strings.Contains(currentFunc, "view") || strings.Contains(currentFunc, "handler"),
			})
		}

		// 2. Imports
		if matches := pyImportRegex.FindStringSubmatch(line); len(matches) > 0 {
			imp := matches[1]
			if imp == "" && len(matches) > 2 {
				imp = matches[2]
			}
			if imp != "" {
				b.index.Imports = append(b.index.Imports, ImportInfo{
					File: displayFile,
					Path: strings.TrimSpace(imp),
				})
			}
		}

		// 3. Lightweight Python Sources
		if strings.Contains(trimmed, "request.args") ||
			strings.Contains(trimmed, "request.form") ||
			strings.Contains(trimmed, "request.GET") ||
			strings.Contains(trimmed, "request.POST") ||
			strings.Contains(trimmed, "request.values") {
			b.index.Sources = append(b.index.Sources, SourceInfo{
				File:     displayFile,
				Function: currentFunc,
				Source: analyzer.Source{
					Type:   analyzer.SourceHTTPInput,
					Name:   "request.input",
					Line:   lineNum,
					Column: 1,
					Detail: "Flask/Django HTTP request input",
				},
			})
		} else if strings.Contains(trimmed, "os.environ") || strings.Contains(trimmed, "os.getenv") {
			b.index.Sources = append(b.index.Sources, SourceInfo{
				File:     displayFile,
				Function: currentFunc,
				Source: analyzer.Source{
					Type:   analyzer.SourceEnvironment,
					Name:   "os.environ",
					Line:   lineNum,
					Column: 1,
					Detail: "Environment variable",
				},
			})
		}

		// 4. Lightweight Python Sinks
		if strings.Contains(trimmed, "subprocess.run") ||
			strings.Contains(trimmed, "subprocess.Popen") ||
			strings.Contains(trimmed, "subprocess.call") ||
			strings.Contains(trimmed, "subprocess.check_output") ||
			strings.Contains(trimmed, "os.system") ||
			strings.Contains(trimmed, "os.popen") {
			b.index.Sinks = append(b.index.Sinks, SinkInfo{
				File:     displayFile,
				Function: currentFunc,
				Sink: analyzer.Sink{
					Type:   analyzer.SinkShell,
					Name:   "subprocess/os.system",
					Line:   lineNum,
					Column: 1,
					Detail: "Shell execution sink",
				},
			})
		} else if strings.Contains(trimmed, ".execute(") || strings.Contains(trimmed, ".executemany(") {
			b.index.Sinks = append(b.index.Sinks, SinkInfo{
				File:     displayFile,
				Function: currentFunc,
				Sink: analyzer.Sink{
					Type:   analyzer.SinkSQL,
					Name:   "cursor.execute",
					Line:   lineNum,
					Column: 1,
					Detail: "Database SQL execution sink",
				},
			})
		} else if strings.Contains(trimmed, "open(") || strings.Contains(trimmed, "os.remove(") {
			b.index.Sinks = append(b.index.Sinks, SinkInfo{
				File:     displayFile,
				Function: currentFunc,
				Sink: analyzer.Sink{
					Type:   analyzer.SinkFilesystem,
					Name:   "filesystem_access",
					Line:   lineNum,
					Column: 1,
					Detail: "Filesystem operation sink",
				},
			})
		}
	}

	return nil
}

func renderASTNode(fset *token.FileSet, node ast.Node) string {
	if node == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}
