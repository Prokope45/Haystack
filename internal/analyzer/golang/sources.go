package golang

import (
	"go/ast"
	"go/token"
	"strings"

	"haystack/internal/analyzer"
)

// MatchSource inspects an AST expression to determine if it produces untrusted input.
func MatchSource(expr ast.Expr, fset *token.FileSet) (*analyzer.Source, bool) {
	if expr == nil {
		return nil, false
	}

	pos := fset.Position(expr.Pos())

	switch e := expr.(type) {
	case *ast.CallExpr:
		callStr := exprToString(e.Fun)

		// HTTP Sources
		if strings.Contains(callStr, "URL.Query().Get") ||
			strings.HasSuffix(callStr, ".FormValue") ||
			strings.HasSuffix(callStr, ".PostFormValue") ||
			strings.Contains(callStr, "Header.Get") {
			return &analyzer.Source{
				Type:   analyzer.SourceHTTPInput,
				Name:   callStr,
				Line:   pos.Line,
				Column: pos.Column,
				Detail: "HTTP request parameter or header",
			}, true
		}

		if callStr == "io.ReadAll" || callStr == "ioutil.ReadAll" {
			if len(e.Args) > 0 && strings.Contains(exprToString(e.Args[0]), "Body") {
				return &analyzer.Source{
					Type:   analyzer.SourceHTTPInput,
					Name:   callStr + "(r.Body)",
					Line:   pos.Line,
					Column: pos.Column,
					Detail: "HTTP request body read",
				}, true
			}
		}

		// Environment Variables
		if callStr == "os.Getenv" {
			return &analyzer.Source{
				Type:   analyzer.SourceEnvironment,
				Name:   "os.Getenv",
				Line:   pos.Line,
				Column: pos.Column,
				Detail: "Environment variable read",
			}, true
		}

		// File Input
		if callStr == "os.ReadFile" || callStr == "ioutil.ReadFile" {
			return &analyzer.Source{
				Type:   analyzer.SourceFileInput,
				Name:   callStr,
				Line:   pos.Line,
				Column: pos.Column,
				Detail: "File read",
			}, true
		}

	case *ast.IndexExpr:
		// CLI arguments e.g. os.Args[1]
		if exprToString(e.X) == "os.Args" {
			return &analyzer.Source{
				Type:   analyzer.SourceCLIInput,
				Name:   "os.Args",
				Line:   pos.Line,
				Column: pos.Column,
				Detail: "Command line argument",
			}, true
		}
	}

	return nil, false
}
