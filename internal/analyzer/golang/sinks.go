package golang

import (
	"go/ast"
	"go/token"
	"strings"

	"haystack/internal/analyzer"
)

// MatchSink inspects an AST CallExpr to determine if it is a security-sensitive sink.
func MatchSink(call *ast.CallExpr, fset *token.FileSet) (*analyzer.Sink, []ast.Expr, bool) {
	if call == nil {
		return nil, nil, false
	}

	callStr := exprToString(call.Fun)
	pos := fset.Position(call.Pos())

	// Shell Execution Sinks
	if callStr == "exec.Command" || callStr == "exec.CommandContext" {
		return &analyzer.Sink{
			Type:   analyzer.SinkShell,
			Name:   callStr,
			Line:   pos.Line,
			Column: pos.Column,
			Detail: "Command execution sink via os/exec",
		}, call.Args, true
	}

	// SQL Sinks (e.g. db.Query, db.Exec, db.QueryRow, tx.Query, etc.)
	if strings.HasSuffix(callStr, ".Query") ||
		strings.HasSuffix(callStr, ".QueryRow") ||
		strings.HasSuffix(callStr, ".Exec") ||
		strings.HasSuffix(callStr, ".ExecContext") ||
		strings.HasSuffix(callStr, ".QueryContext") ||
		strings.HasSuffix(callStr, ".QueryRowContext") {
		// Only consider as SQL if the first argument (query string) is dynamic
		if len(call.Args) > 0 {
			return &analyzer.Sink{
				Type:   analyzer.SinkSQL,
				Name:   callStr,
				Line:   pos.Line,
				Column: pos.Column,
				Detail: "Database query execution sink",
			}, call.Args[:1], true // Focus on query argument
		}
	}

	// Filesystem Sinks
	if callStr == "os.Open" || callStr == "os.Create" ||
		callStr == "os.ReadFile" || callStr == "os.WriteFile" ||
		callStr == "os.Remove" || callStr == "os.RemoveAll" {
		return &analyzer.Sink{
			Type:   analyzer.SinkFilesystem,
			Name:   callStr,
			Line:   pos.Line,
			Column: pos.Column,
			Detail: "Filesystem operation sink",
		}, call.Args, true
	}

	return nil, nil, false
}
