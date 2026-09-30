package golang

import (
	"go/ast"
	"go/token"
	"strings"
)

// sourceRoots finds source-bearing functions and callers that can reach them.
func (p *interproceduralGoAnalyzer) sourceRoots() []*ast.FuncDecl {
	sourceFunctions := make(map[*ast.FuncDecl]bool)
	callers := make(map[*ast.FuncDecl][]*ast.FuncDecl)
	for _, fn := range p.declarations {
		if functionHasDirectSource(fn, p.fset) {
			sourceFunctions[fn] = true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callee := p.resolveCall(call); callee != nil {
				callers[callee] = append(callers[callee], fn)
			}
			return true
		})
	}

	roots := make(map[*ast.FuncDecl]bool)
	queue := make([]*ast.FuncDecl, 0, len(sourceFunctions))
	for fn := range sourceFunctions {
		roots[fn] = true
		queue = append(queue, fn)
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for _, caller := range callers[fn] {
			if !roots[caller] {
				roots[caller] = true
				queue = append(queue, caller)
			}
		}
	}

	result := make([]*ast.FuncDecl, 0, len(roots))
	for _, fn := range p.declarations {
		if roots[fn] {
			result = append(result, fn)
		}
	}
	return result
}

// functionHasDirectSource recognizes request-typed parameters and matched source expressions.
func functionHasDirectSource(fn *ast.FuncDecl, fset *token.FileSet) bool {
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			if strings.Contains(exprToString(field.Type), "http.Request") {
				return true
			}
		}
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if expr, ok := n.(ast.Expr); ok {
			if _, match := MatchSource(expr, fset); match {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}

// resolveCall returns an unambiguous same-file function or method declaration, if available.
func (p *interproceduralGoAnalyzer) resolveCall(call *ast.CallExpr) *ast.FuncDecl {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		var matches []*ast.FuncDecl
		for _, candidate := range p.functions[fun.Name] {
			if candidate.Recv == nil {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			return matches[0]
		}
	case *ast.SelectorExpr:
		var matches []*ast.FuncDecl
		for _, candidate := range p.functions[fun.Sel.Name] {
			if candidate.Recv != nil {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			return matches[0]
		}
	default:
	}
	// Without type information, only resolve an unambiguous same-file function
	// or method; package selectors and ambiguous methods remain unresolved.
	return nil
}
