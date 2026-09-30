package golang

import (
	"fmt"
	"go/ast"
	"strings"
)

// invoke evaluates one function with mapped inputs while enforcing recursion and resource limits.
func (p *interproceduralGoAnalyzer) invoke(
	fn *ast.FuncDecl,
	inputs map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
) (*interproceduralTaint, []interproceduralTaint) {
	if fn == nil || depth > p.maxCalls || stack[fn] || p.invocations >= maxInterproceduralInvocations || p.ctx.Err() != nil {
		return nil, nil
	}
	p.invocations++
	stack[fn] = true
	defer delete(stack, fn)

	state := make(map[string]*interproceduralTaint, len(inputs)+8)
	for name, taint := range inputs {
		state[name] = taint
	}

	var returned []interproceduralTaint
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil || p.ctx.Err() != nil || p.invocations >= maxInterproceduralInvocations {
			return false
		}
		switch stmt := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			p.processGoAssignment(stmt, state, depth, stack, crossed)
			return false
		case *ast.DeclStmt:
			p.processGoDeclaration(stmt, state, depth, stack, crossed)
			return false
		case *ast.ExprStmt:
			p.eval(stmt.X, state, depth, stack, crossed)
			return false
		case *ast.ReturnStmt:
			for _, result := range stmt.Results {
				taint := p.eval(result, state, depth, stack, crossed)
				if call, ok := result.(*ast.CallExpr); ok && len(p.callReturns[call]) > 0 {
					for _, ret := range p.callReturns[call] {
						returned = append(returned, *ret)
					}
				} else if taint != nil {
					returned = append(returned, *taint)
				}
			}
			return false
		}
		return true
	})

	if len(returned) > 0 {
		ret := returned[0]
		return &ret, returned
	}
	return nil, returned
}

// processGoDeclaration evaluates local declarations and binds their taint to declared names.
func (p *interproceduralGoAnalyzer) processGoDeclaration(
	stmt *ast.DeclStmt,
	state map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
) {
	gen, ok := stmt.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		var returned []*interproceduralTaint
		var single *interproceduralTaint
		if len(value.Values) == 1 {
			single = p.eval(value.Values[0], state, depth, stack, crossed)
			if call, isCall := value.Values[0].(*ast.CallExpr); isCall {
				returned = p.callReturns[call]
			}
		}
		for i, name := range value.Names {
			delete(state, name.Name)
			if len(returned) > 0 {
				if i < len(returned) {
					state[name.Name] = returned[i]
				}
			} else if len(value.Values) > 1 && i < len(value.Values) {
				state[name.Name] = p.eval(value.Values[i], state, depth, stack, crossed)
			} else if len(value.Values) == 1 {
				state[name.Name] = single
			}
		}
	}
}

// processGoAssignment evaluates right-hand sides and updates taint for each left-hand side.
func (p *interproceduralGoAnalyzer) processGoAssignment(
	stmt *ast.AssignStmt,
	state map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
) {
	values := make([]*interproceduralTaint, 0, len(stmt.Rhs))
	for _, rhs := range stmt.Rhs {
		values = append(values, p.eval(rhs, state, depth, stack, crossed))
	}
	for i, lhs := range stmt.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
			continue
		}
		name := exprToString(lhs)
		delete(state, name)
		if len(stmt.Rhs) == 1 {
			if call, ok := stmt.Rhs[0].(*ast.CallExpr); ok && len(p.callReturns[call]) > 0 {
				if i < len(p.callReturns[call]) {
					state[name] = p.callReturns[call][i]
				}
			} else if len(values) > 0 {
				state[name] = values[0]
			}
		} else if i < len(values) {
			state[name] = values[i]
		}
	}
}

// eval interprets an expression, propagating taint and recording crossed flows at sinks.
func (p *interproceduralGoAnalyzer) eval(
	expr ast.Expr,
	state map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
) *interproceduralTaint {
	if expr == nil || p.ctx.Err() != nil {
		return nil
	}
	if source, ok := MatchSource(expr, p.fset); ok {
		return newInterproceduralTaint(*source)
	}

	switch value := expr.(type) {
	case *ast.Ident:
		return state[value.Name]
	case *ast.CallExpr:
		if sink, args, ok := MatchSink(value, p.fset); ok {
			for _, arg := range args {
				taint := p.eval(arg, state, depth, stack, crossed)
				if taint != nil && taint.crossed {
					p.addEvidence(*sink, *taint, renderNode(p.fset, value))
					break
				}
			}
			return nil
		}
		if callee := p.resolveCall(value); callee != nil && depth < p.maxCalls {
			arguments := p.callInputs(value, callee, state, depth, stack, crossed)
			_, returned := p.invoke(callee, arguments, depth+1, stack, crossed)
			results := make([]*interproceduralTaint, 0, len(returned))
			for _, ret := range returned {
				if result := p.withOperation(ret, "return_value", fmt.Sprintf("%s returns to caller", callee.Name.Name), p.fset.Position(value.Pos()).Line, true); result != nil {
					results = append(results, result)
				}
			}
			p.callReturns[value] = results
			if len(results) > 0 {
				return results[0]
			}
			return nil
		}
		if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
			p.eval(selector.X, state, depth, stack, crossed)
		}
		var derived *interproceduralTaint
		for _, arg := range value.Args {
			if taint := p.eval(arg, state, depth, stack, crossed); taint != nil && derived == nil {
				derived = taint
			}
		}
		if derived != nil {
			return p.withOperation(*derived, "function_call", renderNode(p.fset, value), p.fset.Position(value.Pos()).Line, crossed)
		}
		return nil
	case *ast.SelectorExpr:
		if taint := state[exprToString(value)]; taint != nil {
			return taint
		}
		return p.eval(value.X, state, depth, stack, crossed)
	case *ast.ParenExpr:
		return p.eval(value.X, state, depth, stack, crossed)
	case *ast.BinaryExpr:
		return p.combine(value, state, depth, stack, crossed, "concatenation")
	case *ast.UnaryExpr:
		return p.eval(value.X, state, depth, stack, crossed)
	case *ast.CompositeLit:
		return p.combine(value, state, depth, stack, crossed, "composite_value")
	case *ast.KeyValueExpr:
		if taint := p.eval(value.Value, state, depth, stack, crossed); taint != nil {
			return p.withOperation(*taint, "field_assignment", exprToString(value), p.fset.Position(value.Pos()).Line, crossed)
		}
		return p.eval(value.Key, state, depth, stack, crossed)
	case *ast.IndexExpr:
		if taint := p.eval(value.X, state, depth, stack, crossed); taint != nil {
			return taint
		}
		return p.eval(value.Index, state, depth, stack, crossed)
	case *ast.SliceExpr:
		return p.eval(value.X, state, depth, stack, crossed)
	case *ast.StarExpr:
		return p.eval(value.X, state, depth, stack, crossed)
	}
	return nil
}

// combine finds taint inside a compound expression and adds its transformation operation.
func (p *interproceduralGoAnalyzer) combine(
	expr ast.Expr,
	state map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
	op string,
) *interproceduralTaint {
	var result *interproceduralTaint
	ast.Inspect(expr, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		if _, nested := n.(*ast.CallExpr); nested {
			if taint := p.eval(n.(ast.Expr), state, depth, stack, crossed); taint != nil && result == nil {
				result = taint
			}
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			if taint := state[id.Name]; taint != nil && result == nil {
				result = taint
			}
			return false
		}
		return true
	})
	if result != nil {
		return p.withOperation(*result, op, renderNode(p.fset, expr), p.fset.Position(expr.Pos()).Line, crossed)
	}
	return nil
}

// callInputs maps tainted actual arguments and tracked fields onto callee parameters.
func (p *interproceduralGoAnalyzer) callInputs(
	call *ast.CallExpr,
	callee *ast.FuncDecl,
	state map[string]*interproceduralTaint,
	depth int,
	stack map[*ast.FuncDecl]bool,
	crossed bool,
) map[string]*interproceduralTaint {
	inputs := make(map[string]*interproceduralTaint)
	params := make([]*ast.Field, 0)
	if callee.Recv != nil {
		params = append(params, callee.Recv.List...)
	}
	if callee.Type.Params != nil {
		params = append(params, callee.Type.Params.List...)
	}
	actuals := append([]ast.Expr(nil), call.Args...)
	if callee.Recv != nil {
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			actuals = append([]ast.Expr{selector.X}, actuals...)
		}
	}
	paramIndex := 0
	for _, field := range params {
		if len(field.Names) == 0 {
			paramIndex++
			continue
		}
		for _, name := range field.Names {
			if paramIndex < len(actuals) {
				actual := actuals[paramIndex]
				if taint := p.eval(actual, state, depth, stack, crossed); taint != nil {
					if passed := p.withOperation(*taint, "argument_passing", fmt.Sprintf("%s -> %s", expressionFunctionName(call.Fun), name.Name), p.fset.Position(actuals[paramIndex].Pos()).Line, true); passed != nil {
						inputs[name.Name] = passed
					}
				}
				fieldPrefix := exprToString(actual) + "."
				for actualField, taint := range state {
					if !strings.HasPrefix(actualField, fieldPrefix) || taint == nil {
						continue
					}
					fieldName := name.Name + actualField[len(exprToString(actual)):]
					if passed := p.withOperation(*taint, "argument_passing", fmt.Sprintf("%s -> %s", expressionFunctionName(call.Fun), fieldName), p.fset.Position(actual.Pos()).Line, true); passed != nil {
						inputs[fieldName] = passed
					}
				}
			}
			paramIndex++
		}
	}
	return inputs
}
