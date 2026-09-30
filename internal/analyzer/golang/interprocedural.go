package golang

import (
	"context"
	"go/ast"
	"go/token"
	"path/filepath"

	"haystack/internal/analyzer"
)

const (
	defaultInterproceduralDepth   = 5
	maxInterproceduralInvocations = 500
)

// interproceduralTaint carries source lineage and boundary state across function calls.
type interproceduralTaint struct {
	source     analyzer.Source
	operations []analyzer.Operation
	flowSteps  []string
	crossed    bool
}

// interproceduralGoAnalyzer owns indexes, limits, caches, and evidence for one file pass.
type interproceduralGoAnalyzer struct {
	ctx          context.Context
	fset         *token.FileSet
	file         string
	filename     string
	directives   map[string]analyzer.AnalysisDirectives
	functions    map[string][]*ast.FuncDecl
	declarations []*ast.FuncDecl
	maxCalls     int
	maxFlow      int
	invocations  int
	evidence     []analyzer.Evidence
	seen         map[string]struct{}
	callReturns  map[*ast.CallExpr][]*interproceduralTaint
}

// analyzeGoInterprocedural builds an analysis pass, indexes functions, and analyzes source roots.
func analyzeGoInterprocedural(
	ctx context.Context,
	fset *token.FileSet,
	file *ast.File,
	filename string,
	directives map[string]analyzer.AnalysisDirectives,
) []analyzer.Evidence {
	maxCalls := defaultInterproceduralDepth
	for _, directive := range directives {
		if directive.MaxInterproceduralDepth > 0 {
			maxCalls = directive.MaxInterproceduralDepth
		}
	}
	if maxCalls <= 0 {
		return nil
	}

	pass := &interproceduralGoAnalyzer{
		ctx: ctx, fset: fset, file: filename,
		filename: filepath.Base(filename), directives: directives,
		functions: make(map[string][]*ast.FuncDecl),
		maxCalls:  maxCalls, maxFlow: 32,
		callReturns: make(map[*ast.CallExpr][]*interproceduralTaint),
		seen:        make(map[string]struct{}),
	}
	pass.collectFunctions(file)
	pass.analyzeRoots()
	return pass.evidence
}

// collectFunctions indexes body-bearing declarations for same-file call resolution.
func (p *interproceduralGoAnalyzer) collectFunctions(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		p.functions[fn.Name.Name] = append(p.functions[fn.Name.Name], fn)
		p.declarations = append(p.declarations, fn)
	}
}

// analyzeRoots invokes each discovered root until the context is cancelled.
func (p *interproceduralGoAnalyzer) analyzeRoots() {
	for _, fn := range p.sourceRoots() {
		if p.ctx.Err() != nil {
			break
		}
		p.invoke(fn, nil, 0, make(map[*ast.FuncDecl]bool), false)
	}
}
