package golang

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/flow"
)

// GoAnalyzer implements the analyzer.Analyzer interface for Go source files.
type GoAnalyzer struct {
	directives map[string]analyzer.AnalysisDirectives
}

// NewGoAnalyzer constructs a Go analyzer with no candidate-specific directives.
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{}
}

// SetDirectives installs the candidate policies used during analysis.
func (ga *GoAnalyzer) SetDirectives(directives map[string]analyzer.AnalysisDirectives) {
	ga.directives = directives
}

// Language returns the language identifier used in emitted evidence.
func (ga *GoAnalyzer) Language() string {
	return "go"
}

// Supports reports whether path has a Go source-file extension.
func (ga *GoAnalyzer) Supports(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".go"
}

// Analyze parses a Go file, runs local and interprocedural analysis, and merges their evidence.
func (ga *GoAnalyzer) Analyze(ctx context.Context, source []byte, filePath string) ([]analyzer.Evidence, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, source, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	evidences := ga.analyzeFunctions(fset, node, filePath)

	interproceduralEvidences := analyzeGoInterprocedural(ctx, fset, node, filePath, ga.directives)
	return mergeEvidence(evidences, interproceduralEvidences), nil
}

// analyzeFunctions runs the directive-aware local pass for each function body.
func (ga *GoAnalyzer) analyzeFunctions(fset *token.FileSet, file *ast.File, filePath string) []analyzer.Evidence {
	var evidences []analyzer.Evidence
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		directive := ga.directiveForFunction(fn.Name.Name, filePath)
		if directive != nil && !directive.Analyze {
			continue
		}
		evidences = append(evidences, ga.analyzeFunction(fset, fn, filePath, directive)...)
	}
	return evidences
}

// directiveForFunction returns a matching file/function directive; map iteration selects among matches.
func (ga *GoAnalyzer) directiveForFunction(functionName, filePath string) *analyzer.AnalysisDirectives {
	baseNameSanitized := sanitizeIdentifier(filepath.Base(filePath))
	for key, directive := range ga.directives {
		if strings.Contains(key, baseNameSanitized) && strings.Contains(key, functionName) {
			matched := directive
			return &matched
		}
	}
	return nil
}

// analyzeFunction runs the local flow tracker for one function and applies its directive metadata.
func (ga *GoAnalyzer) analyzeFunction(
	fset *token.FileSet,
	fn *ast.FuncDecl,
	filePath string,
	directive *analyzer.AnalysisDirectives,
) []analyzer.Evidence {
	maxDepth := 0
	if directive != nil {
		maxDepth = directive.MaxDepth
	}

	scope := &functionAnalysis{
		fset:        fset,
		filePath:    filePath,
		flowTracker: flow.NewBoundedFlowTracker(maxDepth),
	}
	scope.analyze(fn.Body)

	for i := range scope.evidences {
		if directive != nil {
			scope.evidences[i].CandidateID = directive.CandidateID
			scope.evidences[i].Mode = directive.Mode
		} else {
			scope.evidences[i].Mode = "deep"
		}
	}
	return scope.evidences
}

// mergeEvidence combines equivalent local and interprocedural flows, preferring the longer trace.
func mergeEvidence(local, interprocedural []analyzer.Evidence) []analyzer.Evidence {
	evidences := append([]analyzer.Evidence(nil), local...)
	for _, candidate := range interprocedural {
		matched := false
		for i := range evidences {
			if !sameEvidenceFlow(evidences[i], candidate) {
				continue
			}
			if len(candidate.Operations) > len(evidences[i].Operations) {
				evidences[i] = candidate
			}
			matched = true
			break
		}
		if !matched {
			evidences = append(evidences, candidate)
		}
	}
	return evidences
}

// sameEvidenceFlow compares evidence identity by source and sink type, name, and location.
func sameEvidenceFlow(left, right analyzer.Evidence) bool {
	return left.Source.Type == right.Source.Type && left.Source.Name == right.Source.Name &&
		left.Source.Line == right.Source.Line && left.Source.Column == right.Source.Column &&
		left.Sink.Type == right.Sink.Type && left.Sink.Name == right.Sink.Name &&
		left.Sink.Line == right.Sink.Line && left.Sink.Column == right.Sink.Column
}

// sanitizeIdentifier normalizes path fragments for matching candidate identifiers.
func sanitizeIdentifier(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
