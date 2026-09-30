package golang

import (
	"fmt"
	"go/ast"
	"strings"

	"haystack/internal/analyzer"
)

// addEvidence deduplicates a cross-function flow and attaches matching candidate metadata.
func (p *interproceduralGoAnalyzer) addEvidence(sink analyzer.Sink, taint interproceduralTaint, code string) {
	key := fmt.Sprintf("%s:%d:%d|%s:%d:%d", taint.source.Name, taint.source.Line, taint.source.Column, sink.Name, sink.Line, sink.Column)
	if _, exists := p.seen[key]; exists {
		return
	}
	p.seen[key] = struct{}{}
	functionName := p.functionAtLine(sink.Line)
	evidence := analyzer.Evidence{
		File: p.file, Line: sink.Line, Column: sink.Column, Language: "go",
		Source: taint.source, Sink: sink, Operations: append([]analyzer.Operation(nil), taint.operations...),
		FlowSteps: append(append([]string(nil), taint.flowSteps...), fmt.Sprintf("sink: %s (%s)", sink.Name, sink.Type)),
		Code:      strings.TrimSpace(code),
	}
	for _, directive := range p.directives {
		if strings.Contains(directive.CandidateID, sanitizeIdentifier(p.filename)) &&
			strings.Contains(directive.CandidateID, functionName) &&
			strings.HasSuffix(directive.CandidateID, fmt.Sprintf("-%d", sink.Line)) {
			evidence.CandidateID = directive.CandidateID
			evidence.Mode = directive.Mode
			break
		}
	}
	if evidence.CandidateID == "" {
		for _, directive := range p.directives {
			if strings.Contains(directive.CandidateID, sanitizeIdentifier(p.filename)) && strings.Contains(directive.CandidateID, functionName) {
				evidence.CandidateID = directive.CandidateID
				evidence.Mode = directive.Mode
				break
			}
		}
	}
	p.evidence = append(p.evidence, evidence)
}

// functionAtLine returns the indexed function with the latest start line that contains line.
func (p *interproceduralGoAnalyzer) functionAtLine(line int) string {
	var name string
	var latest int
	for _, decls := range p.functions {
		for _, fn := range decls {
			start := p.fset.Position(fn.Pos()).Line
			end := p.fset.Position(fn.End()).Line
			if line >= start && line <= end && start >= latest {
				name, latest = fn.Name.Name, start
			}
		}
	}
	return name
}

// expressionFunctionName renders a concise callable name for argument-flow details.
func expressionFunctionName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	}
	return exprToString(expr)
}

// newInterproceduralTaint starts a flow trace at a recognized source.
func newInterproceduralTaint(source analyzer.Source) *interproceduralTaint {
	return &interproceduralTaint{
		source:    source,
		flowSteps: []string{fmt.Sprintf("source: %s (%s)", source.Name, source.Type)},
	}
}

// taintWithOperation copies a flow trace and appends one propagation operation.
func taintWithOperation(input interproceduralTaint, op, detail string, line int, crossed bool) *interproceduralTaint {
	result := interproceduralTaint{
		source: input.source, operations: append([]analyzer.Operation(nil), input.operations...),
		flowSteps: append([]string(nil), input.flowSteps...), crossed: input.crossed || crossed,
	}
	result.operations = append(result.operations, analyzer.Operation{Type: op, Detail: detail, Line: line})
	result.flowSteps = append(result.flowSteps, fmt.Sprintf("%s (%s)", op, detail))
	return &result
}

// withOperation appends an operation unless the configured flow-length limit has been reached.
func (p *interproceduralGoAnalyzer) withOperation(input interproceduralTaint, op, detail string, line int, crossed bool) *interproceduralTaint {
	if p.maxFlow > 0 && len(input.operations) >= p.maxFlow {
		return nil
	}
	return taintWithOperation(input, op, detail, line, crossed)
}
