package flow

import (
	"fmt"
	"strings"

	"haystack/internal/analyzer"
)

// TaintNode tracks the history of a tainted variable or expression.
type TaintNode struct {
	VarName    string
	Source     analyzer.Source
	Operations []analyzer.Operation
	FlowSteps  []string
}

// FlowTracker maintains variable taint states within a procedural scope (e.g., function body).
type FlowTracker struct {
	taints map[string]*TaintNode
}

// NewFlowTracker creates an initialized FlowTracker.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		taints: make(map[string]*TaintNode),
	}
}

// IntroduceSource registers a variable as holding untrusted source data.
func (ft *FlowTracker) IntroduceSource(varName string, src analyzer.Source) {
	node := &TaintNode{
		VarName:    varName,
		Source:     src,
		Operations: nil,
		FlowSteps: []string{
			fmt.Sprintf("source: %s (%s)", src.Name, src.Type),
		},
	}
	ft.taints[varName] = node
}

// Propagate creates a new tainted variable derived from existing tainted variable(s).
func (ft *FlowTracker) Propagate(targetVar string, fromVars []string, op analyzer.Operation) bool {
	for _, v := range fromVars {
		if node, exists := ft.taints[v]; exists {
			newOps := make([]analyzer.Operation, len(node.Operations), len(node.Operations)+1)
			copy(newOps, node.Operations)
			newOps = append(newOps, op)

			newSteps := make([]string, len(node.FlowSteps), len(node.FlowSteps)+2)
			copy(newSteps, node.FlowSteps)
			newSteps = append(newSteps, fmt.Sprintf("%s (%s)", op.Type, op.Detail))

			ft.taints[targetVar] = &TaintNode{
				VarName:    targetVar,
				Source:     node.Source,
				Operations: newOps,
				FlowSteps:  newSteps,
			}
			return true
		}
	}
	return false
}

// IsTainted checks if any of the given variable names are tainted.
func (ft *FlowTracker) IsTainted(varNames ...string) (*TaintNode, bool) {
	for _, v := range varNames {
		if node, ok := ft.taints[v]; ok {
			return node, true
		}
	}
	return nil, false
}

// BuildEvidence creates a complete Evidence struct if a sink receives tainted data.
func (ft *FlowTracker) BuildEvidence(filePath string, sink analyzer.Sink, taintedNode *TaintNode, codeSnippet string) analyzer.Evidence {
	steps := make([]string, 0, len(taintedNode.FlowSteps)+1)
	steps = append(steps, taintedNode.FlowSteps...)
	steps = append(steps, fmt.Sprintf("sink: %s (%s)", sink.Name, sink.Type))

	return analyzer.Evidence{
		File:       filePath,
		Line:       sink.Line,
		Column:     sink.Column,
		Source:     taintedNode.Source,
		Sink:       sink,
		Operations: taintedNode.Operations,
		FlowSteps:  steps,
		Code:       strings.TrimSpace(codeSnippet),
	}
}
