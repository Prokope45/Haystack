package flow

import (
	"testing"

	"haystack/internal/analyzer"
)

func TestFlowTracker(t *testing.T) {
	tracker := NewFlowTracker()

	src := analyzer.Source{
		Type:   analyzer.SourceHTTPInput,
		Name:   "r.URL.Query().Get(\"cmd\")",
		Line:   10,
		Column: 5,
	}

	tracker.IntroduceSource("userInput", src)

	node, tainted := tracker.IsTainted("userInput")
	if !tainted {
		t.Fatalf("expected userInput to be tainted")
	}
	if node.Source.Type != analyzer.SourceHTTPInput {
		t.Errorf("expected SourceHTTPInput, got %v", node.Source.Type)
	}

	// Propagate via concatenation
	propagated := tracker.Propagate("commandStr", []string{"userInput"}, analyzer.Operation{
		Type:   "concatenation",
		Detail: `"sh -c " + userInput`,
		Line:   12,
	})
	if !propagated {
		t.Fatalf("expected propagation to succeed")
	}

	cmdNode, cmdTainted := tracker.IsTainted("commandStr")
	if !cmdTainted {
		t.Fatalf("expected commandStr to be tainted")
	}
	if len(cmdNode.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(cmdNode.Operations))
	}
	if cmdNode.Operations[0].Type != "concatenation" {
		t.Errorf("expected concatenation op, got %s", cmdNode.Operations[0].Type)
	}

	// Sink evidence build
	sink := analyzer.Sink{
		Type:   analyzer.SinkShell,
		Name:   "exec.Command",
		Line:   15,
		Column: 8,
	}

	evidence := tracker.BuildEvidence("test.go", sink, cmdNode, "exec.Command(\"sh\", \"-c\", commandStr)")
	if evidence.Line != 15 {
		t.Errorf("expected line 15, got %d", evidence.Line)
	}
	if len(evidence.FlowSteps) != 3 { // source, op, sink
		t.Errorf("expected 3 flow steps, got %d: %v", len(evidence.FlowSteps), evidence.FlowSteps)
	}
}
