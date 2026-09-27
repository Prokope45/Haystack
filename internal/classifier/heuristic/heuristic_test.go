package heuristic

import (
	"context"
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
)

func TestHeuristicClassifierCommandInjection(t *testing.T) {
	c := NewHeuristicClassifier()

	input := classifier.ClassificationInput{
		Question: "Classify this finding",
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			File:     "test.go",
			Language: "go",
			Source: analyzer.Source{
				Type: analyzer.SourceHTTPInput,
				Name: "r.URL.Query().Get(\"c\")",
			},
			Sink: analyzer.Sink{
				Type: analyzer.SinkShell,
				Name: "exec.Command",
			},
			FlowSteps: []string{"source", "assignment", "sink"},
			Code:      "exec.Command(\"sh\", \"-c\", cmd)",
		},
	}

	res, err := c.Classify(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Label != "command_injection" {
		t.Errorf("expected label command_injection, got %s", res.Label)
	}
	if res.Confidence < 0.85 {
		t.Errorf("expected confidence >= 0.85, got %f", res.Confidence)
	}
	if res.Probabilities["command_injection"] != res.Confidence {
		t.Errorf("probabilities map did not match confidence: %v", res.Probabilities)
	}
}

func TestHeuristicClassifierSanitized(t *testing.T) {
	c := NewHeuristicClassifier()

	input := classifier.ClassificationInput{
		Question: "Classify this finding",
		Category: "path_traversal",
		Evidence: analyzer.Evidence{
			File: "path.go",
			Source: analyzer.Source{
				Type: analyzer.SourceHTTPInput,
			},
			Sink: analyzer.Sink{
				Type: analyzer.SinkFilesystem,
			},
			Code: "safePath := filepath.Clean(userPath)",
		},
	}

	res, err := c.Classify(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Confidence > 0.5 {
		t.Errorf("expected sanitized code to have low confidence, got %f", res.Confidence)
	}
}
