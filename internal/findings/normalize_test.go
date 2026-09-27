package findings

import (
	"context"
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
	"haystack/internal/rules"
)

type staticClassifier struct {
	result classifier.ClassificationResult
}

func (s *staticClassifier) ModelName() string {
	return "mock"
}

func (s *staticClassifier) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	return s.result, nil
}

func TestNormalizerNormalize(t *testing.T) {
	mockCls := &staticClassifier{
		result: classifier.ClassificationResult{
			Label:      "command_injection",
			Confidence: 0.94,
			Probabilities: map[string]float64{
				"command_injection": 0.94,
				"safe_code":         0.06,
			},
		},
	}

	norm := NewNormalizer(mockCls, NormalizerOptions{
		MinSeverity:   "low",
		MinConfidence: 0.80,
	})

	candidate := rules.CandidateFinding{
		RuleID:          "RULE-CMD-001",
		RuleName:        "OS Command Injection",
		Category:        "command_injection",
		CWE:             "CWE-78",
		DefaultSeverity: "high",
		Evidence: analyzer.Evidence{
			File:   "cmd.go",
			Line:   10,
			Column: 4,
		},
	}

	results, err := norm.Normalize(context.Background(), []rules.CandidateFinding{candidate})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}

	f := results[0]
	if f.Severity != "high" {
		t.Errorf("expected high severity, got %s", f.Severity)
	}
	if f.Confidence != 0.94 {
		t.Errorf("expected 0.94 confidence, got %f", f.Confidence)
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-78" {
		t.Errorf("expected CWE-78, got %v", f.CWE)
	}
	if f.Remediation == "" {
		t.Errorf("expected non-empty remediation guidance")
	}
	if f.Fingerprint == "" {
		t.Errorf("expected non-empty fingerprint")
	}
}

func TestNormalizerFilterThreshold(t *testing.T) {
	mockCls := &staticClassifier{
		result: classifier.ClassificationResult{
			Label:      "command_injection",
			Confidence: 0.70,
		},
	}

	// Min confidence is 0.85, so 0.70 should be filtered out
	norm := NewNormalizer(mockCls, NormalizerOptions{
		MinSeverity:   "low",
		MinConfidence: 0.85,
	})

	candidate := rules.CandidateFinding{
		RuleID:          "RULE-CMD-001",
		Category:        "command_injection",
		CWE:             "CWE-78",
		DefaultSeverity: "high",
	}

	results, err := norm.Normalize(context.Background(), []rules.CandidateFinding{candidate})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("expected finding to be filtered out by confidence, got %d", len(results))
	}
}
