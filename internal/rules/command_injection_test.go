package rules

import (
	"testing"

	"haystack/internal/analyzer"
)

func TestCommandInjectionRuleMatch(t *testing.T) {
	rule := NewCommandInjectionRule()
	reg := NewRegistry(rule)

	ev := analyzer.Evidence{
		File:     "app.py",
		Line:     12,
		Language: "python",
		Source: analyzer.Source{
			Type: analyzer.SourceHTTPInput,
			Name: "request.args.get('cmd')",
		},
		Sink: analyzer.Sink{
			Type: analyzer.SinkShell,
			Name: "subprocess.run",
		},
		FlowSteps: []string{"source", "sink"},
	}

	candidates := reg.EvaluateAll([]analyzer.Evidence{ev})
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	c := candidates[0]
	if c.RuleID != "RULE-CMD-001" {
		t.Errorf("expected RULE-CMD-001, got %s", c.RuleID)
	}
	if c.CWE != "CWE-78" {
		t.Errorf("expected CWE-78, got %s", c.CWE)
	}
}

func TestCommandInjectionRuleNoMatchSafe(t *testing.T) {
	rule := NewCommandInjectionRule()
	reg := NewRegistry(rule)

	ev := analyzer.Evidence{
		File: "app.go",
		Source: analyzer.Source{
			Type: analyzer.SourceHardcoded,
			Name: "apiKey",
		},
		Sink: analyzer.Sink{
			Type: analyzer.SinkFilesystem,
			Name: "os.Open",
		},
	}

	candidates := reg.EvaluateAll([]analyzer.Evidence{ev})
	if len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(candidates))
	}
}
