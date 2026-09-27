package findings

import (
	"testing"

	"haystack/internal/analyzer"
)

func TestCalculateFingerprintStability(t *testing.T) {
	ev1 := analyzer.Evidence{
		File:   "handlers/api.go",
		Line:   25,
		Column: 4,
		Source: analyzer.Source{
			Type: analyzer.SourceHTTPInput,
			Name: "req.URL.Query()",
			Line: 20,
		},
		Sink: analyzer.Sink{
			Type: analyzer.SinkShell,
			Name: "exec.Command",
			Line: 25,
		},
		FlowSteps: []string{"param", "cmd", "exec.Command"},
	}

	// ev2 is the same vulnerability, but shifted down 10 lines
	ev2 := analyzer.Evidence{
		File:   "handlers/api.go",
		Line:   35,
		Column: 4,
		Source: analyzer.Source{
			Type: analyzer.SourceHTTPInput,
			Name: "req.URL.Query()",
			Line: 30,
		},
		Sink: analyzer.Sink{
			Type: analyzer.SinkShell,
			Name: "exec.Command",
			Line: 35,
		},
		FlowSteps: []string{"param", "cmd", "exec.Command"},
	}

	fp1 := CalculateFingerprint("RULE-CMD-001", ev1.File, ev1)
	fp2 := CalculateFingerprint("RULE-CMD-001", ev2.File, ev2)

	if fp1 == "" {
		t.Fatal("fingerprint should not be empty")
	}

	if fp1 != fp2 {
		t.Errorf("fingerprint should be identical across line number shifts, got %s vs %s", fp1, fp2)
	}

	// Verify that different file or rule produces different fingerprint
	fpDiffRule := CalculateFingerprint("RULE-SQL-001", ev1.File, ev1)
	if fp1 == fpDiffRule {
		t.Errorf("different rule should produce different fingerprint")
	}

	fpDiffFile := CalculateFingerprint("RULE-CMD-001", "handlers/other.go", ev1)
	if fp1 == fpDiffFile {
		t.Errorf("different file should produce different fingerprint")
	}
}
