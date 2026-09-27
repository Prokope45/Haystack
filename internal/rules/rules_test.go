package rules

import (
	"testing"

	"haystack/internal/analyzer"
)

func TestDefaultRegistryAllRules(t *testing.T) {
	reg := DefaultRegistry()
	if len(reg.Rules()) != 5 {
		t.Fatalf("expected 5 rules in default registry, got %d", len(reg.Rules()))
	}

	testCases := []struct {
		name         string
		ev           analyzer.Evidence
		expectedRule string
		expectedCWE  string
	}{
		{
			name: "SQL Injection",
			ev: analyzer.Evidence{
				Source: analyzer.Source{Type: analyzer.SourceHTTPInput, Name: "param"},
				Sink:   analyzer.Sink{Type: analyzer.SinkSQL, Name: "db.Query"},
			},
			expectedRule: "RULE-SQL-001",
			expectedCWE:  "CWE-89",
		},
		{
			name: "Path Traversal",
			ev: analyzer.Evidence{
				Source: analyzer.Source{Type: analyzer.SourceHTTPInput, Name: "fileParam"},
				Sink:   analyzer.Sink{Type: analyzer.SinkFilesystem, Name: "os.Open"},
			},
			expectedRule: "RULE-PATH-001",
			expectedCWE:  "CWE-22",
		},
		{
			name: "Hardcoded Secret",
			ev: analyzer.Evidence{
				Source: analyzer.Source{Type: analyzer.SourceHardcoded, Name: "apiKey"},
				Sink:   analyzer.Sink{Type: analyzer.SinkShell, Name: "apiKey"},
			},
			expectedRule: "RULE-SEC-001",
			expectedCWE:  "CWE-798",
		},
		{
			name: "Deserialization",
			ev: analyzer.Evidence{
				Source: analyzer.Source{Type: analyzer.SourceHTTPInput, Name: "body"},
				Sink:   analyzer.Sink{Type: analyzer.SinkDeserialization, Name: "pickle.loads"},
			},
			expectedRule: "RULE-DESER-001",
			expectedCWE:  "CWE-502",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			candidates := reg.EvaluateAll([]analyzer.Evidence{tc.ev})
			if len(candidates) != 1 {
				t.Fatalf("expected 1 match for %s, got %d", tc.name, len(candidates))
			}
			if candidates[0].RuleID != tc.expectedRule {
				t.Errorf("expected rule %s, got %s", tc.expectedRule, candidates[0].RuleID)
			}
			if candidates[0].CWE != tc.expectedCWE {
				t.Errorf("expected CWE %s, got %s", tc.expectedCWE, candidates[0].CWE)
			}
		})
	}
}
