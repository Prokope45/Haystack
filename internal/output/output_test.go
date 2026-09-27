package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/findings"
)

func sampleFinding() findings.Finding {
	return findings.Finding{
		ID:          "RULE-CMD-001-test.py-12-1",
		RuleID:      "RULE-CMD-001",
		RuleName:    "OS Command Injection",
		File:        "test.py",
		Line:        12,
		Column:      5,
		Category:    "command_injection",
		CWE:         []string{"CWE-78"},
		CWEName:     "Improper Neutralization of Special Elements used in an OS Command",
		Severity:    "high",
		Confidence:  0.94,
		Description: "OS command injection weakness",
		Remediation: "Avoid shell invocation",
		Evidence: analyzer.Evidence{
			File:      "test.py",
			Line:      12,
			FlowSteps: []string{"source: request.args", "sink: subprocess.run"},
			Code:      "subprocess.run(cmd, shell=True)",
		},
	}
}

func TestTextFormatter(t *testing.T) {
	tf := NewTextFormatter(true)
	buf := new(bytes.Buffer)

	summary := ScanSummary{
		FilesScanned:  1,
		PythonFiles:   1,
		FindingsCount: 1,
		Duration:      15 * time.Millisecond,
	}

	err := tf.Format(buf, []findings.Finding{sampleFinding()}, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "HIGH") {
		t.Errorf("expected output to contain HIGH")
	}
	if !strings.Contains(out, "CWE-78") {
		t.Errorf("expected output to contain CWE-78")
	}
	if !strings.Contains(out, "subprocess.run") {
		t.Errorf("expected output to contain code snippet")
	}
	if !strings.Contains(out, "Explanation (CWE description):") {
		t.Errorf("expected CWE description to be used when no generated explanation is available")
	}
	if !strings.Contains(out, "OS command injection weakness") {
		t.Errorf("expected output to contain the CWE description fallback")
	}
}

func TestJSONFormatter(t *testing.T) {
	jf := NewJSONFormatter()
	buf := new(bytes.Buffer)

	summary := ScanSummary{
		FilesScanned:  1,
		PythonFiles:   1,
		FindingsCount: 1,
	}

	err := jf.Format(buf, []findings.Finding{sampleFinding()}, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed JSONReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if len(parsed.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].RuleID != "RULE-CMD-001" {
		t.Errorf("expected RULE-CMD-001, got %s", parsed.Findings[0].RuleID)
	}
}

func TestJSONFormatterWithAnalysisTelemetry(t *testing.T) {
	jf := NewJSONFormatter()
	buf := new(bytes.Buffer)

	summary := ScanSummary{
		FilesScanned:  2,
		GoFiles:       2,
		FindingsCount: 1,
		Analysis: AnalysisStats{
			Strategy:             "adaptive",
			CandidatesDiscovered: 5,
			CandidatesAnalyzed:   3,
			CandidatesSkipped:    2,
			DeepAnalyses:         1,
			MediumAnalyses:       2,
		},
	}

	err := jf.Format(buf, []findings.Finding{sampleFinding()}, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed JSONReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if parsed.Analysis.Strategy != "adaptive" {
		t.Errorf("expected strategy adaptive, got %s", parsed.Analysis.Strategy)
	}
	if parsed.Analysis.CandidatesDiscovered != 5 {
		t.Errorf("expected 5 candidates discovered, got %d", parsed.Analysis.CandidatesDiscovered)
	}
}

func TestTextFormatterVerboseAnalysis(t *testing.T) {
	tf := NewVerboseTextFormatter(true, true)
	buf := new(bytes.Buffer)

	summary := ScanSummary{
		FilesScanned:  1,
		GoFiles:       1,
		FindingsCount: 1,
		Analysis: AnalysisStats{
			Strategy:             "adaptive",
			CandidatesDiscovered: 4,
			CandidatesAnalyzed:   3,
			CandidatesSkipped:    1,
			DeepAnalyses:         2,
			MediumAnalyses:       1,
		},
	}

	f := sampleFinding()
	f.AnalysisMetadata = &findings.AnalysisMetadata{
		Strategy:        "adaptive",
		Priority:        85,
		Depth:           6,
		PlannerProvider: "deterministic",
	}

	if err := tf.Format(buf, []findings.Finding{f}, summary); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Analysis Telemetry") {
		t.Errorf("expected output to contain 'Analysis Telemetry'")
	}
	if !strings.Contains(out, "Strategy:   adaptive") {
		t.Errorf("expected finding to display strategy adaptive")
	}
}

func TestSARIFFormatter(t *testing.T) {
	sf := NewSARIFFormatter()
	buf := new(bytes.Buffer)

	summary := ScanSummary{
		FilesScanned:  1,
		FindingsCount: 1,
	}

	err := sf.Format(buf, []findings.Finding{sampleFinding()}, summary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed sarifReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal SARIF output: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", parsed.Version)
	}
	if len(parsed.Runs) != 1 || len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 run with 1 result")
	}
	if parsed.Runs[0].Results[0].Level != "error" {
		t.Errorf("expected error level for high severity finding, got %s", parsed.Runs[0].Results[0].Level)
	}
}
