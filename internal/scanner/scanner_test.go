package scanner

import (
	"context"
	"testing"

	"haystack/internal/config"
)

func TestScanCodeGoVulnerable(t *testing.T) {
	cfg := config.DefaultConfig()
	orch := NewOrchestrator(cfg)

	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
`

	findings, summary, err := orch.ScanCode(context.Background(), []byte(code), "go", "main.go")
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if summary.FindingsCount == 0 || len(findings) == 0 {
		t.Fatal("expected finding for command injection, got 0")
	}

	if findings[0].RuleID != "RULE-CMD-001" {
		t.Errorf("expected RULE-CMD-001, got %s", findings[0].RuleID)
	}
}

func TestScanCodePythonSafe(t *testing.T) {
	cfg := config.DefaultConfig()
	orch := NewOrchestrator(cfg)

	code := `import subprocess
def ping():
    subprocess.run(["ping", "-c", "1", "127.0.0.1"], check=True)
`

	findings, summary, err := orch.ScanCode(context.Background(), []byte(code), "python", "script.py")
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if summary.FindingsCount != 0 || len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe code, got %d", len(findings))
	}
}

func TestScanCodeSyntaxError(t *testing.T) {
	cfg := config.DefaultConfig()
	orch := NewOrchestrator(cfg)

	brokenCode := `package main
func Broken( {
`

	_, _, err := orch.ScanCode(context.Background(), []byte(brokenCode), "go", "broken.go")
	if err == nil {
		t.Fatal("expected syntax error, got nil")
	}
}

func TestScannerServiceScanRequest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TargetDir = "../../testdata/go"

	scannerSvc := NewScanner(cfg)
	req := ScanRequest{
		Paths:       []string{"../../testdata/go"},
		MinSeverity: "low",
	}

	result, err := scannerSvc.Scan(context.Background(), req)
	if err != nil {
		t.Fatalf("Scanner.Scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Errorf("expected findings from testdata/go, got 0")
	}

	for _, f := range result.Findings {
		if f.Fingerprint == "" {
			t.Errorf("expected non-empty fingerprint for finding %s", f.ID)
		}
	}
}

func TestScanCodeAdaptiveMetadata(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AnalysisStrategy = "adaptive"
	orch := NewOrchestrator(cfg)

	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
`

	findings, summary, err := orch.ScanCode(context.Background(), []byte(code), "go", "main.go")
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}

	if summary.Analysis.Strategy != "adaptive" {
		t.Errorf("expected strategy 'adaptive', got %s", summary.Analysis.Strategy)
	}
	if summary.Analysis.CandidatesDiscovered != 1 {
		t.Errorf("expected 1 candidate discovered, got %d", summary.Analysis.CandidatesDiscovered)
	}
	if summary.Analysis.CandidatesAnalyzed != 1 {
		t.Errorf("expected 1 candidate analyzed, got %d", summary.Analysis.CandidatesAnalyzed)
	}

	meta := findings[0].AnalysisMetadata
	if meta == nil {
		t.Fatal("expected AnalysisMetadata to be populated, got nil")
	}
	if meta.Strategy != "adaptive" {
		t.Errorf("expected metadata strategy 'adaptive', got %s", meta.Strategy)
	}
	if meta.Priority < 70 {
		t.Errorf("expected high priority in metadata, got %d", meta.Priority)
	}
}

func TestGetAnalysisPlan(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TargetDir = "../../testdata/go"

	scannerSvc := NewScanner(cfg)
	req := ScanRequest{
		Paths:    []string{"../../testdata/go"},
		Strategy: "adaptive",
	}

	plan, err := scannerSvc.GetAnalysisPlan(context.Background(), req)
	if err != nil {
		t.Fatalf("GetAnalysisPlan failed: %v", err)
	}

	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if len(plan.Candidates) == 0 {
		t.Errorf("expected candidates in plan, got 0")
	}
}
