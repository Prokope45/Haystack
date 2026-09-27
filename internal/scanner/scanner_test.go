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
