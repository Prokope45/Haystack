package issues_test

import (
	"context"
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/findings"
	"haystack/internal/issues"
	"haystack/internal/issues/providers/mock"
)

func TestFormatIssueAndFingerprintExtraction(t *testing.T) {
	f := findings.Finding{
		ID:          "SEC-CMD-001",
		RuleID:      "RULE-CMD-001",
		RuleName:    "Command Injection",
		File:        "handlers/exec.go",
		Line:        42,
		Severity:    "high",
		Confidence:  0.95,
		Model:       "heuristic",
		CWE:         []string{"CWE-78"},
		CWEName:     "OS Command Injection",
		Description: "Untrusted input reaches shell command",
		Remediation: "Use exec.Command with separate args",
		Fingerprint: "a83c91f000deadbeef",
		Evidence: analyzer.Evidence{
			FlowSteps: []string{"r.URL.Query()", "cmd", "exec.Command"},
			Code:      `exec.Command("sh", "-c", cmd)`,
		},
	}

	req := issues.PrepareIssueFromFinding(f, "owner/repo", "Agent discovered this while implementing search endpoint.")

	if req.Fingerprint != f.Fingerprint {
		t.Errorf("expected fingerprint %s, got %s", f.Fingerprint, req.Fingerprint)
	}
	if req.FindingID != f.ID {
		t.Errorf("expected finding ID %s, got %s", f.ID, req.FindingID)
	}

	extractedFP := issues.ExtractFingerprint(req.Body)
	if extractedFP != f.Fingerprint {
		t.Errorf("extracted fingerprint %s != %s", extractedFP, f.Fingerprint)
	}

	extractedID := issues.ExtractFindingID(req.Body)
	if extractedID != f.ID {
		t.Errorf("extracted finding ID %s != %s", extractedID, f.ID)
	}
}

func TestMockProviderDeduplication(t *testing.T) {
	provider := mock.NewMockProvider()
	ctx := context.Background()

	req1 := issues.IssueRequest{
		Title:       "Security: Command injection",
		Body:        "Issue body\nScanner-Fingerprint: fp123\n",
		Fingerprint: "fp123",
		Labels:      []string{"security"},
	}

	iss1, err := provider.CreateIssue(ctx, req1)
	if err != nil {
		t.Fatalf("first CreateIssue failed: %v", err)
	}
	if iss1.IsDuplicate {
		t.Errorf("first issue should NOT be duplicate")
	}
	if iss1.Number != 1 {
		t.Errorf("expected issue number 1, got %d", iss1.Number)
	}

	// Repeated scan with same fingerprint
	iss2, err := provider.CreateIssue(ctx, req1)
	if err != nil {
		t.Fatalf("second CreateIssue failed: %v", err)
	}
	if !iss2.IsDuplicate {
		t.Errorf("second issue SHOULD be marked as duplicate")
	}
	if iss2.ID != iss1.ID {
		t.Errorf("expected duplicate to return existing issue ID %s, got %s", iss1.ID, iss2.ID)
	}

	// Different fingerprint creates new issue
	req3 := issues.IssueRequest{
		Title:       "Security: SQL injection",
		Body:        "Issue body\nScanner-Fingerprint: fp456\n",
		Fingerprint: "fp456",
	}
	iss3, err := provider.CreateIssue(ctx, req3)
	if err != nil {
		t.Fatalf("third CreateIssue failed: %v", err)
	}
	if iss3.IsDuplicate {
		t.Errorf("third issue should not be duplicate")
	}
	if iss3.Number != 2 {
		t.Errorf("expected issue number 2, got %d", iss3.Number)
	}
}
