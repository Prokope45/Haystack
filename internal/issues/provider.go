package issues

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"haystack/internal/findings"
)

// IssueProvider defines the abstraction contract for issue tracking integrations per DESIGN_PLAN.md Section 39.
type IssueProvider interface {
	Name() string
	CreateIssue(ctx context.Context, req IssueRequest) (*Issue, error)
	FindIssueByFingerprint(ctx context.Context, repo string, fingerprint string) (*Issue, error)
	UpdateIssue(ctx context.Context, repo string, id IssueID, update IssueUpdate) error
	CloseIssue(ctx context.Context, repo string, id IssueID, reason string) error
}

var fingerprintRegex = regexp.MustCompile(`Scanner-Fingerprint:\s*([^\s\r\n]+)`)
var findingIDRegex = regexp.MustCompile(`Scanner-Finding:\s*([^\s\r\n]+)`)

// ExtractFingerprint finds the embedded fingerprint in an issue body.
func ExtractFingerprint(body string) string {
	matches := fingerprintRegex.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// ExtractFindingID finds the embedded finding ID in an issue body.
func ExtractFindingID(body string) string {
	matches := findingIDRegex.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// FormatIssueBody formats a finding into an issue description with embedded metadata.
func FormatIssueBody(f findings.Finding, additionalContext string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("### 🚨 Security Vulnerability: %s (%s severity)\n\n", f.RuleName, strings.ToUpper(f.Severity)))
	sb.WriteString(fmt.Sprintf("- **Rule:** `%s`\n", f.RuleID))
	sb.WriteString(fmt.Sprintf("- **Location:** `%s:%d`\n", f.File, f.Line))
	if len(f.CWE) > 0 {
		sb.WriteString(fmt.Sprintf("- **CWE:** %s (%s)\n", strings.Join(f.CWE, ", "), f.CWEName))
	}
	sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%% (Model: %s)\n", f.Confidence*100, f.Model))

	if additionalContext != "" {
		sb.WriteString(fmt.Sprintf("\n#### Agent Context:\n%s\n", strings.TrimSpace(additionalContext)))
	}

	if f.Description != "" {
		sb.WriteString(fmt.Sprintf("\n#### Description:\n%s\n", f.Description))
	}

	if len(f.Evidence.FlowSteps) > 0 {
		sb.WriteString("\n#### Static Analysis Taint Flow:\n")
		for i, step := range f.Evidence.FlowSteps {
			sb.WriteString(fmt.Sprintf("%d. `%s`\n", i+1, step))
		}
	}

	if f.Evidence.Code != "" {
		sb.WriteString(fmt.Sprintf("\n#### Vulnerable Code Snippet:\n```\n%s\n```\n", f.Evidence.Code))
	}

	if f.Remediation != "" {
		sb.WriteString(fmt.Sprintf("\n#### Remediation Guidance:\n%s\n", f.Remediation))
	}

	if len(f.References) > 0 {
		sb.WriteString("\n#### References:\n")
		for _, ref := range f.References {
			sb.WriteString(fmt.Sprintf("- <%s>\n", ref))
		}
	}

	sb.WriteString("\n---\n")
	sb.WriteString("<!--\n")
	sb.WriteString(fmt.Sprintf("Scanner-Finding: %s\n", f.ID))
	sb.WriteString(fmt.Sprintf("Scanner-Fingerprint: %s\n", f.Fingerprint))
	sb.WriteString("-->\n")

	return sb.String()
}

// PrepareIssueFromFinding drafts an IssueRequest without performing any external side-effect.
func PrepareIssueFromFinding(f findings.Finding, repo string, additionalContext string) IssueRequest {
	title := fmt.Sprintf("Security: %s in %s", f.RuleName, f.File)

	labels := []string{"security", "vulnerability", strings.ToLower(f.Severity)}
	if len(f.CWE) > 0 {
		labels = append(labels, f.CWE[0])
	}

	body := FormatIssueBody(f, additionalContext)

	return IssueRequest{
		Title:       title,
		Body:        body,
		Labels:      labels,
		FindingID:   f.ID,
		Fingerprint: f.Fingerprint,
		Repository:  repo,
	}
}
