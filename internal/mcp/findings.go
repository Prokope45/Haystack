package mcp

import (
	"context"
	"fmt"
	"strings"

	"haystack/internal/findings"
	"haystack/internal/intelligence/cwe"
)

func (s *Server) callExplainFinding(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	findingID, _ := args["finding_id"].(string)
	if findingID == "" {
		return s.toolError(id, "'finding_id' argument is required")
	}

	f, ok := s.getFinding(findingID)
	if !ok {
		return s.toolError(id, fmt.Sprintf("finding with ID or fingerprint %q not found in recent scan results; please run scan or scan_diff first", findingID))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 🔍 Vulnerability Deep-Dive: [%s] %s\n\n", f.RuleID, f.RuleName))
	sb.WriteString(fmt.Sprintf("- **Finding ID:** `%s`\n", f.ID))
	sb.WriteString(fmt.Sprintf("- **Stable Fingerprint:** `%s`\n", f.Fingerprint))
	sb.WriteString(fmt.Sprintf("- **Location:** `%s:%d:%d`\n", f.File, f.Line, f.Column))
	sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
	sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%% (Adjudicated by: %s)\n", f.Confidence*100, f.Model))

	if len(f.CWE) > 0 {
		sb.WriteString(fmt.Sprintf("- **CWE:** %s (%s)\n", strings.Join(f.CWE, ", "), f.CWEName))
		if f.Description != "" {
			sb.WriteString(fmt.Sprintf("- **CWE Description:** %s\n", f.Description))
		}
	}

	sb.WriteString("\n#### Data Flow Analysis:\n")
	sb.WriteString(fmt.Sprintf("- **Source (Untrusted Origin):** `%s` (type: `%s`, line %d)\n", f.Evidence.Source.Name, f.Evidence.Source.Type, f.Evidence.Source.Line))
	sb.WriteString(fmt.Sprintf("- **Sink (Dangerous Target):** `%s` (type: `%s`, line %d)\n", f.Evidence.Sink.Name, f.Evidence.Sink.Type, f.Evidence.Sink.Line))

	if len(f.Evidence.FlowSteps) > 0 {
		sb.WriteString("- **Taint Propagation Chain:**\n")
		for i, step := range f.Evidence.FlowSteps {
			sb.WriteString(fmt.Sprintf("  %d. `%s`\n", i+1, step))
		}
	}

	if f.Evidence.Code != "" {
		sb.WriteString(fmt.Sprintf("\n#### Code Snippet:\n```\n%s\n```\n", f.Evidence.Code))
	}

	if len(f.Probabilities) > 0 {
		sb.WriteString("\n#### Classifier Probability Distribution:\n")
		for cat, p := range f.Probabilities {
			sb.WriteString(fmt.Sprintf("- `%s`: %.1f%%\n", cat, p*100))
		}
	}

	if f.Remediation != "" {
		sb.WriteString(fmt.Sprintf("\n#### Remediation Recommendation:\n%s\n", f.Remediation))
	}

	if len(f.References) > 0 {
		sb.WriteString("\n#### Authoritative References:\n")
		for _, ref := range f.References {
			sb.WriteString(fmt.Sprintf("- <%s>\n", ref))
		}
	}

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: sb.String(),
			},
		},
		IsError: false,
		Meta: map[string]interface{}{
			"finding": f,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *Server) callGetRemediation(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	findingID, _ := args["finding_id"].(string)
	cweID, _ := args["cwe"].(string)

	var remediation, cweName, desc string
	var references []string

	if findingID != "" {
		if f, ok := s.getFinding(findingID); ok {
			remediation = f.Remediation
			cweName = f.CWEName
			desc = f.Description
			references = f.References
			if len(f.CWE) > 0 && cweID == "" {
				cweID = f.CWE[0]
			}
		}
	}

	if remediation == "" && cweID != "" {
		w := cwe.Lookup(cweID)
		remediation = w.Remediation
		cweName = w.Name
		desc = w.Description
		references = w.References
	}

	if remediation == "" {
		return s.toolError(id, "provide a valid 'finding_id' from a previous scan or a 'cwe' ID (e.g. 'CWE-78')")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 🛡️ Remediation Guidance for %s: %s\n\n", cweID, cweName))
	if desc != "" {
		sb.WriteString(fmt.Sprintf("**Vulnerability Nature:**\n%s\n\n", desc))
	}
	sb.WriteString(fmt.Sprintf("**Secure Coding Fix:**\n%s\n\n", remediation))

	if len(references) > 0 {
		sb.WriteString("**References:**\n")
		for _, ref := range references {
			sb.WriteString(fmt.Sprintf("- <%s>\n", ref))
		}
	}

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: sb.String(),
			},
		},
		IsError: false,
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *Server) callGetSecurityStatus(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	// De-duplicate unique findings by Fingerprint
	uniqueFindings := make(map[string]findings.Finding)
	for _, f := range s.findingsCache {
		uniqueFindings[f.Fingerprint] = f
	}

	total := len(uniqueFindings)
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, f := range uniqueFindings {
		sev := strings.ToLower(f.Severity)
		severityCounts[sev]++
	}

	var sb strings.Builder
	sb.WriteString("### 📊 Repository Security Status\n\n")

	if total == 0 {
		sb.WriteString("✅ **Status:** CLEAN\n")
		sb.WriteString("No active security findings in the current session.\n")
	} else {
		sb.WriteString(fmt.Sprintf("🚨 **Status:** %d Active Finding(s)\n\n", total))
		sb.WriteString(fmt.Sprintf("- **Critical:** %d\n", severityCounts["critical"]))
		sb.WriteString(fmt.Sprintf("- **High:**     %d\n", severityCounts["high"]))
		sb.WriteString(fmt.Sprintf("- **Medium:**   %d\n", severityCounts["medium"]))
		sb.WriteString(fmt.Sprintf("- **Low:**      %d\n", severityCounts["low"]))
	}

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: sb.String(),
			},
		},
		IsError: total > 0,
		Meta: map[string]interface{}{
			"total_findings":  total,
			"severity_counts": severityCounts,
			"is_clean":        total == 0,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
