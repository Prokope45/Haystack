package mcp

import (
	"context"
	"fmt"
	"strings"

	"haystack/internal/findings"
	"haystack/internal/scanner"
)

func (s *Server) callScan(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	path, _ := args["path"].(string)
	if path == "" {
		path = s.cfg.TargetDir
	}

	req := scanner.ScanRequest{
		Paths: []string{path},
	}
	if sev, ok := args["min_severity"].(string); ok && sev != "" {
		req.MinSeverity = sev
	}
	if conf, ok := args["min_confidence"].(float64); ok && conf > 0 {
		req.MinConfidence = conf
	}
	if strat, ok := args["strategy"].(string); ok && strat != "" {
		req.Strategy = strat
	}
	if aip, ok := args["ai_planner"].(bool); ok {
		req.AIPlanner = aip
	}

	result, err := s.scannerSvc.Scan(ctx, req)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("Scan error: %v", err))
	}

	s.storeFindings(result.Findings)
	return s.renderFindingsResult(id, result.Findings)
}

func (s *Server) callScanDiff(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	diffRange, _ := args["diff_range"].(string)
	base, _ := args["base"].(string)
	head, _ := args["head"].(string)
	path, _ := args["path"].(string)
	if path == "" {
		path = s.cfg.TargetDir
	}

	// Default to working directory diff (HEAD) if no range provided
	if diffRange == "" && base == "" {
		diffRange = "HEAD"
	}

	req := scanner.ScanRequest{
		Paths:     []string{path},
		DiffRange: diffRange,
		GitBase:   base,
		GitHead:   head,
	}
	if sev, ok := args["min_severity"].(string); ok && sev != "" {
		req.MinSeverity = sev
	}
	if conf, ok := args["min_confidence"].(float64); ok && conf > 0 {
		req.MinConfidence = conf
	}
	if strat, ok := args["strategy"].(string); ok && strat != "" {
		req.Strategy = strat
	}
	if aip, ok := args["ai_planner"].(bool); ok {
		req.AIPlanner = aip
	}

	result, err := s.scannerSvc.Scan(ctx, req)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("Git diff scan error: %v", err))
	}

	s.storeFindings(result.Findings)
	return s.renderFindingsResult(id, result.Findings)
}

func (s *Server) callGetAnalysisPlan(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	path, _ := args["path"].(string)
	if path == "" {
		path = s.cfg.TargetDir
	}

	strategy, _ := args["strategy"].(string)
	aiPlanner, _ := args["ai_planner"].(bool)

	req := scanner.ScanRequest{
		Paths:     []string{path},
		Strategy:  strategy,
		AIPlanner: aiPlanner,
	}

	plan, err := s.scannerSvc.GetAnalysisPlan(ctx, req)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("GetAnalysisPlan error: %v", err))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 📋 Adaptive Analysis Plan (Strategy: %s)\n\n", plan.Strategy))
	sb.WriteString(fmt.Sprintf("Discovered %d security candidate flows.\n\n", len(plan.Candidates)))

	for i, c := range plan.Candidates {
		status := "🔍 ANALYZE"
		if !c.Analyze {
			status = "⏭️ SKIP"
		}
		sb.WriteString(fmt.Sprintf("%d. **[%s]** `%s` (Priority: %d, Mode: `%s`, Depth: %d)\n",
			i+1, status, c.CandidateID, c.Priority, c.Mode, c.Depth))
		if len(c.VulnerabilityClasses) > 0 {
			sb.WriteString(fmt.Sprintf("   - Vulnerability Classes: %s\n", strings.Join(c.VulnerabilityClasses, ", ")))
		}
		sb.WriteString(fmt.Sprintf("   - Rationale: %s (Planner: %s)\n\n", c.Reason, c.PlannerProvider))
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
			"plan": plan,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *Server) callScanFile(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	path, _ := args["path"].(string)
	if path == "" {
		return s.toolError(id, "'path' argument is required")
	}

	result, err := s.scannerSvc.ScanFile(ctx, scanner.ScanCodeRequest{
		Filename:      path,
		MinSeverity:   stringArgument(args, "min_severity"),
		MinConfidence: numberArgument(args, "min_confidence"),
	})
	if err != nil {
		return s.toolError(id, fmt.Sprintf("File scan error: %v", err))
	}

	s.storeFindings(result.Findings)
	return s.renderFindingsResult(id, result.Findings)
}

func (s *Server) callScanCode(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	codeStr, _ := args["code"].(string)
	langStr, _ := args["language"].(string)
	filename, _ := args["filename"].(string)

	if codeStr == "" {
		return s.toolError(id, "'code' argument is required and cannot be empty")
	}
	if langStr == "" {
		return s.toolError(id, "'language' argument is required ('go' or 'python')")
	}

	result, err := s.scannerSvc.ScanCode(ctx, scanner.ScanCodeRequest{
		Code: []byte(codeStr), Language: langStr, Filename: filename,
		MinSeverity:   stringArgument(args, "min_severity"),
		MinConfidence: numberArgument(args, "min_confidence"),
	})
	if err != nil {
		return s.toolError(id, fmt.Sprintf("Analysis error: %v", err))
	}

	s.storeFindings(result.Findings)
	return s.renderFindingsResult(id, result.Findings)
}

func stringArgument(args map[string]interface{}, key string) string {
	value, _ := args[key].(string)
	return value
}

func numberArgument(args map[string]interface{}, key string) float64 {
	value, _ := args[key].(float64)
	return value
}

func (s *Server) renderFindingsResult(id interface{}, list []findings.Finding) *JSONRPCResponse {
	var report strings.Builder

	isSafe := len(list) == 0

	if isSafe {
		report.WriteString("### ✅ Security Scan: PASSED (SAFE)\n\n")
		report.WriteString("No security vulnerabilities or tainted data-flow paths were detected.\n")
		report.WriteString("The code adheres to deterministic AST safety rules and calibrated decision models.\n")
	} else {
		report.WriteString(fmt.Sprintf("### 🚨 Security Scan: FAILED (%d Vulnerabilities Detected)\n\n", len(list)))
		report.WriteString("The static analysis engine and decision classifier identified potential security vulnerabilities:\n\n")

		for i, f := range list {
			report.WriteString(fmt.Sprintf("#### %d. [%s] %s (%s severity)\n", i+1, f.RuleID, f.RuleName, strings.ToUpper(f.Severity)))
			report.WriteString(fmt.Sprintf("- **Finding ID:** `%s`\n", f.ID))
			report.WriteString(fmt.Sprintf("- **Fingerprint:** `%s`\n", f.Fingerprint))
			report.WriteString(fmt.Sprintf("- **File & Line:** `%s:%d`\n", f.File, f.Line))
			if len(f.CWE) > 0 {
				report.WriteString(fmt.Sprintf("- **CWE:** %s (%s)\n", strings.Join(f.CWE, ", "), f.CWEName))
			}
			report.WriteString(fmt.Sprintf("- **Confidence:** %.0f%% (Model: %s)\n", f.Confidence*100, f.Model))

			if len(f.Evidence.FlowSteps) > 0 {
				report.WriteString("- **Taint Flow:**\n")
				for idx, step := range f.Evidence.FlowSteps {
					report.WriteString(fmt.Sprintf("  %d. `%s`\n", idx+1, step))
				}
			}

			if f.Evidence.Code != "" {
				report.WriteString(fmt.Sprintf("- **Vulnerable Code:**\n  ```\n  %s\n  ```\n", f.Evidence.Code))
			}

			if f.Remediation != "" {
				report.WriteString(fmt.Sprintf("- **Remediation:** %s\n", f.Remediation))
			}
			report.WriteString("\n")
		}
	}

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: report.String(),
			},
		},
		IsError: !isSafe,
		Meta: map[string]interface{}{
			"is_safe":        isSafe,
			"findings_count": len(list),
			"findings":       list,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
