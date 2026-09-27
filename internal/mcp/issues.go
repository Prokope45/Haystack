package mcp

import (
	"context"
	"fmt"
	"strings"

	"haystack/internal/issues"
)

func (s *Server) callPrepareIssue(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	findingID, _ := args["finding_id"].(string)
	if findingID == "" {
		return s.toolError(id, "'finding_id' argument is required")
	}

	f, ok := s.getFinding(findingID)
	if !ok {
		return s.toolError(id, fmt.Sprintf("finding %q not found; run a scan first", findingID))
	}

	repo, _ := args["repo"].(string)
	if repo == "" {
		repo = s.defaultRepo
	}

	contextStr, _ := args["additional_context"].(string)

	issueReq := issues.PrepareIssueFromFinding(f, repo, contextStr)

	var sb strings.Builder
	sb.WriteString("### 📝 Proposed Security Issue Draft\n\n")
	sb.WriteString(fmt.Sprintf("**Title:** %s\n\n", issueReq.Title))
	sb.WriteString(fmt.Sprintf("**Labels:** `%s`\n\n", strings.Join(issueReq.Labels, ", ")))
	sb.WriteString(fmt.Sprintf("**Target Repository:** `%s`\n\n", issueReq.Repository))
	sb.WriteString(fmt.Sprintf("**Fingerprint:** `%s`\n\n", issueReq.Fingerprint))
	sb.WriteString("**Body Preview:**\n```markdown\n")
	sb.WriteString(issueReq.Body)
	sb.WriteString("\n```\n\n")
	sb.WriteString("💡 *Review this draft. Call `create_issue` to publish it to your issue tracker.*")

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: sb.String(),
			},
		},
		IsError: false,
		Meta: map[string]interface{}{
			"prepared_issue": issueReq,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *Server) callCreateIssue(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	// 1. Enforce write authorization per DESIGN_PLAN.md Section 42
	if !s.allowWrite {
		return s.toolError(id, "permission denied: write tools (issue creation) are disabled on this MCP server. "+
			"Enable issue creation with --allow-write or --enable-issues")
	}

	if s.issueProvider == nil {
		return s.toolError(id, "no issue provider configured. Specify --issue-provider (github, mock) and credentials")
	}

	findingID, _ := args["finding_id"].(string)
	if findingID == "" {
		return s.toolError(id, "'finding_id' argument is required")
	}

	f, ok := s.getFinding(findingID)
	if !ok {
		return s.toolError(id, fmt.Sprintf("finding %q not found; run a scan first", findingID))
	}

	repo, _ := args["repo"].(string)
	if repo == "" {
		repo = s.defaultRepo
	}

	contextStr, _ := args["additional_context"].(string)

	issueReq := issues.PrepareIssueFromFinding(f, repo, contextStr)

	// Allow custom title/body overrides if provided
	if customTitle, ok := args["title"].(string); ok && customTitle != "" {
		issueReq.Title = customTitle
	}
	if customBody, ok := args["body"].(string); ok && customBody != "" {
		issueReq.Body = customBody
	}

	createdIssue, err := s.issueProvider.CreateIssue(ctx, issueReq)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("failed to create issue via %s provider: %v", s.issueProvider.Name(), err))
	}

	var sb strings.Builder
	if createdIssue.IsDuplicate {
		sb.WriteString("### ℹ️ Existing Issue Reused (Deduplicated)\n\n")
		sb.WriteString("An open issue for this exact vulnerability fingerprint already exists:\n\n")
	} else {
		sb.WriteString("### 🎉 Security Issue Created Successfully\n\n")
	}

	sb.WriteString(fmt.Sprintf("- **Issue Number:** #%d\n", createdIssue.Number))
	sb.WriteString(fmt.Sprintf("- **Title:** %s\n", createdIssue.Title))
	sb.WriteString(fmt.Sprintf("- **URL:** <%s>\n", createdIssue.URL))
	sb.WriteString(fmt.Sprintf("- **Fingerprint:** `%s`\n", createdIssue.Fingerprint))
	sb.WriteString(fmt.Sprintf("- **Provider:** `%s`\n", s.issueProvider.Name()))

	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: sb.String(),
			},
		},
		IsError: false,
		Meta: map[string]interface{}{
			"issue":        createdIssue,
			"is_duplicate": createdIssue.IsDuplicate,
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func (s *Server) callUpdateIssue(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	if !s.allowWrite {
		return s.toolError(id, "permission denied: write tools are disabled on this MCP server (--allow-write required)")
	}
	if s.issueProvider == nil {
		return s.toolError(id, "no issue provider configured")
	}

	issueIDStr, _ := args["issue_id"].(string)
	if issueIDStr == "" {
		return s.toolError(id, "'issue_id' argument is required")
	}

	repo, _ := args["repo"].(string)
	if repo == "" {
		repo = s.defaultRepo
	}

	title, _ := args["title"].(string)
	body, _ := args["body"].(string)
	state, _ := args["state"].(string)
	comment, _ := args["comment"].(string)

	update := issues.IssueUpdate{
		Title:   title,
		Body:    body,
		State:   state,
		Comment: comment,
	}

	err := s.issueProvider.UpdateIssue(ctx, repo, issues.IssueID(issueIDStr), update)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("failed to update issue: %v", err))
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ToolContentItem{
				{
					Type: "text",
					Text: fmt.Sprintf("Issue %s updated successfully.", issueIDStr),
				},
			},
		},
	}
}

func (s *Server) callCloseIssue(id interface{}, ctx context.Context, args map[string]interface{}) *JSONRPCResponse {
	if !s.allowWrite {
		return s.toolError(id, "permission denied: write tools are disabled on this MCP server (--allow-write required)")
	}
	if s.issueProvider == nil {
		return s.toolError(id, "no issue provider configured")
	}

	issueIDStr, _ := args["issue_id"].(string)
	if issueIDStr == "" {
		return s.toolError(id, "'issue_id' argument is required")
	}

	repo, _ := args["repo"].(string)
	if repo == "" {
		repo = s.defaultRepo
	}

	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "Security finding resolved by AI coding agent."
	}

	err := s.issueProvider.CloseIssue(ctx, repo, issues.IssueID(issueIDStr), reason)
	if err != nil {
		return s.toolError(id, fmt.Sprintf("failed to close issue: %v", err))
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: ToolCallResult{
			Content: []ToolContentItem{
				{
					Type: "text",
					Text: fmt.Sprintf("Issue %s closed successfully: %s", issueIDStr, reason),
				},
			},
		},
	}
}
