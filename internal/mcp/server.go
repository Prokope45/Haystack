package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/issues"
	"haystack/internal/scanner"
)

const protocolVersion = "2024-11-05"

// ServerOptions contains settings for creating an MCP server.
type ServerOptions struct {
	Config        *config.Config
	Scanner       scanner.Scanner
	IssueProvider issues.IssueProvider
	AllowWrite    bool
	DefaultRepo   string
}

// Server implements a Model Context Protocol (MCP) server over Stdio JSON-RPC 2.0.
type Server struct {
	cfg           *config.Config
	scannerSvc    scanner.Scanner
	issueProvider issues.IssueProvider
	allowWrite    bool
	defaultRepo   string

	findingsMu    sync.RWMutex
	findingsCache map[string]findings.Finding // indexed by ID and by Fingerprint

	tools []Tool
}

// NewServer creates a new MCP server with default options.
func NewServer(cfg *config.Config) *Server {
	return NewServerWithOptions(ServerOptions{
		Config: cfg,
	})
}

// NewServerWithOptions creates an MCP server with custom options.
func NewServerWithOptions(opts ServerOptions) *Server {
	cfg := opts.Config
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	scannerSvc := opts.Scanner
	if scannerSvc == nil {
		scannerSvc = scanner.NewScanner(cfg)
	}

	s := &Server{
		cfg:           cfg,
		scannerSvc:    scannerSvc,
		issueProvider: opts.IssueProvider,
		allowWrite:    opts.AllowWrite,
		defaultRepo:   opts.DefaultRepo,
		findingsCache: make(map[string]findings.Finding),
	}

	s.registerTools()
	return s
}

// SetIssueProvider configures or updates the IssueProvider.
func (s *Server) SetIssueProvider(p issues.IssueProvider) {
	s.issueProvider = p
}

// SetAllowWrite toggles write permissions.
func (s *Server) SetAllowWrite(allow bool) {
	s.allowWrite = allow
}

func (s *Server) storeFindings(list []findings.Finding) {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()

	for _, f := range list {
		if f.ID != "" {
			s.findingsCache[f.ID] = f
		}
		if f.Fingerprint != "" {
			s.findingsCache[f.Fingerprint] = f
		}
	}
}

func (s *Server) getFinding(idOrFingerprint string) (findings.Finding, bool) {
	s.findingsMu.RLock()
	defer s.findingsMu.RUnlock()

	f, ok := s.findingsCache[idOrFingerprint]
	return f, ok
}

func (s *Server) registerTools() {
	s.tools = []Tool{
		// 1. Scan tools
		{
			Name: "scan",
			Description: "Full project security scan across Go and Python source files. " +
				"Analyzes ASTs, traces source-to-sink taint flows, evaluates deterministic security rules, " +
				"and classifies findings using decision models.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"path": {
						Type:        "string",
						Description: "Optional target directory or file path. Defaults to current workspace root.",
					},
					"min_severity": {
						Type:        "string",
						Description: "Optional minimum severity: 'low', 'medium', 'high', 'critical'.",
						Enum:        []string{"low", "medium", "high", "critical"},
					},
					"min_confidence": {
						Type:        "number",
						Description: "Optional minimum confidence threshold (0.0 to 1.0).",
					},
					"strategy": {
						Type:        "string",
						Description: "Optional analysis strategy: 'adaptive' (default) or 'full'.",
						Enum:        []string{"adaptive", "full"},
					},
					"ai_planner": {
						Type:        "boolean",
						Description: "Optional boolean to consult the external AI planner for candidate triage.",
					},
				},
			},
		},
		{
			Name: "get_analysis_plan",
			Description: "Inspect security candidate triage and the scanner's adaptive analysis plan without executing full static analysis. " +
				"Returns candidate prioritization, estimated analysis depth, and mode (shallow, medium, deep) per DESIGN_PLAN.md Section 28.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"path": {
						Type:        "string",
						Description: "Optional target directory or file path. Defaults to workspace root.",
					},
					"strategy": {
						Type:        "string",
						Description: "Optional analysis strategy: 'adaptive' or 'full'. Defaults to 'adaptive'.",
						Enum:        []string{"adaptive", "full"},
					},
					"ai_planner": {
						Type:        "boolean",
						Description: "Optional boolean to consult the external AI planner for candidate triage.",
					},
				},
			},
		},
		{
			Name: "scan_diff",
			Description: "Scan only code modified between two Git references (or unstaged changes in the working tree). " +
				"This is the primary security tool for AI coding agents to verify pending changes before committing or completing tasks.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"diff_range": {
						Type:        "string",
						Description: "Git diff range (e.g. 'HEAD~1', 'main...HEAD', or 'HEAD'). Defaults to 'HEAD' if not provided.",
					},
					"base": {
						Type:        "string",
						Description: "Base Git reference (e.g. 'main').",
					},
					"head": {
						Type:        "string",
						Description: "Head Git reference (e.g. 'HEAD').",
					},
					"path": {
						Type:        "string",
						Description: "Optional target directory. Defaults to workspace root.",
					},
					"min_severity": {
						Type:        "string",
						Description: "Optional minimum severity: 'low', 'medium', 'high', 'critical'.",
						Enum:        []string{"low", "medium", "high", "critical"},
					},
				},
			},
		},
		{
			Name:        "scan_file",
			Description: "Scan an individual Go or Python file on disk for security vulnerabilities and taint flows.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"path": {
						Type:        "string",
						Description: "Path to the file to scan.",
					},
					"min_severity": {
						Type:        "string",
						Description: "Optional minimum severity: 'low', 'medium', 'high', 'critical'.",
						Enum:        []string{"low", "medium", "high", "critical"},
					},
				},
				Required: []string{"path"},
			},
		},
		{
			Name: "scan_code",
			Description: "Scan in-memory Go or Python source code directly. " +
				"Use this whenever you generate or modify code to verify you did not introduce security flaws before saving to disk.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"code": {
						Type:        "string",
						Description: "Source code snippet to analyze.",
					},
					"language": {
						Type:        "string",
						Description: "Programming language: 'go' or 'python'.",
						Enum:        []string{"go", "python"},
					},
					"filename": {
						Type:        "string",
						Description: "Optional virtual filename (e.g. 'main.go', 'app.py').",
					},
					"min_severity": {
						Type:        "string",
						Description: "Optional minimum severity: 'low', 'medium', 'high', 'critical'.",
						Enum:        []string{"low", "medium", "high", "critical"},
					},
				},
				Required: []string{"code", "language"},
			},
		},

		// 2. Finding & Remediation Explanation Tools
		{
			Name: "explain_finding",
			Description: "Provide an in-depth security explanation of a finding, including untrusted input source, " +
				"dangerous sink, taint propagation chain, matching CWE, model confidence, and code location.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"finding_id": {
						Type:        "string",
						Description: "The Finding ID or stable Fingerprint from a scan result.",
					},
				},
				Required: []string{"finding_id"},
			},
		},
		{
			Name: "get_remediation",
			Description: "Retrieve authoritative secure-coding remediation guidance, mitigation strategies, and safe code patterns " +
				"for a specific finding or CWE identifier.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"finding_id": {
						Type:        "string",
						Description: "Optional Finding ID or stable Fingerprint from a scan result.",
					},
					"cwe": {
						Type:        "string",
						Description: "Optional CWE identifier (e.g. 'CWE-78', 'CWE-89', 'CWE-22', 'CWE-798', 'CWE-502').",
					},
				},
			},
		},
		{
			Name:        "get_security_status",
			Description: "Retrieve current repository security status, total active findings count, and breakdown by severity.",
			InputSchema: InputSchema{
				Type:       "object",
				Properties: map[string]PropertyDef{},
			},
		},

		// 3. Issue Management Tools (Read & Write)
		{
			Name: "prepare_issue",
			Description: "Draft a security issue from a finding for review without performing any external side-effects. " +
				"Returns the proposed issue title, markdown body, labels, and stable fingerprint.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"finding_id": {
						Type:        "string",
						Description: "The Finding ID or Fingerprint from a scan.",
					},
					"additional_context": {
						Type:        "string",
						Description: "Optional context or notes explaining what you were implementing when this was found.",
					},
					"repo": {
						Type:        "string",
						Description: "Optional target repository ('owner/repo').",
					},
				},
				Required: []string{"finding_id"},
			},
		},
		{
			Name: "create_issue",
			Description: "Create a tracked security issue for a discovered finding in the configured issue provider (e.g. GitHub). " +
				"Automatically searches for existing issues by fingerprint to prevent duplicate issues. " +
				"Requires write authorization (--allow-write / --enable-issues).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"finding_id": {
						Type:        "string",
						Description: "The Finding ID or Fingerprint to file an issue for.",
					},
					"additional_context": {
						Type:        "string",
						Description: "Optional agent notes or implementation context.",
					},
					"repo": {
						Type:        "string",
						Description: "Optional target repository ('owner/repo').",
					},
					"title": {
						Type:        "string",
						Description: "Optional title override.",
					},
					"body": {
						Type:        "string",
						Description: "Optional body override.",
					},
				},
				Required: []string{"finding_id"},
			},
		},
		{
			Name: "update_issue",
			Description: "Update an existing security issue (e.g. add comments or update labels). " +
				"Requires write authorization (--allow-write / --enable-issues).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"issue_id": {
						Type:        "string",
						Description: "The Issue ID or number to update.",
					},
					"repo": {
						Type:        "string",
						Description: "Repository ('owner/repo').",
					},
					"comment": {
						Type:        "string",
						Description: "Comment or remediation notes to add.",
					},
					"state": {
						Type:        "string",
						Description: "Issue state: 'open' or 'closed'.",
						Enum:        []string{"open", "closed"},
					},
				},
				Required: []string{"issue_id"},
			},
		},
		{
			Name: "close_issue",
			Description: "Close an existing security issue once the vulnerability has been remediated and confirmed safe. " +
				"Requires write authorization (--allow-write / --enable-issues).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"issue_id": {
						Type:        "string",
						Description: "The Issue ID or number to close.",
					},
					"repo": {
						Type:        "string",
						Description: "Repository ('owner/repo').",
					},
					"reason": {
						Type:        "string",
						Description: "Reason for closing the issue.",
					},
				},
				Required: []string{"issue_id"},
			},
		},
	}
}

// Serve reads JSON-RPC requests from in and writes responses to out until EOF.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read error: %w", err)
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		resp := s.HandleMessage(line)
		if resp != nil {
			respBytes, err := json.Marshal(resp)
			if err != nil {
				return fmt.Errorf("failed to marshal response: %w", err)
			}
			if _, err := fmt.Fprintf(out, "%s\n", respBytes); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
		}
	}
}

// HandleMessage parses and executes a single raw JSON-RPC message.
func (s *Server) HandleMessage(raw []byte) *JSONRPCResponse {
	var req JSONRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      nil,
			Error: &JSONRPCError{
				Code:    CodeParseError,
				Message: "Parse error: " + err.Error(),
			},
		}
	}

	// Notifications don't get responses
	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		return nil
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "ping":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
		}
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("Method %q not found", req.Method),
			},
		}
	}
}

func (s *Server) handleInitialize(req JSONRPCRequest) *JSONRPCResponse {
	result := InitializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: ServerCapabilities{
			Tools: map[string]interface{}{},
		},
		ServerInfo: ServerInfo{
			Name:    "haystack-scanner",
			Version: "0.2.0",
		},
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

func (s *Server) handleToolsList(req JSONRPCRequest) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": s.tools,
		},
	}
}

func (s *Server) handleToolsCall(req JSONRPCRequest) *JSONRPCResponse {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidParams,
				Message: "Invalid parameters: " + err.Error(),
			},
		}
	}

	ctx := context.Background()

	switch params.Name {
	// Scan tools
	case "scan", "scan_directory":
		return s.callScan(req.ID, ctx, params.Arguments)
	case "scan_diff":
		return s.callScanDiff(req.ID, ctx, params.Arguments)
	case "scan_file":
		return s.callScanFile(req.ID, ctx, params.Arguments)
	case "scan_code":
		return s.callScanCode(req.ID, ctx, params.Arguments)
	case "get_analysis_plan":
		return s.callGetAnalysisPlan(req.ID, ctx, params.Arguments)

	// Findings tools
	case "explain_finding":
		return s.callExplainFinding(req.ID, ctx, params.Arguments)
	case "get_remediation":
		return s.callGetRemediation(req.ID, ctx, params.Arguments)
	case "get_security_status":
		return s.callGetSecurityStatus(req.ID, ctx, params.Arguments)

	// Issue tools
	case "prepare_issue":
		return s.callPrepareIssue(req.ID, ctx, params.Arguments)
	case "create_issue":
		return s.callCreateIssue(req.ID, ctx, params.Arguments)
	case "update_issue":
		return s.callUpdateIssue(req.ID, ctx, params.Arguments)
	case "close_issue":
		return s.callCloseIssue(req.ID, ctx, params.Arguments)

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidParams,
				Message: fmt.Sprintf("Unknown tool %q", params.Name),
			},
		}
	}
}

func (s *Server) toolError(id interface{}, msg string) *JSONRPCResponse {
	result := ToolCallResult{
		Content: []ToolContentItem{
			{
				Type: "text",
				Text: "Error: " + msg,
			},
		},
		IsError: true,
	}
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}
