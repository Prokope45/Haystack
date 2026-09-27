package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/issues/providers/mock"
	"haystack/internal/planning"
)

func TestMCPInitialize(t *testing.T) {
	server := NewServer(config.DefaultConfig())

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	raw, _ := json.Marshal(req)

	resp := server.HandleMessage(raw)
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	initRes, ok := resp.Result.(InitializeResult)
	if !ok {
		t.Fatalf("expected InitializeResult, got %T", resp.Result)
	}
	if initRes.ServerInfo.Name != "haystack-scanner" {
		t.Errorf("expected server name haystack-scanner, got %s", initRes.ServerInfo.Name)
	}
}

func TestMCPToolsList(t *testing.T) {
	server := NewServer(config.DefaultConfig())

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	raw, _ := json.Marshal(req)

	resp := server.HandleMessage(raw)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", resp.Result)
	}

	tools, ok := resultMap["tools"].([]Tool)
	if !ok {
		t.Fatalf("expected []Tool, got %T", resultMap["tools"])
	}

	expectedTools := []string{
		"scan", "scan_diff", "scan_file", "scan_code", "get_analysis_plan",
		"explain_finding", "get_remediation", "get_security_status",
		"prepare_issue", "create_issue", "update_issue", "close_issue",
	}

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}

	for _, exp := range expectedTools {
		if !names[exp] {
			t.Errorf("missing expected tool: %s", exp)
		}
	}
}

func TestMCPScanCodeAndWorkflow(t *testing.T) {
	mockProv := mock.NewMockProvider()
	server := NewServerWithOptions(ServerOptions{
		Config:        config.DefaultConfig(),
		IssueProvider: mockProv,
		AllowWrite:    false, // start read-only
		DefaultRepo:   "testowner/testrepo",
	})

	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	cmd := "ping -c 1 " + target
	exec.Command("sh", "-c", cmd).Run()
}
`

	// 1. scan_code
	params := ToolCallParams{
		Name: "scan_code",
		Arguments: map[string]interface{}{
			"code":     code,
			"language": "go",
			"filename": "handler.go",
		},
	}
	paramsRaw, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  paramsRaw,
	}
	raw, _ := json.Marshal(req)

	resp := server.HandleMessage(raw)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	toolResult, ok := resp.Result.(ToolCallResult)
	if !ok {
		t.Fatalf("expected ToolCallResult, got %T", resp.Result)
	}

	if !toolResult.IsError {
		t.Error("expected IsError true for vulnerable code")
	}

	findingsList, ok := toolResult.Meta["findings"].([]findings.Finding)
	if !ok || len(findingsList) == 0 {
		t.Fatalf("expected findings in meta, got %v", toolResult.Meta["findings"])
	}

	findingID := findingsList[0].ID
	fingerprint := findingsList[0].Fingerprint
	if findingID == "" || fingerprint == "" {
		t.Fatalf("finding ID or fingerprint empty: %s, %s", findingID, fingerprint)
	}

	// 2. explain_finding
	explainReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: mustMarshal(ToolCallParams{
			Name: "explain_finding",
			Arguments: map[string]interface{}{
				"finding_id": findingID,
			},
		}),
	}
	explainResp := server.HandleMessage(mustMarshal(explainReq))
	if explainResp == nil || explainResp.Error != nil {
		t.Fatalf("explain_finding failed: %v", explainResp.Error)
	}
	explainRes := explainResp.Result.(ToolCallResult)
	if !strings.Contains(explainRes.Content[0].Text, "CWE-78") {
		t.Errorf("expected CWE-78 in explanation, got %s", explainRes.Content[0].Text)
	}

	// 3. get_remediation
	remReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: mustMarshal(ToolCallParams{
			Name: "get_remediation",
			Arguments: map[string]interface{}{
				"cwe": "CWE-78",
			},
		}),
	}
	remResp := server.HandleMessage(mustMarshal(remReq))
	if remResp == nil || remResp.Error != nil {
		t.Fatalf("get_remediation failed: %v", remResp.Error)
	}

	// 4. get_security_status
	statusReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params: mustMarshal(ToolCallParams{
			Name:      "get_security_status",
			Arguments: map[string]interface{}{},
		}),
	}
	statusResp := server.HandleMessage(mustMarshal(statusReq))
	if statusResp == nil || statusResp.Error != nil {
		t.Fatalf("get_security_status failed: %v", statusResp.Error)
	}

	// 5. prepare_issue (read-only)
	prepReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "tools/call",
		Params: mustMarshal(ToolCallParams{
			Name: "prepare_issue",
			Arguments: map[string]interface{}{
				"finding_id":         findingID,
				"additional_context": "Discovered during new handler PR",
			},
		}),
	}
	prepResp := server.HandleMessage(mustMarshal(prepReq))
	if prepResp == nil || prepResp.Error != nil {
		t.Fatalf("prepare_issue failed: %v", prepResp.Error)
	}
	prepRes := prepResp.Result.(ToolCallResult)
	if !strings.Contains(prepRes.Content[0].Text, "Scanner-Fingerprint:") {
		t.Errorf("expected Scanner-Fingerprint in draft, got %s", prepRes.Content[0].Text)
	}

	// 6. create_issue while allowWrite == false -> MUST be rejected
	createReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      8,
		Method:  "tools/call",
		Params: mustMarshal(ToolCallParams{
			Name: "create_issue",
			Arguments: map[string]interface{}{
				"finding_id": findingID,
			},
		}),
	}
	createResp := server.HandleMessage(mustMarshal(createReq))
	createRes := createResp.Result.(ToolCallResult)
	if !createRes.IsError || !strings.Contains(createRes.Content[0].Text, "permission denied") {
		t.Errorf("expected permission denied error, got %s", createRes.Content[0].Text)
	}

	// 7. Enable write permissions and create issue
	server.SetAllowWrite(true)
	createResp2 := server.HandleMessage(mustMarshal(createReq))
	createRes2 := createResp2.Result.(ToolCallResult)
	if createRes2.IsError {
		t.Fatalf("expected successful issue creation, got error: %s", createRes2.Content[0].Text)
	}
	if !strings.Contains(createRes2.Content[0].Text, "Created Successfully") {
		t.Errorf("expected creation message, got %s", createRes2.Content[0].Text)
	}

	// 8. Re-call create_issue with same finding -> MUST be deduplicated
	dupResp := server.HandleMessage(mustMarshal(createReq))
	dupRes := dupResp.Result.(ToolCallResult)
	if dupRes.IsError {
		t.Fatalf("unexpected error on deduplication call: %s", dupRes.Content[0].Text)
	}
	if isDup, ok := dupRes.Meta["is_duplicate"].(bool); !ok || !isDup {
		t.Errorf("expected is_duplicate: true, got %v", dupRes.Meta["is_duplicate"])
	}
	if !strings.Contains(dupRes.Content[0].Text, "Deduplicated") {
		t.Errorf("expected deduplicated banner in message, got %s", dupRes.Content[0].Text)
	}
}

func TestMCPServeStream(t *testing.T) {
	server := NewServer(config.DefaultConfig())

	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
	var output bytes.Buffer

	err := server.Serve(input, &output)
	if err != nil {
		t.Fatalf("unexpected Serve error: %v", err)
	}

	var resp JSONRPCResponse
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode server output: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("unexpected error in ping: %v", resp.Error)
	}
}

func TestMCPGetAnalysisPlan(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TargetDir = "../../testdata/go"
	server := NewServer(cfg)

	params := ToolCallParams{
		Name: "get_analysis_plan",
		Arguments: map[string]interface{}{
			"path":     "../../testdata/go",
			"strategy": "adaptive",
		},
	}
	paramsRaw, _ := json.Marshal(params)

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      10,
		Method:  "tools/call",
		Params:  paramsRaw,
	}
	raw, _ := json.Marshal(req)

	resp := server.HandleMessage(raw)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	toolResult, ok := resp.Result.(ToolCallResult)
	if !ok {
		t.Fatalf("expected ToolCallResult, got %T", resp.Result)
	}

	if toolResult.IsError {
		t.Errorf("expected IsError false for get_analysis_plan")
	}

	plan, ok := toolResult.Meta["plan"].(*planning.AnalysisPlan)
	if !ok || plan == nil {
		t.Fatalf("expected non-nil AnalysisPlan in meta, got %T", toolResult.Meta["plan"])
	}

	if len(plan.Candidates) == 0 {
		t.Errorf("expected candidates in plan, got 0")
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
