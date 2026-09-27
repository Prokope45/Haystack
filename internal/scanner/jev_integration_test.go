// build+ integration
package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haystack/internal/config"
)

// TestSASTWithMockJevEndpoint verifies that the SAST scan pipeline correctly parses
// code, detects vulnerability candidates, and calls the Jev endpoint to classify findings.
func TestSASTWithMockJevEndpoint(t *testing.T) {
	var jevCalled bool
	var explainerCalled bool
	var receivedPrompt string

	// Mock Jev decisions and LLM explanation HTTP endpoints
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("expected Bearer test-api-key, got %s", r.Header.Get("Authorization"))
		}

		w.Header().Set("Content-Type", "application/json")

		// Route 1: Jev Decisions endpoint
		if strings.Contains(r.URL.Path, "decisions") {
			jevCalled = true

			var decReq struct {
				Model     string                 `json:"model"`
				State     string                 `json:"state"`
				Questions map[string]interface{} `json:"questions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&decReq); err != nil {
				t.Fatalf("failed to decode decisions request body: %v", err)
			}

			if !strings.Contains(decReq.State, "exec.Command") {
				t.Errorf("expected state to contain exec.Command, got %s", decReq.State)
			}

			jevResponse := map[string]interface{}{
				"id":    "gen-mock-jev-123",
				"model": "~typesafe/jev-latest",
				"answers": map[string]interface{}{
					"is_vulnerable": map[string]interface{}{
						"type": "noul",
						"noul": 0.98,
					},
					"classification": map[string]interface{}{
						"type":       "choice",
						"choice":     "command_injection",
						"confidence": 0.98,
						"probabilities": map[string]interface{}{
							"command_injection": 0.98,
							"safe_code":         0.02,
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(jevResponse)
			return
		}

		// Route 2: Normal LLM Chat Completions endpoint (vulnerability explainer)
		if strings.Contains(r.URL.Path, "chat/completions") {
			explainerCalled = true

			var chatReq struct {
				Model    string `json:"model"`
				Messages []struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"messages"`
			}
			if err := json.NewDecoder(r.Body).Decode(&chatReq); err != nil {
				t.Fatalf("failed to decode chat request body: %v", err)
			}

			for _, m := range chatReq.Messages {
				if m.Role == "user" {
					receivedPrompt = m.Content
				}
			}

			llmResponse := map[string]interface{}{
				"id":    "gen-mock-llm-456",
				"model": "openrouter/free",
				"choices": []map[string]interface{}{
					{
						"message": map[string]interface{}{
							"role":    "assistant",
							"content": "Unsanitized user input flows into exec.Command, allowing arbitrary shell command execution.",
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(llmResponse)
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	// Configure SAST tool to use the mocked Jev endpoint
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "jev"
	cfg.ClassifierEndpoint = ts.URL
	cfg.OpenRouterBaseURL = ts.URL
	cfg.OpenRouterAPIKey = "test-api-key"
	cfg.ClassifierAPIKey = "test-api-key"
	cfg.ClassifierTimeout = 5 * time.Second

	orch := NewOrchestrator(cfg)

	// Mock source code with a command injection vulnerability
	mockCode := `package main

import (
	"net/http"
	"os/exec"
)

func vulnHandler(w http.ResponseWriter, r *http.Request) {
	cmdName := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmdName).Run()
}
`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, summary, err := orch.ScanCode(ctx, []byte(mockCode), "go", "mock_handler.go")
	if err != nil {
		t.Fatalf("ScanCode failed: %v", err)
	}

	if !jevCalled {
		t.Fatal("expected Jev decisions endpoint to be called during scan, but it was not")
	}

	if !explainerCalled {
		t.Fatal("expected LLM explainer endpoint to be called during scan, but it was not")
	}

	if receivedPrompt == "" {
		t.Error("expected non-empty prompt sent to LLM explainer endpoint")
	}

	if summary.FindingsCount != 1 || len(findings) != 1 {
		t.Fatalf("expected 1 finding, got summary=%d findings=%d", summary.FindingsCount, len(findings))
	}

	f := findings[0]
	if f.RuleID != "RULE-CMD-001" {
		t.Errorf("expected RULE-CMD-001, got %s", f.RuleID)
	}
	if f.Model != "jev" {
		t.Errorf("expected finding model 'jev', got %q", f.Model)
	}
	if f.Classification == nil {
		t.Fatal("expected finding Classification to be populated, got nil")
	}
	if f.Classification.Model != "jev" {
		t.Errorf("expected classification model 'jev', got %q", f.Classification.Model)
	}
	if f.Classification.Confidence != 0.98 {
		t.Errorf("expected confidence 0.98, got %f", f.Classification.Confidence)
	}
	if f.Classification.Explanation == "" {
		t.Error("expected non-empty explanation in classification")
	}

	t.Logf("Mock Jev test passed: finding classified by model %s with confidence %.2f: %s",
		f.Classification.Model, f.Classification.Confidence, f.Classification.Explanation)
}

// TestSASTWithLiveJevEndpoint runs the end-to-end scan pipeline against the live
// OpenRouter Jev endpoint using the API key loaded from .env.
// All code and environment inputs are mocked in-memory except for the Jev classification call.
func TestSASTWithLiveJevEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.OpenRouterAPIKey == "" {
		t.Skip("Skipping live Jev test: OPENROUTER_API_KEY is not set in .env or environment")
	}

	cfg.ClassifierProvider = "jev"
	// Allow sufficient timeout for remote LLM inference
	cfg.ClassifierTimeout = 45 * time.Second

	orch := NewOrchestrator(cfg)

	// In-memory mock source code with an explicit shell command injection
	mockVulnerableCode := `package main

import (
	"net/http"
	"os/exec"
)

func runCommand(w http.ResponseWriter, r *http.Request) {
	cmdParam := r.URL.Query().Get("action")
	fullCmd := "run_task " + cmdParam
	exec.Command("sh", "-c", fullCmd).Run()
}
`

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Log("Initiating SAST scan on mock code with live Jev classification...")
	findings, summary, err := orch.ScanCode(ctx, []byte(mockVulnerableCode), "go", "diagnostics.go")
	if err != nil {
		t.Fatalf("SAST scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected candidate finding to be detected, got 0 (summary count: %d)", summary.FindingsCount)
	}

	f := findings[0]
	t.Logf("Finding detected: %s (Rule: %s, Category: %s)", f.ID, f.RuleID, f.Category)

	if f.Classification == nil {
		t.Fatalf("expected classification to be present, got nil")
	}

	if f.Model != "jev" {
		t.Fatalf("expected classification model 'jev', got %q (classification may have failed and fallen back to heuristic)", f.Model)
	}

	if f.Classification.Model != "jev" {
		t.Fatalf("expected classification.Model to be 'jev', got %q", f.Classification.Model)
	}

	if f.Confidence <= 0 {
		t.Errorf("expected positive confidence score, got %f", f.Confidence)
	}

	if f.Classification.Explanation == "" {
		t.Errorf("expected non-empty explanation from Jev")
	}

	t.Logf("Successfully verified SAST + Jev classification:")
	t.Logf("  Model:       %s", f.Classification.Model)
	t.Logf("  Label:       %s", f.Classification.Label)
	t.Logf("  Confidence:  %.2f", f.Classification.Confidence)
	t.Logf("  Explanation: %s", f.Classification.Explanation)
	t.Logf("  Explanation: %s", f.AnalysisMetadata.Strategy)
}
