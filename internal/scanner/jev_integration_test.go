// build+ integration
package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haystack/internal/config"
)

// TestSASTWithMockJevEndpoint verifies that the SAST scan pipeline correctly parses
// code, detects vulnerability candidates, and calls the Jev endpoint to classify findings.
func TestSASTWithMockJevEndpoint(t *testing.T) {
	var jevCalled bool
	var receivedPrompt string

	// Mock Jev HTTP endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jevCalled = true

		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("expected Bearer test-api-key, got %s", r.Header.Get("Authorization"))
		}

		var chatReq struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&chatReq); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		for _, m := range chatReq.Messages {
			if m.Role == "user" {
				receivedPrompt = m.Content
			}
		}

		jevResponse := map[string]interface{}{
			"id":    "gen-mock-123",
			"model": "jev",
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": `{"label": "command_injection", "confidence": 0.98, "probabilities": {"command_injection": 0.98, "safe_code": 0.02}, "explanation": "Unsanitized user input flows into exec.Command."}`,
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jevResponse)
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
		t.Fatal("expected Jev endpoint to be called during scan, but it was not")
	}

	if receivedPrompt == "" {
		t.Error("expected non-empty prompt sent to Jev endpoint")
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
}
