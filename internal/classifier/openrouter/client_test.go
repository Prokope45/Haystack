package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
	"haystack/internal/classifier/heuristic"
)

func TestOpenRouterClientTwoStepPipeline(t *testing.T) {
	var jevCalled bool
	var explainerCalled bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-openrouter-key" {
			t.Errorf("expected Authorization header Bearer test-openrouter-key, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		if strings.Contains(r.URL.Path, "decisions") {
			jevCalled = true
			var decReq jevDecisionRequest
			if err := json.NewDecoder(r.Body).Decode(&decReq); err != nil {
				t.Fatalf("failed to decode decisions request: %v", err)
			}

			if decReq.Model != SystemOneModel {
				t.Errorf("expected model %s, got %s", SystemOneModel, decReq.Model)
			}
			if !strings.Contains(decReq.State, "exec.Command") {
				t.Errorf("expected state to contain code snippet, got: %s", decReq.State)
			}

			noulVal := 0.96
			confVal := 0.96
			decResp := jevDecisionResponse{
				ID:    "gen-dec-12345",
				Model: SystemOneModel,
				Answers: map[string]jevAnswer{
					"is_vulnerable": {
						Type: "noul",
						Noul: &noulVal,
					},
					"classification": {
						Type:       "choice",
						Choice:     "command_injection",
						Confidence: &confVal,
						Probabilities: map[string]float64{
							"command_injection": 0.96,
							"safe_code":         0.04,
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(decResp)
			return
		}

		if strings.Contains(r.URL.Path, "chat/completions") {
			explainerCalled = true
			var chatReq chatRequest
			if err := json.NewDecoder(r.Body).Decode(&chatReq); err != nil {
				t.Fatalf("failed to decode chat request: %v", err)
			}

			if chatReq.Model != "openrouter/free" {
				t.Errorf("expected explainer model openrouter/free, got %s", chatReq.Model)
			}

			chatResp := chatResponse{
				ID:    "gen-chat-67890",
				Model: "openrouter/free",
				Choices: []chatChoice{
					{
						Message: chatMessage{
							Role:    "assistant",
							Content: "Unsanitized user input flows from HTTP query into exec.Command, allowing arbitrary shell command injection.",
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(chatResp)
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{
		BaseURL:        ts.URL,
		APIKey:         "test-openrouter-key",
		ExplainerModel: "openrouter/free",
		Timeout:        2 * time.Second,
	})

	ctx := context.Background()
	input := classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			File: "server.go",
			Line: 20,
			Source: analyzer.Source{
				Type: analyzer.SourceHTTPInput,
				Name: "r.URL.Query()",
			},
			Sink: analyzer.Sink{
				Type: analyzer.SinkShell,
				Name: "exec.Command",
			},
			FlowSteps: []string{"param", "cmd", "exec.Command"},
			Code:      "exec.Command(\"sh\", \"-c\", cmd)",
		},
	}

	res, err := client.Classify(ctx, input)
	if err != nil {
		t.Fatalf("unexpected classify error: %v", err)
	}

	if !jevCalled {
		t.Error("expected Jev decisions endpoint to be invoked")
	}
	if !explainerCalled {
		t.Error("expected LLM explainer endpoint to be invoked")
	}

	if res.Model != "jev" {
		t.Errorf("expected model jev, got %s", res.Model)
	}
	if res.Label != "command_injection" {
		t.Errorf("expected label command_injection, got %s", res.Label)
	}
	if res.Confidence != 0.96 {
		t.Errorf("expected confidence 0.96, got %f", res.Confidence)
	}
	if !strings.Contains(res.Explanation, "Unsanitized user input") {
		t.Errorf("expected LLM explanation, got: %s", res.Explanation)
	}
}

func TestOpenRouterClientSafeCodeSkipsExplanation(t *testing.T) {
	var chatCalled bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "decisions") {
			noulVal := 0.05
			confVal := 0.95
			decResp := jevDecisionResponse{
				ID:    "gen-dec-safe",
				Model: SystemOneModel,
				Answers: map[string]jevAnswer{
					"is_vulnerable": {
						Type: "noul",
						Noul: &noulVal,
					},
					"classification": {
						Type:       "choice",
						Choice:     "safe_code",
						Confidence: &confVal,
						Probabilities: map[string]float64{
							"command_injection": 0.05,
							"safe_code":         0.95,
						},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(decResp)
			return
		}

		if strings.Contains(r.URL.Path, "chat/completions") {
			chatCalled = true
		}
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{
		BaseURL: ts.URL,
		APIKey:  "test-key",
	})

	res, err := client.Classify(context.Background(), classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Code: "strconv.Atoi(input)",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Label != "safe_code" {
		t.Errorf("expected label safe_code, got %s", res.Label)
	}
	if chatCalled {
		t.Error("expected LLM explainer call to be skipped when code is classified as safe_code")
	}
}

func TestOpenRouterClientExplainerErrorResilience(t *testing.T) {
	var logOutput bytes.Buffer
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "decisions") {
			noulVal := 0.95
			decResp := jevDecisionResponse{
				Answers: map[string]jevAnswer{
					"classification": {
						Choice: "sql_injection",
						Probabilities: map[string]float64{
							"sql_injection": 0.95,
							"safe_code":     0.05,
						},
					},
					"is_vulnerable": {
						Noul: &noulVal,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(decResp)
			return
		}

		if strings.Contains(r.URL.Path, "chat/completions") {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{
		BaseURL: ts.URL,
		APIKey:  "test-key",
		Logger:  slog.New(slog.NewTextHandler(&logOutput, nil)),
	})

	res, err := client.Classify(context.Background(), classifier.ClassificationInput{
		Category: "sql_injection",
	})
	if err != nil {
		t.Fatalf("expected classification to succeed even if LLM explainer encounters an error, got: %v", err)
	}

	if res.Label != "sql_injection" {
		t.Errorf("expected sql_injection, got %s", res.Label)
	}
	if res.Explanation != "" {
		t.Errorf("expected no generated explanation when explainer fails, got: %s", res.Explanation)
	}
	if strings.Contains(res.Explanation, "Vulnerability classified by Jev decision model") {
		t.Errorf("expected the old generic classifier fallback to be absent, got: %s", res.Explanation)
	}
	if !strings.Contains(logOutput.String(), "HTTP 429") {
		t.Errorf("expected the explainer HTTP failure to be logged, got: %s", logOutput.String())
	}
}

func TestOpenRouterClientFallbackOnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	fallback := heuristic.NewHeuristicClassifier()
	client := NewClient(ClientOptions{
		BaseURL:  ts.URL,
		APIKey:   "test-key",
		Fallback: fallback,
	})

	input := classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Source: analyzer.Source{Type: analyzer.SourceHTTPInput},
			Sink:   analyzer.Sink{Type: analyzer.SinkShell},
			Code:   "exec.Command(input)",
		},
	}

	res, err := client.Classify(context.Background(), input)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got %v", err)
	}

	if res.Model != "heuristic" {
		t.Errorf("expected fallback model heuristic, got %s", res.Model)
	}
	if res.Label != "command_injection" {
		t.Errorf("expected label command_injection, got %s", res.Label)
	}
}
