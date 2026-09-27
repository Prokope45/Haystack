package openrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
	"haystack/internal/classifier/kev"
)

func TestOpenRouterClientSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-openrouter-key" {
			t.Errorf("expected Authorization header Bearer test-openrouter-key, got %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		var req chatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if req.Model != "openrouter/free" {
			t.Errorf("expected model openrouter/free, got %s", req.Model)
		}

		jevJSON := `{"label": "command_injection", "confidence": 0.96, "probabilities": {"command_injection": 0.96, "safe_code": 0.04}, "explanation": "Direct shell execution with tainted parameter."}`

		resp := chatResponse{
			ID:    "gen-12345",
			Model: "openrouter/free",
			Choices: []chatChoice{
				{
					Message: chatMessage{
						Role:    "assistant",
						Content: jevJSON,
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{
		BaseURL: ts.URL,
		APIKey:  "test-openrouter-key",
		Model:   "openrouter/free",
		Timeout: 2 * time.Second,
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

	if res.Model != "jev" {
		t.Errorf("expected model jev, got %s", res.Model)
	}
	if res.Label != "command_injection" {
		t.Errorf("expected label command_injection, got %s", res.Label)
	}
	if res.Confidence != 0.96 {
		t.Errorf("expected confidence 0.96, got %f", res.Confidence)
	}
}

func TestOpenRouterClientMarkdownJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jevJSON := "```json\n{\"label\": \"safe_code\", \"confidence\": 0.98, \"probabilities\": {\"safe_code\": 0.98}, \"explanation\": \"Input sanitized via strconv.Atoi.\"}\n```"

		resp := chatResponse{
			ID:    "gen-67890",
			Model: "openrouter/free",
			Choices: []chatChoice{
				{
					Message: chatMessage{
						Role:    "assistant",
						Content: jevJSON,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{
		BaseURL: ts.URL,
		APIKey:  "test-key",
		Model:   "openrouter/free",
	})

	res, err := client.Classify(context.Background(), classifier.ClassificationInput{Category: "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Label != "safe_code" {
		t.Errorf("expected label safe_code, got %s", res.Label)
	}
}

func TestOpenRouterClientFallbackOnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	}))
	defer ts.Close()

	fallback := kev.NewHeuristicClassifier()
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
