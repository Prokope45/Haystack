package rlcd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
	"haystack/internal/classifier/heuristic"
)

func TestRLCDClientSystemOneModel(t *testing.T) {
	var receivedModelHeader string
	var receivedAuthHeader string
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedModelHeader = r.Header.Get("X-Model-Name")
		receivedAuthHeader = r.Header.Get("Authorization")

		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)

		res := classifier.ClassificationResult{
			Model:      "system-one",
			Label:      "command_injection",
			Confidence: 0.97,
			Probabilities: map[string]float64{
				"command_injection": 0.97,
				"safe_code":         0.02,
			},
			Explanation: "System-One RLCD decision model classified command injection pattern.",
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	defer server.Close()

	client := NewClient(ClientOptions{
		Endpoint: server.URL,
		Model:    "system-one",
		APIKey:   "secret-token-123",
		Timeout:  2 * time.Second,
	})

	if client.ModelName() != "system-one" {
		t.Fatalf("expected model system-one, got %s", client.ModelName())
	}

	ctx := context.Background()
	input := classifier.ClassificationInput{
		Question: "Classify potential vulnerability",
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Code: "os.system(cmd)",
		},
	}

	result, err := client.Classify(ctx, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedModelHeader != "system-one" {
		t.Errorf("expected X-Model-Name header 'system-one', got %s", receivedModelHeader)
	}
	if receivedAuthHeader != "Bearer secret-token-123" {
		t.Errorf("expected Authorization header 'Bearer secret-token-123', got %s", receivedAuthHeader)
	}
	if receivedPayload["model"] != "system-one" {
		t.Errorf("expected payload model 'system-one', got %v", receivedPayload["model"])
	}
	if result.Model != "system-one" {
		t.Errorf("expected result model 'system-one', got %s", result.Model)
	}
	if result.Confidence != 0.97 {
		t.Errorf("expected confidence 0.97, got %f", result.Confidence)
	}
}

func TestRLCDClientFallbackOnServerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	fallback := heuristic.NewHeuristicClassifier()
	client := NewClient(ClientOptions{
		Endpoint: server.URL,
		Model:    "custom-model",
		Fallback: fallback,
	})

	ctx := context.Background()
	input := classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Source: analyzer.Source{Type: analyzer.SourceHTTPInput},
			Sink:   analyzer.Sink{Type: analyzer.SinkShell},
			Code:   "exec.Command(input)",
		},
	}

	result, err := client.Classify(ctx, input)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}

	if result.Label != "command_injection" {
		t.Errorf("expected fallback label command_injection, got %s", result.Label)
	}
	if result.Model != "heuristic" {
		t.Errorf("expected fallback model 'heuristic', got %s", result.Model)
	}
}
