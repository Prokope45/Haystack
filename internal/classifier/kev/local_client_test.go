package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
)

func TestLocalClientSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		res := classifier.ClassificationResult{
			Model:      "kev",
			Label:      "command_injection",
			Confidence: 0.95,
			Probabilities: map[string]float64{
				"command_injection": 0.95,
				"safe_code":         0.05,
			},
			Explanation: "Local Kev classified command injection.",
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	defer ts.Close()

	client := NewLocalClient(LocalClientOptions{
		Endpoint: ts.URL,
		Timeout:  2 * time.Second,
	})

	if client.ModelName() != "kev" {
		t.Errorf("expected model kev, got %s", client.ModelName())
	}

	res, err := client.Classify(context.Background(), classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Code: "exec.Command(cmd)",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Model != "kev" {
		t.Errorf("expected model kev, got %s", res.Model)
	}
	if res.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", res.Confidence)
	}
}

func TestLocalClientFallbackWhenOffline(t *testing.T) {
	// Point to an unreachable port
	fallback := NewHeuristicClassifier()
	client := NewLocalClient(LocalClientOptions{
		Endpoint: "http://127.0.0.1:59123/classify",
		Timeout:  100 * time.Millisecond,
		Fallback: fallback,
	})

	input := classifier.ClassificationInput{
		Category: "command_injection",
		Evidence: analyzer.Evidence{
			Source: analyzer.Source{Type: analyzer.SourceHTTPInput},
			Sink:   analyzer.Sink{Type: analyzer.SinkShell},
			Code:   "exec.Command(cmd)",
		},
	}

	res, err := client.Classify(context.Background(), input)
	if err != nil {
		t.Fatalf("expected fallback to succeed when local Kev is offline, got: %v", err)
	}

	if res.Model != "heuristic" {
		t.Errorf("expected fallback model heuristic, got %s", res.Model)
	}
	if res.Label != "command_injection" {
		t.Errorf("expected label command_injection, got %s", res.Label)
	}
}
