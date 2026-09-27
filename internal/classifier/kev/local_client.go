package kev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"haystack/internal/classifier"
)

const (
	DefaultLocalEndpoint = "http://localhost:8080/classify"
)

// LocalClientOptions configures a client to a locally deployed Kev instance.
type LocalClientOptions struct {
	Endpoint string
	Timeout  time.Duration
	APIKey   string
	Fallback classifier.Classifier
}

// LocalClient connects to a local Kev microservice instance.
type LocalClient struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
	fallback   classifier.Classifier
}

// NewLocalClient creates a client pointing to a local Kev instance.
func NewLocalClient(opts LocalClientOptions) *LocalClient {
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("KEV_URL")
		if endpoint == "" {
			endpoint = os.Getenv("KEV_ENDPOINT")
		}
		if endpoint == "" {
			endpoint = DefaultLocalEndpoint
		}
	}
	endpoint = strings.TrimRight(endpoint, "/")

	apiKey := opts.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("KEV_API_KEY")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	fallback := opts.Fallback
	if fallback == nil {
		fallback = NewHeuristicClassifier()
	}

	return &LocalClient{
		endpoint: endpoint,
		apiKey:   apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		fallback: fallback,
	}
}

func (c *LocalClient) ModelName() string {
	return "kev"
}

// Classify queries the local Kev service, falling back to heuristic engine if unavailable.
func (c *LocalClient) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	if c.endpoint == "" {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("no local kev endpoint configured")
	}

	if input.Model == "" {
		input.Model = "kev"
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to marshal input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Connection refused or timeout: fallback to heuristic classifier
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("local kev service unavailable at %s: %w", c.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("local kev returned HTTP %d", resp.StatusCode)
	}

	var result classifier.ClassificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("invalid json from local kev: %w", err)
	}

	if result.Model == "" {
		result.Model = "kev"
	}

	return result, nil
}
