package rlcd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"haystack/internal/classifier"
)

// Supported canonical model names
const (
	ModelHeuristic = "heuristic"
	ModelKev       = "kev"
	ModelJev       = "jev"
	ModelRLCD      = "rlcd"
)

// ClientOptions configures an RLCD inference client.
type ClientOptions struct {
	Endpoint string
	Model    string
	APIKey   string
	Timeout  time.Duration
	Fallback classifier.Classifier
}

// Client connects to an RLCD (Reinforcement Learning from Canonical Decisions)
// or calibrated decision model API (such as Jev, Kev, or custom RLCD models).
type Client struct {
	endpoint   string
	model      string
	apiKey     string
	httpClient *http.Client
	fallback   classifier.Classifier
}

// NewClient creates a new calibrated RLCD model API client.
func NewClient(opts ClientOptions) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	modelName := opts.Model
	if modelName == "" {
		modelName = ModelRLCD
	}

	return &Client{
		endpoint: opts.Endpoint,
		model:    modelName,
		apiKey:   opts.APIKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		fallback: opts.Fallback,
	}
}

// ModelName returns the configured decision model name (e.g. "jev", "kev", "rlcd").
func (c *Client) ModelName() string {
	return c.model
}

// Classify queries the remote calibrated decision model via its inference API.
func (c *Client) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	if c.endpoint == "" {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("no RLCD endpoint configured and no fallback classifier available")
	}

	// Attach model name to request input
	input.Model = c.model

	payload, err := json.Marshal(input)
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to marshal classification input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Model-Name", c.model)
	req.Header.Set("X-Decision-Type", "rlcd")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("rlcd model API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("rlcd model API returned HTTP %d", resp.StatusCode)
	}

	var result classifier.ClassificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("invalid json response from rlcd model API: %w", err)
	}

	if result.Model == "" {
		result.Model = c.model
	}

	return result, nil
}
