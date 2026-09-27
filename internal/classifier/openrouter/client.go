package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"haystack/internal/classifier"
)

const (
	DefaultBaseURL = "https://openrouter.ai/api/v1"
	DefaultModel   = "openrouter/free"
)

// ClientOptions configures an OpenRouter inference client for Jev.
type ClientOptions struct {
	BaseURL  string
	APIKey   string
	Model    string
	Timeout  time.Duration
	Fallback classifier.Classifier
}

// Client connects to OpenRouter API to run Jev classifications.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
	fallback   classifier.Classifier
}

// NewClient creates a new OpenRouter client for Jev.
func NewClient(opts ClientOptions) *Client {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("OPENROUTER_BASE_URL")
		if baseURL == "" {
			baseURL = DefaultBaseURL
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	apiKey := opts.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}

	model := opts.Model
	if model == "" {
		model = os.Getenv("OPENROUTER_MODEL")
		if model == "" {
			model = DefaultModel
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		fallback: opts.Fallback,
	}
}

func (c *Client) ModelName() string {
	return "jev"
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
	Temperature    float64         `json:"temperature"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponse struct {
	ID      string       `json:"id"`
	Model   string       `json:"model"`
	Choices []chatChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

type jevJSONOutput struct {
	Label         string             `json:"label"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
	Explanation   string             `json:"explanation"`
}

// Classify sends candidate evidence to OpenRouter for Jev adjudication.
func (c *Client) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	// If no API key provided, fall back immediately if available
	if c.apiKey == "" {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("no OPENROUTER_API_KEY configured and no fallback classifier available")
	}

	systemPrompt := "You are Jev, a specialized Static Application Security Testing (SAST) classifier. " +
		"Analyze the provided static analysis evidence (source, sink, taint flow, code snippet) and classify whether " +
		"it is a real vulnerability or safe/mitigated code. " +
		"You must respond in valid JSON with fields: " +
		"\"label\" (string, either the vulnerability category or 'safe_code'), " +
		"\"confidence\" (number between 0.0 and 1.0), " +
		"\"probabilities\" (object mapping labels to probabilities summing to 1.0), " +
		"and \"explanation\" (concise string)."

	var userPrompt strings.Builder
	userPrompt.WriteString(fmt.Sprintf("Category: %s\n", input.Category))
	if input.Question != "" {
		userPrompt.WriteString(fmt.Sprintf("Question: %s\n", input.Question))
	}
	userPrompt.WriteString(fmt.Sprintf("File: %s:%d\n", input.Evidence.File, input.Evidence.Line))
	userPrompt.WriteString(fmt.Sprintf("Source: %s (%s)\n", input.Evidence.Source.Name, input.Evidence.Source.Type))
	userPrompt.WriteString(fmt.Sprintf("Sink: %s (%s)\n", input.Evidence.Sink.Name, input.Evidence.Sink.Type))
	if len(input.Evidence.FlowSteps) > 0 {
		userPrompt.WriteString(fmt.Sprintf("Taint Flow: %s\n", strings.Join(input.Evidence.FlowSteps, " -> ")))
	}
	if input.Evidence.Code != "" {
		userPrompt.WriteString(fmt.Sprintf("Code Snippet:\n```\n%s\n```\n", input.Evidence.Code))
	}

	chatReq := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt.String()},
		},
		ResponseFormat: &responseFormat{Type: "json_object"},
		Temperature:    0.1,
	}

	reqBytes, err := json.Marshal(chatReq)
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to marshal openrouter request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/chat/completions", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return classifier.ClassificationResult{}, fmt.Errorf("failed to create openrouter request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/haystack-security/haystack")
	httpReq.Header.Set("X-Title", "Haystack Security Scanner")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("openrouter request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("openrouter returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("failed to decode openrouter response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("openrouter returned empty choices")
	}

	content := cleanJSONFence(chatResp.Choices[0].Message.Content)

	var jevRes jevJSONOutput
	if err := json.Unmarshal([]byte(content), &jevRes); err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("failed to parse jev json output: %w", err)
	}

	// Validate / normalize label
	label := jevRes.Label
	if label == "" {
		label = input.Category
	}

	conf := jevRes.Confidence
	if conf <= 0 {
		conf = 0.90
	} else if conf > 1.0 {
		conf = 1.0
	}

	probs := jevRes.Probabilities
	if probs == nil {
		probs = map[string]float64{
			label: conf,
		}
		if label != "safe_code" {
			probs["safe_code"] = 1.0 - conf
		}
	}

	return classifier.ClassificationResult{
		Model:         "jev",
		Label:         label,
		Confidence:    conf,
		Probabilities: probs,
		Explanation:   jevRes.Explanation,
	}, nil
}

func cleanJSONFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimSuffix(s, "```")
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
	}
	return strings.TrimSpace(s)
}
