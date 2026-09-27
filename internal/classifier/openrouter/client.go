package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"haystack/internal/classifier"
)

const (
	DefaultDecisionsURL   = "https://openrouter.ai/api/alpha/decisions"
	DefaultChatURL        = "https://openrouter.ai/api/v1/chat/completions"
	SystemOneModel        = "~typesafe/jev-latest"
	DefaultExplainerModel = "openrouter/free"
)

// ClientOptions configures an OpenRouter inference client for Jev and LLM explanations.
type ClientOptions struct {
	BaseURL        string
	DecisionsURL   string
	ChatURL        string
	APIKey         string
	Model          string // Alias/fallback for ExplainerModel
	SystemOneModel string // Jev decision model (default: ~typesafe/jev-latest)
	ExplainerModel string // Explainer LLM model (default: openrouter/free)
	Timeout        time.Duration
	Fallback       classifier.Classifier
}

// Client executes candidate classification via Jev (/api/alpha/decisions)
// and enriches vulnerable findings with contextual descriptions via standard LLM chat completions.
type Client struct {
	decisionsURL   string
	chatURL        string
	apiKey         string
	systemOneModel string
	explainerModel string
	httpClient     *http.Client
	fallback       classifier.Classifier
}

// NewClient creates a new client for Jev decisions and LLM explanations.
func NewClient(opts ClientOptions) *Client {
	apiKey := opts.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}

	systemOneModel := opts.SystemOneModel
	if systemOneModel == "" {
		systemOneModel = os.Getenv("SYSTEM_ONE_MODEL")
		if systemOneModel == "" {
			systemOneModel = SystemOneModel
		}
	}

	explainerModel := opts.ExplainerModel
	if explainerModel == "" {
		explainerModel = opts.Model
		if explainerModel == "" {
			explainerModel = os.Getenv("OPENROUTER_MODEL")
			if explainerModel == "" {
				explainerModel = DefaultExplainerModel
			}
		}
	}

	decisionsURL := opts.DecisionsURL
	chatURL := opts.ChatURL

	if decisionsURL == "" || chatURL == "" {
		baseURL := opts.BaseURL
		if baseURL == "" {
			baseURL = os.Getenv("OPENROUTER_BASE_URL")
		}

		if baseURL != "" {
			cleanBase := strings.TrimRight(baseURL, "/")
			if decisionsURL == "" {
				if strings.HasSuffix(cleanBase, "/v1") {
					decBase := strings.TrimSuffix(cleanBase, "/v1")
					decisionsURL = decBase + "/alpha/decisions"
				} else if strings.HasSuffix(cleanBase, "/api") {
					decisionsURL = cleanBase + "/alpha/decisions"
				} else if strings.HasSuffix(cleanBase, "/alpha/decisions") {
					decisionsURL = cleanBase
				} else {
					decisionsURL = cleanBase + "/api/alpha/decisions"
				}
			}

			if chatURL == "" {
				if strings.HasSuffix(cleanBase, "/chat/completions") {
					chatURL = cleanBase
				} else if strings.HasSuffix(cleanBase, "/v1") {
					chatURL = cleanBase + "/chat/completions"
				} else if strings.HasSuffix(cleanBase, "/api") {
					chatURL = cleanBase + "/v1/chat/completions"
				} else {
					chatURL = cleanBase + "/api/v1/chat/completions"
				}
			}
		} else {
			if decisionsURL == "" {
				decisionsURL = DefaultDecisionsURL
			}
			if chatURL == "" {
				chatURL = DefaultChatURL
			}
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		decisionsURL:   decisionsURL,
		chatURL:        chatURL,
		apiKey:         apiKey,
		systemOneModel: systemOneModel,
		explainerModel: explainerModel,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		fallback: opts.Fallback,
	}
}

func (c *Client) ModelName() string {
	return "jev"
}

// Jev Decision API Request and Response schema
type jevDecisionRequest struct {
	Model     string                 `json:"model"`
	State     string                 `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevQuestion struct {
	Type         string      `json:"type"`               // "noul", "choice", or "score"
	Instructions string      `json:"instructions"`       // question prompt
	Criteria     interface{} `json:"criteria,omitempty"` // map[string]string or []string
}

type jevDecisionResponse struct {
	ID      string               `json:"id,omitempty"`
	Model   string               `json:"model,omitempty"`
	Answers map[string]jevAnswer `json:"answers"`
	Error   *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

type jevAnswer struct {
	Type          string             `json:"type,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

// OpenRouter Chat Completion API Request and Response schema (for vulnerability description)
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
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

// Classify executes the two-step triage workflow:
// 1. Invokes Jev on OpenRouter's decisions endpoint (/api/alpha/decisions) to classify the candidate.
// 2. If classified as a vulnerability, invokes a standard LLM (/api/v1/chat/completions) to explain what and why it is vulnerable.
func (c *Client) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	if c.apiKey == "" {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("no OPENROUTER_API_KEY configured and no fallback classifier available")
	}

	// -------------------------------------------------------------------------
	// Step 1: Execute Jev Decision Classification
	// -------------------------------------------------------------------------
	targetCategory := input.Category
	if targetCategory == "" {
		targetCategory = "vulnerability"
	}

	state := formatCandidateState(input)

	categoryReadable := strings.ReplaceAll(targetCategory, "_", " ")
	questions := map[string]jevQuestion{
		"is_vulnerable": {
			Type:         "noul",
			Instructions: fmt.Sprintf("Does this code contain an exploitable %s vulnerability?", categoryReadable),
			Criteria: map[string]string{
				"true":  "Untrusted input reaches a sensitive sink without adequate sanitization or validation, creating an exploitable risk.",
				"false": "The code is safe, properly sanitized, benign, or not exploitable.",
			},
		},
		"classification": {
			Type:         "choice",
			Instructions: "Classify whether this code is a true positive vulnerability or safe/mitigated code.",
			Criteria: map[string]string{
				targetCategory: fmt.Sprintf("Exploitable %s vulnerability pattern.", targetCategory),
				"safe_code":    "Safe, sanitized, mitigated, or false positive code pattern.",
			},
		},
	}

	jevReq := jevDecisionRequest{
		Model:     c.systemOneModel,
		State:     state,
		Questions: questions,
	}

	reqBytes, err := json.Marshal(jevReq)
	if err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("failed to marshal jev request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.decisionsURL, bytes.NewReader(reqBytes))
	if err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("failed to create jev decisions request: %w", err)
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
		return classifier.ClassificationResult{}, fmt.Errorf("jev decisions request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("jev decisions returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var jevResp jevDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&jevResp); err != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("failed to decode jev decisions response: %w", err)
	}

	if jevResp.Error != nil {
		if c.fallback != nil {
			return c.fallback.Classify(ctx, input)
		}
		return classifier.ClassificationResult{}, fmt.Errorf("jev decision API error (%d): %s", jevResp.Error.Code, jevResp.Error.Message)
	}

	// Extract Label, Confidence, and Probabilities from Jev response
	var label string
	var conf float64
	var probs map[string]float64

	if ans, ok := jevResp.Answers["classification"]; ok {
		label = ans.Choice
		if ans.Probabilities != nil {
			probs = ans.Probabilities
		}
		if ans.Confidence != nil && *ans.Confidence > 0 {
			conf = *ans.Confidence
		} else if probs != nil && label != "" {
			conf = probs[label]
		}
	}

	if isVulnAns, ok := jevResp.Answers["is_vulnerable"]; ok && isVulnAns.Noul != nil {
		noulVal := *isVulnAns.Noul
		if label == "" {
			if noulVal >= 0.5 {
				label = targetCategory
				conf = noulVal
			} else {
				label = "safe_code"
				conf = 1.0 - noulVal
			}
		} else if conf == 0 {
			if label == "safe_code" {
				conf = 1.0 - noulVal
			} else {
				conf = noulVal
			}
		}
	}

	if label == "" {
		label = targetCategory
	}

	if conf <= 0 {
		conf = 0.90
	} else if conf > 1.0 {
		conf = 1.0
	}

	if probs == nil {
		probs = map[string]float64{
			label: conf,
		}
		if label != "safe_code" {
			probs["safe_code"] = math.Max(0, 1.0-conf)
		}
	}

	// If classified as safe_code, skip LLM explanation and return immediately
	if label == "safe_code" {
		return classifier.ClassificationResult{
			Model:         "jev",
			Label:         "safe_code",
			Confidence:    conf,
			Probabilities: probs,
			Explanation:   "Candidate analyzed and classified as safe/mitigated code by Jev decision model.",
		}, nil
	}

	// -------------------------------------------------------------------------
	// Step 2: Use LLM to describe what the vulnerability is and why it's a vulnerability
	// -------------------------------------------------------------------------
	explanation := c.explainVulnerability(ctx, input, label, conf)

	return classifier.ClassificationResult{
		Model:         "jev",
		Label:         label,
		Confidence:    conf,
		Probabilities: probs,
		Explanation:   explanation,
	}, nil
}

// explainVulnerability queries an OpenRouter LLM to explain the vulnerability context.
func (c *Client) explainVulnerability(ctx context.Context, input classifier.ClassificationInput, label string, conf float64) string {
	systemPrompt := "You are a specialized application security expert. " +
		"Provide a concise, direct description of the identified vulnerability in the provided code snippet. " +
		"Explain what the vulnerability is and why it is a vulnerability in this specific code context. " +
		"Keep the explanation clear, professional, and within 2 to 4 sentences. " +
		"Do not wrap in markdown quotes or conversational filler; output the description directly."

	var userPrompt strings.Builder
	userPrompt.WriteString(fmt.Sprintf("Vulnerability Category: %s\n", label))
	userPrompt.WriteString(fmt.Sprintf("Location: %s:%d\n", input.Evidence.File, input.Evidence.Line))
	if input.Evidence.Source.Name != "" {
		userPrompt.WriteString(fmt.Sprintf("Untrusted Source: %s (%s)\n", input.Evidence.Source.Name, input.Evidence.Source.Type))
	}
	if input.Evidence.Sink.Name != "" {
		userPrompt.WriteString(fmt.Sprintf("Dangerous Sink: %s (%s)\n", input.Evidence.Sink.Name, input.Evidence.Sink.Type))
	}
	if len(input.Evidence.FlowSteps) > 0 {
		userPrompt.WriteString(fmt.Sprintf("Taint Propagation: %s\n", strings.Join(input.Evidence.FlowSteps, " -> ")))
	}
	if input.Evidence.Code != "" {
		userPrompt.WriteString(fmt.Sprintf("Code Snippet:\n```\n%s\n```\n", input.Evidence.Code))
	}
	userPrompt.WriteString(fmt.Sprintf("Jev Decision Verdict: %s (Confidence: %.0f%%)\n\n", label, conf*100))
	userPrompt.WriteString("Explain what this vulnerability is and why this code is vulnerable.")

	chatReq := chatRequest{
		Model: c.explainerModel,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt.String()},
		},
		Temperature: 0.2,
	}

	reqBytes, err := json.Marshal(chatReq)
	if err != nil {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.chatURL, bytes.NewReader(reqBytes))
	if err != nil {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/haystack-security/haystack")
	httpReq.Header.Set("X-Title", "Haystack Security Scanner")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil || len(chatResp.Choices) == 0 {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}

	explanation := strings.TrimSpace(chatResp.Choices[0].Message.Content)
	if explanation == "" {
		return fmt.Sprintf("Vulnerability classified by Jev decision model as %s (confidence %.2f).", label, conf)
	}

	return explanation
}

func formatCandidateState(input classifier.ClassificationInput) string {
	var sb strings.Builder
	if input.Category != "" {
		sb.WriteString(fmt.Sprintf("Category: %s\n", input.Category))
	}
	if input.Question != "" {
		sb.WriteString(fmt.Sprintf("Question: %s\n", input.Question))
	}
	sb.WriteString(fmt.Sprintf("File: %s:%d\n", input.Evidence.File, input.Evidence.Line))
	if input.Evidence.Source.Name != "" {
		sb.WriteString(fmt.Sprintf("Source: %s (%s)\n", input.Evidence.Source.Name, input.Evidence.Source.Type))
	}
	if input.Evidence.Sink.Name != "" {
		sb.WriteString(fmt.Sprintf("Sink: %s (%s)\n", input.Evidence.Sink.Name, input.Evidence.Sink.Type))
	}
	if len(input.Evidence.FlowSteps) > 0 {
		sb.WriteString(fmt.Sprintf("Taint Flow: %s\n", strings.Join(input.Evidence.FlowSteps, " -> ")))
	}
	if input.Evidence.Code != "" {
		sb.WriteString(fmt.Sprintf("Code Snippet:\n%s\n", input.Evidence.Code))
	}
	return sb.String()
}
