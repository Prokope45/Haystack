package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"haystack/internal/candidates"
	"haystack/internal/planning"
)

const (
	DefaultDecisionsURL = "https://openrouter.ai/api/alpha/decisions"
	DefaultSystemOne    = "~typesafe/jev-latest"
)

// PlannerOptions configures a System-One-based AnalysisPlanner.
type PlannerOptions struct {
	DecisionsURL string
	APIKey       string
	Model        string // e.g. ~typesafe/jev-latest
	Timeout      time.Duration
	Mode         string // "disabled", "optional", "required"
	Fallback     planning.AnalysisPlanner
}

// SystemOnePlanner queries the System-One decisions endpoint to formulate an AnalysisPlan.
type SystemOnePlanner struct {
	decisionsURL string
	apiKey       string
	model        string
	mode         string
	httpClient   *http.Client
	fallback     planning.AnalysisPlanner

	mu              sync.Mutex
	planningCalls   int
	planningLatency time.Duration
}

// NewSystemOnePlanner constructs a SystemOnePlanner instance.
func NewSystemOnePlanner(opts PlannerOptions) *SystemOnePlanner {
	decisionsURL := opts.DecisionsURL
	if decisionsURL == "" {
		decisionsURL = os.Getenv("OPENROUTER_BASE_URL")
		if decisionsURL != "" {
			cleanBase := strings.TrimRight(decisionsURL, "/")
			if strings.HasSuffix(cleanBase, "/v1") {
				decisionsURL = strings.TrimSuffix(cleanBase, "/v1") + "/alpha/decisions"
			} else if strings.HasSuffix(cleanBase, "/api") {
				decisionsURL = cleanBase + "/alpha/decisions"
			} else {
				decisionsURL = cleanBase + "/api/alpha/decisions"
			}
		} else {
			decisionsURL = DefaultDecisionsURL
		}
	}

	apiKey := opts.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}

	model := opts.Model
	if model == "" {
		model = os.Getenv("SYSTEM_ONE_MODEL")
		if model == "" {
			model = DefaultSystemOne
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	mode := strings.ToLower(opts.Mode)
	if mode == "" {
		mode = "optional"
	}

	fallback := opts.Fallback
	if fallback == nil {
		fallback = planning.NewDeterministicPlanner()
	}

	return &SystemOnePlanner{
		decisionsURL: decisionsURL,
		apiKey:       apiKey,
		model:        model,
		mode:         mode,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		fallback: fallback,
	}
}

func (jp *SystemOnePlanner) Name() string {
	return "system-one"
}

// CacheIdentity returns the non-secret provider details that affect planner
// output. Credentials are intentionally excluded.
func (jp *SystemOnePlanner) CacheIdentity() (provider, model, endpoint string) {
	return "system-one", jp.model, jp.decisionsURL
}

// Telemetry returns recorded planning request count and latency.
func (jp *SystemOnePlanner) Telemetry() (int, time.Duration) {
	jp.mu.Lock()
	defer jp.mu.Unlock()
	return jp.planningCalls, jp.planningLatency
}

type systemOneDecisionRequest struct {
	Model     string                       `json:"model"`
	State     string                       `json:"state"`
	Questions map[string]systemOneQuestion `json:"questions"`
}

type systemOneQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

type systemOneDecisionResponse struct {
	ID      string                     `json:"id,omitempty"`
	Model   string                     `json:"model,omitempty"`
	Answers map[string]systemOneAnswer `json:"answers"`
	Error   *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

type systemOneAnswer struct {
	Type          string             `json:"type,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

// Plan consults System-One to decide priority and analysis mode for each candidate.
func (jp *SystemOnePlanner) Plan(ctx context.Context, cands []candidates.AnalysisCandidate, budget planning.AnalysisBudget) (planning.AnalysisPlan, error) {
	if jp.mode == "disabled" || jp.apiKey == "" {
		if jp.fallback != nil {
			return jp.fallback.Plan(ctx, cands, budget)
		}
		if jp.mode == "required" {
			return planning.AnalysisPlan{}, fmt.Errorf("AI planner is required but not configured (missing API key or disabled)")
		}
		return planning.NewDeterministicPlanner().Plan(ctx, cands, budget)
	}

	if len(cands) == 0 {
		return planning.AnalysisPlan{
			Strategy:   "adaptive",
			Candidates: nil,
		}, nil
	}

	plans := make([]planning.CandidatePlan, 0, len(cands))

	start := time.Now()
	for _, c := range cands {
		plan, err := jp.planSingleCandidate(ctx, c, budget)
		if err != nil {
			if jp.mode == "required" {
				return planning.AnalysisPlan{}, fmt.Errorf("System-One planning failed on candidate %s: %w", c.ID, err)
			}
			// In optional mode, fallback to deterministic planning for this batch
			return jp.fallback.Plan(ctx, cands, budget)
		}
		plans = append(plans, plan)
	}

	elapsed := time.Since(start)
	jp.mu.Lock()
	jp.planningCalls += len(cands)
	jp.planningLatency += elapsed
	jp.mu.Unlock()

	// Enforce budgets and bounds
	sort.SliceStable(plans, func(i, j int) bool {
		return plans[i].Priority > plans[j].Priority
	})

	// 1. MaxCandidates cap
	if budget.MaxCandidates > 0 && len(plans) > budget.MaxCandidates {
		for i := budget.MaxCandidates; i < len(plans); i++ {
			plans[i].Analyze = false
			plans[i].Mode = planning.AnalysisShallow
			plans[i].Reason = "SKIPPED_BY_ANALYSIS_POLICY"
		}
	}

	// 2. MaxDeepCandidates cap
	if budget.MaxDeepCandidates > 0 {
		deepCount := 0
		for i := range plans {
			if plans[i].Analyze && plans[i].Mode == planning.AnalysisDeep {
				deepCount++
				if deepCount > budget.MaxDeepCandidates {
					plans[i].Mode = planning.AnalysisMedium
					if plans[i].Depth > 4 {
						plans[i].Depth = 4
					}
					plans[i].Reason += " (downgraded to medium: deep candidate budget reached)"
				}
			}
		}
	}

	return planning.AnalysisPlan{
		Strategy:   "adaptive",
		Candidates: plans,
	}, nil
}

func (jp *SystemOnePlanner) planSingleCandidate(ctx context.Context, c candidates.AnalysisCandidate, budget planning.AnalysisBudget) (planning.CandidatePlan, error) {
	state := formatCandidateState(c)

	questions := map[string]systemOneQuestion{
		"should_analyze": {
			Type:         "noul",
			Instructions: "Does this candidate represent a potentially exploitable taint flow requiring deeper analysis?",
			Criteria: map[string]string{
				"true":  "Untrusted input may reach sensitive sink, requires deep or medium data flow analysis.",
				"false": "Candidate is clearly benign, disconnected, or low priority.",
			},
		},
		"analysis_mode": {
			Type:         "choice",
			Instructions: "Which static analysis depth should be performed on this candidate?",
			Criteria: map[string]string{
				"deep":    "Complex multi-step or interprocedural flow requiring full taint tracking.",
				"medium":  "Local function-level flow requiring standard propagation tracking.",
				"shallow": "Direct or immediate invocation requiring minimal AST verification.",
			},
		},
	}

	reqBody := systemOneDecisionRequest{
		Model:     jp.model,
		State:     state,
		Questions: questions,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return planning.CandidatePlan{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, jp.decisionsURL, bytes.NewReader(reqBytes))
	if err != nil {
		return planning.CandidatePlan{}, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+jp.apiKey)
	httpReq.Header.Set("HTTP-Referer", "https://github.com/haystack-security/haystack")
	httpReq.Header.Set("X-Title", "Haystack Security Scanner")

	resp, err := jp.httpClient.Do(httpReq)
	if err != nil {
		return planning.CandidatePlan{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return planning.CandidatePlan{}, fmt.Errorf("System-One decisions API returned status %d: %s", resp.StatusCode, string(body))
	}

	var decResp systemOneDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decResp); err != nil {
		return planning.CandidatePlan{}, fmt.Errorf("failed to decode System-One response: %w", err)
	}

	if decResp.Error != nil {
		return planning.CandidatePlan{}, fmt.Errorf("System-One API error (%d): %s", decResp.Error.Code, decResp.Error.Message)
	}

	// Extract answers
	shouldAnalyze := true
	priority := 70
	if ans, ok := decResp.Answers["should_analyze"]; ok && ans.Noul != nil {
		noulVal := *ans.Noul
		priority = int(noulVal * 100)
		shouldAnalyze = noulVal >= 0.5
	}

	mode := planning.AnalysisMedium
	if ans, ok := decResp.Answers["analysis_mode"]; ok {
		switch strings.ToLower(ans.Choice) {
		case "deep":
			mode = planning.AnalysisDeep
		case "shallow":
			mode = planning.AnalysisShallow
		case "medium":
			mode = planning.AnalysisMedium
		}
	}

	depth := 4
	switch mode {
	case planning.AnalysisDeep:
		depth = 6
	case planning.AnalysisMedium:
		depth = 4
	case planning.AnalysisShallow:
		depth = 2
	}

	if budget.MaxDepth > 0 && depth > budget.MaxDepth {
		depth = budget.MaxDepth
	}

	reason := fmt.Sprintf("AI decision: %s analysis recommended with %d%% priority", mode, priority)
	if !shouldAnalyze {
		reason = "LOW_PRIORITY"
	}

	return planning.CandidatePlan{
		CandidateID:          c.ID,
		Priority:             priority,
		Analyze:              shouldAnalyze,
		Mode:                 mode,
		Depth:                depth,
		Interprocedural:      mode == planning.AnalysisDeep,
		ControlFlow:          false,
		VulnerabilityClasses: c.VulnerabilityClasses,
		Reason:               reason,
		PlannerProvider:      "system-one",
		PlannerModel:         jp.model,
	}, nil
}

func formatCandidateState(c candidates.AnalysisCandidate) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Candidate ID: %s\n", c.ID))
	sb.WriteString(fmt.Sprintf("Language: %s\n", c.Language))
	sb.WriteString(fmt.Sprintf("File: %s\n", c.File))
	sb.WriteString(fmt.Sprintf("Function: %s\n", c.Function))
	if len(c.VulnerabilityClasses) > 0 {
		sb.WriteString(fmt.Sprintf("Vulnerability Classes: %s\n", strings.Join(c.VulnerabilityClasses, ", ")))
	}
	for _, src := range c.Sources {
		sb.WriteString(fmt.Sprintf("Source: %s (%s) at line %d\n", src.Name, src.Type, src.Line))
	}
	for _, snk := range c.Sinks {
		sb.WriteString(fmt.Sprintf("Sink: %s (%s) at line %d\n", snk.Name, snk.Type, snk.Line))
	}
	sb.WriteString(fmt.Sprintf("Estimated Depth: %d, Complexity: %d\n", c.EstimatedCost.EstimatedDepth, c.EstimatedCost.Complexity))
	return sb.String()
}
