package scanner

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"time"

	"haystack/internal/ai"
	"haystack/internal/buildinfo"
	"haystack/internal/cache"
	"haystack/internal/candidates"
	"haystack/internal/classifier"
	"haystack/internal/config"
	"haystack/internal/planning"
)

type aiCacheIdentity struct {
	Provider              string `json:"provider"`
	Model                 string `json:"model"`
	ModelVersion          string `json:"model_version,omitempty"`
	Endpoint              string `json:"endpoint,omitempty"`
	PromptVersion         string `json:"prompt_version"`
	RequestSchemaVersion  string `json:"request_schema_version"`
	ResponseSchemaVersion string `json:"response_schema_version"`
	Configuration         any    `json:"configuration,omitempty"`
}

type cachedPlanner struct {
	next     planning.AnalysisPlanner
	store    cache.Cache
	identity aiCacheIdentity
}

func (p *cachedPlanner) Name() string { return p.next.Name() }

func (p *cachedPlanner) Telemetry() (int, time.Duration) {
	if telemetry, ok := p.next.(interface{ Telemetry() (int, time.Duration) }); ok {
		return telemetry.Telemetry()
	}
	return 0, 0
}

func (p *cachedPlanner) Plan(ctx context.Context, cands []candidates.AnalysisCandidate, budget planning.AnalysisBudget) (planning.AnalysisPlan, error) {
	state := stateFromContext(ctx)
	if p.store == nil || (state != nil && state.bypass) {
		return p.next.Plan(ctx, cands, budget)
	}
	key, err := makeCacheKey("planner", struct {
		Identity   aiCacheIdentity                `json:"identity"`
		Candidates []candidates.AnalysisCandidate `json:"candidates"`
		Budget     planning.AnalysisBudget        `json:"budget"`
	}{p.identity, cands, budget})
	if err == nil {
		if payload, hit, getErr := p.store.Get(ctx, key); getErr == nil && hit {
			var plan planning.AnalysisPlan
			if json.Unmarshal(payload, &plan) == nil && validAIPlan(plan, cands) {
				stateCount(state, func(stats *CacheStats) { stats.PlannerHits++ })
				return plan, nil
			}
		}
	}
	stateCount(state, func(stats *CacheStats) { stats.PlannerMisses++ })
	plan, err := p.next.Plan(ctx, cands, budget)
	if err != nil || !validAIPlan(plan, cands) || key == "" {
		return plan, err
	}
	payload, err := json.Marshal(plan)
	if err == nil {
		_ = p.store.Put(ctx, key, payload, cache.Metadata{
			Namespace: "planner", ScannerVersion: buildinfo.ScannerVersion,
			Provider: p.identity.Provider, Model: p.identity.Model,
			PromptVersion: p.identity.PromptVersion, RequestSchemaVersion: p.identity.RequestSchemaVersion,
		})
	}
	return plan, nil
}

type cachedClassifier struct {
	next     classifier.Classifier
	store    cache.Cache
	identity aiCacheIdentity
}

func (c *cachedClassifier) ModelName() string { return c.next.ModelName() }

func (c *cachedClassifier) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	state := stateFromContext(ctx)
	if c.store == nil || (state != nil && state.bypass) {
		return c.next.Classify(ctx, input)
	}
	key, err := makeCacheKey("classifier", struct {
		Identity aiCacheIdentity                `json:"identity"`
		Input    classifier.ClassificationInput `json:"input"`
	}{c.identity, input})
	if err == nil {
		if payload, hit, getErr := c.store.Get(ctx, key); getErr == nil && hit {
			var result classifier.ClassificationResult
			if json.Unmarshal(payload, &result) == nil && validClassificationResult(result) {
				stateCount(state, func(stats *CacheStats) { stats.ClassifierHits++ })
				return result, nil
			}
		}
	}
	stateCount(state, func(stats *CacheStats) { stats.ClassifierMisses++ })
	result, err := c.next.Classify(ctx, input)
	if err != nil || !validClassificationResult(result) || result.Model == "heuristic" || key == "" {
		return result, err
	}
	payload, err := json.Marshal(result)
	if err == nil {
		_ = c.store.Put(ctx, key, payload, cache.Metadata{
			Namespace: "classifier", ScannerVersion: buildinfo.ScannerVersion,
			Provider: c.identity.Provider, Model: c.identity.Model,
			PromptVersion: c.identity.PromptVersion, RequestSchemaVersion: c.identity.RequestSchemaVersion,
		})
	}
	return result, nil
}

func stateCount(state *invocationCacheState, update func(*CacheStats)) {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	update(&state.stats)
}

func validAnalysisPlan(plan planning.AnalysisPlan) bool {
	if plan.Strategy != "adaptive" && plan.Strategy != "full" {
		return false
	}
	for _, candidate := range plan.Candidates {
		if candidate.CandidateID == "" || candidate.Priority < 0 || candidate.Priority > 100 || candidate.Depth < 0 {
			return false
		}
		switch candidate.Mode {
		case planning.AnalysisShallow, planning.AnalysisMedium, planning.AnalysisDeep:
		default:
			return false
		}
	}
	return true
}

func aiPlannerSucceeded(plan planning.AnalysisPlan) bool {
	for _, candidate := range plan.Candidates {
		if candidate.PlannerProvider != "jev" {
			return false
		}
	}
	return true
}

func validAIPlan(plan planning.AnalysisPlan, cands []candidates.AnalysisCandidate) bool {
	if !validAnalysisPlan(plan) || len(plan.Candidates) != len(cands) || !aiPlannerSucceeded(plan) {
		return false
	}
	expected := make(map[string]bool, len(cands))
	for _, candidate := range cands {
		expected[candidate.ID] = true
	}
	for _, candidatePlan := range plan.Candidates {
		if !expected[candidatePlan.CandidateID] {
			return false
		}
		delete(expected, candidatePlan.CandidateID)
	}
	return len(expected) == 0
}

func validClassificationResult(result classifier.ClassificationResult) bool {
	if result.Model == "" || result.Label == "" || result.Confidence < 0 || result.Confidence > 1 || math.IsNaN(result.Confidence) || math.IsInf(result.Confidence, 0) {
		return false
	}
	for _, probability := range result.Probabilities {
		if probability < 0 || probability > 1 || math.IsNaN(probability) || math.IsInf(probability, 0) {
			return false
		}
	}
	return true
}

func classifierModelIdentity(cfg *config.Config) string {
	if cfg.ClassifierModel != "" && cfg.ClassifierModel != "heuristic" {
		return cfg.ClassifierModel
	}
	if cfg.ClassifierProvider == "jev" || cfg.ClassifierProvider == "openrouter" {
		return cfg.SystemOneModel + ":" + cfg.OpenRouterModel
	}
	return cfg.ClassifierProvider + ":" + cfg.ClassifierModel
}

func classifierConfigIdentity(cfg *config.Config) map[string]any {
	return map[string]any{
		"classifier_enabled":    cfg.ClassifierEnabled,
		"ai_classifier_enabled": cfg.AIClassifierEnabled,
		"ai_mode":               cfg.AIMode,
		"credential_configured": cfg.ClassifierAPIKey != "" || cfg.OpenRouterAPIKey != "",
		"system_one_model":      cfg.SystemOneModel,
		"openrouter_model":      cfg.OpenRouterModel,
		"classifier_timeout_ns": int64(cfg.ClassifierTimeout),
		"endpoint":              classifierEndpointIdentity(cfg),
	}
}

func classifierEndpointIdentity(cfg *config.Config) string {
	if cfg.ClassifierEndpoint != "" {
		return cfg.ClassifierEndpoint
	}
	switch cfg.ClassifierProvider {
	case "kev":
		return cfg.KevEndpoint
	case "jev", "openrouter":
		return cfg.OpenRouterBaseURL
	default:
		if cfg.OpenRouterAPIKey != "" {
			return cfg.OpenRouterBaseURL
		}
		return cfg.KevEndpoint
	}
}

func plannerEndpointIdentity(cfg *config.Config) string {
	if cfg.ClassifierEndpoint != "" {
		return cfg.ClassifierEndpoint
	}
	if cfg.OpenRouterBaseURL != "" {
		return cfg.OpenRouterBaseURL
	}
	if endpoint := os.Getenv("OPENROUTER_BASE_URL"); endpoint != "" {
		return endpoint
	}
	return ai.DefaultDecisionsURL
}
