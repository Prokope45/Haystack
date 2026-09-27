package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"haystack/internal/ai"
	"haystack/internal/buildinfo"
	"haystack/internal/cache"
	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/rules"
)

type sourceIdentity struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Hash     string `json:"hash"`
}

type scanIdentity struct {
	ScannerVersion                 string           `json:"scanner_version"`
	RulesVersion                   string           `json:"rules_version"`
	RuntimeVersion                 string           `json:"runtime_version"`
	PythonVersion                  string           `json:"python_version,omitempty"`
	Sources                        []sourceIdentity `json:"sources"`
	Diff                           DiffMap          `json:"diff,omitempty"`
	MinSeverity                    string           `json:"min_severity"`
	MinConfidence                  float64          `json:"min_confidence"`
	Strategy                       string           `json:"strategy"`
	AIPlanner                      bool             `json:"ai_planner"`
	AIClassifier                   bool             `json:"ai_classifier"`
	AIMode                         string           `json:"ai_mode"`
	PlannerCredentialConfigured    bool             `json:"planner_credential_configured"`
	ClassifierCredentialConfigured bool             `json:"classifier_credential_configured"`
	MaxDepth                       int              `json:"max_depth"`
	MaxInterproceduralDepth        int              `json:"max_interprocedural_depth"`
	MaxCandidates                  int              `json:"max_candidates"`
	MaxDeepCandidates              int              `json:"max_deep_candidates"`
	MaxPathsPerCandidate           int              `json:"max_paths_per_candidate"`
	ClassifierProvider             string           `json:"classifier_provider"`
	ClassifierModel                string           `json:"classifier_model"`
	ClassifierEndpoint             string           `json:"classifier_endpoint"`
	PlannerEndpoint                string           `json:"planner_endpoint"`
	SystemOneModel                 string           `json:"system_one_model"`
	OpenRouterModel                string           `json:"openrouter_model"`
	ClassifierTimeout              int64            `json:"classifier_timeout_ns"`
	ExcludeDirs                    []string         `json:"exclude_dirs"`
	PlannerPromptVersion           string           `json:"planner_prompt_version"`
	PlannerSchemaVersion           string           `json:"planner_schema_version"`
	ClassifierPromptVersion        string           `json:"classifier_prompt_version"`
	ClassifierSchemaVersion        string           `json:"classifier_schema_version"`
}

type codeScanIdentity struct {
	ScannerVersion                 string  `json:"scanner_version"`
	RulesVersion                   string  `json:"rules_version"`
	RuntimeVersion                 string  `json:"runtime_version"`
	PythonVersion                  string  `json:"python_version,omitempty"`
	SourceHash                     string  `json:"source_hash"`
	Language                       string  `json:"language"`
	Filename                       string  `json:"filename"`
	MinSeverity                    string  `json:"min_severity"`
	MinConfidence                  float64 `json:"min_confidence"`
	Strategy                       string  `json:"strategy"`
	AIPlanner                      bool    `json:"ai_planner"`
	AIClassifier                   bool    `json:"ai_classifier"`
	AIMode                         string  `json:"ai_mode"`
	PlannerCredentialConfigured    bool    `json:"planner_credential_configured"`
	ClassifierCredentialConfigured bool    `json:"classifier_credential_configured"`
	MaxDepth                       int     `json:"max_depth"`
	MaxInterproceduralDepth        int     `json:"max_interprocedural_depth"`
	MaxCandidates                  int     `json:"max_candidates"`
	MaxDeepCandidates              int     `json:"max_deep_candidates"`
	MaxPathsPerCandidate           int     `json:"max_paths_per_candidate"`
	ClassifierProvider             string  `json:"classifier_provider"`
	ClassifierModel                string  `json:"classifier_model"`
	ClassifierEndpoint             string  `json:"classifier_endpoint"`
	PlannerEndpoint                string  `json:"planner_endpoint"`
	SystemOneModel                 string  `json:"system_one_model"`
	OpenRouterModel                string  `json:"openrouter_model"`
	ClassifierTimeout              int64   `json:"classifier_timeout_ns"`
	PlannerPromptVersion           string  `json:"planner_prompt_version"`
	PlannerSchemaVersion           string  `json:"planner_schema_version"`
	ClassifierPromptVersion        string  `json:"classifier_prompt_version"`
	ClassifierSchemaVersion        string  `json:"classifier_schema_version"`
}

type invocationCacheState struct {
	mu     sync.Mutex
	stats  CacheStats
	bypass bool
}

type invocationStateKey struct{}

func (s *ScannerService) scanRequest(ctx context.Context, orch *Orchestrator, req ScanRequest) (*ScanResult, error) {
	started := time.Now()
	bypass := req.NoCache || orch.cfg.NoCache
	state := &invocationCacheState{bypass: bypass}
	workCtx := context.WithValue(ctx, invocationStateKey{}, state)
	if bypass || s.cache == nil {
		if bypass {
			state.stats.FinalResult = "BYPASS"
		} else if s.cacheUnavailable {
			state.stats.FinalResult = "UNAVAILABLE"
		} else {
			state.stats.FinalResult = "DISABLED"
		}
		result, err := s.runScanRequest(workCtx, orch, req)
		if result != nil {
			result.Cache = state.snapshot()
		}
		return result, err
	}

	key, sourceHash, language, strategy, keyErr := s.scanRequestKey(ctx, orch.cfg, req)
	if keyErr == nil {
		payload, hit, err := s.cache.Get(ctx, key)
		if err != nil {
			state.stats.FinalResult = "UNAVAILABLE"
		} else if hit {
			var result ScanResult
			if json.Unmarshal(payload, &result) == nil && validScanResult(payload, result, true) {
				prepareFinalCacheHit(&result, time.Since(started))
				return &result, nil
			}
			state.stats.FinalResult = "MISS"
			_ = s.cache.Delete(ctx, key)
		} else {
			state.stats.FinalResult = "MISS"
		}
	} else {
		state.stats.FinalResult = "UNAVAILABLE"
	}

	result, err := s.runScanRequest(workCtx, orch, req)
	if err != nil || result == nil {
		return result, err
	}
	result.Cache = state.snapshot()
	if keyErr == nil {
		if payload, err := json.Marshal(result); err == nil {
			metadata := cache.Metadata{
				Namespace: "scan", ScannerVersion: buildinfo.ScannerVersion,
				RulesVersion: rules.RulesVersion, Language: language,
				Strategy: strategy, SourceHash: sourceHash,
			}
			if err := s.cache.Put(ctx, key, payload, metadata); err != nil {
				state.stats.FinalResult = "WRITE_ERROR"
			}
		} else {
			state.stats.FinalResult = "WRITE_ERROR"
		}
	}
	result.Cache = state.snapshot()
	return result, nil
}

func (s *ScannerService) scanCode(ctx context.Context, orch *Orchestrator, req ScanCodeRequest) (*ScanResult, error) {
	started := time.Now()
	bypass := req.NoCache || orch.cfg.NoCache
	state := &invocationCacheState{bypass: bypass}
	workCtx := context.WithValue(ctx, invocationStateKey{}, state)
	if bypass || s.cache == nil {
		if bypass {
			state.stats.FinalResult = "BYPASS"
		} else if s.cacheUnavailable {
			state.stats.FinalResult = "UNAVAILABLE"
		} else {
			state.stats.FinalResult = "DISABLED"
		}
		return s.runCodeScan(workCtx, orch, req, state)
	}

	key, sourceHash, language, strategy, keyErr := s.codeScanKey(ctx, orch.cfg, req)
	if keyErr == nil {
		payload, hit, err := s.cache.Get(ctx, key)
		if err != nil {
			state.stats.FinalResult = "UNAVAILABLE"
		} else if hit {
			var result ScanResult
			if json.Unmarshal(payload, &result) == nil && validScanResult(payload, result, false) {
				prepareFinalCacheHit(&result, time.Since(started))
				return &result, nil
			}
			state.stats.FinalResult = "MISS"
			_ = s.cache.Delete(ctx, key)
		} else {
			state.stats.FinalResult = "MISS"
		}
	} else {
		state.stats.FinalResult = "UNAVAILABLE"
	}

	result, err := s.runCodeScan(workCtx, orch, req, state)
	if err != nil || result == nil {
		return result, err
	}
	if keyErr == nil {
		if payload, err := json.Marshal(result); err == nil {
			metadata := cache.Metadata{
				Namespace: "scan", ScannerVersion: buildinfo.ScannerVersion,
				RulesVersion: rules.RulesVersion, Language: language,
				Strategy: strategy, SourceHash: sourceHash,
			}
			if err := s.cache.Put(ctx, key, payload, metadata); err != nil {
				state.stats.FinalResult = "WRITE_ERROR"
			}
		} else {
			state.stats.FinalResult = "WRITE_ERROR"
		}
	}
	result.Cache = state.snapshot()
	return result, nil
}

func (s *ScannerService) runCodeScan(ctx context.Context, orch *Orchestrator, req ScanCodeRequest, state *invocationCacheState) (*ScanResult, error) {
	codeCfg := orch.cfg
	if req.MinSeverity != "" || req.MinConfidence > 0 {
		cfg := *orch.cfg
		if req.MinSeverity != "" {
			cfg.MinSeverity = req.MinSeverity
		}
		if req.MinConfidence > 0 {
			cfg.MinConfidence = req.MinConfidence
		}
		codeCfg = &cfg
		orch = NewOrchestrator(codeCfg)
		s.configureIndependentCaches(orch)
	}
	findingsList, summary, err := orch.ScanCode(ctx, req.Code, req.Language, req.Filename)
	if err != nil {
		return nil, err
	}
	return &ScanResult{Findings: findingsList, Summary: summary, Cache: state.snapshot()}, nil
}

func (s *ScannerService) runScanRequest(ctx context.Context, orch *Orchestrator, req ScanRequest) (*ScanResult, error) {
	if req.AIPlanner && !orch.cfg.AIPlannerEnabled {
		cfg := *orch.cfg
		cfg.AIPlannerEnabled = true
		orch = NewOrchestrator(&cfg)
		s.configureIndependentCaches(orch)
	}
	return orch.ScanRequest(ctx, req)
}

func (s *ScannerService) scanRequestKey(ctx context.Context, cfg *config.Config, req ScanRequest) (cache.Key, string, string, string, error) {
	targetDir := cfg.TargetDir
	if len(req.Paths) == 1 && req.Paths[0] != "" {
		targetDir = req.Paths[0]
	}
	files, err := DiscoverFiles(targetDir, DiscoveryOptions{ExcludeDirs: cfg.ExcludeDirs})
	if err != nil {
		return "", "", "", "", err
	}
	if len(req.Paths) > 1 {
		pathSet := make(map[string]bool, len(req.Paths))
		for _, path := range req.Paths {
			pathSet[path] = true
		}
		filtered := files[:0]
		for _, file := range files {
			if pathSet[file.Path] || pathSet[file.RelPath] {
				filtered = append(filtered, file)
			}
		}
		files = filtered
	}

	sources := make([]sourceIdentity, 0, len(files))
	for _, file := range files {
		content, err := os.ReadFile(file.Path)
		if err != nil {
			return "", "", "", "", fmt.Errorf("read %s for cache key: %w", file.Path, err)
		}
		sources = append(sources, sourceIdentity{Path: filepath.ToSlash(file.RelPath), Language: string(file.Language), Hash: cache.HashBytes(content)})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	sourceJSON, _ := json.Marshal(sources)
	sourceHash := cache.HashBytes(sourceJSON)
	pythonVersion := ""
	if hasLanguage(sources, "python") {
		pythonVersion, err = pythonRuntimeVersion(ctx)
		if err != nil {
			return "", "", "", "", err
		}
	}

	diffRange := req.DiffRange
	if diffRange == "" {
		diffRange = cfg.DiffRange
	}
	var diffMap DiffMap
	if diffRange != "" || req.GitBase != "" {
		diffOut, err := RunGitDiff(targetDir, diffRange, req.GitBase, req.GitHead)
		if err != nil {
			return "", "", "", "", err
		}
		diffMap, err = ParseUnifiedDiff(diffOut)
		if err != nil {
			return "", "", "", "", err
		}
	}

	strategy := cfg.AnalysisStrategy
	if req.Strategy != "" {
		strategy = req.Strategy
	}
	if strategy == "" {
		strategy = "adaptive"
	}
	minSeverity := cfg.MinSeverity
	if req.MinSeverity != "" {
		minSeverity = req.MinSeverity
	}
	minConfidence := cfg.MinConfidence
	if req.MinConfidence > 0 {
		minConfidence = req.MinConfidence
	}
	identity := scanIdentity{
		ScannerVersion: buildinfo.ScannerVersion, RulesVersion: rules.RulesVersion,
		RuntimeVersion: runtime.Version(), PythonVersion: pythonVersion, Sources: sources, Diff: diffMap,
		MinSeverity: minSeverity, MinConfidence: minConfidence, Strategy: strategy,
		AIPlanner: cfg.AIPlannerEnabled || req.AIPlanner, AIClassifier: cfg.AIClassifierEnabled || cfg.ClassifierEnabled,
		AIMode:                         cfg.AIMode,
		PlannerCredentialConfigured:    cfg.ClassifierAPIKey != "" || os.Getenv("OPENROUTER_API_KEY") != "",
		ClassifierCredentialConfigured: cfg.ClassifierAPIKey != "" || cfg.OpenRouterAPIKey != "",
		MaxDepth:                       cfg.MaxDepth,
		MaxInterproceduralDepth:        cfg.MaxInterproceduralDepth, MaxCandidates: cfg.MaxCandidates,
		MaxDeepCandidates: cfg.MaxDeepCandidates, MaxPathsPerCandidate: cfg.MaxPathsPerCandidate,
		ClassifierProvider: cfg.ClassifierProvider, ClassifierModel: cfg.ClassifierModel,
		ClassifierEndpoint: classifierEndpointIdentity(cfg), PlannerEndpoint: plannerEndpointIdentity(cfg), SystemOneModel: cfg.SystemOneModel,
		OpenRouterModel: cfg.OpenRouterModel, ClassifierTimeout: int64(cfg.ClassifierTimeout),
		ExcludeDirs:             sortedCopy(cfg.ExcludeDirs),
		PlannerPromptVersion:    buildinfo.PlannerPromptVersion,
		PlannerSchemaVersion:    buildinfo.PlannerSchemaVersion,
		ClassifierPromptVersion: buildinfo.ClassifierPromptVersion,
		ClassifierSchemaVersion: buildinfo.ClassifierSchemaVersion,
	}
	key, err := makeCacheKey("scan", identity)
	return key, sourceHash, languageForSources(sources), strategy, err
}

func (s *ScannerService) codeScanKey(ctx context.Context, cfg *config.Config, req ScanCodeRequest) (cache.Key, string, string, string, error) {
	filename := req.Filename
	if filename == "" {
		language := strings.ToLower(req.Language)
		if language == "go" || language == "golang" {
			filename = "snippet.go"
		} else {
			filename = "snippet.py"
		}
	}
	language := strings.ToLower(strings.TrimSpace(req.Language))
	if language == "golang" {
		language = "go"
	}
	if language == "py" {
		language = "python"
	}
	if language == "" {
		switch strings.ToLower(filepath.Ext(filename)) {
		case ".go":
			language = "go"
		case ".py":
			language = "python"
		}
	}
	pythonVersion := ""
	if language == "python" {
		var err error
		pythonVersion, err = pythonRuntimeVersion(ctx)
		if err != nil {
			return "", "", "", "", err
		}
	}
	minSeverity := cfg.MinSeverity
	if req.MinSeverity != "" {
		minSeverity = req.MinSeverity
	}
	minConfidence := cfg.MinConfidence
	if req.MinConfidence > 0 {
		minConfidence = req.MinConfidence
	}
	strategy := cfg.AnalysisStrategy
	if strategy == "" {
		strategy = "adaptive"
	}
	identity := codeScanIdentity{
		ScannerVersion: buildinfo.ScannerVersion, RulesVersion: rules.RulesVersion,
		RuntimeVersion: runtime.Version(), PythonVersion: pythonVersion, SourceHash: cache.HashBytes(req.Code),
		Language: language, Filename: filepath.ToSlash(filename), MinSeverity: minSeverity,
		MinConfidence: minConfidence, Strategy: strategy,
		AIPlanner: cfg.AIPlannerEnabled, AIClassifier: cfg.AIClassifierEnabled || cfg.ClassifierEnabled,
		AIMode:                         cfg.AIMode,
		PlannerCredentialConfigured:    cfg.ClassifierAPIKey != "" || os.Getenv("OPENROUTER_API_KEY") != "",
		ClassifierCredentialConfigured: cfg.ClassifierAPIKey != "" || cfg.OpenRouterAPIKey != "",
		MaxDepth:                       cfg.MaxDepth,
		MaxInterproceduralDepth:        cfg.MaxInterproceduralDepth, MaxCandidates: cfg.MaxCandidates,
		MaxDeepCandidates: cfg.MaxDeepCandidates, MaxPathsPerCandidate: cfg.MaxPathsPerCandidate,
		ClassifierProvider: cfg.ClassifierProvider, ClassifierModel: cfg.ClassifierModel,
		ClassifierEndpoint: classifierEndpointIdentity(cfg), PlannerEndpoint: plannerEndpointIdentity(cfg), SystemOneModel: cfg.SystemOneModel,
		OpenRouterModel: cfg.OpenRouterModel, ClassifierTimeout: int64(cfg.ClassifierTimeout),
		PlannerPromptVersion:    buildinfo.PlannerPromptVersion,
		PlannerSchemaVersion:    buildinfo.PlannerSchemaVersion,
		ClassifierPromptVersion: buildinfo.ClassifierPromptVersion,
		ClassifierSchemaVersion: buildinfo.ClassifierSchemaVersion,
	}
	key, err := makeCacheKey("scan", identity)
	return key, identity.SourceHash, language, strategy, err
}

func makeCacheKey(namespace string, input any) (cache.Key, error) {
	digest, err := cache.KeyFor(namespace, input)
	if err != nil {
		return "", err
	}
	return cache.NamespacedKey(namespace, digest)
}

func validScanResult(payload []byte, result ScanResult, requirePlan bool) bool {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil || envelope["findings"] == nil || envelope["summary"] == nil {
		return false
	}
	var summary map[string]json.RawMessage
	if json.Unmarshal(envelope["summary"], &summary) != nil || summary["findings_count"] == nil || summary["analysis"] == nil {
		return false
	}
	var analysis map[string]json.RawMessage
	if json.Unmarshal(summary["analysis"], &analysis) != nil || analysis["strategy"] == nil {
		return false
	}
	if result.Summary.FindingsCount < 0 || result.Summary.FindingsCount != len(result.Findings) {
		return false
	}
	for _, finding := range result.Findings {
		if finding.ID == "" || finding.RuleID == "" || finding.RuleName == "" || finding.File == "" ||
			finding.Fingerprint == "" || findings.SeverityWeight(finding.Severity) == 0 ||
			finding.Confidence < 0 || finding.Confidence > 1 || math.IsNaN(finding.Confidence) || math.IsInf(finding.Confidence, 0) {
			return false
		}
		if finding.Classification != nil && !validClassificationResult(*finding.Classification) {
			return false
		}
	}
	if requirePlan && result.Plan == nil {
		return false
	}
	return result.Plan == nil || validAnalysisPlan(*result.Plan)
}

func prepareFinalCacheHit(result *ScanResult, elapsed time.Duration) {
	result.Summary.Duration = elapsed
	result.Summary.Analysis.FilesParsed = 0
	result.Summary.Analysis.AIPlanningRequests = 0
	result.Summary.Analysis.AIPlanningLatency = 0
	result.Summary.Analysis.AIClassificationRequests = 0
	result.Summary.Analysis.AIClassificationLatency = 0
	result.Cache = CacheStats{FinalResult: "HIT"}
}

func languageForSources(sources []sourceIdentity) string {
	seen := make(map[string]struct{})
	for _, source := range sources {
		seen[source.Language] = struct{}{}
	}
	if len(seen) == 1 {
		for language := range seen {
			return language
		}
	}
	return "mixed"
}

func hasLanguage(sources []sourceIdentity, language string) bool {
	for _, source := range sources {
		if source.Language == language {
			return true
		}
	}
	return false
}

func pythonRuntimeVersion(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "python3", "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("determine Python parser version: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func (state *invocationCacheState) snapshot() CacheStats {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.stats
}

func stateFromContext(ctx context.Context) *invocationCacheState {
	state, _ := ctx.Value(invocationStateKey{}).(*invocationCacheState)
	return state
}

func (s *ScannerService) configureIndependentCaches(orch *Orchestrator) {
	if s.cache == nil {
		return
	}
	if planner, ok := orch.planner.(*ai.JevPlanner); ok {
		provider, model, endpoint := planner.CacheIdentity()
		orch.planner = &cachedPlanner{
			next: planner, store: s.cache,
			identity: aiCacheIdentity{
				Provider: provider, Model: model, ModelVersion: model, Endpoint: endpoint,
				PromptVersion:         buildinfo.PlannerPromptVersion,
				RequestSchemaVersion:  buildinfo.PlannerSchemaVersion,
				ResponseSchemaVersion: buildinfo.PlannerSchemaVersion,
				Configuration: map[string]any{
					"mode":                  orch.cfg.AIMode,
					"timeout_ns":            int64(orch.cfg.ClassifierTimeout),
					"credential_configured": orch.cfg.ClassifierAPIKey != "" || os.Getenv("OPENROUTER_API_KEY") != "",
				},
			},
		}
	}
	if orch.cls != nil && orch.cls.ModelName() != "heuristic" {
		orch.cls = &cachedClassifier{
			next: orch.cls, store: s.cache,
			identity: aiCacheIdentity{
				Provider:              orch.cfg.ClassifierProvider,
				Model:                 classifierModelIdentity(orch.cfg),
				ModelVersion:          classifierModelIdentity(orch.cfg),
				Endpoint:              classifierEndpointIdentity(orch.cfg),
				PromptVersion:         buildinfo.ClassifierPromptVersion,
				RequestSchemaVersion:  buildinfo.ClassifierSchemaVersion,
				ResponseSchemaVersion: buildinfo.ClassifierSchemaVersion,
				Configuration:         classifierConfigIdentity(orch.cfg),
			},
		}
		orch.normalizer = findings.NewNormalizer(orch.cls, findings.NormalizerOptions{
			MinSeverity: orch.cfg.MinSeverity, MinConfidence: orch.cfg.MinConfidence,
		})
	}
}
