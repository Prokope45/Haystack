package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"haystack/internal/ai"
	"haystack/internal/analyzer"
	"haystack/internal/analyzer/golang"
	"haystack/internal/analyzer/python"
	"haystack/internal/cache"
	"haystack/internal/candidates"
	"haystack/internal/classifier"
	"haystack/internal/classifier/factory"
	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/index"
	"haystack/internal/output"
	"haystack/internal/planning"
	"haystack/internal/rules"
)

// ScanRequest specifies parameters for a scan operation per DESIGN_PLAN.md Section 28.
type ScanRequest struct {
	Paths         []string `json:"paths,omitempty"`
	GitBase       string   `json:"git_base,omitempty"`
	GitHead       string   `json:"git_head,omitempty"`
	DiffRange     string   `json:"diff_range,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	MinSeverity   string   `json:"min_severity,omitempty"`
	MinConfidence float64  `json:"min_confidence,omitempty"`
	Strategy      string   `json:"strategy,omitempty"`   // "adaptive" or "full"
	AIPlanner     bool     `json:"ai_planner,omitempty"` // enable external AI planner
	NoCache       bool     `json:"-"`                    // bypass all cache reads and writes
}

// ScanCodeRequest describes a scan of in-memory code or one file's contents.
type ScanCodeRequest struct {
	Code          []byte
	Language      string
	Filename      string
	MinSeverity   string
	MinConfidence float64
	NoCache       bool
}

// ScanResult encapsulates findings and operational statistics.
type ScanResult struct {
	Findings []findings.Finding     `json:"findings"`
	Summary  output.ScanSummary     `json:"summary"`
	Plan     *planning.AnalysisPlan `json:"plan,omitempty"`
	Cache    CacheStats             `json:"-"`
}

// CacheStats reports cache activity for one scanner-service invocation.
type CacheStats struct {
	FinalResult      string `json:"final_result,omitempty"`
	PlannerHits      int    `json:"planner_hits,omitempty"`
	PlannerMisses    int    `json:"planner_misses,omitempty"`
	ClassifierHits   int    `json:"classifier_hits,omitempty"`
	ClassifierMisses int    `json:"classifier_misses,omitempty"`
}

// Scanner defines the primary security scanner interface per DESIGN_PLAN.md Section 28.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (*ScanResult, error)
	ScanCode(ctx context.Context, req ScanCodeRequest) (*ScanResult, error)
	ScanFile(ctx context.Context, req ScanCodeRequest) (*ScanResult, error)
	GetAnalysisPlan(ctx context.Context, req ScanRequest) (*planning.AnalysisPlan, error)
}

// Orchestrator coordinates the end-to-end static analysis and classification pipeline.
type Orchestrator struct {
	cfg        *config.Config
	analyzers  []analyzer.Analyzer
	rulesReg   *rules.Registry
	cls        classifier.Classifier
	planner    planning.AnalysisPlanner
	normalizer *findings.Normalizer
}

// NewOrchestrator creates a fully configured scan Orchestrator.
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	cls := factory.NewClassifier(cfg)

	var planner planning.AnalysisPlanner
	if cfg.AIPlannerEnabled || (cfg.ClassifierProvider == "jev" && cfg.AIPlannerEnabled) {
		planner = ai.NewJevPlanner(ai.PlannerOptions{
			DecisionsURL: cfg.ClassifierEndpoint,
			APIKey:       cfg.ClassifierAPIKey,
			Model:        cfg.SystemOneModel,
			Timeout:      cfg.ClassifierTimeout,
			Mode:         cfg.AIMode,
			Fallback:     planning.NewDeterministicPlanner(),
		})
	} else {
		planner = planning.NewDeterministicPlanner()
	}

	normalizerOpts := findings.NormalizerOptions{
		MinSeverity:   cfg.MinSeverity,
		MinConfidence: cfg.MinConfidence,
	}

	return &Orchestrator{
		cfg: cfg,
		analyzers: []analyzer.Analyzer{
			golang.NewGoAnalyzer(),
			python.NewPythonAnalyzer(),
		},
		rulesReg:   rules.DefaultRegistry(),
		cls:        cls,
		planner:    planner,
		normalizer: findings.NewNormalizer(cls, normalizerOpts),
	}
}

// ScannerService adapts Orchestrator to the Scanner interface.
type ScannerService struct {
	orch             *Orchestrator
	cache            cache.Cache
	cacheUnavailable bool
}

// NewScanner creates a new Scanner instance conforming to the Scanner interface.
func NewScanner(cfg *config.Config) Scanner {
	disk, err := cache.NewDisk("")
	service := NewScannerWithCache(cfg, disk)
	service.cacheUnavailable = err != nil
	return service
}

// NewScannerWithCache creates a scanner service with an injected cache. Passing
// nil disables caching and is useful for embedding and tests.
func NewScannerWithCache(cfg *config.Config, cacheStore cache.Cache) *ScannerService {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	service := &ScannerService{orch: NewOrchestrator(cfg), cache: cacheStore}
	service.configureIndependentCaches(service.orch)
	return service
}

// Scan satisfies the Scanner interface.
func (s *ScannerService) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	return s.scanRequest(ctx, s.orch, req)
}

// ScanCode executes and caches an in-memory source scan through the shared service.
func (s *ScannerService) ScanCode(ctx context.Context, req ScanCodeRequest) (*ScanResult, error) {
	return s.scanCode(ctx, s.orch, req)
}

// ScanFile reads and scans a source file through the shared service.
func (s *ScannerService) ScanFile(ctx context.Context, req ScanCodeRequest) (*ScanResult, error) {
	content, err := os.ReadFile(req.Filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", req.Filename, err)
	}
	req.Code = content
	return s.scanCode(ctx, s.orch, req)
}

// GetAnalysisPlan satisfies the Scanner interface.
func (s *ScannerService) GetAnalysisPlan(ctx context.Context, req ScanRequest) (*planning.AnalysisPlan, error) {
	state := &invocationCacheState{bypass: req.NoCache || s.orch.cfg.NoCache}
	ctx = context.WithValue(ctx, invocationStateKey{}, state)
	orch := s.orch
	if req.AIPlanner && !orch.cfg.AIPlannerEnabled {
		cfg := *orch.cfg
		cfg.AIPlannerEnabled = true
		orch = NewOrchestrator(&cfg)
		s.configureIndependentCaches(orch)
	}
	return orch.GetAnalysisPlan(ctx, req)
}

// Scan executes the full scanning workflow against target path (file or directory).
func (o *Orchestrator) Scan(ctx context.Context) ([]findings.Finding, output.ScanSummary, error) {
	req := ScanRequest{
		DiffRange:     o.cfg.DiffRange,
		MinSeverity:   o.cfg.MinSeverity,
		MinConfidence: o.cfg.MinConfidence,
		Strategy:      o.cfg.AnalysisStrategy,
		AIPlanner:     o.cfg.AIPlannerEnabled,
	}
	res, err := o.ScanRequest(ctx, req)
	if err != nil {
		return nil, output.ScanSummary{}, err
	}
	return res.Findings, res.Summary, nil
}

// GetAnalysisPlan discovers candidates and generates an AnalysisPlan without running static analysis.
func (o *Orchestrator) GetAnalysisPlan(ctx context.Context, req ScanRequest) (*planning.AnalysisPlan, error) {
	targetDir := o.cfg.TargetDir
	if len(req.Paths) == 1 && req.Paths[0] != "" {
		targetDir = req.Paths[0]
	}

	files, err := DiscoverFiles(targetDir, DiscoveryOptions{
		ExcludeDirs: o.cfg.ExcludeDirs,
	})
	if err != nil {
		return nil, fmt.Errorf("file discovery failed: %w", err)
	}

	if len(req.Paths) > 1 {
		pathSet := make(map[string]bool)
		for _, p := range req.Paths {
			pathSet[p] = true
		}
		var filtered []DiscoveredFile
		for _, f := range files {
			if pathSet[f.Path] || pathSet[f.RelPath] {
				filtered = append(filtered, f)
			}
		}
		files = filtered
	}

	indexer := index.NewIndexer()
	for _, file := range files {
		content, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file.Path, err)
		}
		if err := indexer.IndexFile(file.Path, file.RelPath, content); err != nil {
			return nil, fmt.Errorf("indexing error in %s: %w", file.RelPath, err)
		}
	}

	cands := candidates.DiscoverCandidates(indexer.Index())

	budget := planning.AnalysisBudget{
		MaxDepth:                o.cfg.MaxDepth,
		MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
		MaxCandidates:           o.cfg.MaxCandidates,
		MaxDeepCandidates:       o.cfg.MaxDeepCandidates,
		MaxPathsPerCandidate:    o.cfg.MaxPathsPerCandidate,
		Timeout:                 o.cfg.ClassifierTimeout,
	}

	planner := o.planner
	if req.AIPlanner && !o.cfg.AIPlannerEnabled {
		planner = ai.NewJevPlanner(ai.PlannerOptions{
			DecisionsURL: o.cfg.ClassifierEndpoint,
			APIKey:       o.cfg.ClassifierAPIKey,
			Model:        o.cfg.SystemOneModel,
			Timeout:      o.cfg.ClassifierTimeout,
			Mode:         o.cfg.AIMode,
			Fallback:     planning.NewDeterministicPlanner(),
		})
	}

	plan, err := planner.Plan(ctx, cands, budget)
	if err != nil {
		return nil, fmt.Errorf("planning error: %w", err)
	}

	return &plan, nil
}

// ScanRequest executes a scan according to a specific ScanRequest, including diff filtering.
func (o *Orchestrator) ScanRequest(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	start := time.Now()
	summary := output.ScanSummary{}

	targetDir := o.cfg.TargetDir
	if len(req.Paths) == 1 && req.Paths[0] != "" {
		targetDir = req.Paths[0]
	}

	// 1. Check if Git diff scanning is requested
	diffRange := req.DiffRange
	if diffRange == "" && o.cfg.DiffRange != "" {
		diffRange = o.cfg.DiffRange
	}

	var diffMap DiffMap
	if diffRange != "" || req.GitBase != "" {
		diffOut, err := RunGitDiff(targetDir, diffRange, req.GitBase, req.GitHead)
		if err != nil {
			return nil, fmt.Errorf("failed to run git diff: %w", err)
		}
		dm, err := ParseUnifiedDiff(diffOut)
		if err != nil {
			return nil, fmt.Errorf("failed to parse git diff: %w", err)
		}
		diffMap = dm
	}

	// 2. File Discovery
	files, err := DiscoverFiles(targetDir, DiscoveryOptions{
		ExcludeDirs: o.cfg.ExcludeDirs,
	})
	if err != nil {
		return nil, fmt.Errorf("file discovery failed: %w", err)
	}

	// If explicit paths were passed (multiple files), filter to those
	if len(req.Paths) > 1 {
		pathSet := make(map[string]bool)
		for _, p := range req.Paths {
			pathSet[p] = true
		}
		var filteredFiles []DiscoveredFile
		for _, f := range files {
			if pathSet[f.Path] || pathSet[f.RelPath] {
				filteredFiles = append(filteredFiles, f)
			}
		}
		files = filteredFiles
	}

	summary.FilesScanned = len(files)
	fileContents := make(map[string][]byte, len(files))

	for _, f := range files {
		switch f.Language {
		case LangGo:
			summary.GoFiles++
		case LangPython:
			summary.PythonFiles++
		}
		c, err := os.ReadFile(f.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", f.Path, err)
		}
		fileContents[f.Path] = c
	}

	// 3. Program Indexing
	indexer := index.NewIndexer()
	for _, f := range files {
		if err := indexer.IndexFile(f.Path, f.RelPath, fileContents[f.Path]); err != nil {
			return nil, fmt.Errorf("indexing error in %s: %w", f.RelPath, err)
		}
	}
	progIndex := indexer.Index()

	// 4. Candidate Discovery
	discoveredCandidates := candidates.DiscoverCandidates(progIndex)

	// 5. Analysis Planning
	strategy := o.cfg.AnalysisStrategy
	if req.Strategy != "" {
		strategy = req.Strategy
	}
	if strategy == "" {
		strategy = "adaptive"
	}

	budget := planning.AnalysisBudget{
		MaxDepth:                o.cfg.MaxDepth,
		MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
		MaxCandidates:           o.cfg.MaxCandidates,
		MaxDeepCandidates:       o.cfg.MaxDeepCandidates,
		MaxPathsPerCandidate:    o.cfg.MaxPathsPerCandidate,
		Timeout:                 o.cfg.ClassifierTimeout,
	}

	planner := o.planner
	if req.AIPlanner && !o.cfg.AIPlannerEnabled {
		planner = ai.NewJevPlanner(ai.PlannerOptions{
			DecisionsURL: o.cfg.ClassifierEndpoint,
			APIKey:       o.cfg.ClassifierAPIKey,
			Model:        o.cfg.SystemOneModel,
			Timeout:      o.cfg.ClassifierTimeout,
			Mode:         o.cfg.AIMode,
			Fallback:     planning.NewDeterministicPlanner(),
		})
	}

	var analysisPlan planning.AnalysisPlan
	if strategy == "full" {
		fullPlans := make([]planning.CandidatePlan, 0, len(discoveredCandidates))
		for _, c := range discoveredCandidates {
			fullPlans = append(fullPlans, planning.CandidatePlan{
				CandidateID:          c.ID,
				Priority:             100,
				Analyze:              true,
				Mode:                 planning.AnalysisDeep,
				Depth:                budget.MaxDepth,
				Interprocedural:      true,
				VulnerabilityClasses: c.VulnerabilityClasses,
				Reason:               "Full scan strategy requested",
				PlannerProvider:      "deterministic",
				PlannerModel:         "full",
			})
		}
		analysisPlan = planning.AnalysisPlan{
			Strategy:   "full",
			Candidates: fullPlans,
		}
	} else {
		p, err := planner.Plan(ctx, discoveredCandidates, budget)
		if err != nil {
			if o.cfg.AIMode == "required" {
				return nil, fmt.Errorf("planning error: %w", err)
			}
			// In optional mode fallback to deterministic
			fallbackPlan, fbErr := planning.NewDeterministicPlanner().Plan(ctx, discoveredCandidates, budget)
			if fbErr != nil {
				return nil, fmt.Errorf("deterministic fallback planner failed: %w", fbErr)
			}
			analysisPlan = fallbackPlan
		} else {
			analysisPlan = p
		}
	}

	// 6. Directives and Metadata maps
	directives := make(map[string]analyzer.AnalysisDirectives)
	metaMap := make(map[string]*findings.AnalysisMetadata)

	var analyzedCount, skippedCount, shallowCount, mediumCount, deepCount int
	for _, p := range analysisPlan.Candidates {
		directives[p.CandidateID] = analyzer.AnalysisDirectives{
			Analyze:                 p.Analyze,
			Mode:                    string(p.Mode),
			MaxDepth:                p.Depth,
			MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
			CandidateID:             p.CandidateID,
		}

		metaMap[p.CandidateID] = &findings.AnalysisMetadata{
			Strategy:        strategy,
			Priority:        p.Priority,
			Depth:           p.Depth,
			Interprocedural: p.Interprocedural,
			PlannerProvider: p.PlannerProvider,
			PlannerModel:    p.PlannerModel,
		}

		if p.Analyze {
			analyzedCount++
			switch p.Mode {
			case planning.AnalysisDeep:
				deepCount++
			case planning.AnalysisMedium:
				mediumCount++
			case planning.AnalysisShallow:
				shallowCount++
			}
		} else {
			skippedCount++
		}
	}

	// 7. Execute Adaptive Static Analysis
	for _, an := range o.analyzers {
		if aa, ok := an.(analyzer.AdaptiveAnalyzer); ok {
			aa.SetDirectives(directives)
		}
	}

	var allEvidences []analyzer.Evidence

	for _, file := range files {
		content := fileContents[file.Path]

		for _, an := range o.analyzers {
			if an.Supports(file.Path) {
				evidences, err := an.Analyze(ctx, content, file.RelPath)
				if err != nil {
					return nil, fmt.Errorf("parser error in %s: %w", file.RelPath, err)
				}
				allEvidences = append(allEvidences, evidences...)
			}
		}
	}

	// 8. Rule Evaluation
	ruleCandidates := o.rulesReg.EvaluateAll(allEvidences)

	// 9. ML Classification & CWE Normalization
	normalizer := o.normalizer
	if req.MinSeverity != "" || req.MinConfidence > 0 {
		minSev := o.cfg.MinSeverity
		if req.MinSeverity != "" {
			minSev = req.MinSeverity
		}
		minConf := o.cfg.MinConfidence
		if req.MinConfidence > 0 {
			minConf = req.MinConfidence
		}
		normalizer = findings.NewNormalizer(o.cls, findings.NormalizerOptions{
			MinSeverity:   minSev,
			MinConfidence: minConf,
		})
	}

	normalizedFindings, err := normalizer.NormalizeWithMetadata(ctx, ruleCandidates, metaMap)
	if err != nil {
		return nil, fmt.Errorf("findings normalization error: %w", err)
	}

	// 10. Diff Filtering
	if len(diffMap) > 0 {
		normalizedFindings = FilterFindingsByDiff(normalizedFindings, diffMap)
	}

	summary.FindingsCount = len(normalizedFindings)
	summary.Duration = time.Since(start)

	var aiReqs int
	var aiLat time.Duration
	if jp, ok := planner.(interface{ Telemetry() (int, time.Duration) }); ok {
		aiReqs, aiLat = jp.Telemetry()
	}

	summary.Analysis = output.AnalysisStats{
		Strategy:                 strategy,
		FilesDiscovered:          len(files),
		FilesParsed:              len(files),
		CandidatesDiscovered:     len(discoveredCandidates),
		CandidatesAnalyzed:       analyzedCount,
		CandidatesSkipped:        skippedCount,
		ShallowAnalyses:          shallowCount,
		MediumAnalyses:           mediumCount,
		DeepAnalyses:             deepCount,
		PathsConsidered:          analyzedCount * 3,
		PathsAnalyzed:            analyzedCount * 2,
		AIPlanningRequests:       aiReqs,
		AIPlanningLatency:        aiLat,
		AIClassificationRequests: 0,
		AIClassificationLatency:  0,
	}

	return &ScanResult{
		Findings: normalizedFindings,
		Summary:  summary,
		Plan:     &analysisPlan,
	}, nil
}

// ScanCode performs static analysis directly on in-memory source code.
// Designed for agentic workflows, IDE integrations, and MCP tool calls.
func (o *Orchestrator) ScanCode(ctx context.Context, code []byte, language string, filename string) ([]findings.Finding, output.ScanSummary, error) {
	start := time.Now()
	summary := output.ScanSummary{
		FilesScanned: 1,
	}

	normLang := strings.ToLower(language)
	if filename == "" {
		if normLang == "go" || normLang == "golang" {
			filename = "snippet.go"
		} else {
			filename = "snippet.py"
		}
	}

	var targetAnalyzer analyzer.Analyzer
	for _, an := range o.analyzers {
		if an.Supports(filename) {
			targetAnalyzer = an
			break
		}
	}

	if targetAnalyzer == nil {
		switch normLang {
		case "go", "golang":
			targetAnalyzer = o.analyzers[0]
		case "py", "python":
			targetAnalyzer = o.analyzers[1]
		default:
			return nil, summary, fmt.Errorf("unsupported language %q: must be 'go' or 'python'", language)
		}
	}

	if targetAnalyzer.Language() == "go" {
		summary.GoFiles = 1
	} else {
		summary.PythonFiles = 1
	}

	// 1. Index in-memory code
	indexer := index.NewIndexer()
	if err := indexer.IndexFile(filename, filename, code); err != nil {
		return nil, summary, fmt.Errorf("indexing error in %s: %w", filename, err)
	}

	// 2. Discover Candidates
	discoveredCandidates := candidates.DiscoverCandidates(indexer.Index())

	// 3. Plan Candidates
	budget := planning.AnalysisBudget{
		MaxDepth:                o.cfg.MaxDepth,
		MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
		MaxCandidates:           o.cfg.MaxCandidates,
		MaxDeepCandidates:       o.cfg.MaxDeepCandidates,
		MaxPathsPerCandidate:    o.cfg.MaxPathsPerCandidate,
		Timeout:                 o.cfg.ClassifierTimeout,
	}

	plan, err := o.planner.Plan(ctx, discoveredCandidates, budget)
	if err != nil {
		// Fallback to deterministic if required
		plan, _ = planning.NewDeterministicPlanner().Plan(ctx, discoveredCandidates, budget)
	}

	// 4. Set directives
	directives := make(map[string]analyzer.AnalysisDirectives)
	metaMap := make(map[string]*findings.AnalysisMetadata)

	var analyzedCount, skippedCount, shallowCount, mediumCount, deepCount int
	for _, p := range plan.Candidates {
		directives[p.CandidateID] = analyzer.AnalysisDirectives{
			Analyze:                 p.Analyze,
			Mode:                    string(p.Mode),
			MaxDepth:                p.Depth,
			MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
			CandidateID:             p.CandidateID,
		}

		metaMap[p.CandidateID] = &findings.AnalysisMetadata{
			Strategy:        o.cfg.AnalysisStrategy,
			Priority:        p.Priority,
			Depth:           p.Depth,
			Interprocedural: p.Interprocedural,
			PlannerProvider: p.PlannerProvider,
			PlannerModel:    p.PlannerModel,
		}

		if p.Analyze {
			analyzedCount++
			switch p.Mode {
			case planning.AnalysisDeep:
				deepCount++
			case planning.AnalysisMedium:
				mediumCount++
			case planning.AnalysisShallow:
				shallowCount++
			}
		} else {
			skippedCount++
		}
	}

	if aa, ok := targetAnalyzer.(analyzer.AdaptiveAnalyzer); ok {
		aa.SetDirectives(directives)
	}

	// 5. Execute static analysis
	evidences, err := targetAnalyzer.Analyze(ctx, code, filename)
	if err != nil {
		return nil, summary, fmt.Errorf("parser error in %s: %w", filename, err)
	}

	// 6. Rules & Normalization
	ruleCandidates := o.rulesReg.EvaluateAll(evidences)

	normalizedFindings, err := o.normalizer.NormalizeWithMetadata(ctx, ruleCandidates, metaMap)
	if err != nil {
		return nil, summary, fmt.Errorf("findings normalization error: %w", err)
	}

	summary.FindingsCount = len(normalizedFindings)
	summary.Duration = time.Since(start)

	var aiReqs int
	var aiLat time.Duration
	if jp, ok := o.planner.(interface{ Telemetry() (int, time.Duration) }); ok {
		aiReqs, aiLat = jp.Telemetry()
	}

	summary.Analysis = output.AnalysisStats{
		Strategy:                 o.cfg.AnalysisStrategy,
		FilesDiscovered:          1,
		FilesParsed:              1,
		CandidatesDiscovered:     len(discoveredCandidates),
		CandidatesAnalyzed:       analyzedCount,
		CandidatesSkipped:        skippedCount,
		ShallowAnalyses:          shallowCount,
		MediumAnalyses:           mediumCount,
		DeepAnalyses:             deepCount,
		PathsConsidered:          analyzedCount * 2,
		PathsAnalyzed:            analyzedCount * 2,
		AIPlanningRequests:       aiReqs,
		AIPlanningLatency:        aiLat,
		AIClassificationRequests: 0,
		AIClassificationLatency:  0,
	}

	return normalizedFindings, summary, nil
}

// ScanFile scans an individual file directly from the filesystem.
func (o *Orchestrator) ScanFile(ctx context.Context, filePath string) ([]findings.Finding, output.ScanSummary, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, output.ScanSummary{}, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return o.ScanCode(ctx, content, "", filePath)
}

func sanitizeCandidateFile(s string) string {
	s = filepath.Base(s)
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
