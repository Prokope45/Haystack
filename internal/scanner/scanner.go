package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/analyzer/golang"
	"haystack/internal/analyzer/python"
	"haystack/internal/classifier"
	"haystack/internal/classifier/factory"
	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/output"
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
}

// ScanResult encapsulates findings and operational statistics.
type ScanResult struct {
	Findings []findings.Finding `json:"findings"`
	Summary  output.ScanSummary `json:"summary"`
}

// Scanner defines the primary security scanner interface per DESIGN_PLAN.md Section 28.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (*ScanResult, error)
}

// Orchestrator coordinates the end-to-end static analysis and classification pipeline.
type Orchestrator struct {
	cfg       *config.Config
	analyzers []analyzer.Analyzer
	rulesReg   *rules.Registry
	cls        classifier.Classifier
	normalizer *findings.Normalizer
}

// NewOrchestrator creates a fully configured scan Orchestrator.
func NewOrchestrator(cfg *config.Config) *Orchestrator {
	cls := factory.NewClassifier(cfg)

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
		normalizer: findings.NewNormalizer(cls, normalizerOpts),
	}
}

// ScannerService adapts Orchestrator to the Scanner interface.
type ScannerService struct {
	orch *Orchestrator
}

// NewScanner creates a new Scanner instance conforming to the Scanner interface.
func NewScanner(cfg *config.Config) Scanner {
	return &ScannerService{
		orch: NewOrchestrator(cfg),
	}
}

// Scan satisfies the Scanner interface.
func (s *ScannerService) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	return s.orch.ScanRequest(ctx, req)
}

// Scan executes the full scanning workflow against target path (file or directory).
func (o *Orchestrator) Scan(ctx context.Context) ([]findings.Finding, output.ScanSummary, error) {
	req := ScanRequest{
		DiffRange:     o.cfg.DiffRange,
		MinSeverity:   o.cfg.MinSeverity,
		MinConfidence: o.cfg.MinConfidence,
	}
	res, err := o.ScanRequest(ctx, req)
	if err != nil {
		return nil, output.ScanSummary{}, err
	}
	return res.Findings, res.Summary, nil
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
	for _, f := range files {
		switch f.Language {
		case LangGo:
			summary.GoFiles++
		case LangPython:
			summary.PythonFiles++
		}
	}

	// 3. Deterministic AST & Flow Analysis
	var allEvidences []analyzer.Evidence

	for _, file := range files {
		content, err := os.ReadFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file.Path, err)
		}

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

	// 4. Rule Evaluation (Generates Candidate Findings)
	candidates := o.rulesReg.EvaluateAll(allEvidences)

	// 5. ML Classification & CWE Normalization
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

	normalizedFindings, err := normalizer.Normalize(ctx, candidates)
	if err != nil {
		return nil, fmt.Errorf("findings normalization error: %w", err)
	}

	// 6. Diff Filtering
	if len(diffMap) > 0 {
		normalizedFindings = FilterFindingsByDiff(normalizedFindings, diffMap)
	}

	summary.FindingsCount = len(normalizedFindings)
	summary.Duration = time.Since(start)

	return &ScanResult{
		Findings: normalizedFindings,
		Summary:  summary,
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

	evidences, err := targetAnalyzer.Analyze(ctx, code, filename)
	if err != nil {
		return nil, summary, fmt.Errorf("parser error in %s: %w", filename, err)
	}

	candidates := o.rulesReg.EvaluateAll(evidences)

	normalizedFindings, err := o.normalizer.Normalize(ctx, candidates)
	if err != nil {
		return nil, summary, fmt.Errorf("findings normalization error: %w", err)
	}

	summary.FindingsCount = len(normalizedFindings)
	summary.Duration = time.Since(start)

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
