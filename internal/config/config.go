package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Exit codes conforming to PROJECT_PLAN.md Section 22.
const (
	ExitSuccess       = 0 // Scan completed with no findings above threshold
	ExitFindingsFound = 1 // Findings exceeded configured threshold
	ExitConfigError   = 2 // Configuration error
	ExitParseError    = 3 // Source parsing error
	ExitInternalError = 4 // Internal scanner error
)

// Config represents the parsed configuration for a scan run.
type Config struct {
	TargetDir               string
	Format                  string // text, json, sarif
	MinSeverity             string // low, medium, high, critical
	MinConfidence           float64
	FailOn                  string // none, low, medium, high, critical
	ExcludeDirs             []string
	NoColor                 bool
	Verbose                 bool
	ShowVersion             bool
	DiffRange               string        // Git diff range (e.g. HEAD~1, main...HEAD)
	ClassifierEnabled       bool          // Whether classifier is explicitly enabled
	ClassifierProvider      string        // kev, jev, heuristic, rlcd
	ClassifierEndpoint      string        // Optional remote RLCD/Kev/Jev classifier URL
	ClassifierModel         string        // heuristic, kev, jev, rlcd, or custom model identifier
	ClassifierAPIKey        string        // Optional auth token for remote model API
	ClassifierTimeout       time.Duration // Timeout for classifier requests
	OpenRouterAPIKey        string        // OpenRouter API key for Jev
	OpenRouterModel         string        // OpenRouter model for explanation LLM (default: openrouter/free)
	OpenRouterBaseURL       string        // OpenRouter API base URL
	SystemOneModel          string        // Jev decision model (default: ~typesafe/jev-latest)
	KevEndpoint             string        // Local Kev endpoint (default: http://localhost:8080/classify)
	AnalysisStrategy        string        // Analysis strategy: adaptive, full (default: adaptive)
	AIPlannerEnabled        bool          // Enable external AI candidate planner
	AIClassifierEnabled     bool          // Enable external AI finding classifier
	AIMode                  string        // disabled, optional, required (default: optional)
	MaxDepth                int           // Maximum data flow search depth (default: 8)
	MaxInterproceduralDepth int           // Maximum interprocedural call depth (default: 5)
	MaxCandidates           int           // Maximum candidate flows to analyze (default: 1000)
	MaxDeepCandidates       int           // Maximum candidates receiving deep analysis (default: 100)
	MaxPathsPerCandidate    int           // Maximum exploration paths per candidate (default: 500)
	VerboseAnalysis         bool          // Display detailed candidate planning telemetry
}

// DefaultConfig returns default configuration settings.
func DefaultConfig() *Config {
	LoadDotEnv()

	modelEnv := os.Getenv("RLCD_MODEL")
	if modelEnv == "" {
		modelEnv = os.Getenv("KEV_MODEL")
	}
	if modelEnv == "" {
		modelEnv = "heuristic"
	}

	endpointEnv := os.Getenv("RLCD_API_URL")
	if endpointEnv == "" {
		endpointEnv = os.Getenv("KEV_API_URL")
	}

	apiKeyEnv := os.Getenv("RLCD_API_KEY")
	if apiKeyEnv == "" {
		apiKeyEnv = os.Getenv("KEV_API_KEY")
	}

	openrouterKey := os.Getenv("OPENROUTER_API_KEY")
	openrouterModel := os.Getenv("OPENROUTER_MODEL")
	if openrouterModel == "" {
		openrouterModel = "openrouter/free"
	}
	openrouterURL := os.Getenv("OPENROUTER_BASE_URL")
	if openrouterURL == "" {
		openrouterURL = "https://openrouter.ai/api/v1"
	}

	systemOneModel := os.Getenv("SYSTEM_ONE_MODEL")
	if systemOneModel == "" {
		systemOneModel = "~typesafe/jev-latest"
	}

	kevEndpoint := os.Getenv("KEV_URL")
	if kevEndpoint == "" {
		kevEndpoint = os.Getenv("KEV_ENDPOINT")
	}
	if kevEndpoint == "" {
		kevEndpoint = "http://localhost:8080/classify"
	}

	provider := os.Getenv("CLASSIFIER_PROVIDER")
	if provider == "" {
		provider = "heuristic"
	}

	analysisStrategy := os.Getenv("ANALYSIS_STRATEGY")
	if analysisStrategy == "" {
		analysisStrategy = "adaptive"
	}

	aiMode := os.Getenv("AI_MODE")
	if aiMode == "" {
		aiMode = "optional"
	}

	aiPlanner := false
	if v := os.Getenv("AI_PLANNER"); v != "" {
		aiPlanner = strings.EqualFold(v, "true") || v == "1"
	}

	aiClassifier := false
	if v := os.Getenv("AI_CLASSIFIER"); v != "" {
		aiClassifier = strings.EqualFold(v, "true") || v == "1"
	}

	return &Config{
		TargetDir:               ".",
		Format:                  "text",
		MinSeverity:             "low",
		MinConfidence:           0.0,
		FailOn:                  "",
		ExcludeDirs:             []string{"vendor", ".git", "node_modules", "testdata"},
		NoColor:                 false,
		Verbose:                 false,
		ShowVersion:             false,
		ClassifierProvider:      provider,
		ClassifierEndpoint:      endpointEnv,
		ClassifierModel:         modelEnv,
		ClassifierAPIKey:        apiKeyEnv,
		ClassifierTimeout:       5 * time.Second,
		OpenRouterAPIKey:        openrouterKey,
		OpenRouterModel:         openrouterModel,
		OpenRouterBaseURL:       openrouterURL,
		SystemOneModel:          systemOneModel,
		KevEndpoint:             kevEndpoint,
		AnalysisStrategy:        analysisStrategy,
		AIPlannerEnabled:        aiPlanner,
		AIClassifierEnabled:     aiClassifier,
		AIMode:                  aiMode,
		MaxDepth:                8,
		MaxInterproceduralDepth: 5,
		MaxCandidates:           1000,
		MaxDeepCandidates:       100,
		MaxPathsPerCandidate:    500,
		VerboseAnalysis:         false,
	}
}

// ParseFlags parses command line arguments and populates Config.
func ParseFlags(args []string, stderr io.Writer) (*Config, error) {
	cfg := DefaultConfig()

	fs := flag.NewFlagSet("scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var excludeRaw string
	var timeoutSec int

	fs.StringVar(&cfg.Format, "format", cfg.Format, "Output format: text, json, sarif")
	fs.StringVar(&cfg.MinSeverity, "severity", cfg.MinSeverity, "Minimum finding severity to display: low, medium, high, critical")
	fs.Float64Var(&cfg.MinConfidence, "confidence", cfg.MinConfidence, "Minimum confidence threshold (0.0 - 1.0)")
	fs.StringVar(&cfg.FailOn, "fail-on", cfg.FailOn, "Exit with code 1 if findings reach or exceed severity: low, medium, high, critical")
	fs.StringVar(&excludeRaw, "exclude", "", "Comma-separated paths or directories to exclude")
	fs.BoolVar(&cfg.NoColor, "no-color", cfg.NoColor, "Disable colored terminal output")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "Enable verbose output logging")
	fs.BoolVar(&cfg.ShowVersion, "version", cfg.ShowVersion, "Print scanner version and exit")
	fs.StringVar(&cfg.DiffRange, "diff", "", "Scan only code modified in git diff range (e.g. HEAD~1, main...HEAD)")

	// Classifier configuration
	fs.BoolVar(&cfg.ClassifierEnabled, "classifier", false, "Enable external classifier service")
	fs.StringVar(&cfg.ClassifierProvider, "classifier-provider", "heuristic", "Classifier provider: kev, jev, heuristic, rlcd")
	fs.StringVar(&cfg.ClassifierEndpoint, "classifier-endpoint", cfg.ClassifierEndpoint, "External RLCD / Kev / Jev classifier endpoint URL")
	fs.StringVar(&cfg.ClassifierEndpoint, "classifier-url", cfg.ClassifierEndpoint, "Alias for --classifier-endpoint")
	fs.StringVar(&cfg.ClassifierModel, "classifier-model", cfg.ClassifierModel, "Decision model to use: heuristic, kev, jev, rlcd, or custom")
	fs.StringVar(&cfg.ClassifierModel, "model", cfg.ClassifierModel, "Alias for --classifier-model")
	fs.StringVar(&cfg.ClassifierAPIKey, "classifier-api-key", cfg.ClassifierAPIKey, "API key / token for external classifier service")
	fs.IntVar(&timeoutSec, "classifier-timeout", 5, "Classifier HTTP timeout in seconds")

	// OpenRouter and Kev specific options
	fs.StringVar(&cfg.OpenRouterAPIKey, "openrouter-api-key", cfg.OpenRouterAPIKey, "OpenRouter API Key for Jev classifier")
	fs.StringVar(&cfg.SystemOneModel, "system-one-model", cfg.SystemOneModel, "Jev decision model identifier (default: ~typesafe/jev-latest)")
	fs.StringVar(&cfg.OpenRouterModel, "openrouter-model", cfg.OpenRouterModel, "OpenRouter model identifier for vulnerability explanation LLM (default: openrouter/free)")
	fs.StringVar(&cfg.KevEndpoint, "kev-url", cfg.KevEndpoint, "Local Kev service endpoint URL (default: http://localhost:8080/classify)")

	// Adaptive analysis and AI planning options
	fs.StringVar(&cfg.AnalysisStrategy, "analysis", cfg.AnalysisStrategy, "Analysis strategy: 'adaptive' or 'full' (default: adaptive)")
	fs.BoolVar(&cfg.AIPlannerEnabled, "ai-planner", false, "Enable external AI planner for candidate triage")
	fs.BoolVar(&cfg.AIClassifierEnabled, "ai-classifier", false, "Enable external AI finding classifier")
	fs.StringVar(&cfg.AIMode, "ai-mode", cfg.AIMode, "AI mode: 'disabled', 'optional', or 'required' (default: optional)")
	fs.BoolVar(&cfg.VerboseAnalysis, "verbose-analysis", false, "Display detailed analysis breakdown and telemetry")
	fs.IntVar(&cfg.MaxDepth, "max-depth", cfg.MaxDepth, "Maximum data flow depth (default: 8)")
	fs.IntVar(&cfg.MaxCandidates, "max-candidates", cfg.MaxCandidates, "Maximum security candidates to analyze (default: 1000)")
	fs.IntVar(&cfg.MaxDeepCandidates, "max-deep-candidates", cfg.MaxDeepCandidates, "Maximum candidates to analyze with deep mode (default: 100)")

	boolFlags := map[string]bool{
		"no-color":          true,
		"-no-color":         true,
		"verbose":           true,
		"-verbose":          true,
		"version":           true,
		"-version":          true,
		"classifier":        true,
		"-classifier":       true,
		"ai-planner":        true,
		"-ai-planner":       true,
		"ai-classifier":     true,
		"-ai-classifier":    true,
		"verbose-analysis":  true,
		"-verbose-analysis": true,
	}

	var flagArgs []string
	var posArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			flagName := strings.TrimLeft(arg, "-")
			if strings.Contains(flagName, "=") {
				continue
			}
			if boolFlags[flagName] {
				continue
			}
			// Value flag: consume next arg if available
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}

	reordered := append(flagArgs, posArgs...)

	if err := fs.Parse(reordered); err != nil {
		return nil, err
	}

	if timeoutSec > 0 {
		cfg.ClassifierTimeout = time.Duration(timeoutSec) * time.Second
	}

	if cfg.ShowVersion {
		return cfg, nil
	}

	remaining := fs.Args()
	if len(remaining) > 0 {
		cfg.TargetDir = remaining[0]
	}

	if excludeRaw != "" {
		parts := strings.Split(excludeRaw, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				cfg.ExcludeDirs = append(cfg.ExcludeDirs, trimmed)
			}
		}
	}

	// Validation
	cfg.Format = strings.ToLower(cfg.Format)
	switch cfg.Format {
	case "text", "json", "sarif":
	default:
		return nil, fmt.Errorf("invalid format %q: must be text, json, or sarif", cfg.Format)
	}

	cfg.MinSeverity = strings.ToLower(cfg.MinSeverity)
	switch cfg.MinSeverity {
	case "low", "medium", "high", "critical":
	default:
		return nil, fmt.Errorf("invalid severity %q: must be low, medium, high, or critical", cfg.MinSeverity)
	}

	if cfg.FailOn != "" {
		cfg.FailOn = strings.ToLower(cfg.FailOn)
		switch cfg.FailOn {
		case "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("invalid fail-on %q: must be low, medium, high, or critical", cfg.FailOn)
		}
	}

	if cfg.MinConfidence < 0.0 || cfg.MinConfidence > 1.0 {
		return nil, errors.New("confidence must be between 0.0 and 1.0")
	}

	cfg.AnalysisStrategy = strings.ToLower(cfg.AnalysisStrategy)
	switch cfg.AnalysisStrategy {
	case "adaptive", "full":
	default:
		return nil, fmt.Errorf("invalid analysis strategy %q: must be 'adaptive' or 'full'", cfg.AnalysisStrategy)
	}

	cfg.AIMode = strings.ToLower(cfg.AIMode)
	switch cfg.AIMode {
	case "disabled", "optional", "required":
	default:
		return nil, fmt.Errorf("invalid ai mode %q: must be 'disabled', 'optional', or 'required'", cfg.AIMode)
	}

	if cfg.AIClassifierEnabled {
		cfg.ClassifierEnabled = true
	}

	// Verify target path exists (can be file or directory)
	_, err := os.Stat(cfg.TargetDir)
	if err != nil {
		return nil, fmt.Errorf("target path error: %w", err)
	}

	return cfg, nil
}
