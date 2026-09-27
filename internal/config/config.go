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
	TargetDir          string
	Format             string // text, json, sarif
	MinSeverity        string // low, medium, high, critical
	MinConfidence      float64
	FailOn             string // none, low, medium, high, critical
	ExcludeDirs        []string
	NoColor            bool
	Verbose            bool
	ShowVersion        bool
	DiffRange          string        // Git diff range (e.g. HEAD~1, main...HEAD)
	ClassifierEnabled  bool          // Whether classifier is explicitly enabled
	ClassifierProvider string        // kev, jev, heuristic, rlcd
	ClassifierEndpoint string        // Optional remote RLCD/Kev/Jev classifier URL
	ClassifierModel    string        // heuristic, kev, jev, rlcd, or custom model identifier
	ClassifierAPIKey   string        // Optional auth token for remote model API
	ClassifierTimeout  time.Duration // Timeout for classifier requests
	OpenRouterAPIKey   string        // OpenRouter API key for Jev
	OpenRouterModel    string        // OpenRouter model for Jev (default: openrouter/free)
	OpenRouterBaseURL  string        // OpenRouter API base URL
	KevEndpoint        string        // Local Kev endpoint (default: http://localhost:8080/classify)
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

	return &Config{
		TargetDir:          ".",
		Format:             "text",
		MinSeverity:        "low",
		MinConfidence:      0.0,
		FailOn:             "",
		ExcludeDirs:        []string{"vendor", ".git", "node_modules", "testdata"},
		NoColor:            false,
		Verbose:            false,
		ShowVersion:        false,
		ClassifierProvider: provider,
		ClassifierEndpoint: endpointEnv,
		ClassifierModel:    modelEnv,
		ClassifierAPIKey:   apiKeyEnv,
		ClassifierTimeout:  5 * time.Second,
		OpenRouterAPIKey:   openrouterKey,
		OpenRouterModel:    openrouterModel,
		OpenRouterBaseURL:  openrouterURL,
		KevEndpoint:        kevEndpoint,
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
	fs.StringVar(&cfg.OpenRouterModel, "openrouter-model", cfg.OpenRouterModel, "OpenRouter model identifier for Jev (default: openrouter/free)")
	fs.StringVar(&cfg.KevEndpoint, "kev-url", cfg.KevEndpoint, "Local Kev service endpoint URL (default: http://localhost:8080/classify)")

	boolFlags := map[string]bool{
		"no-color":    true,
		"-no-color":   true,
		"verbose":     true,
		"-verbose":    true,
		"version":     true,
		"-version":    true,
		"classifier":  true,
		"-classifier": true,
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

	// Verify target path exists (can be file or directory)
	_, err := os.Stat(cfg.TargetDir)
	if err != nil {
		return nil, fmt.Errorf("target path error: %w", err)
	}

	return cfg, nil
}
