package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"haystack/internal/buildinfo"
	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/mcp"
	"haystack/internal/output"
	"haystack/internal/scanner"
)

const version = buildinfo.ScannerVersion

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "mcp":
			runMCP(os.Args[2:])
			return
		case "scan-code":
			runScanCode(os.Args[2:])
			return
		}
	}

	runScan(os.Args[1:])
}

func runMCP(args []string) {
	if err := mcp.RunCLI("scanner mcp", args); err != nil {
		fmt.Fprintf(os.Stderr, "MCP error: %v\n", err)
		os.Exit(config.ExitInternalError)
	}
	os.Exit(config.ExitSuccess)
}

func runScanCode(args []string) {
	cfg := config.DefaultConfig()

	var lang, code, filename string
	fs := flag.NewFlagSet("scan-code", flag.ContinueOnError)
	fs.StringVar(&lang, "lang", "", "Programming language: 'go' or 'python'")
	fs.StringVar(&lang, "language", "", "Alias for --lang")
	fs.StringVar(&code, "code", "", "Source code string (reads from stdin if omitted)")
	fs.StringVar(&filename, "filename", "", "Virtual filename (e.g. main.go, app.py)")
	fs.StringVar(&cfg.Format, "format", "text", "Output format: text, json, sarif")
	fs.StringVar(&cfg.MinSeverity, "severity", "low", "Minimum severity: low, medium, high, critical")
	fs.Float64Var(&cfg.MinConfidence, "confidence", 0.0, "Minimum confidence threshold (0.0 - 1.0)")
	fs.StringVar(&cfg.FailOn, "fail-on", "low", "Exit with code 1 if findings reach severity")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Logging verbosity: debug, info, warn, or error")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored terminal output")
	fs.StringVar(&cfg.ClassifierProvider, "classifier-provider", cfg.ClassifierProvider, "Classifier provider: system-one, heuristic, rlcd, or custom")
	fs.StringVar(&cfg.ClassifierEndpoint, "classifier-endpoint", cfg.ClassifierEndpoint, "Classifier endpoint URL")
	fs.StringVar(&cfg.ClassifierModel, "classifier-model", cfg.ClassifierModel, "Classifier model: heuristic, system-one, openrouter/free, or custom")
	fs.StringVar(&cfg.ClassifierModel, "model", cfg.ClassifierModel, "Alias for --classifier-model")
	fs.StringVar(&cfg.ClassifierAPIKey, "classifier-api-key", cfg.ClassifierAPIKey, "API key for classifier")
	fs.StringVar(&cfg.OpenRouterAPIKey, "openrouter-api-key", cfg.OpenRouterAPIKey, "OpenRouter API key for System-One classifier")
	fs.StringVar(&cfg.SystemOneModel, "system-one-model", cfg.SystemOneModel, "System-One decision model identifier (default: ~typesafe/jev-latest)")
	fs.StringVar(&cfg.OpenRouterModel, "openrouter-model", cfg.OpenRouterModel, "OpenRouter model identifier for vulnerability explanation LLM (default: openrouter/free)")
	fs.StringVar(&cfg.KevEndpoint, "kev-url", cfg.KevEndpoint, "Local Kev service endpoint URL (default: http://localhost:8080/classify)")
	fs.StringVar(&cfg.AnalysisStrategy, "analysis", cfg.AnalysisStrategy, "Analysis strategy: 'adaptive' or 'full'")
	fs.BoolVar(&cfg.AIPlannerEnabled, "ai-planner", false, "Enable external AI planner for candidate triage")
	fs.BoolVar(&cfg.AIClassifierEnabled, "ai-classifier", false, "Enable external AI finding classifier")
	fs.BoolVar(&cfg.VerboseAnalysis, "verbose-analysis", false, "Display detailed analysis breakdown and telemetry")
	fs.BoolVar(&cfg.NoCache, "no-cache", false, "Bypass scanner cache for this invocation")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(config.ExitConfigError)
	}
	if _, err := config.ParseLogLevel(cfg.LogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(config.ExitConfigError)
	}

	if lang == "" {
		fmt.Fprintf(os.Stderr, "Configuration error: --lang (go or python) is required\n")
		os.Exit(config.ExitConfigError)
	}

	var codeBytes []byte
	if code != "" {
		codeBytes = []byte(code)
	} else {
		// Read from stdin
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(config.ExitInternalError)
		}
		codeBytes = data
	}

	if len(codeBytes) == 0 {
		fmt.Fprintf(os.Stderr, "Configuration error: no source code provided\n")
		os.Exit(config.ExitConfigError)
	}

	svc := scanner.NewScanner(cfg)
	ctx := context.Background()

	result, err := svc.ScanCode(ctx, scanner.ScanCodeRequest{
		Code: codeBytes, Language: lang, Filename: filename,
		MinSeverity: cfg.MinSeverity, MinConfidence: cfg.MinConfidence,
		NoCache: cfg.NoCache,
	})
	if err != nil {
		if strings.Contains(err.Error(), "parser error") || strings.Contains(err.Error(), "syntax error") {
			fmt.Fprintf(os.Stderr, "Source parsing error: %v\n", err)
			os.Exit(config.ExitParseError)
		}
		fmt.Fprintf(os.Stderr, "Internal scanner error: %v\n", err)
		os.Exit(config.ExitInternalError)
	}

	results, summary := result.Findings, result.Summary
	if cfg.VerboseAnalysis {
		writeCacheDiagnostics(os.Stderr, result.Cache)
	}
	var formatter output.Formatter
	switch strings.ToLower(cfg.Format) {
	case "json":
		formatter = output.NewJSONFormatter()
	case "sarif":
		formatter = output.NewSARIFFormatter()
	default:
		formatter = output.NewVerboseTextFormatter(cfg.NoColor, cfg.VerboseAnalysis)
	}

	if err := formatter.Format(os.Stdout, results, summary); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(config.ExitInternalError)
	}

	if cfg.FailOn != "" {
		failThreshold := findings.SeverityWeight(cfg.FailOn)
		for _, f := range results {
			if findings.SeverityWeight(f.Severity) >= failThreshold {
				os.Exit(config.ExitFindingsFound)
			}
		}
	}

	os.Exit(config.ExitSuccess)
}

func runScan(args []string) {
	cfg, err := config.ParseFlags(args, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(config.ExitConfigError)
	}

	if cfg.ShowVersion {
		fmt.Printf("haystack version %s\n", version)
		os.Exit(config.ExitSuccess)
	}

	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[info] Scanning path: %s\n", cfg.TargetDir)
	}

	svc := scanner.NewScanner(cfg)
	ctx := context.Background()

	result, err := svc.Scan(ctx, scanner.ScanRequest{NoCache: cfg.NoCache})
	if err != nil {
		if strings.Contains(err.Error(), "parser error") || strings.Contains(err.Error(), "syntax error") {
			fmt.Fprintf(os.Stderr, "Source parsing error: %v\n", err)
			os.Exit(config.ExitParseError)
		}
		fmt.Fprintf(os.Stderr, "Internal scanner error: %v\n", err)
		os.Exit(config.ExitInternalError)
	}

	results, summary := result.Findings, result.Summary
	if cfg.Verbose || cfg.VerboseAnalysis {
		writeCacheDiagnostics(os.Stderr, result.Cache)
	}
	// Select formatter
	var formatter output.Formatter
	switch cfg.Format {
	case "json":
		formatter = output.NewJSONFormatter()
	case "sarif":
		formatter = output.NewSARIFFormatter()
	default:
		formatter = output.NewVerboseTextFormatter(cfg.NoColor, cfg.VerboseAnalysis)
	}

	if err := formatter.Format(os.Stdout, results, summary); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing scan output: %v\n", err)
		os.Exit(config.ExitInternalError)
	}

	// Evaluate fail-on threshold
	if cfg.FailOn != "" {
		failThreshold := findings.SeverityWeight(cfg.FailOn)
		for _, f := range results {
			if findings.SeverityWeight(f.Severity) >= failThreshold {
				os.Exit(config.ExitFindingsFound)
			}
		}
	}

	os.Exit(config.ExitSuccess)
}

func writeCacheDiagnostics(w io.Writer, stats scanner.CacheStats) {
	if stats.FinalResult == "" {
		return
	}
	fmt.Fprintf(w, "Cache:\n  final result: %s\n", stats.FinalResult)
	if stats.PlannerHits+stats.PlannerMisses > 0 {
		fmt.Fprintf(w, "  AI planner:   %d hit(s), %d miss(es)\n", stats.PlannerHits, stats.PlannerMisses)
	}
	if stats.ClassifierHits+stats.ClassifierMisses > 0 {
		fmt.Fprintf(w, "  classifier:   %d hit(s), %d miss(es)\n", stats.ClassifierHits, stats.ClassifierMisses)
	}
}
