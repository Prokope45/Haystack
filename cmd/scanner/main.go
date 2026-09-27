package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/mcp"
	"haystack/internal/output"
	"haystack/internal/scanner"
)

const version = "0.1.0-poc"

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
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable colored terminal output")
	fs.StringVar(&cfg.ClassifierProvider, "classifier-provider", cfg.ClassifierProvider, "Classifier provider: kev, jev, openrouter, heuristic")
	fs.StringVar(&cfg.ClassifierEndpoint, "classifier-endpoint", cfg.ClassifierEndpoint, "Classifier endpoint URL")
	fs.StringVar(&cfg.ClassifierModel, "classifier-model", cfg.ClassifierModel, "Classifier model: heuristic, kev, jev, openrouter/free")
	fs.StringVar(&cfg.ClassifierModel, "model", cfg.ClassifierModel, "Alias for --classifier-model")
	fs.StringVar(&cfg.ClassifierAPIKey, "classifier-api-key", cfg.ClassifierAPIKey, "API key for classifier")
	fs.StringVar(&cfg.OpenRouterAPIKey, "openrouter-api-key", cfg.OpenRouterAPIKey, "OpenRouter API Key for Jev classifier")
	fs.StringVar(&cfg.SystemOneModel, "system-one-model", cfg.SystemOneModel, "Jev decision model identifier (default: ~typesafe/jev-latest)")
	fs.StringVar(&cfg.OpenRouterModel, "openrouter-model", cfg.OpenRouterModel, "OpenRouter model identifier for vulnerability explanation LLM (default: openrouter/free)")
	fs.StringVar(&cfg.KevEndpoint, "kev-url", cfg.KevEndpoint, "Local Kev service endpoint URL (default: http://localhost:8080/classify)")
	fs.StringVar(&cfg.AnalysisStrategy, "analysis", cfg.AnalysisStrategy, "Analysis strategy: 'adaptive' or 'full'")
	fs.BoolVar(&cfg.AIPlannerEnabled, "ai-planner", false, "Enable external AI planner for candidate triage")
	fs.BoolVar(&cfg.AIClassifierEnabled, "ai-classifier", false, "Enable external AI finding classifier")
	fs.BoolVar(&cfg.VerboseAnalysis, "verbose-analysis", false, "Display detailed analysis breakdown and telemetry")

	if err := fs.Parse(args); err != nil {
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

	orch := scanner.NewOrchestrator(cfg)
	ctx := context.Background()

	results, summary, err := orch.ScanCode(ctx, codeBytes, lang, filename)
	if err != nil {
		if strings.Contains(err.Error(), "parser error") || strings.Contains(err.Error(), "syntax error") {
			fmt.Fprintf(os.Stderr, "Source parsing error: %v\n", err)
			os.Exit(config.ExitParseError)
		}
		fmt.Fprintf(os.Stderr, "Internal scanner error: %v\n", err)
		os.Exit(config.ExitInternalError)
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

	orch := scanner.NewOrchestrator(cfg)
	ctx := context.Background()

	results, summary, err := orch.Scan(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "parser error") || strings.Contains(err.Error(), "syntax error") {
			fmt.Fprintf(os.Stderr, "Source parsing error: %v\n", err)
			os.Exit(config.ExitParseError)
		}
		fmt.Fprintf(os.Stderr, "Internal scanner error: %v\n", err)
		os.Exit(config.ExitInternalError)
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
