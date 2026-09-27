package mcp

import (
	"flag"
	"fmt"
	"os"

	"haystack/internal/config"
	"haystack/internal/issues"
	"haystack/internal/issues/providers/github"
	"haystack/internal/issues/providers/mock"
)

// RunCLI parses flags, creates an MCP Server with configured providers, and serves stdio JSON-RPC.
func RunCLI(cmdName string, args []string) error {
	cfg := config.DefaultConfig()

	var allowWrite bool
	var enableIssues bool
	var issueProviderName string
	var githubToken string
	var githubRepo string
	var targetDir string

	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.StringVar(&targetDir, "dir", ".", "Target repository workspace directory")
	fs.StringVar(&targetDir, "target-dir", ".", "Alias for --dir")
	fs.BoolVar(&allowWrite, "allow-write", false, "Enable write tools (issue creation, updating, closing)")
	fs.BoolVar(&enableIssues, "enable-issues", false, "Alias for --allow-write")
	fs.StringVar(&issueProviderName, "issue-provider", "github", "Issue provider: 'github' or 'mock'")
	fs.StringVar(&githubToken, "github-token", "", "GitHub personal access token (defaults to GITHUB_TOKEN / GH_TOKEN env)")
	fs.StringVar(&githubRepo, "github-repo", os.Getenv("GITHUB_REPOSITORY"), "Target GitHub repository in 'owner/repo' format")

	// Classifier configuration
	fs.StringVar(&cfg.ClassifierProvider, "classifier-provider", cfg.ClassifierProvider, "Classifier provider: kev, jev, openrouter, heuristic")
	fs.StringVar(&cfg.ClassifierEndpoint, "classifier-endpoint", cfg.ClassifierEndpoint, "External classifier endpoint URL")
	fs.StringVar(&cfg.ClassifierModel, "classifier-model", cfg.ClassifierModel, "Classifier model: heuristic, kev, jev, openrouter/free")
	fs.StringVar(&cfg.ClassifierAPIKey, "classifier-api-key", cfg.ClassifierAPIKey, "API key for external classifier")
	fs.StringVar(&cfg.OpenRouterAPIKey, "openrouter-api-key", cfg.OpenRouterAPIKey, "OpenRouter API Key")
	fs.StringVar(&cfg.SystemOneModel, "system-one-model", cfg.SystemOneModel, "Jev decision model identifier (default: ~typesafe/jev-latest)")
	fs.StringVar(&cfg.OpenRouterModel, "openrouter-model", cfg.OpenRouterModel, "OpenRouter model identifier for vulnerability explanation LLM (default: openrouter/free)")
	fs.StringVar(&cfg.KevEndpoint, "kev-url", cfg.KevEndpoint, "Local Kev service endpoint URL (default: http://localhost:8080/classify)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg.TargetDir = targetDir
	if enableIssues {
		allowWrite = true
	}

	var issueProv issues.IssueProvider
	switch issueProviderName {
	case "github":
		issueProv = github.NewGitHubProvider(github.Config{
			Token:       githubToken,
			DefaultRepo: githubRepo,
		})
	case "mock":
		issueProv = mock.NewMockProvider()
	}

	server := NewServerWithOptions(ServerOptions{
		Config:        cfg,
		IssueProvider: issueProv,
		AllowWrite:    allowWrite,
		DefaultRepo:   githubRepo,
	})

	if err := server.Serve(os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("mcp server error: %w", err)
	}

	return nil
}
