package analyzer

import "context"

// Analyzer is the common interface implemented by language-specific static analyzers.
type Analyzer interface {
	Language() string
	Supports(path string) bool
	Analyze(ctx context.Context, source []byte, path string) ([]Evidence, error)
}

// AdaptiveAnalyzer extends Analyzer with the capability to accept analysis directives from a planner.
type AdaptiveAnalyzer interface {
	Analyzer
	SetDirectives(directives map[string]AnalysisDirectives)
}
