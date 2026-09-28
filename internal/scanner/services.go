package scanner

import (
	"haystack/internal/analyzer"
	"haystack/internal/cache"
	"haystack/internal/classifier"
	"haystack/internal/config"
	"haystack/internal/findings"
	"haystack/internal/planning"
	"haystack/internal/rules"
)

// Orchestrator coordinates the end-to-end static analysis and classification pipeline.
type Orchestrator struct {
	cfg        *config.Config
	analyzers  []analyzer.Analyzer
	rulesReg   *rules.Registry
	cls        classifier.Classifier
	planner    planning.AnalysisPlanner
	normalizer *findings.Normalizer
}

// ScannerService adapts Orchestrator to the Scanner interface.
type ScannerService struct {
	orch             *Orchestrator
	cache            cache.Cache
	cacheUnavailable bool
}
