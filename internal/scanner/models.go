package scanner

import (
	"haystack/internal/findings"
	"haystack/internal/output"
	"haystack/internal/planning"
)

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
