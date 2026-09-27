package planning

import "time"

// AnalysisBudget limits the computational and depth resources allocated during scanning.
type AnalysisBudget struct {
	MaxDepth                int           `json:"max_depth"`
	MaxInterproceduralDepth int           `json:"max_interprocedural_depth"`
	MaxCandidates           int           `json:"max_candidates"`
	MaxDeepCandidates       int           `json:"max_deep_candidates"`
	MaxPathsPerCandidate    int           `json:"max_paths_per_candidate"`
	Timeout                 time.Duration `json:"timeout"`
}

// DefaultBudget returns production-safe analysis budget defaults.
func DefaultBudget() AnalysisBudget {
	return AnalysisBudget{
		MaxDepth:                8,
		MaxInterproceduralDepth: 5,
		MaxCandidates:           1000,
		MaxDeepCandidates:       100,
		MaxPathsPerCandidate:    500,
		Timeout:                 30 * time.Second,
	}
}
