package planning

import (
	"context"

	"haystack/internal/candidates"
)

// AnalysisPlanner defines the abstraction contract for candidate planning.
type AnalysisPlanner interface {
	Name() string
	Plan(ctx context.Context, cands []candidates.AnalysisCandidate, budget AnalysisBudget) (AnalysisPlan, error)
}
