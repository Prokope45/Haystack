package planning

import (
	"context"
	"sort"

	"haystack/internal/analyzer"
	"haystack/internal/candidates"
)

// DeterministicPlanner produces heuristic analysis plans without external AI dependencies.
type DeterministicPlanner struct{}

// NewDeterministicPlanner creates an instance of DeterministicPlanner.
func NewDeterministicPlanner() *DeterministicPlanner {
	return &DeterministicPlanner{}
}

func (dp *DeterministicPlanner) Name() string {
	return "deterministic"
}

// Plan constructs a budgeted AnalysisPlan for the provided candidates.
func (dp *DeterministicPlanner) Plan(ctx context.Context, cands []candidates.AnalysisCandidate, budget AnalysisBudget) (AnalysisPlan, error) {
	if budget.MaxDepth <= 0 {
		budget.MaxDepth = 8
	}
	if budget.MaxCandidates <= 0 {
		budget.MaxCandidates = 1000
	}
	if budget.MaxDeepCandidates <= 0 {
		budget.MaxDeepCandidates = 100
	}

	plans := make([]CandidatePlan, 0, len(cands))

	for _, c := range cands {
		plan := dp.planCandidate(c, budget)
		plans = append(plans, plan)
	}

	// Sort plans by Priority descending to apply resource caps fairly
	sort.SliceStable(plans, func(i, j int) bool {
		return plans[i].Priority > plans[j].Priority
	})

	// 1. Enforce MaxCandidates cap
	if len(plans) > budget.MaxCandidates {
		for i := budget.MaxCandidates; i < len(plans); i++ {
			plans[i].Analyze = false
			plans[i].Mode = AnalysisShallow
			plans[i].Reason = "SKIPPED_BY_ANALYSIS_POLICY"
		}
	}

	// 2. Enforce MaxDeepCandidates cap
	deepCount := 0
	for i := range plans {
		if plans[i].Analyze && plans[i].Mode == AnalysisDeep {
			deepCount++
			if deepCount > budget.MaxDeepCandidates {
				plans[i].Mode = AnalysisMedium
				if plans[i].Depth > 4 {
					plans[i].Depth = 4
				}
				plans[i].Reason += " (downgraded to medium: deep candidate budget reached)"
			}
		}
	}

	return AnalysisPlan{
		Strategy:   "adaptive",
		Candidates: plans,
	}, nil
}

func (dp *DeterministicPlanner) planCandidate(c candidates.AnalysisCandidate, budget AnalysisBudget) CandidatePlan {
	plan := CandidatePlan{
		CandidateID:          c.ID,
		VulnerabilityClasses: c.VulnerabilityClasses,
		PlannerProvider:      "deterministic",
		PlannerModel:         "heuristic",
	}

	// Case 1: Hardcoded Secret
	if len(c.VulnerabilityClasses) > 0 && c.VulnerabilityClasses[0] == "hardcoded_secret" {
		plan.Analyze = true
		plan.Priority = 90
		plan.Mode = AnalysisShallow
		plan.Depth = 1
		plan.Reason = "Hardcoded secret pattern in variable assignment"
		return plan
	}

	hasSources := len(c.Sources) > 0
	hasSinks := len(c.Sinks) > 0

	// Case 2: Known Sink + Known Source
	if hasSinks && hasSources {
		plan.Analyze = true
		hasUntrustedExternal := false
		for _, s := range c.Sources {
			if s.Type == analyzer.SourceHTTPInput || s.Type == analyzer.SourceCLIInput || s.Type == analyzer.SourceEnvironment {
				hasUntrustedExternal = true
				break
			}
		}

		if hasUntrustedExternal {
			plan.Priority = 85
			plan.Mode = AnalysisDeep
			plan.Depth = minInt(6, budget.MaxDepth)
			plan.Interprocedural = true
			plan.ControlFlow = false
			plan.Reason = "External untrusted input potentially reaches security sink"
		} else {
			plan.Priority = 75
			plan.Mode = AnalysisDeep
			plan.Depth = minInt(5, budget.MaxDepth)
			plan.Interprocedural = true
			plan.ControlFlow = false
			plan.Reason = "Function parameter or local source reaches sensitive sink"
		}
		return plan
	}

	// Case 3: Known Sink + Unknown Source
	if hasSinks && !hasSources {
		plan.Analyze = true
		plan.Priority = 55
		plan.Mode = AnalysisMedium
		plan.Depth = minInt(4, budget.MaxDepth)
		plan.Interprocedural = false
		plan.ControlFlow = false
		plan.Reason = "Security sink detected without identified local source"
		return plan
	}

	// Case 4: Known Source + No Dangerous Sink
	plan.Analyze = false
	plan.Priority = 20
	plan.Mode = AnalysisShallow
	plan.Depth = 1
	plan.Interprocedural = false
	plan.ControlFlow = false
	plan.Reason = "LOW_PRIORITY"
	return plan
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
