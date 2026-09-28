package scanner

import (
	"context"

	"haystack/internal/ai"
	"haystack/internal/candidates"
	"haystack/internal/planning"
)

func (o *Orchestrator) analysisBudget() planning.AnalysisBudget {
	return planning.AnalysisBudget{
		MaxDepth:                o.cfg.MaxDepth,
		MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
		MaxCandidates:           o.cfg.MaxCandidates,
		MaxDeepCandidates:       o.cfg.MaxDeepCandidates,
		MaxPathsPerCandidate:    o.cfg.MaxPathsPerCandidate,
		Timeout:                 o.cfg.ClassifierTimeout,
	}
}

func (o *Orchestrator) plannerFor(aiRequested bool) planning.AnalysisPlanner {
	if !aiRequested || o.cfg.AIPlannerEnabled {
		return o.planner
	}

	return ai.NewSystemOnePlanner(ai.PlannerOptions{
		DecisionsURL: o.cfg.ClassifierEndpoint,
		APIKey:       o.cfg.ClassifierAPIKey,
		Model:        o.cfg.SystemOneModel,
		Timeout:      o.cfg.ClassifierTimeout,
		Mode:         o.cfg.AIMode,
		Fallback:     planning.NewDeterministicPlanner(),
	})
}

func (o *Orchestrator) planCandidates(ctx context.Context, cands []candidates.AnalysisCandidate, strategy string, aiRequested bool) (planning.AnalysisPlan, planning.AnalysisPlanner, error) {
	budget := o.analysisBudget()
	planner := o.plannerFor(aiRequested)
	if strategy == "full" {
		plans := make([]planning.CandidatePlan, 0, len(cands))
		for _, c := range cands {
			plans = append(plans, planning.CandidatePlan{
				CandidateID:          c.ID,
				Priority:             100,
				Analyze:              true,
				Mode:                 planning.AnalysisDeep,
				Depth:                budget.MaxDepth,
				Interprocedural:      true,
				VulnerabilityClasses: c.VulnerabilityClasses,
				Reason:               "Full scan strategy requested",
				PlannerProvider:      "deterministic",
				PlannerModel:         "full",
			})
		}
		return planning.AnalysisPlan{Strategy: "full", Candidates: plans}, planner, nil
	}

	plan, err := planner.Plan(ctx, cands, budget)
	if err != nil {
		if o.cfg.AIMode == "required" {
			return planning.AnalysisPlan{}, planner, err
		}
		fallbackPlan, fallbackErr := planning.NewDeterministicPlanner().Plan(ctx, cands, budget)
		if fallbackErr != nil {
			return planning.AnalysisPlan{}, planner, fallbackErr
		}
		return fallbackPlan, planner, nil
	}
	return plan, planner, nil
}
