package planning

import (
	"context"
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/candidates"
)

func TestDeterministicPlannerPrioritization(t *testing.T) {
	planner := NewDeterministicPlanner()

	cands := []candidates.AnalysisCandidate{
		{
			ID:                   "c1",
			VulnerabilityClasses: []string{"command_injection"},
			Sources: []candidates.SourceRef{
				{Type: analyzer.SourceHTTPInput, Name: "query"},
			},
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkShell, Name: "exec.Command"},
			},
		},
		{
			ID:                   "c2",
			VulnerabilityClasses: []string{"sql_injection"},
			Sources:              nil, // Sink with unknown source
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkSQL, Name: "db.Query"},
			},
		},
		{
			ID:                   "c3",
			VulnerabilityClasses: []string{"general"},
			Sources: []candidates.SourceRef{
				{Type: analyzer.SourceHTTPInput, Name: "param"},
			},
			Sinks: nil, // Source with no sink
		},
	}

	budget := DefaultBudget()
	plan, err := planner.Plan(context.Background(), cands, budget)
	if err != nil {
		t.Fatalf("planner error: %v", err)
	}

	if len(plan.Candidates) != 3 {
		t.Fatalf("expected 3 candidate plans, got %d", len(plan.Candidates))
	}

	p1, ok := plan.FindPlan("c1")
	if !ok || !p1.Analyze || p1.Mode != AnalysisDeep {
		t.Errorf("expected c1 to be analyzed with deep mode, got %+v", p1)
	}
	if p1.Priority < 80 {
		t.Errorf("expected high priority for c1, got %d", p1.Priority)
	}

	p2, ok := plan.FindPlan("c2")
	if !ok || !p2.Analyze || p2.Mode != AnalysisMedium {
		t.Errorf("expected c2 to be analyzed with medium mode, got %+v", p2)
	}

	p3, ok := plan.FindPlan("c3")
	if !ok || p3.Analyze {
		t.Errorf("expected c3 not to be analyzed, got %+v", p3)
	}
	if p3.Reason != "LOW_PRIORITY" {
		t.Errorf("expected c3 reason to be LOW_PRIORITY, got %q", p3.Reason)
	}
}

func TestDeterministicPlannerBudgetEnforcement(t *testing.T) {
	planner := NewDeterministicPlanner()

	var cands []candidates.AnalysisCandidate
	for i := 0; i < 10; i++ {
		cands = append(cands, candidates.AnalysisCandidate{
			ID:                   string(rune('a' + i)),
			VulnerabilityClasses: []string{"command_injection"},
			Sources: []candidates.SourceRef{
				{Type: analyzer.SourceHTTPInput, Name: "input"},
			},
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkShell, Name: "exec.Command"},
			},
		})
	}

	budget := AnalysisBudget{
		MaxDepth:          6,
		MaxCandidates:     5,
		MaxDeepCandidates: 2,
	}

	plan, err := planner.Plan(context.Background(), cands, budget)
	if err != nil {
		t.Fatalf("planner error: %v", err)
	}

	analyzedCount := 0
	deepCount := 0
	skippedCount := 0

	for _, p := range plan.Candidates {
		if p.Analyze {
			analyzedCount++
			if p.Mode == AnalysisDeep {
				deepCount++
			}
		} else {
			skippedCount++
			if p.Reason != "SKIPPED_BY_ANALYSIS_POLICY" {
				t.Errorf("expected SKIPPED_BY_ANALYSIS_POLICY, got %s", p.Reason)
			}
		}
	}

	if analyzedCount != 5 {
		t.Errorf("expected 5 analyzed candidates, got %d", analyzedCount)
	}
	if deepCount != 2 {
		t.Errorf("expected 2 deep candidates, got %d", deepCount)
	}
	if skippedCount != 5 {
		t.Errorf("expected 5 skipped candidates, got %d", skippedCount)
	}
}
