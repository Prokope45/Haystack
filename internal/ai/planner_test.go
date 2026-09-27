package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"haystack/internal/analyzer"
	"haystack/internal/candidates"
	"haystack/internal/planning"
)

func TestJevPlannerSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %s", r.Header.Get("Authorization"))
		}

		var req jevDecisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode error: %v", err)
		}

		if !strings.Contains(req.State, "exec.Command") {
			t.Errorf("expected state to contain exec.Command, got %s", req.State)
		}

		noulVal := 0.95
		resp := jevDecisionResponse{
			ID:    "dec-123",
			Model: DefaultSystemOne,
			Answers: map[string]jevAnswer{
				"should_analyze": {
					Type: "noul",
					Noul: &noulVal,
				},
				"analysis_mode": {
					Type:   "choice",
					Choice: "deep",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	planner := NewJevPlanner(PlannerOptions{
		DecisionsURL: ts.URL,
		APIKey:       "test-key",
		Model:        DefaultSystemOne,
		Timeout:      2 * time.Second,
		Mode:         "optional",
	})

	cands := []candidates.AnalysisCandidate{
		{
			ID:                   "c-test",
			Language:             "go",
			File:                 "app.go",
			Function:             "handler",
			VulnerabilityClasses: []string{"command_injection"},
			Sources: []candidates.SourceRef{
				{Type: analyzer.SourceHTTPInput, Name: "input", Line: 10},
			},
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkShell, Name: "exec.Command", Line: 12},
			},
		},
	}

	budget := planning.DefaultBudget()
	plan, err := planner.Plan(context.Background(), cands, budget)
	if err != nil {
		t.Fatalf("unexpected plan error: %v", err)
	}

	if len(plan.Candidates) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plan.Candidates))
	}

	p := plan.Candidates[0]
	if !p.Analyze {
		t.Errorf("expected Analyze to be true")
	}
	if p.Mode != planning.AnalysisDeep {
		t.Errorf("expected deep analysis mode, got %s", p.Mode)
	}
	if p.Priority != 95 {
		t.Errorf("expected priority 95, got %d", p.Priority)
	}
	if p.PlannerProvider != "jev" {
		t.Errorf("expected planner provider jev, got %s", p.PlannerProvider)
	}

	reqs, lat := planner.Telemetry()
	if reqs != 1 || lat <= 0 {
		t.Errorf("expected telemetry reqs=1, got %d (latency %v)", reqs, lat)
	}
}

func TestJevPlannerFallbackInOptionalMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	planner := NewJevPlanner(PlannerOptions{
		DecisionsURL: ts.URL,
		APIKey:       "test-key",
		Mode:         "optional",
		Fallback:     planning.NewDeterministicPlanner(),
	})

	cands := []candidates.AnalysisCandidate{
		{
			ID:                   "c-fb",
			Language:             "go",
			File:                 "main.go",
			Function:             "run",
			VulnerabilityClasses: []string{"command_injection"},
			Sources: []candidates.SourceRef{
				{Type: analyzer.SourceHTTPInput, Name: "input"},
			},
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkShell, Name: "exec.Command"},
			},
		},
	}

	// Should not fail; falls back to deterministic planner
	plan, err := planner.Plan(context.Background(), cands, planning.DefaultBudget())
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}

	if len(plan.Candidates) != 1 {
		t.Fatalf("expected 1 candidate plan from fallback, got %d", len(plan.Candidates))
	}

	if plan.Candidates[0].PlannerProvider != "deterministic" {
		t.Errorf("expected fallback provider deterministic, got %s", plan.Candidates[0].PlannerProvider)
	}
}

func TestJevPlannerFailureInRequiredMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	planner := NewJevPlanner(PlannerOptions{
		DecisionsURL: ts.URL,
		APIKey:       "test-key",
		Mode:         "required",
	})

	cands := []candidates.AnalysisCandidate{
		{
			ID: "c-req",
			Sinks: []candidates.SinkRef{
				{Type: analyzer.SinkShell, Name: "exec.Command"},
			},
		},
	}

	_, err := planner.Plan(context.Background(), cands, planning.DefaultBudget())
	if err == nil {
		t.Fatalf("expected error in required mode when API fails, got nil")
	}
}
