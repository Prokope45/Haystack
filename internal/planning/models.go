package planning

// CandidatePlan contains the execution directives for analyzing an individual candidate.
type CandidatePlan struct {
	CandidateID          string       `json:"candidate_id"`
	Priority             int          `json:"priority"` // 0 to 100
	Analyze              bool         `json:"analyze"`
	Mode                 AnalysisMode `json:"mode"`
	Depth                int          `json:"depth"`
	Interprocedural      bool         `json:"interprocedural"`
	ControlFlow          bool         `json:"control_flow"`
	VulnerabilityClasses []string     `json:"vulnerability_classes"`
	Reason               string       `json:"reason"`
	PlannerProvider      string       `json:"planner_provider,omitempty"`
	PlannerModel         string       `json:"planner_model,omitempty"`
}

// AnalysisPlan is the coordinated set of plans across all identified candidates.
type AnalysisPlan struct {
	Strategy   string          `json:"strategy"`
	Candidates []CandidatePlan `json:"candidates"`
}
