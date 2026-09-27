package planning

// AnalysisMode represents the intensity and depth of static analysis for a candidate.
type AnalysisMode string

const (
	AnalysisShallow AnalysisMode = "shallow"
	AnalysisMedium  AnalysisMode = "medium"
	AnalysisDeep    AnalysisMode = "deep"
)

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

// FindPlan returns the CandidatePlan for a given candidate ID, if present.
func (p *AnalysisPlan) FindPlan(candidateID string) (*CandidatePlan, bool) {
	for i := range p.Candidates {
		if p.Candidates[i].CandidateID == candidateID {
			return &p.Candidates[i], true
		}
	}
	return nil, false
}
