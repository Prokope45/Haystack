package planning

// FindPlan returns the CandidatePlan for a given candidate ID, if present.
func (p *AnalysisPlan) FindPlan(candidateID string) (*CandidatePlan, bool) {
	for i := range p.Candidates {
		if p.Candidates[i].CandidateID == candidateID {
			return &p.Candidates[i], true
		}
	}
	return nil, false
}
