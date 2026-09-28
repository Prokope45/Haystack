package analyzer

// AnalysisDirectives provides execution constraints (mode, depth, candidate association) to an analyzer.
type AnalysisDirectives struct {
	Analyze                 bool   `json:"analyze"`
	Mode                    string `json:"mode"`
	MaxDepth                int    `json:"max_depth"`
	MaxInterproceduralDepth int    `json:"max_interprocedural_depth,omitempty"`
	CandidateID             string `json:"candidate_id"`
}
