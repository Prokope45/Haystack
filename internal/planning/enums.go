package planning

// AnalysisMode represents the intensity and depth of static analysis for a candidate.
type AnalysisMode string

const (
	AnalysisShallow AnalysisMode = "shallow"
	AnalysisMedium  AnalysisMode = "medium"
	AnalysisDeep    AnalysisMode = "deep"
)
