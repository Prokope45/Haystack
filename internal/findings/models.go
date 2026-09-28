package findings

import (
	"haystack/internal/analyzer"
	"haystack/internal/classifier"
)

// AnalysisMetadata preserves the planning and strategy directives leading to a finding.
type AnalysisMetadata struct {
	Strategy        string `json:"strategy,omitempty"`
	Priority        int    `json:"priority,omitempty"`
	Depth           int    `json:"depth,omitempty"`
	Interprocedural bool   `json:"interprocedural,omitempty"`
	PlannerProvider string `json:"planner_provider,omitempty"`
	PlannerModel    string `json:"planner_model,omitempty"`
}

// Finding represents a fully normalized security vulnerability finding.
type Finding struct {
	ID               string                           `json:"id"`
	Fingerprint      string                           `json:"fingerprint"`
	RuleID           string                           `json:"rule_id"`
	RuleName         string                           `json:"rule_name"`
	File             string                           `json:"file"`
	Line             int                              `json:"line"`
	Column           int                              `json:"column"`
	Category         string                           `json:"category"`
	Model            string                           `json:"model,omitempty"`
	CWE              []string                         `json:"cwe"`
	CWEName          string                           `json:"cwe_name"`
	Severity         string                           `json:"severity"`
	Confidence       float64                          `json:"confidence"`
	Probabilities    map[string]float64               `json:"probabilities,omitempty"`
	Description      string                           `json:"description"`
	Remediation      string                           `json:"remediation"`
	References       []string                         `json:"references"`
	Evidence         analyzer.Evidence                `json:"evidence"`
	Classification   *classifier.ClassificationResult `json:"classification,omitempty"`
	AnalysisMetadata *AnalysisMetadata                `json:"analysis_metadata,omitempty"`
}
