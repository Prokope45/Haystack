package findings

import (
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
)

// Severity represents vulnerability severity levels.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityWeight assigns an integer score for comparisons.
func SeverityWeight(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// Finding represents a fully normalized security vulnerability finding.
type Finding struct {
	ID             string                         `json:"id"`
	Fingerprint    string                         `json:"fingerprint"`
	RuleID         string                         `json:"rule_id"`
	RuleName       string                         `json:"rule_name"`
	File           string                         `json:"file"`
	Line           int                            `json:"line"`
	Column         int                            `json:"column"`
	Category       string                         `json:"category"`
	Model          string                         `json:"model,omitempty"`
	CWE            []string                       `json:"cwe"`
	CWEName        string                         `json:"cwe_name"`
	Severity       string                         `json:"severity"`
	Confidence     float64                        `json:"confidence"`
	Probabilities  map[string]float64             `json:"probabilities,omitempty"`
	Description    string                         `json:"description"`
	Remediation    string                         `json:"remediation"`
	References     []string                       `json:"references"`
	Evidence       analyzer.Evidence              `json:"evidence"`
	Classification *classifier.ClassificationResult `json:"classification,omitempty"`
}
