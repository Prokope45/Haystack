package rules

import (
	"haystack/internal/analyzer"
)

// CandidateFinding represents a rule match before Kev classifier adjudication.
type CandidateFinding struct {
	RuleID          string            `json:"rule_id"`
	RuleName        string            `json:"rule_name"`
	Category        string            `json:"category"`
	CWE             string            `json:"cwe"`
	DefaultSeverity string            `json:"default_severity"`
	Evidence        analyzer.Evidence `json:"evidence"`
	Reason          string            `json:"reason"`
}

// Rule defines the deterministic contract for matching evidence to candidate findings.
type Rule interface {
	ID() string
	Name() string
	Category() string
	CWE() string
	DefaultSeverity() string
	Evaluate(ev analyzer.Evidence) (bool, string)
}

// Registry manages the set of active security rules.
type Registry struct {
	rules []Rule
}

// NewRegistry initializes a registry with given rules.
func NewRegistry(rules ...Rule) *Registry {
	return &Registry{rules: rules}
}

// Rules returns all registered rules.
func (r *Registry) Rules() []Rule {
	return r.rules
}

// EvaluateAll tests all registered rules against a slice of evidence.
func (r *Registry) EvaluateAll(evidences []analyzer.Evidence) []CandidateFinding {
	var candidates []CandidateFinding

	for _, ev := range evidences {
		for _, rule := range r.rules {
			matched, reason := rule.Evaluate(ev)
			if matched {
				candidates = append(candidates, CandidateFinding{
					RuleID:          rule.ID(),
					RuleName:        rule.Name(),
					Category:        rule.Category(),
					CWE:             rule.CWE(),
					DefaultSeverity: rule.DefaultSeverity(),
					Evidence:        ev,
					Reason:          reason,
				})
			}
		}
	}

	return candidates
}
