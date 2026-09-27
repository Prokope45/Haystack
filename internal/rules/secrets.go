package rules

import (
	"fmt"

	"haystack/internal/analyzer"
)

// HardcodedSecretRule detects static credentials and API keys stored in source.
type HardcodedSecretRule struct{}

func NewHardcodedSecretRule() *HardcodedSecretRule {
	return &HardcodedSecretRule{}
}

func (r *HardcodedSecretRule) ID() string {
	return "RULE-SEC-001"
}

func (r *HardcodedSecretRule) Name() string {
	return "Hardcoded Credential or Secret"
}

func (r *HardcodedSecretRule) Category() string {
	return "hardcoded_secret"
}

func (r *HardcodedSecretRule) CWE() string {
	return "CWE-798"
}

func (r *HardcodedSecretRule) DefaultSeverity() string {
	return "high"
}

func (r *HardcodedSecretRule) Evaluate(ev analyzer.Evidence) (bool, string) {
	if ev.Source.Type == analyzer.SourceHardcoded {
		return true, fmt.Sprintf(
			"Variable %q contains hardcoded credentials or secret token in source code",
			ev.Source.Name,
		)
	}
	return false, ""
}
