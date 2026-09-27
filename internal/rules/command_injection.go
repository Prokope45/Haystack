package rules

import (
	"fmt"

	"haystack/internal/analyzer"
)

// CommandInjectionRule detects untrusted input reaching command execution sinks.
type CommandInjectionRule struct{}

func NewCommandInjectionRule() *CommandInjectionRule {
	return &CommandInjectionRule{}
}

func (r *CommandInjectionRule) ID() string {
	return "RULE-CMD-001"
}

func (r *CommandInjectionRule) Name() string {
	return "OS Command Injection"
}

func (r *CommandInjectionRule) Category() string {
	return "command_injection"
}

func (r *CommandInjectionRule) CWE() string {
	return "CWE-78"
}

func (r *CommandInjectionRule) DefaultSeverity() string {
	return "high"
}

func (r *CommandInjectionRule) Evaluate(ev analyzer.Evidence) (bool, string) {
	if ev.Sink.Type != analyzer.SinkShell {
		return false, ""
	}

	// Verify the source represents untrusted input
	switch ev.Source.Type {
	case analyzer.SourceHTTPInput,
		analyzer.SourceCLIInput,
		analyzer.SourceEnvironment,
		analyzer.SourceFileInput,
		analyzer.SourceFuncParam:
		return true, fmt.Sprintf(
			"Untrusted input from source %q (%s) flows into command execution sink %q without validation",
			ev.Source.Name,
			ev.Source.Type,
			ev.Sink.Name,
		)
	default:
		return false, ""
	}
}
