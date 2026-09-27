package rules

import (
	"fmt"

	"haystack/internal/analyzer"
)

// SQLInjectionRule detects untrusted input reaching SQL execution sinks.
type SQLInjectionRule struct{}

func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{}
}

func (r *SQLInjectionRule) ID() string {
	return "RULE-SQL-001"
}

func (r *SQLInjectionRule) Name() string {
	return "SQL Injection"
}

func (r *SQLInjectionRule) Category() string {
	return "sql_injection"
}

func (r *SQLInjectionRule) CWE() string {
	return "CWE-89"
}

func (r *SQLInjectionRule) DefaultSeverity() string {
	return "high"
}

func (r *SQLInjectionRule) Evaluate(ev analyzer.Evidence) (bool, string) {
	if ev.Sink.Type != analyzer.SinkSQL {
		return false, ""
	}

	switch ev.Source.Type {
	case analyzer.SourceHTTPInput,
		analyzer.SourceCLIInput,
		analyzer.SourceEnvironment,
		analyzer.SourceFileInput,
		analyzer.SourceFuncParam:
		return true, fmt.Sprintf(
			"Untrusted input from source %q (%s) flows into SQL query execution sink %q",
			ev.Source.Name,
			ev.Source.Type,
			ev.Sink.Name,
		)
	default:
		return false, ""
	}
}
