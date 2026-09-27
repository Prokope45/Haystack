package rules

import (
	"fmt"

	"haystack/internal/analyzer"
)

// DeserializationRule detects untrusted deserialization operations.
type DeserializationRule struct{}

func NewDeserializationRule() *DeserializationRule {
	return &DeserializationRule{}
}

func (r *DeserializationRule) ID() string {
	return "RULE-DESER-001"
}

func (r *DeserializationRule) Name() string {
	return "Deserialization of Untrusted Data"
}

func (r *DeserializationRule) Category() string {
	return "deserialization"
}

func (r *DeserializationRule) CWE() string {
	return "CWE-502"
}

func (r *DeserializationRule) DefaultSeverity() string {
	return "high"
}

func (r *DeserializationRule) Evaluate(ev analyzer.Evidence) (bool, string) {
	if ev.Sink.Type != analyzer.SinkDeserialization {
		return false, ""
	}

	switch ev.Source.Type {
	case analyzer.SourceHTTPInput,
		analyzer.SourceCLIInput,
		analyzer.SourceEnvironment,
		analyzer.SourceFileInput,
		analyzer.SourceFuncParam:
		return true, fmt.Sprintf(
			"Untrusted input from source %q (%s) is passed to deserialization sink %q",
			ev.Source.Name,
			ev.Source.Type,
			ev.Sink.Name,
		)
	default:
		return false, ""
	}
}
