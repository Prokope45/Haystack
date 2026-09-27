package rules

import (
	"fmt"

	"haystack/internal/analyzer"
)

// PathTraversalRule detects untrusted input reaching filesystem access sinks.
type PathTraversalRule struct{}

func NewPathTraversalRule() *PathTraversalRule {
	return &PathTraversalRule{}
}

func (r *PathTraversalRule) ID() string {
	return "RULE-PATH-001"
}

func (r *PathTraversalRule) Name() string {
	return "Path Traversal"
}

func (r *PathTraversalRule) Category() string {
	return "path_traversal"
}

func (r *PathTraversalRule) CWE() string {
	return "CWE-22"
}

func (r *PathTraversalRule) DefaultSeverity() string {
	return "high"
}

func (r *PathTraversalRule) Evaluate(ev analyzer.Evidence) (bool, string) {
	if ev.Sink.Type != analyzer.SinkFilesystem {
		return false, ""
	}

	switch ev.Source.Type {
	case analyzer.SourceHTTPInput,
		analyzer.SourceCLIInput,
		analyzer.SourceEnvironment,
		analyzer.SourceFileInput,
		analyzer.SourceFuncParam:
		return true, fmt.Sprintf(
			"Untrusted input from source %q (%s) flows into filesystem path access sink %q",
			ev.Source.Name,
			ev.Source.Type,
			ev.Sink.Name,
		)
	default:
		return false, ""
	}
}
