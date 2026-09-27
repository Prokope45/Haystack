package analyzer

import (
	"context"
)

// SourceType represents the category of untrusted input.
type SourceType string

const (
	SourceHTTPInput   SourceType = "http_input"
	SourceCLIInput    SourceType = "cli_input"
	SourceEnvironment SourceType = "environment"
	SourceFileInput   SourceType = "file_input"
	SourceFuncParam   SourceType = "function_parameter"
	SourceHardcoded   SourceType = "hardcoded_secret"
)

// SinkType represents the category of security-sensitive operations.
type SinkType string

const (
	SinkShell           SinkType = "shell_execution"
	SinkSQL             SinkType = "sql_execution"
	SinkFilesystem      SinkType = "filesystem_access"
	SinkDeserialization SinkType = "deserialization"
)

// Source describes the origin of untrusted or sensitive data.
type Source struct {
	Type   SourceType `json:"type"`
	Name   string     `json:"name"`
	Line   int        `json:"line"`
	Column int        `json:"column"`
	Detail string     `json:"detail,omitempty"`
}

// Sink describes a security-sensitive operation receiving data.
type Sink struct {
	Type   SinkType `json:"type"`
	Name   string   `json:"name"`
	Line   int      `json:"line"`
	Column int      `json:"column"`
	Detail string   `json:"detail,omitempty"`
}

// Operation represents an intermediate transformation or data propagation step.
type Operation struct {
	Type   string `json:"type"` // e.g. "assignment", "concatenation", "format_string", "argument_passing"
	Detail string `json:"detail"`
	Line   int    `json:"line,omitempty"`
}

// Evidence captures the deterministic static analysis proof of a security-relevant flow.
type Evidence struct {
	File       string      `json:"file"`
	Line       int         `json:"line"`
	Column     int         `json:"column"`
	Language   string      `json:"language"`
	Source     Source      `json:"source"`
	Sink       Sink        `json:"sink"`
	Operations []Operation `json:"operations"`
	FlowSteps  []string    `json:"flow_steps"`
	Code       string      `json:"code"`
	Context    string      `json:"context,omitempty"`
}

// Analyzer is the common interface implemented by language-specific static analyzers.
type Analyzer interface {
	Language() string
	Supports(path string) bool
	Analyze(ctx context.Context, source []byte, path string) ([]Evidence, error)
}
