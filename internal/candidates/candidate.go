package candidates

import (
	"haystack/internal/analyzer"
)

// SourceRef represents a discovered source reference.
type SourceRef struct {
	Type   analyzer.SourceType `json:"type"`
	Name   string              `json:"name"`
	Line   int                 `json:"line"`
	Column int                 `json:"column"`
	Detail string              `json:"detail,omitempty"`
}

// SinkRef represents a discovered sink reference.
type SinkRef struct {
	Type   analyzer.SinkType `json:"type"`
	Name   string            `json:"name"`
	Line   int               `json:"line"`
	Column int               `json:"column"`
	Detail string            `json:"detail,omitempty"`
}

// TransformationRef represents a lightweight transformation hint.
type TransformationRef struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Line   int    `json:"line,omitempty"`
}

// AnalysisCost estimates the computational cost of analyzing this candidate.
type AnalysisCost struct {
	EstimatedDepth int `json:"estimated_depth"`
	Complexity     int `json:"complexity"` // 1 (simple) to 10 (complex)
	FilesCrossed   int `json:"files_crossed"`
}

// AnalysisCandidate represents a lightweight candidate pairing identified from the ProgramIndex.
type AnalysisCandidate struct {
	ID                   string              `json:"id"`
	Language             string              `json:"language"`
	File                 string              `json:"file"`
	Function             string              `json:"function"`
	VulnerabilityClasses []string            `json:"vulnerability_classes"`
	Sources              []SourceRef         `json:"sources"`
	Sinks                []SinkRef           `json:"sinks"`
	Transformations      []TransformationRef `json:"transformations,omitempty"`
	EstimatedCost        AnalysisCost        `json:"estimated_cost"`
	Metadata             map[string]any      `json:"metadata,omitempty"`
}
