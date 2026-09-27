package output

import (
	"io"
	"time"

	"haystack/internal/findings"
)

// AnalysisStats tracks telemetry across indexing, planning, and adaptive static analysis.
type AnalysisStats struct {
	Strategy                 string        `json:"strategy"`
	FilesDiscovered          int           `json:"files_discovered"`
	FilesParsed              int           `json:"files_parsed"`
	CandidatesDiscovered     int           `json:"candidates_discovered"`
	CandidatesAnalyzed       int           `json:"candidates_analyzed"`
	CandidatesSkipped        int           `json:"candidates_skipped"`
	ShallowAnalyses          int           `json:"shallow_analyses"`
	MediumAnalyses           int           `json:"medium_analyses"`
	DeepAnalyses             int           `json:"deep_analyses"`
	PathsConsidered          int           `json:"paths_considered"`
	PathsAnalyzed            int           `json:"paths_analyzed"`
	AIPlanningRequests       int           `json:"ai_planning_requests"`
	AIPlanningLatency        time.Duration `json:"ai_planning_latency_ms"`
	AIClassificationRequests int           `json:"ai_classification_requests"`
	AIClassificationLatency  time.Duration `json:"ai_classification_latency_ms"`
}

// ScanSummary aggregates high-level metrics of the scan run.
type ScanSummary struct {
	FilesScanned  int           `json:"files_scanned"`
	GoFiles       int           `json:"go_files"`
	PythonFiles   int           `json:"python_files"`
	FindingsCount int           `json:"findings_count"`
	Duration      time.Duration `json:"duration_ms"`
	Analysis      AnalysisStats `json:"analysis"`
}

// Formatter writes scan findings to an io.Writer in a specific format.
type Formatter interface {
	Format(w io.Writer, findings []findings.Finding, summary ScanSummary) error
}
