package output

import (
	"io"
	"time"

	"haystack/internal/findings"
)

// ScanSummary aggregates high-level metrics of the scan run.
type ScanSummary struct {
	FilesScanned  int           `json:"files_scanned"`
	GoFiles       int           `json:"go_files"`
	PythonFiles   int           `json:"python_files"`
	FindingsCount int           `json:"findings_count"`
	Duration      time.Duration `json:"duration_ms"`
}

// Formatter writes scan findings to an io.Writer in a specific format.
type Formatter interface {
	Format(w io.Writer, findings []findings.Finding, summary ScanSummary) error
}
