package output

import (
	"encoding/json"
	"io"

	"haystack/internal/findings"
)

// JSONReport represents the top-level JSON structure.
type JSONReport struct {
	Version  string             `json:"version"`
	Summary  ScanSummary        `json:"summary"`
	Findings []findings.Finding `json:"findings"`
}

// JSONFormatter formats findings and summary as clean JSON.
type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (jf *JSONFormatter) Format(w io.Writer, list []findings.Finding, summary ScanSummary) error {
	if list == nil {
		list = []findings.Finding{}
	}

	report := JSONReport{
		Version:  "0.1.0",
		Summary:  summary,
		Findings: list,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
