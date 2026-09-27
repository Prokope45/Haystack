package output

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"haystack/internal/findings"
)

// TextFormatter outputs human-readable scan reports to the terminal.
type TextFormatter struct {
	NoColor bool
}

func NewTextFormatter(noColor bool) *TextFormatter {
	return &TextFormatter{NoColor: noColor}
}

func (tf *TextFormatter) Format(w io.Writer, list []findings.Finding, summary ScanSummary) error {
	red := "\033[1;31m"
	yellow := "\033[1;33m"
	cyan := "\033[1;36m"
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"

	if tf.NoColor {
		red, yellow, cyan, bold, dim, reset = "", "", "", "", "", ""
	}

	var buf bytes.Buffer

	_, _ = fmt.Fprintf(&buf, "\n%sSecurity Scan%s\n", bold, reset)
	_, _ = fmt.Fprintf(&buf, "%s──────────────────────────────────────────────%s\n", dim, reset)

	if len(list) == 0 {
		_, _ = fmt.Fprintf(&buf, "\nNo security vulnerabilities detected above threshold.\n")
	} else {
		for _, f := range list {
			sevColor := yellow
			if strings.EqualFold(f.Severity, "critical") || strings.EqualFold(f.Severity, "high") {
				sevColor = red
			}

			cweStr := strings.Join(f.CWE, ", ")
			_, _ = fmt.Fprintf(&buf, "\n%s%-7s%s %s%s%s\n\n", sevColor, strings.ToUpper(f.Severity), reset, bold, f.RuleName, reset)
			_, _ = fmt.Fprintf(&buf, "File:       %s\n", f.File)
			_, _ = fmt.Fprintf(&buf, "Line:       %d\n", f.Line)
			if cweStr != "" {
				_, _ = fmt.Fprintf(&buf, "CWE:        %s\n", cweStr)
			}
			_, _ = fmt.Fprintf(&buf, "Confidence: %.0f%%\n", f.Confidence*100)

			// Render Evidence Flow
			if len(f.Evidence.FlowSteps) > 0 {
				_, _ = fmt.Fprintf(&buf, "\nEvidence Flow:\n")
				for idx, step := range f.Evidence.FlowSteps {
					_, _ = fmt.Fprintf(&buf, "  %s%s%s\n", cyan, step, reset)
					if idx < len(f.Evidence.FlowSteps)-1 {
						_, _ = fmt.Fprintf(&buf, "      %s↓%s\n", dim, reset)
					}
				}
			}

			if f.Evidence.Code != "" {
				_, _ = fmt.Fprintf(&buf, "\nCode:\n  %s%s%s\n", dim, f.Evidence.Code, reset)
			}

			if f.Remediation != "" {
				_, _ = fmt.Fprintf(&buf, "\nRecommendation:\n")
				remedLines := strings.Split(f.Remediation, "\n")
				for _, rl := range remedLines {
					_, _ = fmt.Fprintf(&buf, "  %s\n", rl)
				}
			}

			_, _ = fmt.Fprintf(&buf, "\n%s──────────────────────────────────────────────%s\n", dim, reset)
		}
	}

	_, _ = fmt.Fprintf(&buf, "\nFiles scanned: %d (Go: %d, Python: %d)\n", summary.FilesScanned, summary.GoFiles, summary.PythonFiles)
	_, _ = fmt.Fprintf(&buf, "Findings:      %d\n", summary.FindingsCount)
	if summary.Duration > 0 {
		_, _ = fmt.Fprintf(&buf, "Scan time:     %v\n\n", summary.Duration)
	} else {
		_, _ = fmt.Fprintf(&buf, "\n")
	}

	_, err := w.Write(buf.Bytes())
	return err
}
