package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"haystack/internal/analyzer"
)

// CalculateFingerprint generates a stable, deterministic hash for a vulnerability finding.
// It is designed to remain stable even when line numbers shift due to unrelated edits.
func CalculateFingerprint(ruleID string, filePath string, ev analyzer.Evidence) string {
	// Normalize path using forward slashes
	normPath := filepath.ToSlash(filePath)
	normPath = strings.TrimPrefix(normPath, "./")

	// Collect normalized flow step signatures (ignoring line numbers)
	flowSig := ""
	if len(ev.FlowSteps) > 0 {
		flowSig = strings.Join(ev.FlowSteps, "->")
	}

	raw := fmt.Sprintf("rule:%s|file:%s|sink_type:%s|sink_name:%s|source_type:%s|source_name:%s|flow:%s",
		strings.TrimSpace(ruleID),
		strings.TrimSpace(normPath),
		strings.TrimSpace(string(ev.Sink.Type)),
		strings.TrimSpace(ev.Sink.Name),
		strings.TrimSpace(string(ev.Source.Type)),
		strings.TrimSpace(ev.Source.Name),
		strings.TrimSpace(flowSig),
	)

	h := sha256.New()
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil))
}
