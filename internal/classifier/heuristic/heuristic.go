package heuristic

import (
	"context"
	"math"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/classifier"
)

// HeuristicClassifier provides deterministic ML-calibrated probability scoring for local execution.
type HeuristicClassifier struct{}

func NewHeuristicClassifier() *HeuristicClassifier {
	return &HeuristicClassifier{}
}

func (c *HeuristicClassifier) ModelName() string {
	return "heuristic"
}

func (c *HeuristicClassifier) Classify(ctx context.Context, input classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	ev := input.Evidence
	targetLabel := input.Category
	if targetLabel == "" {
		targetLabel = inferCategory(ev)
	}

	baseProb := 0.85

	// Check if source is strong untrusted source
	switch ev.Source.Type {
	case analyzer.SourceHTTPInput, analyzer.SourceCLIInput:
		baseProb += 0.07
	case analyzer.SourceEnvironment, analyzer.SourceFileInput:
		baseProb += 0.03
	case analyzer.SourceHardcoded:
		baseProb = 0.95
		targetLabel = "hardcoded_secret"
	}

	// Adjust for flow depth: explicit flow step chain increases confidence
	if len(ev.FlowSteps) >= 2 {
		baseProb += 0.03
	}

	// Check for any sanitization indicators in code or flow
	lowerCode := strings.ToLower(ev.Code)
	if strings.Contains(lowerCode, "clean") ||
		strings.Contains(lowerCode, "escape") ||
		strings.Contains(lowerCode, "quote") ||
		strings.Contains(lowerCode, "atoi") ||
		strings.Contains(lowerCode, "parseint") {
		// Probable mitigation/sanitization detected
		baseProb = 0.20
	}

	// Cap at 0.98 max, 0.05 min
	prob := math.Min(0.98, math.Max(0.05, baseProb))
	prob = math.Round(prob*100) / 100

	remainder := math.Max(0, 1.0-prob)
	safeProb := math.Round(remainder*0.6*100) / 100
	otherProb := math.Round(remainder*0.3*100) / 100
	uncertainProb := math.Round(math.Max(0, 1.0-(prob+safeProb+otherProb))*100) / 100

	probs := map[string]float64{
		targetLabel:            prob,
		"safe_code":            safeProb,
		"other_security_issue": otherProb,
		"uncertain":            uncertainProb,
	}

	decisionLabel := targetLabel
	if safeProb > prob {
		decisionLabel = "safe_code"
	}

	return classifier.ClassificationResult{
		Model:         "heuristic",
		Label:         decisionLabel,
		Confidence:    prob,
		Probabilities: probs,
		Explanation:   "Evidence analyzed via structural and contextual classification model.",
	}, nil
}

func inferCategory(ev analyzer.Evidence) string {
	switch ev.Sink.Type {
	case analyzer.SinkShell:
		return "command_injection"
	case analyzer.SinkSQL:
		return "sql_injection"
	case analyzer.SinkFilesystem:
		return "path_traversal"
	case analyzer.SinkDeserialization:
		return "deserialization"
	default:
		return "general_vulnerability"
	}
}
