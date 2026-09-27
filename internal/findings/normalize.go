package findings

import (
	"context"
	"fmt"
	"strings"

	"haystack/internal/classifier"
	"haystack/internal/intelligence/cwe"
	"haystack/internal/rules"
)

// NormalizerOptions contains threshold configurations for finding normalization.
type NormalizerOptions struct {
	MinSeverity   string
	MinConfidence float64
}

// Normalizer transforms candidate rule matches into enriched, deduplicated findings.
type Normalizer struct {
	cls  classifier.Classifier
	opts NormalizerOptions
}

// NewNormalizer creates a new findings Normalizer.
func NewNormalizer(cls classifier.Classifier, opts NormalizerOptions) *Normalizer {
	return &Normalizer{
		cls:  cls,
		opts: opts,
	}
}

// Normalize processes candidate findings into final normalized Finding objects.
func (n *Normalizer) Normalize(ctx context.Context, candidates []rules.CandidateFinding) ([]Finding, error) {
	var results []Finding

	for i, c := range candidates {
		input := classifier.ClassificationInput{
			Question: fmt.Sprintf("Classify security risk for potential %s weakness.", c.Category),
			Evidence: c.Evidence,
			Category: c.Category,
		}

		var res classifier.ClassificationResult
		var resPtr *classifier.ClassificationResult

		if n.cls != nil {
			r, err := n.cls.Classify(ctx, input)
			if err != nil {
				return nil, fmt.Errorf("classifier error on candidate %s: %w", c.RuleID, err)
			}
			res = r
			resPtr = &res

			// If classifier concluded it is safe code, discard
			if res.Label == "safe_code" {
				continue
			}

			// Confidence filter
			if res.Confidence < n.opts.MinConfidence {
				continue
			}
		} else {
			// Classifier disabled: default confidence is 1.0 from deterministic rule
			res = classifier.ClassificationResult{
				Model:      "deterministic",
				Label:      c.Category,
				Confidence: 1.0,
			}
			resPtr = nil // Section 23: Classification can be nil when disabled
		}

		// Severity determination: default to rule's severity or adjust if confidence is lower
		sev := c.DefaultSeverity
		if res.Confidence < 0.60 && sev == string(SeverityHigh) {
			sev = string(SeverityMedium)
		}

		// Severity filter
		if SeverityWeight(sev) < SeverityWeight(n.opts.MinSeverity) {
			continue
		}

		// CWE enrichment
		weakness := cwe.Lookup(c.CWE)

		findingID := fmt.Sprintf("%s-%s-%d-%d", c.RuleID, strings.ReplaceAll(c.Evidence.File, "/", "-"), c.Evidence.Line, i+1)
		fingerprint := CalculateFingerprint(c.RuleID, c.Evidence.File, c.Evidence)

		results = append(results, Finding{
			ID:             findingID,
			Fingerprint:    fingerprint,
			RuleID:         c.RuleID,
			RuleName:       c.RuleName,
			File:           c.Evidence.File,
			Line:           c.Evidence.Line,
			Column:         c.Evidence.Column,
			Category:       c.Category,
			Model:          res.Model,
			CWE:            []string{c.CWE},
			CWEName:        weakness.Name,
			Severity:       sev,
			Confidence:     res.Confidence,
			Probabilities:  res.Probabilities,
			Description:    weakness.Description,
			Remediation:    weakness.Remediation,
			References:     weakness.References,
			Evidence:       c.Evidence,
			Classification: resPtr,
		})
	}

	return results, nil
}
