package classifier

import (
	"context"

	"haystack/internal/analyzer"
)

// ClassificationInput is the standardized schema sent to the classifier.
type ClassificationInput struct {
	Model    string            `json:"model,omitempty"`
	Question string            `json:"question"`
	Evidence analyzer.Evidence `json:"evidence"`
	Category string            `json:"category,omitempty"`
}

// ClassificationResult contains the model's classification decision and raw probability distribution.
type ClassificationResult struct {
	Model         string             `json:"model,omitempty"`
	Label         string             `json:"label"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
	Explanation   string             `json:"explanation,omitempty"`
}

// Classifier provides the abstraction boundary for ML / decision layers.
type Classifier interface {
	ModelName() string
	Classify(ctx context.Context, input ClassificationInput) (ClassificationResult, error)
}
