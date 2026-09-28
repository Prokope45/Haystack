// Package buildinfo exposes versions used for output and cache invalidation.
package buildinfo

// ScannerVersion must be updated when scanner behavior changes in a way that
// cannot be captured by the rule, parser, or configuration identities.
const ScannerVersion = "0.1.1-poc"

// PlannerPromptVersion identifies the AI planner prompt and request contract.
const PlannerPromptVersion = "system-one-planner-v1"

// PlannerSchemaVersion identifies the AI planner request and response schemas.
const PlannerSchemaVersion = "1"

// ClassifierPromptVersion identifies the classifier prompts and response contract.
const ClassifierPromptVersion = "classifier-v1"

// ClassifierSchemaVersion identifies the classifier request and response schemas.
const ClassifierSchemaVersion = "1"
