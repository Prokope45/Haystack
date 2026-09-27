// Package cache provides a small filesystem-backed cache for scanner results.
package cache

import (
	"context"
	"time"
)

// Key is a SHA-256 content-addressed cache key.
type Key string

// Metadata describes the cached value without exposing sensitive request data.
type Metadata struct {
	Key                  string    `json:"key"`
	Namespace            string    `json:"namespace"`
	CreatedAt            time.Time `json:"created_at"`
	ScannerVersion       string    `json:"scanner_version,omitempty"`
	RulesVersion         string    `json:"rules_version,omitempty"`
	Provider             string    `json:"provider,omitempty"`
	Model                string    `json:"model,omitempty"`
	PromptVersion        string    `json:"prompt_version,omitempty"`
	RequestSchemaVersion string    `json:"request_schema_version,omitempty"`
	Language             string    `json:"language,omitempty"`
	Strategy             string    `json:"strategy,omitempty"`
	SourceHash           string    `json:"source_hash,omitempty"`
}

// Cache stores serialized values. A missing or invalid entry is a cache miss.
type Cache interface {
	Get(ctx context.Context, key Key) ([]byte, bool, error)
	Put(ctx context.Context, key Key, value []byte, metadata Metadata) error
	Delete(ctx context.Context, key Key) error
	Clear(ctx context.Context) error
}
