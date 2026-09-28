package scanner

import (
	"context"

	"haystack/internal/planning"
)

// Scanner defines the primary security scanner interface.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (*ScanResult, error)
	ScanCode(ctx context.Context, req ScanCodeRequest) (*ScanResult, error)
	ScanFile(ctx context.Context, req ScanCodeRequest) (*ScanResult, error)
	GetAnalysisPlan(ctx context.Context, req ScanRequest) (*planning.AnalysisPlan, error)
}
