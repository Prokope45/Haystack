package benchmarks

import (
	"context"
	"path/filepath"
	"testing"

	"haystack/internal/config"
	"haystack/internal/scanner"
)

func BenchmarkScannerPipeline(b *testing.B) {
	testDataDir, err := filepath.Abs("../testdata")
	if err != nil {
		b.Fatalf("failed to resolve testdata dir: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.TargetDir = testDataDir
	cfg.ExcludeDirs = nil

	orch := scanner.NewOrchestrator(cfg)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		findings, summary, err := orch.Scan(ctx)
		if err != nil {
			b.Fatalf("benchmark scan failed: %v", err)
		}
		if len(findings) != 6 {
			b.Fatalf("expected 6 findings, got %d", len(findings))
		}
		b.ReportMetric(float64(summary.FilesScanned), "files/op")
	}
}
