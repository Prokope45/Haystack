package benchmarks

import (
	"context"
	"path/filepath"
	"testing"

	"haystack/internal/cache"
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

func BenchmarkScannerCache(b *testing.B) {
	ctx := context.Background()
	code := []byte(`package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
`)

	b.Run("cold-code", func(b *testing.B) {
		store, err := cache.NewDisk(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		service := scanner.NewScannerWithCache(cacheBenchmarkConfig(), store)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			if err := store.Clear(ctx); err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			result, err := service.ScanCode(ctx, scanner.ScanCodeRequest{Code: code, Language: "go", Filename: "bench.go"})
			if err != nil {
				b.Fatal(err)
			}
			if result.Cache.FinalResult != "MISS" {
				b.Fatalf("expected cold cache miss, got %q", result.Cache.FinalResult)
			}
		}
	})

	b.Run("warm-code", func(b *testing.B) {
		store, err := cache.NewDisk(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		service := scanner.NewScannerWithCache(cacheBenchmarkConfig(), store)
		req := scanner.ScanCodeRequest{Code: code, Language: "go", Filename: "bench.go"}
		if _, err := service.ScanCode(ctx, req); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, err := service.ScanCode(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
			if result.Cache.FinalResult != "HIT" {
				b.Fatalf("expected warm cache hit, got %q", result.Cache.FinalResult)
			}
		}
		b.ReportMetric(1, "cache-hit/op")
	})

	b.Run("warm-repository", func(b *testing.B) {
		root, err := filepath.Abs("../testdata")
		if err != nil {
			b.Fatal(err)
		}
		store, err := cache.NewDisk(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		cfg := cacheBenchmarkConfig()
		cfg.TargetDir = root
		cfg.ExcludeDirs = nil
		service := scanner.NewScannerWithCache(cfg, store)
		req := scanner.ScanRequest{}
		if _, err := service.Scan(ctx, req); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, err := service.Scan(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
			if result.Cache.FinalResult != "HIT" {
				b.Fatalf("expected warm repository cache hit, got %q", result.Cache.FinalResult)
			}
		}
		b.ReportMetric(1, "cache-hit/op")
	})

	b.Run("cold-repository", func(b *testing.B) {
		root, err := filepath.Abs("../testdata")
		if err != nil {
			b.Fatal(err)
		}
		store, err := cache.NewDisk(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		cfg := cacheBenchmarkConfig()
		cfg.TargetDir = root
		cfg.ExcludeDirs = nil
		service := scanner.NewScannerWithCache(cfg, store)
		req := scanner.ScanRequest{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			if err := store.Clear(ctx); err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			result, err := service.Scan(ctx, req)
			if err != nil {
				b.Fatal(err)
			}
			if result.Cache.FinalResult != "MISS" {
				b.Fatalf("expected cold repository cache miss, got %q", result.Cache.FinalResult)
			}
		}
	})
}

func cacheBenchmarkConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "heuristic"
	cfg.ClassifierModel = "heuristic"
	cfg.ClassifierEndpoint = ""
	cfg.ClassifierAPIKey = ""
	cfg.OpenRouterAPIKey = ""
	cfg.AIPlannerEnabled = false
	cfg.AIClassifierEnabled = false
	return cfg
}
