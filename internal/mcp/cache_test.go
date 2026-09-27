package mcp

import (
	"context"
	"testing"

	"haystack/internal/cache"
	"haystack/internal/config"
	"haystack/internal/scanner"
)

type observingCache struct {
	inner cache.Cache
	gets  int
	puts  int
}

func (c *observingCache) Get(ctx context.Context, key cache.Key) ([]byte, bool, error) {
	c.gets++
	return c.inner.Get(ctx, key)
}

func (c *observingCache) Put(ctx context.Context, key cache.Key, value []byte, metadata cache.Metadata) error {
	c.puts++
	return c.inner.Put(ctx, key, value, metadata)
}

func (c *observingCache) Delete(ctx context.Context, key cache.Key) error {
	return c.inner.Delete(ctx, key)
}

func (c *observingCache) Clear(ctx context.Context) error {
	return c.inner.Clear(ctx)
}

func TestMCPCodeScansUseSharedScannerCache(t *testing.T) {
	disk, err := cache.NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &observingCache{inner: disk}
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "heuristic"
	cfg.ClassifierModel = "heuristic"
	cfg.ClassifierEndpoint = ""
	cfg.OpenRouterAPIKey = ""
	svc := scanner.NewScannerWithCache(cfg, store)
	server := NewServerWithOptions(ServerOptions{Config: cfg, Scanner: svc})
	args := map[string]interface{}{
		"code":     "package main; func main() {}",
		"language": "go",
		"filename": "main.go",
	}

	for i := 0; i < 2; i++ {
		response := server.callScanCode(i+1, context.Background(), args)
		if response == nil || response.Error != nil {
			t.Fatalf("MCP scan_code call %d failed: %+v", i+1, response)
		}
	}
	if store.gets != 2 || store.puts != 1 {
		t.Fatalf("cache calls: gets=%d puts=%d; want two lookups and one write", store.gets, store.puts)
	}
}
