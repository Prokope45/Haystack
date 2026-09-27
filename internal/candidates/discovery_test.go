package candidates

import (
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/index"
)

func TestDiscoverCandidates(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handleCmd(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("c")
	exec.Command("sh", "-c", cmd).Run()
}

func safeWorker() {
	println("doing safe work")
}
`

	indexer := index.NewIndexer()
	if err := indexer.IndexFile("main.go", "main.go", []byte(code)); err != nil {
		t.Fatalf("failed to index file: %v", err)
	}

	cands := DiscoverCandidates(indexer.Index())
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}

	c := cands[0]
	if c.Function != "handleCmd" {
		t.Errorf("expected function handleCmd, got %s", c.Function)
	}
	if len(c.VulnerabilityClasses) == 0 || c.VulnerabilityClasses[0] != "command_injection" {
		t.Errorf("expected vulnerability class command_injection, got %v", c.VulnerabilityClasses)
	}
	if len(c.Sources) == 0 {
		t.Errorf("expected at least 1 source, got 0")
	}
	if len(c.Sinks) == 0 {
		t.Errorf("expected at least 1 sink, got 0")
	}
}

func TestDiscoverCandidatesMultiple(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"os/exec"
)

func multiHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	path := r.URL.Query().Get("path")
	exec.Command("sh", "-c", cmd).Run()
	os.Open(path)
}
`

	indexer := index.NewIndexer()
	if err := indexer.IndexFile("multi.go", "multi.go", []byte(code)); err != nil {
		t.Fatalf("failed to index file: %v", err)
	}

	cands := DiscoverCandidates(indexer.Index())
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates (command injection and filesystem), got %d", len(cands))
	}
}

func TestEstimateCost(t *testing.T) {
	// Case 1: Close proximity source + Shell sink (dist <= 5)
	sourcesClose := []SourceRef{
		{Line: 10, Name: "input"},
	}
	shellSinkClose := analyzer.Sink{
		Type: analyzer.SinkShell,
		Line: 12,
	}
	cost1 := estimateCost(sourcesClose, shellSinkClose)
	if cost1.EstimatedDepth != 2 {
		t.Errorf("expected EstimatedDepth 2 for close proximity, got %d", cost1.EstimatedDepth)
	}
	if cost1.Complexity != 5 { // 5 (base) + 2 (shell) - 2 (close)
		t.Errorf("expected Complexity 5 for close shell sink, got %d", cost1.Complexity)
	}

	// Case 2: Medium proximity source + SQL sink (dist = 10, <= 15)
	sqlSinkMed := analyzer.Sink{
		Type: analyzer.SinkSQL,
		Line: 20,
	}
	cost2 := estimateCost(sourcesClose, sqlSinkMed)
	if cost2.EstimatedDepth != 3 {
		t.Errorf("expected EstimatedDepth 3 for medium proximity, got %d", cost2.EstimatedDepth)
	}
	if cost2.Complexity != 6 { // 5 (base) + 2 (sql) - 1 (med)
		t.Errorf("expected Complexity 6 for med SQL sink, got %d", cost2.Complexity)
	}

	// Case 3: Far distance source + Deserialization sink (dist = 30)
	deserSinkFar := analyzer.Sink{
		Type: analyzer.SinkDeserialization,
		Line: 40,
	}
	cost3 := estimateCost(sourcesClose, deserSinkFar)
	if cost3.EstimatedDepth != 5 {
		t.Errorf("expected EstimatedDepth 5 for far proximity, got %d", cost3.EstimatedDepth)
	}
	if cost3.Complexity != 8 { // 5 (base) + 3 (deser)
		t.Errorf("expected Complexity 8 for far deserialization sink, got %d", cost3.Complexity)
	}

	// Case 4: No sources (sink-only candidate)
	cost4 := estimateCost(nil, shellSinkClose)
	if cost4.EstimatedDepth != 5 {
		t.Errorf("expected EstimatedDepth 5 for sink-only candidate, got %d", cost4.EstimatedDepth)
	}
	if cost4.Complexity != 8 { // 5 (base) + 2 (shell) + 1 (no source)
		t.Errorf("expected Complexity 8 for sink-only candidate, got %d", cost4.Complexity)
	}
}
