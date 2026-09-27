package index

import (
	"testing"
)

func TestIndexGoSource(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os/exec"
)

func handleCmd(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("c")
	exec.Command("sh", "-c", cmd).Run()
}
`

	indexer := NewIndexer()
	err := indexer.IndexFile("main.go", "main.go", []byte(code))
	if err != nil {
		t.Fatalf("unexpected indexing error: %v", err)
	}

	idx := indexer.Index()
	if len(idx.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(idx.Files))
	}
	if len(idx.Functions) != 1 {
		t.Fatalf("expected 1 function, got %d", len(idx.Functions))
	}
	if idx.Functions[0].Name != "handleCmd" {
		t.Errorf("expected handleCmd function, got %s", idx.Functions[0].Name)
	}
	if !idx.Functions[0].IsHandler {
		t.Errorf("expected handleCmd to be identified as handler")
	}

	// Verify sources and sinks
	sources := idx.FindSourcesInFunction("main.go", "handleCmd")
	if len(sources) == 0 {
		t.Errorf("expected at least 1 source in handleCmd, got 0")
	}

	sinks := idx.FindSinksInFunction("main.go", "handleCmd")
	if len(sinks) == 0 {
		t.Errorf("expected at least 1 sink in handleCmd, got 0")
	}

	// Verify calls
	calls := idx.FindCallsInFunction("main.go", "handleCmd")
	if len(calls) == 0 {
		t.Errorf("expected calls in handleCmd, got 0")
	}
}

func TestIndexPythonSource(t *testing.T) {
	pyCode := `import os
import subprocess

def run_backup():
    query = request.args.get("q")
    subprocess.run(["backup.sh", query])
`

	indexer := NewIndexer()
	err := indexer.IndexFile("backup.py", "backup.py", []byte(pyCode))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idx := indexer.Index()
	if len(idx.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(idx.Files))
	}
	if len(idx.Functions) != 1 {
		t.Fatalf("expected 1 function, got %d", len(idx.Functions))
	}
	if len(idx.Imports) != 2 {
		t.Errorf("expected 2 imports, got %d", len(idx.Imports))
	}
	if len(idx.Sources) == 0 {
		t.Errorf("expected at least 1 source, got 0")
	}
	if len(idx.Sinks) == 0 {
		t.Errorf("expected at least 1 sink, got 0")
	}
}
