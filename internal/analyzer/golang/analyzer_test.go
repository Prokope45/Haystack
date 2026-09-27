package golang

import (
	"context"
	"testing"

	"haystack/internal/analyzer"
)

func TestGoAnalyzerCommandInjection(t *testing.T) {
	code := `
package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("c")
	fullCmd := "bash -c " + cmd
	exec.Command("sh", "-c", fullCmd)
}
`
	ga := NewGoAnalyzer()
	evidences, err := ga.Analyze(context.Background(), []byte(code), "handler.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidences))
	}

	ev := evidences[0]
	if ev.Source.Type != analyzer.SourceHTTPInput {
		t.Errorf("expected SourceHTTPInput, got %v", ev.Source.Type)
	}
	if ev.Sink.Type != analyzer.SinkShell {
		t.Errorf("expected SinkShell, got %v", ev.Sink.Type)
	}
	if len(ev.FlowSteps) < 2 {
		t.Errorf("expected at least 2 flow steps, got %v", ev.FlowSteps)
	}
}

func TestGoAnalyzerSafeCommand(t *testing.T) {
	code := `
package main

import "os/exec"

func runFixed() {
	exec.Command("git", "status")
}
`
	ga := NewGoAnalyzer()
	evidences, err := ga.Analyze(context.Background(), []byte(code), "safe.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 0 {
		t.Fatalf("expected 0 evidences for safe command, got %d", len(evidences))
	}
}

func TestGoAnalyzerSQLInjection(t *testing.T) {
	code := `
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func queryUser(db *sql.DB, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
	db.Query(query)
}
`
	ga := NewGoAnalyzer()
	evidences, err := ga.Analyze(context.Background(), []byte(code), "query.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidences))
	}

	ev := evidences[0]
	if ev.Sink.Type != analyzer.SinkSQL {
		t.Errorf("expected SinkSQL, got %v", ev.Sink.Type)
	}
}

func TestGoAnalyzerHardcodedSecret(t *testing.T) {
	code := `
package main

func initAuth() {
	apiKey := "secret_live_9837498273498273"
	_ = apiKey
}
`
	ga := NewGoAnalyzer()
	evidences, err := ga.Analyze(context.Background(), []byte(code), "auth.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 1 {
		t.Fatalf("expected 1 evidence for hardcoded secret, got %d", len(evidences))
	}
	if evidences[0].Source.Type != analyzer.SourceHardcoded {
		t.Errorf("expected SourceHardcoded, got %v", evidences[0].Source.Type)
	}
}
