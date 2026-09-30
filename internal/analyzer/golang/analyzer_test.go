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

func TestGoAnalyzerInterproceduralArgumentFlow(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	dispatch(command)
}
func dispatch(command string) { execute(command) }
func execute(script string) { exec.Command("sh", "-c", script).Run() }
`
	evidences, err := NewGoAnalyzer().Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one cross-function evidence, got %d: %#v", len(evidences), evidences)
	}
	if evidences[0].Source.Type != analyzer.SourceHTTPInput || evidences[0].Sink.Type != analyzer.SinkShell {
		t.Fatalf("unexpected source/sink: %#v", evidences[0])
	}
	if !hasOperation(evidences[0].Operations, "argument_passing") {
		t.Fatalf("expected argument-passing operations, got %#v", evidences[0].Operations)
	}
}

func TestGoAnalyzerInterproceduralReturnFlow(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	command := readCommand(r)
	exec.Command("sh", "-c", command).Run()
}
func readCommand(r *http.Request) string { return r.URL.Query().Get("cmd") }
`
	evidences, err := NewGoAnalyzer().Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one cross-function evidence, got %d: %#v", len(evidences), evidences)
	}
	if !hasOperation(evidences[0].Operations, "return_value") {
		t.Fatalf("expected return-value operation, got %#v", evidences[0].Operations)
	}
}

func TestGoAnalyzerInterproceduralMethodCall(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
type Executor struct{}
func handler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	executor := Executor{}
	executor.execute(command)
}
func (e Executor) execute(script string) { exec.Command("sh", "-c", script).Run() }
`
	evidences, err := NewGoAnalyzer().Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one method-flow evidence, got %d: %#v", len(evidences), evidences)
	}
	if !hasOperation(evidences[0].Operations, "argument_passing") {
		t.Fatalf("expected method argument-passing operation, got %#v", evidences[0].Operations)
	}
}

func TestGoAnalyzerInterproceduralStructFieldArgument(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
type Task struct { Script string }
func handler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	var task Task
	task.Script = command
	execute(task)
}
func execute(task Task) { launch(task.Script) }
func launch(script string) { exec.Command("sh", "-c", script).Run() }
`
	evidences, err := NewGoAnalyzer().Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one struct-field flow evidence, got %d: %#v", len(evidences), evidences)
	}
	if !hasOperation(evidences[0].Operations, "argument_passing") {
		t.Fatalf("expected argument-passing operation, got %#v", evidences[0].Operations)
	}
}

func TestGoAnalyzerInterproceduralDepthLimit(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) { dispatch(r.URL.Query().Get("cmd")) }
func dispatch(command string) { execute(command) }
func execute(script string) { exec.Command("sh", "-c", script).Run() }
`
	ga := NewGoAnalyzer()
	ga.SetDirectives(map[string]analyzer.AnalysisDirectives{
		"candidate": {Analyze: true, MaxInterproceduralDepth: 1},
	})
	evidences, err := ga.Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 0 {
		t.Fatalf("expected no evidence past interprocedural depth limit, got %#v", evidences)
	}
}

func TestGoAnalyzerInterproceduralDoesNotTaintUnrelatedCalls(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	execute("fixed")
	execute(command)
}
func execute(script string) { exec.Command("sh", "-c", script).Run() }
`
	evidences, err := NewGoAnalyzer().Analyze(context.Background(), []byte(code), "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected only the tainted callsite to produce evidence, got %d: %#v", len(evidences), evidences)
	}
	if evidences[0].Line != 11 {
		t.Fatalf("expected sink on tainted call line 11, got line %d", evidences[0].Line)
	}
}

func hasOperation(operations []analyzer.Operation, kind string) bool {
	for _, operation := range operations {
		if operation.Type == kind {
			return true
		}
	}
	return false
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

func TestGoAnalyzerFunctionDirective(t *testing.T) {
	code := `package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", r.URL.Query().Get("cmd"))
}
`
	tests := []struct {
		name      string
		analyze   bool
		wantCount int
		wantID    string
		wantMode  string
	}{
		{name: "inactive directive", analyze: false, wantCount: 0},
		{name: "active directive metadata", analyze: true, wantCount: 1, wantID: "main_go-handler-7", wantMode: "targeted"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ga := NewGoAnalyzer()
			ga.SetDirectives(map[string]analyzer.AnalysisDirectives{
				"main_go-handler-candidate": {
					Analyze: test.analyze, CandidateID: test.wantID, Mode: test.wantMode,
				},
			})
			evidences, err := ga.Analyze(context.Background(), []byte(code), "main.go")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(evidences) != test.wantCount {
				t.Fatalf("expected %d evidences, got %d: %#v", test.wantCount, len(evidences), evidences)
			}
			if test.wantCount > 0 && (evidences[0].CandidateID != test.wantID || evidences[0].Mode != test.wantMode) {
				t.Fatalf("expected directive metadata candidate=%q mode=%q, got candidate=%q mode=%q", test.wantID, test.wantMode, evidences[0].CandidateID, evidences[0].Mode)
			}
		})
	}
}
