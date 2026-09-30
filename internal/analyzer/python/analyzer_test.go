package python

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"haystack/internal/analyzer"
)

func TestPythonAnalyzerCommandInjection(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}

	code := `
from flask import request
import subprocess

def run_it():
    cmd = request.args.get("c")
    full = "bash -c " + cmd
    subprocess.run(full, shell=True)
`
	pa := NewPythonAnalyzer()
	evidences, err := pa.Analyze(context.Background(), []byte(code), "app.py")
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

func TestPythonAnalyzerInterproceduralArgumentFlow(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	code := `from flask import request
import subprocess

def handler():
    command = request.args.get("cmd")
    dispatch(command)

def dispatch(value):
    execute(value)

def execute(script):
    subprocess.run(script, shell=True)
`
	evidences, err := NewPythonAnalyzer().Analyze(context.Background(), []byte(code), "app.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one cross-function evidence, got %d: %#v", len(evidences), evidences)
	}
	if evidences[0].Source.Type != analyzer.SourceHTTPInput || evidences[0].Sink.Type != analyzer.SinkShell {
		t.Fatalf("unexpected source/sink: %#v", evidences[0])
	}
	if !hasPythonOperation(evidences[0].Operations, "argument_passing") {
		t.Fatalf("expected argument-passing operation, got %#v", evidences[0].Operations)
	}
}

func TestPythonAnalyzerInterproceduralReturnFlow(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	code := `from flask import request
import subprocess

def handler():
    command = read_command()
    subprocess.run(command, shell=True)

def read_command():
    return request.args.get("cmd")
`
	evidences, err := NewPythonAnalyzer().Analyze(context.Background(), []byte(code), "app.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one cross-function evidence, got %d: %#v", len(evidences), evidences)
	}
	if !hasPythonOperation(evidences[0].Operations, "return_value") {
		t.Fatalf("expected return-value operation, got %#v", evidences[0].Operations)
	}
}

func TestPythonAnalyzerInterproceduralDepthLimit(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	code := `from flask import request
import subprocess

def handler():
    dispatch(request.args.get("cmd"))

def dispatch(value):
    execute(value)

def execute(script):
    subprocess.run(script, shell=True)
`
	pa := NewPythonAnalyzer()
	pa.SetDirectives(map[string]analyzer.AnalysisDirectives{
		"candidate": {Analyze: true, MaxInterproceduralDepth: 1},
	})
	evidences, err := pa.Analyze(context.Background(), []byte(code), "app.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 0 {
		t.Fatalf("expected no evidence past interprocedural depth limit, got %#v", evidences)
	}
}

func TestPythonAnalyzerInterproceduralDoesNotTaintUnrelatedCalls(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	code := `from flask import request
import subprocess

def handler():
    command = request.args.get("cmd")
    execute("fixed")
    execute(command)

def execute(script):
    subprocess.run(script, shell=True)
`
	evidences, err := NewPythonAnalyzer().Analyze(context.Background(), []byte(code), "app.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected only the tainted callsite to produce evidence, got %d: %#v", len(evidences), evidences)
	}
}

func hasPythonOperation(operations []analyzer.Operation, kind string) bool {
	for _, operation := range operations {
		if operation.Type == kind {
			return true
		}
	}
	return false
}

func TestPythonAnalyzerSafeCommand(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}

	code := `
import subprocess

def run_fixed():
    subprocess.run(["ls", "-la"])
`
	pa := NewPythonAnalyzer()
	evidences, err := pa.Analyze(context.Background(), []byte(code), "safe.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 0 {
		t.Fatalf("expected 0 evidences for safe command, got %d", len(evidences))
	}
}

func TestPythonAnalyzerSQLInjection(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}

	code := `
from flask import request
import sqlite3

def find_user():
    uid = request.form['uid']
    query = f"SELECT * FROM users WHERE id = '{uid}'"
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
`
	pa := NewPythonAnalyzer()
	evidences, err := pa.Analyze(context.Background(), []byte(code), "query.py")
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

func TestPythonAnalyzerHardcodedSecret(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}

	code := `
API_KEY = "sk_live_98374982734982734"
`
	pa := NewPythonAnalyzer()
	evidences, err := pa.Analyze(context.Background(), []byte(code), "secret.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(evidences) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidences))
	}
	if evidences[0].Source.Type != analyzer.SourceHardcoded {
		t.Errorf("expected SourceHardcoded, got %v", evidences[0].Source.Type)
	}
}

func TestPythonAnalyzerSkipsInactiveFileDirective(t *testing.T) {
	pa := NewPythonAnalyzer()
	pa.PythonBinary = "python-that-must-not-run"
	pa.SetDirectives(map[string]analyzer.AnalysisDirectives{
		"app_py-candidate": {Analyze: false},
	})

	evidences, err := pa.Analyze(context.Background(), []byte("pass\n"), "app.py")
	if err != nil {
		t.Fatalf("inactive file directive should skip bridge execution, got error: %v", err)
	}
	if len(evidences) != 0 {
		t.Fatalf("expected no evidences for inactive file directive, got %#v", evidences)
	}
}

func TestPythonAnalyzerAppliesLineMatchedDirectiveMetadata(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	pa := NewPythonAnalyzer()
	pa.SetDirectives(map[string]analyzer.AnalysisDirectives{
		"app_py-candidate": {Analyze: true, CandidateID: "candidate-5", Mode: "targeted"},
	})
	code := "import subprocess\n\n\ndef run():\n    subprocess.run(input(), shell=True)\n"

	evidences, err := pa.Analyze(context.Background(), []byte(code), "app.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidences) != 1 {
		t.Fatalf("expected one evidence, got %d: %#v", len(evidences), evidences)
	}
	if evidences[0].CandidateID != "candidate-5" || evidences[0].Mode != "targeted" {
		t.Fatalf("expected matching directive metadata, got candidate=%q mode=%q", evidences[0].CandidateID, evidences[0].Mode)
	}
}

func TestPythonAnalyzerSyntaxError(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	_, err := NewPythonAnalyzer().Analyze(context.Background(), []byte("def broken(:\n"), "broken.py")
	if err == nil || !strings.Contains(err.Error(), "python syntax error in broken.py:") {
		t.Fatalf("expected Python syntax error, got %v", err)
	}
}

func TestPythonAnalyzerInvalidBridgeOutput(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	previousBridge := bridgeScript
	bridgeScript = "print('not json')"
	defer func() { bridgeScript = previousBridge }()

	_, err := NewPythonAnalyzer().Analyze(context.Background(), nil, "app.py")
	if err == nil || !strings.Contains(err.Error(), "failed to parse analyzer json output for app.py:") {
		t.Fatalf("expected bridge JSON decoding error, got %v", err)
	}
}
