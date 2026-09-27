package python

import (
	"context"
	"os/exec"
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
