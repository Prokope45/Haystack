package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlagsDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	buf := new(bytes.Buffer)

	cfg, err := ParseFlags([]string{tmpDir}, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.TargetDir != tmpDir {
		t.Errorf("expected TargetDir %q, got %q", tmpDir, cfg.TargetDir)
	}
	if cfg.Format != "text" {
		t.Errorf("expected default format text, got %q", cfg.Format)
	}
	if cfg.MinSeverity != "low" {
		t.Errorf("expected default min severity low, got %q", cfg.MinSeverity)
	}
}

func TestParseFlagsCustom(t *testing.T) {
	tmpDir := t.TempDir()
	buf := new(bytes.Buffer)

	args := []string{
		"--format", "json",
		"--severity", "high",
		"--confidence", "0.85",
		"--fail-on", "high",
		"--exclude", "dist,build",
		"--no-color",
		"--verbose",
		tmpDir,
	}

	cfg, err := ParseFlags(args, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Format != "json" {
		t.Errorf("expected format json, got %q", cfg.Format)
	}
	if cfg.MinSeverity != "high" {
		t.Errorf("expected severity high, got %q", cfg.MinSeverity)
	}
	if cfg.MinConfidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %v", cfg.MinConfidence)
	}
	if cfg.FailOn != "high" {
		t.Errorf("expected fail-on high, got %q", cfg.FailOn)
	}
	if !cfg.NoColor {
		t.Errorf("expected NoColor to be true")
	}
	if !cfg.Verbose {
		t.Errorf("expected Verbose to be true")
	}
}

func TestParseFlagsPositionArgFirst(t *testing.T) {
	tmpDir := t.TempDir()
	buf := new(bytes.Buffer)

	// Directory argument is placed first, as in `scanner . --format json --no-color`
	args := []string{
		tmpDir,
		"--format", "json",
		"--no-color",
		"--fail-on", "medium",
	}

	cfg, err := ParseFlags(args, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.TargetDir != tmpDir {
		t.Errorf("expected TargetDir %q, got %q", tmpDir, cfg.TargetDir)
	}
	if cfg.Format != "json" {
		t.Errorf("expected format json, got %q", cfg.Format)
	}
	if !cfg.NoColor {
		t.Errorf("expected NoColor to be true")
	}
	if cfg.FailOn != "medium" {
		t.Errorf("expected fail-on medium, got %q", cfg.FailOn)
	}
}

func TestParseFlagsInvalidDirectory(t *testing.T) {
	buf := new(bytes.Buffer)
	_, err := ParseFlags([]string{"/path/does/not/exist/at/all"}, buf)
	if err == nil {
		t.Fatalf("expected error for non-existent directory")
	}
}

func TestParseFlagsInvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	buf := new(bytes.Buffer)
	_, err := ParseFlags([]string{"--format", "invalid", tmpDir}, buf)
	if err == nil {
		t.Fatalf("expected error for invalid format")
	}
}

func TestParseFlagsSingleFileAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file.go")
	if err := os.WriteFile(filePath, []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	cfg, err := ParseFlags([]string{filePath}, buf)
	if err != nil {
		t.Fatalf("expected single file target to be allowed, got error: %v", err)
	}
	if cfg.TargetDir != filePath {
		t.Errorf("expected TargetDir %s, got %s", filePath, cfg.TargetDir)
	}
}

func TestParseFlagsClassifierOptions(t *testing.T) {
	tmpDir := t.TempDir()
	buf := new(bytes.Buffer)
	args := []string{
		"--classifier-endpoint", "https://rlcd.example.com/classify",
		"--classifier-model", "jev",
		"--classifier-api-key", "my-key",
		"--classifier-timeout", "10",
		tmpDir,
	}

	cfg, err := ParseFlags(args, buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ClassifierEndpoint != "https://rlcd.example.com/classify" {
		t.Errorf("expected endpoint, got %s", cfg.ClassifierEndpoint)
	}
	if cfg.ClassifierModel != "jev" {
		t.Errorf("expected model jev, got %s", cfg.ClassifierModel)
	}
	if cfg.ClassifierAPIKey != "my-key" {
		t.Errorf("expected api key my-key, got %s", cfg.ClassifierAPIKey)
	}
	if cfg.ClassifierTimeout.Seconds() != 10 {
		t.Errorf("expected timeout 10s, got %v", cfg.ClassifierTimeout)
	}
}
