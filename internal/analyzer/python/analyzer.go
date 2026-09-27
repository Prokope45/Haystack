package python

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"haystack/internal/analyzer"
)

//go:embed bridge.py
var bridgeScript string

// PythonAnalyzer implements the analyzer.Analyzer interface for Python source files.
type PythonAnalyzer struct {
	PythonBinary string
}

func NewPythonAnalyzer() *PythonAnalyzer {
	return &PythonAnalyzer{
		PythonBinary: "python3",
	}
}

func (pa *PythonAnalyzer) Language() string {
	return "python"
}

func (pa *PythonAnalyzer) Supports(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".py"
}

func (pa *PythonAnalyzer) Analyze(ctx context.Context, source []byte, filePath string) ([]analyzer.Evidence, error) {
	cmd := exec.CommandContext(ctx, pa.PythonBinary, "-c", bridgeScript, filePath)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(source)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			// Parsing/syntax error in Python source
			return nil, fmt.Errorf("python syntax error in %s: %s", filePath, stderr.String())
		}
		return nil, fmt.Errorf("failed to run python analyzer for %s: %w, stderr: %s", filePath, err, stderr.String())
	}

	var rawEvidences []analyzer.Evidence
	if stdout.Len() == 0 {
		return nil, nil
	}

	if err := json.Unmarshal(stdout.Bytes(), &rawEvidences); err != nil {
		return nil, fmt.Errorf("failed to parse analyzer json output for %s: %w", filePath, err)
	}

	// Ensure file path and language are properly set
	for i := range rawEvidences {
		if rawEvidences[i].File == "<stdin>" || rawEvidences[i].File == "" {
			rawEvidences[i].File = filePath
		}
		rawEvidences[i].Language = "python"
	}

	return rawEvidences, nil
}
