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
	directives   map[string]analyzer.AnalysisDirectives
}

// NewPythonAnalyzer creates an analyzer configured to invoke python3 by default.
func NewPythonAnalyzer() *PythonAnalyzer {
	return &PythonAnalyzer{
		PythonBinary: "python3",
	}
}

// SetDirectives installs candidate policies for bridge execution and evidence metadata.
func (pa *PythonAnalyzer) SetDirectives(directives map[string]analyzer.AnalysisDirectives) {
	pa.directives = directives
}

// Language returns the language identifier used in emitted evidence.
func (pa *PythonAnalyzer) Language() string {
	return "python"
}

// Supports reports whether path has a Python source-file extension.
func (pa *PythonAnalyzer) Supports(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".py"
}

// Analyze applies directives, runs the embedded bridge, and enriches its decoded evidence.
func (pa *PythonAnalyzer) Analyze(ctx context.Context, source []byte, filePath string) ([]analyzer.Evidence, error) {
	baseNameSanitized := sanitizePyIdentifier(filepath.Base(filePath))
	maxInterproceduralDepth, shouldAnalyze := pa.analysisSettings(baseNameSanitized)
	if !shouldAnalyze {
		return nil, nil
	}

	stdout, err := pa.runBridge(ctx, source, filePath, maxInterproceduralDepth)
	if err != nil {
		return nil, err
	}
	evidences, err := decodeEvidences(stdout, filePath)
	if err != nil {
		return nil, err
	}
	pa.applyMetadata(evidences, filePath, baseNameSanitized)
	return evidences, nil
}

// analysisSettings selects the interprocedural depth and whether file directives permit analysis.
func (pa *PythonAnalyzer) analysisSettings(baseNameSanitized string) (int, bool) {
	maxInterproceduralDepth := 5
	if len(pa.directives) == 0 {
		return maxInterproceduralDepth, true
	}

	for _, directive := range pa.directives {
		if directive.MaxInterproceduralDepth > 0 {
			maxInterproceduralDepth = directive.MaxInterproceduralDepth
			break
		}
	}
	hasActive := false
	for key, directive := range pa.directives {
		if strings.Contains(key, baseNameSanitized) && directive.Analyze {
			hasActive = true
			break
		}
	}
	// If directives exist for this file but none are active, skip analysis.
	hasAny := false
	for key := range pa.directives {
		if strings.Contains(key, baseNameSanitized) {
			hasAny = true
			break
		}
	}
	return maxInterproceduralDepth, !hasAny || hasActive
}

// runBridge executes the embedded Python program and translates process failures into analyzer errors.
func (pa *PythonAnalyzer) runBridge(ctx context.Context, source []byte, filePath string, maxInterproceduralDepth int) ([]byte, error) {
	cmd := exec.CommandContext(ctx, pa.PythonBinary, "-c", bridgeScript, filePath, fmt.Sprint(maxInterproceduralDepth))

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
	return stdout.Bytes(), nil
}

// decodeEvidences parses the bridge's JSON output and annotates malformed-output errors with the path.
func decodeEvidences(output []byte, filePath string) ([]analyzer.Evidence, error) {
	var rawEvidences []analyzer.Evidence
	if len(output) == 0 {
		return nil, nil
	}

	if err := json.Unmarshal(output, &rawEvidences); err != nil {
		return nil, fmt.Errorf("failed to parse analyzer json output for %s: %w", filePath, err)
	}
	return rawEvidences, nil
}

// applyMetadata fills file/language defaults and matches evidence to candidate directives.
func (pa *PythonAnalyzer) applyMetadata(rawEvidences []analyzer.Evidence, filePath, baseNameSanitized string) {
	// Ensure file path and language are properly set
	for i := range rawEvidences {
		if rawEvidences[i].File == "<stdin>" || rawEvidences[i].File == "" {
			rawEvidences[i].File = filePath
		}
		rawEvidences[i].Language = "python"
		rawEvidences[i].Mode = "deep"

		if len(pa.directives) > 0 {
			matched := false
			for k, d := range pa.directives {
				if strings.Contains(k, baseNameSanitized) && strings.HasSuffix(d.CandidateID, fmt.Sprintf("-%d", rawEvidences[i].Line)) {
					rawEvidences[i].CandidateID = d.CandidateID
					rawEvidences[i].Mode = d.Mode
					matched = true
					break
				}
			}
			if !matched {
				for k, d := range pa.directives {
					if strings.Contains(k, baseNameSanitized) {
						rawEvidences[i].CandidateID = d.CandidateID
						rawEvidences[i].Mode = d.Mode
						break
					}
				}
			}
		}
	}
}

// sanitizePyIdentifier normalizes path fragments for directive matching.
func sanitizePyIdentifier(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
