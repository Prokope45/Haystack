// build+ benchmarks
package benchmarks

import (
	"context"
	"path/filepath"
	"testing"

	"haystack/internal/config"
	"haystack/internal/scanner"
)

type ExpectedResult struct {
	RelPath      string
	IsVulnerable bool
	Category     string
	CWE          string
}

func TestEvaluationMetrics(t *testing.T) {
	evalCorpus := []ExpectedResult{
		// Go fixtures
		{RelPath: "go/command_injection.go", IsVulnerable: true, Category: "command_injection", CWE: "CWE-78"},
		{RelPath: "go/command_safe.go", IsVulnerable: false},
		{RelPath: "go/sql_injection.go", IsVulnerable: true, Category: "sql_injection", CWE: "CWE-89"},
		{RelPath: "go/sql_safe.go", IsVulnerable: false},
		{RelPath: "go/path_traversal.go", IsVulnerable: true, Category: "path_traversal", CWE: "CWE-22"},
		{RelPath: "go/path_safe.go", IsVulnerable: false},

		// Python fixtures
		{RelPath: "python/command_injection.py", IsVulnerable: true, Category: "command_injection", CWE: "CWE-78"},
		{RelPath: "python/command_safe.py", IsVulnerable: false},
		{RelPath: "python/sql_injection.py", IsVulnerable: true, Category: "sql_injection", CWE: "CWE-89"},
		{RelPath: "python/sql_safe.py", IsVulnerable: false},
		{RelPath: "python/path_traversal.py", IsVulnerable: true, Category: "path_traversal", CWE: "CWE-22"},
		{RelPath: "python/path_safe.py", IsVulnerable: false},
	}

	testDataDir, err := filepath.Abs("../testdata")
	if err != nil {
		t.Fatalf("failed to resolve testdata dir: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.TargetDir = testDataDir
	cfg.ExcludeDirs = nil // Don't exclude testdata

	orch := scanner.NewOrchestrator(cfg)
	findings, summary, err := orch.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	findingMap := make(map[string]bool)
	findingCategoryMap := make(map[string]string)
	findingCWEMap := make(map[string]string)

	for _, f := range findings {
		normPath := filepath.ToSlash(f.File)
		findingMap[normPath] = true
		findingCategoryMap[normPath] = f.Category
		if len(f.CWE) > 0 {
			findingCWEMap[normPath] = f.CWE[0]
		}
	}

	var tp, fp, tn, fn int

	for _, sample := range evalCorpus {
		hasFinding := findingMap[sample.RelPath]

		if sample.IsVulnerable {
			if hasFinding {
				tp++
				// Validate category and CWE
				cat := findingCategoryMap[sample.RelPath]
				cwe := findingCWEMap[sample.RelPath]
				if cat != sample.Category {
					t.Errorf("[%s] expected category %s, got %s", sample.RelPath, sample.Category, cat)
				}
				if cwe != sample.CWE {
					t.Errorf("[%s] expected CWE %s, got %s", sample.RelPath, sample.CWE, cwe)
				}
			} else {
				fn++
				t.Errorf("[%s] False Negative: expected finding but none was reported", sample.RelPath)
			}
		} else {
			if hasFinding {
				fp++
				t.Errorf("[%s] False Positive: unexpected finding reported for safe fixture", sample.RelPath)
			} else {
				tn++
			}
		}
	}

	precision := float64(tp) / float64(tp+fp)
	recall := float64(tp) / float64(tp+fn)
	f1 := 2 * (precision * recall) / (precision + recall)
	fpRate := float64(fp) / float64(fp+tn)
	fnRate := float64(fn) / float64(fn+tp)

	t.Logf("=== Evaluation Metrics (Corpus Size: %d) ===", len(evalCorpus))
	t.Logf("Files Scanned: %d (Go: %d, Python: %d)", summary.FilesScanned, summary.GoFiles, summary.PythonFiles)
	t.Logf("True Positives:  %d", tp)
	t.Logf("True Negatives:  %d", tn)
	t.Logf("False Positives: %d", fp)
	t.Logf("False Negatives: %d", fn)
	t.Logf("Precision:       %.2f%%", precision*100)
	t.Logf("Recall:          %.2f%%", recall*100)
	t.Logf("F1 Score:        %.4f", f1)
	t.Logf("FP Rate:         %.2f%%", fpRate*100)
	t.Logf("FN Rate:         %.2f%%", fnRate*100)

	if precision < 1.0 {
		t.Errorf("expected 100%% precision on reference fixtures, got %.2f", precision)
	}
	if recall < 1.0 {
		t.Errorf("expected 100%% recall on reference fixtures, got %.2f", recall)
	}
}
