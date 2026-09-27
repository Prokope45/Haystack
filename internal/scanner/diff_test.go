package scanner

import (
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/findings"
)

func TestParseUnifiedDiff(t *testing.T) {
	diff := `diff --git a/internal/handlers.go b/internal/handlers.go
index 1234567..89abcdef 100644
--- a/internal/handlers.go
+++ b/internal/handlers.go
@@ -40,6 +40,9 @@ func safeFunc() {
+	cmd := r.URL.Query().Get("c")
+	exec.Command("sh", "-c", cmd)
+	return
 }
diff --git a/cmd/main.go b/cmd/main.go
index abcdef1..2345678 100644
--- a/cmd/main.go
+++ b/cmd/main.go
@@ -10,3 +10,4 @@ func main() {
+	fmt.Println("hello")
 }
`

	dm, err := ParseUnifiedDiff(diff)
	if err != nil {
		t.Fatalf("unexpected error parsing diff: %v", err)
	}

	if !dm.ContainsLine("internal/handlers.go", 41) {
		t.Errorf("expected line 41 to be included in internal/handlers.go")
	}
	if !dm.ContainsLine("internal/handlers.go", 48) {
		t.Errorf("expected line 48 to be included in internal/handlers.go (range 40-48)")
	}
	if dm.ContainsLine("internal/handlers.go", 39) {
		t.Errorf("line 39 should NOT be in diff")
	}
	if dm.ContainsLine("internal/handlers.go", 50) {
		t.Errorf("line 50 should NOT be in diff")
	}

	if !dm.ContainsLine("cmd/main.go", 10) {
		t.Errorf("expected line 10 in cmd/main.go")
	}
	if dm.ContainsLine("cmd/main.go", 15) {
		t.Errorf("line 15 should NOT be in cmd/main.go diff")
	}
}

func TestFilterFindingsByDiff(t *testing.T) {
	dm := DiffMap{
		"internal/handlers.go": []LineRange{
			{Start: 40, End: 45},
		},
	}

	allFindings := []findings.Finding{
		{
			ID:   "F1-IN-DIFF",
			File: "internal/handlers.go",
			Line: 42,
		},
		{
			ID:   "F2-OUT-OF-DIFF",
			File: "internal/handlers.go",
			Line: 12,
		},
		{
			ID:   "F3-OTHER-FILE",
			File: "pkg/utils.go",
			Line: 42,
		},
		{
			ID:   "F4-SINK-IN-DIFF",
			File: "internal/handlers.go",
			Line: 35,
			Evidence: analyzer.Evidence{
				Sink: analyzer.Sink{
					Line: 43,
				},
			},
		},
	}

	filtered := FilterFindingsByDiff(allFindings, dm)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 filtered findings, got %d", len(filtered))
	}

	ids := map[string]bool{filtered[0].ID: true, filtered[1].ID: true}
	if !ids["F1-IN-DIFF"] || !ids["F4-SINK-IN-DIFF"] {
		t.Errorf("unexpected findings kept: %v", filtered)
	}
}
