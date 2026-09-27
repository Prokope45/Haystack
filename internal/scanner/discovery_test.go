package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file structure:
	// tmpDir/
	//   main.go
	//   app.py
	//   notes.txt (ignored)
	//   empty.go (empty, ignored)
	//   vendor/
	//     vendored.go (ignored)
	//   pkg/
	//     util.go
	//     sub/
	//       helper.py
	//   custom_exclude/
	//     excluded.py

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "app.py"), []byte("print('hello')"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "notes.txt"), []byte("not code"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "empty.go"), []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	vendorDir := filepath.Join(tmpDir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "vendored.go"), []byte("package vendor"), 0644); err != nil {
		t.Fatal(err)
	}

	pkgSubDir := filepath.Join(tmpDir, "pkg", "sub")
	if err := os.MkdirAll(pkgSubDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "pkg", "util.go"), []byte("package pkg"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgSubDir, "helper.py"), []byte("def help(): pass"), 0644); err != nil {
		t.Fatal(err)
	}

	customDir := filepath.Join(tmpDir, "custom_exclude")
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(customDir, "excluded.py"), []byte("pass"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := DiscoveryOptions{
		ExcludeDirs: []string{"custom_exclude"},
	}

	files, err := DiscoverFiles(tmpDir, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedRelPaths := map[string]Language{
		"main.go":           LangGo,
		"app.py":            LangPython,
		"pkg/util.go":       LangGo,
		"pkg/sub/helper.py": LangPython,
	}

	if len(files) != len(expectedRelPaths) {
		t.Fatalf("expected %d files, got %d: %+v", len(expectedRelPaths), len(files), files)
	}

	for _, f := range files {
		expectedLang, ok := expectedRelPaths[filepath.ToSlash(f.RelPath)]
		if !ok {
			t.Errorf("unexpected file discovered: %s", f.RelPath)
			continue
		}
		if f.Language != expectedLang {
			t.Errorf("file %s expected lang %s, got %s", f.RelPath, expectedLang, f.Language)
		}
	}
}
