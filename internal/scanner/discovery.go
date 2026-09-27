package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Language represents a supported programming language.
type Language string

const (
	LangGo     Language = "go"
	LangPython Language = "python"
)

// DiscoveredFile contains metadata about a source file found during scanning.
type DiscoveredFile struct {
	Path     string   `json:"path"`
	RelPath  string   `json:"rel_path"`
	Language Language `json:"language"`
	Size     int64    `json:"size"`
}

// DiscoveryOptions configures the file discovery process.
type DiscoveryOptions struct {
	ExcludeDirs []string
}

// DefaultExcludedDirs lists default directory names to skip during recursive scan.
var DefaultExcludedDirs = map[string]bool{
	".git":         true,
	".github":      true,
	".opencode":    true,
	".devcontainer": true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	".pytest_cache": true,
	".mypy_cache":  true,
	".tox":         true,
	"build":        true,
	"dist":         true,
}

// DiscoverFiles walks the root directory and returns all supported Go and Python files.
func DiscoverFiles(rootDir string, opts DiscoveryOptions) ([]DiscoveredFile, error) {
	var files []DiscoveredFile

	excludedMap := make(map[string]bool)
	for k, v := range DefaultExcludedDirs {
		excludedMap[k] = v
	}
	for _, excl := range opts.ExcludeDirs {
		clean := strings.TrimSpace(excl)
		if clean != "" {
			excludedMap[filepath.Clean(clean)] = true
		}
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	stat, err := os.Stat(absRoot)
	if err != nil {
		return nil, err
	}

	// Support scanning a single file directly
	if !stat.IsDir() {
		ext := strings.ToLower(filepath.Ext(absRoot))
		var lang Language
		switch ext {
		case ".go":
			lang = LangGo
		case ".py":
			lang = LangPython
		default:
			return nil, fmt.Errorf("unsupported file extension %q: must be .go or .py", ext)
		}
		if stat.Size() == 0 {
			return nil, nil
		}
		return []DiscoveredFile{
			{
				Path:     absRoot,
				RelPath:  filepath.Base(absRoot),
				Language: lang,
				Size:     stat.Size(),
			},
		}, nil
	}

	err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		name := d.Name()

		if d.IsDir() {
			// Skip root dir itself
			if path == absRoot {
				return nil
			}
			// Check if excluded by base name or relative path
			rel, _ := filepath.Rel(absRoot, path)
			if excludedMap[name] || excludedMap[rel] || excludedMap[filepath.Base(rel)] {
				return filepath.SkipDir
			}
			// Skip hidden directories (starting with .)
			if strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks pointing outside or irregular files
		if !d.Type().IsRegular() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(name))
		var lang Language

		switch ext {
		case ".go":
			lang = LangGo
		case ".py":
			lang = LangPython
		default:
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Skip empty files
		if info.Size() == 0 {
			return nil
		}

		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			relPath = path
		}

		files = append(files, DiscoveredFile{
			Path:     path,
			RelPath:  relPath,
			Language: lang,
			Size:     info.Size(),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
