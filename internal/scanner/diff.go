package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"haystack/internal/findings"
)

// LineRange represents an inclusive range of line numbers.
type LineRange struct {
	Start int
	End   int
}

// Contains checks if the line falls within the range.
func (lr LineRange) Contains(line int) bool {
	return line >= lr.Start && line <= lr.End
}

// DiffMap maps normalized file paths to their added/modified line ranges.
type DiffMap map[string][]LineRange

// ContainsLine checks if a given file and line number was modified in the diff.
func (dm DiffMap) ContainsLine(filePath string, line int) bool {
	norm := filepath.ToSlash(filePath)
	norm = strings.TrimPrefix(norm, "./")

	ranges, ok := dm[norm]
	if !ok {
		// Also check with relative suffix match
		for k, rList := range dm {
			if strings.HasSuffix(norm, k) || strings.HasSuffix(k, norm) {
				for _, r := range rList {
					if r.Contains(line) {
						return true
					}
				}
			}
		}
		return false
	}

	for _, r := range ranges {
		if r.Contains(line) {
			return true
		}
	}
	return false
}

var hunkRegex = regexp.MustCompile(`^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+([0-9]+)(?:,([0-9]+))?\s+@@`)

// ParseUnifiedDiff parses unified diff text into a DiffMap.
func ParseUnifiedDiff(diffContent string) (DiffMap, error) {
	dm := make(DiffMap)
	scanner := bufio.NewScanner(strings.NewReader(diffContent))

	currentFile := ""

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			currentFile = filepath.ToSlash(currentFile)
			currentFile = strings.TrimPrefix(currentFile, "./")
			continue
		} else if strings.HasPrefix(line, "+++ /dev/null") {
			currentFile = ""
			continue
		}

		if currentFile == "" {
			continue
		}

		if strings.HasPrefix(line, "@@") {
			matches := hunkRegex.FindStringSubmatch(line)
			if len(matches) >= 2 {
				startLine, err := strconv.Atoi(matches[1])
				if err != nil {
					continue
				}
				lineCount := 1
				if len(matches) >= 3 && matches[2] != "" {
					c, err := strconv.Atoi(matches[2])
					if err == nil {
						lineCount = c
					}
				}

				if lineCount > 0 {
					lr := LineRange{
						Start: startLine,
						End:   startLine + lineCount - 1,
					}
					dm[currentFile] = append(dm[currentFile], lr)
				}
			}
		}
	}

	return dm, scanner.Err()
}

// RunGitDiff executes git diff in the specified directory and returns the output.
func RunGitDiff(workDir string, diffRange string, base string, head string) (string, error) {
	var args []string
	args = append(args, "diff")

	if diffRange != "" {
		args = append(args, diffRange)
	} else if base != "" && head != "" {
		args = append(args, fmt.Sprintf("%s...%s", base, head))
	} else if base != "" {
		args = append(args, base)
	}

	cmd := exec.Command("git", args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git diff failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	return string(out), nil
}

// FilterFindingsByDiff retains only findings that touch modified lines in the diff.
func FilterFindingsByDiff(allFindings []findings.Finding, diffMap DiffMap) []findings.Finding {
	if len(diffMap) == 0 {
		return allFindings
	}

	var filtered []findings.Finding
	for _, f := range allFindings {
		// Check primary finding line
		if diffMap.ContainsLine(f.File, f.Line) {
			filtered = append(filtered, f)
			continue
		}
		// Check sink line
		if f.Evidence.Sink.Line > 0 && diffMap.ContainsLine(f.File, f.Evidence.Sink.Line) {
			filtered = append(filtered, f)
			continue
		}
		// Check source line
		if f.Evidence.Source.Line > 0 && diffMap.ContainsLine(f.File, f.Evidence.Source.Line) {
			filtered = append(filtered, f)
			continue
		}
	}

	return filtered
}
