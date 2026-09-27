package index

import (
	"strings"

	"haystack/internal/analyzer"
)

// FileInfo holds metadata about a discovered and indexed source file.
type FileInfo struct {
	Path     string `json:"path"`
	RelPath  string `json:"rel_path"`
	Language string `json:"language"`
	Size     int64  `json:"size"`
}

// FunctionInfo records a declared function or method.
type FunctionInfo struct {
	File       string   `json:"file"`
	Name       string   `json:"name"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	Parameters []string `json:"parameters"`
	IsHandler  bool     `json:"is_handler"`
}

// CallInfo records an invocation of a function or method.
type CallInfo struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Caller   string `json:"caller"`
	Callee   string `json:"callee"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// ImportInfo records an imported package or module.
type ImportInfo struct {
	File string `json:"file"`
	Path string `json:"path"`
}

// SourceInfo tracks a potential untrusted data source occurrence in code.
type SourceInfo struct {
	File     string          `json:"file"`
	Function string          `json:"function"`
	Source   analyzer.Source `json:"source"`
}

// SinkInfo tracks a potential security-sensitive sink occurrence in code.
type SinkInfo struct {
	File     string        `json:"file"`
	Function string        `json:"function"`
	Sink     analyzer.Sink `json:"sink"`
}

// ReferenceInfo records an identifier reference.
type ReferenceInfo struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Name     string `json:"name"`
	Line     int    `json:"line"`
}

// ProgramIndex provides a lightweight structural index across indexed source files.
type ProgramIndex struct {
	Files      []FileInfo      `json:"files"`
	Functions  []FunctionInfo  `json:"functions"`
	Calls      []CallInfo      `json:"calls"`
	Imports    []ImportInfo    `json:"imports"`
	Sources    []SourceInfo    `json:"sources"`
	Sinks      []SinkInfo      `json:"sinks"`
	References []ReferenceInfo `json:"references"`
}

// NewProgramIndex initializes an empty ProgramIndex.
func NewProgramIndex() *ProgramIndex {
	return &ProgramIndex{
		Files:      make([]FileInfo, 0),
		Functions:  make([]FunctionInfo, 0),
		Calls:      make([]CallInfo, 0),
		Imports:    make([]ImportInfo, 0),
		Sources:    make([]SourceInfo, 0),
		Sinks:      make([]SinkInfo, 0),
		References: make([]ReferenceInfo, 0),
	}
}

// FindSourcesInFunction returns all sources identified in the specified function.
func (idx *ProgramIndex) FindSourcesInFunction(file, fn string) []SourceInfo {
	var res []SourceInfo
	for _, s := range idx.Sources {
		if s.File == file && (fn == "" || s.Function == fn) {
			res = append(res, s)
		}
	}
	return res
}

// FindSinksInFunction returns all sinks identified in the specified function.
func (idx *ProgramIndex) FindSinksInFunction(file, fn string) []SinkInfo {
	var res []SinkInfo
	for _, s := range idx.Sinks {
		if s.File == file && (fn == "" || s.Function == fn) {
			res = append(res, s)
		}
	}
	return res
}

// FindCallsTo returns all calls to a specific callee name.
func (idx *ProgramIndex) FindCallsTo(callee string) []CallInfo {
	var res []CallInfo
	for _, c := range idx.Calls {
		if c.Callee == callee || strings.HasSuffix(c.Callee, "."+callee) {
			res = append(res, c)
		}
	}
	return res
}

// FindCallsInFunction returns all calls originating from a specific function.
func (idx *ProgramIndex) FindCallsInFunction(file, fn string) []CallInfo {
	var res []CallInfo
	for _, c := range idx.Calls {
		if c.File == file && (fn == "" || c.Function == fn) {
			res = append(res, c)
		}
	}
	return res
}

// FindFunctionsInFile returns all functions declared in the specified file.
func (idx *ProgramIndex) FindFunctionsInFile(file string) []FunctionInfo {
	var res []FunctionInfo
	for _, f := range idx.Functions {
		if f.File == file {
			res = append(res, f)
		}
	}
	return res
}
