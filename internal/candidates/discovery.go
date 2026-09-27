package candidates

import (
	"fmt"
	"path/filepath"
	"strings"

	"haystack/internal/analyzer"
	"haystack/internal/index"
)

// DiscoverCandidates scans a ProgramIndex and generates lightweight AnalysisCandidates.
func DiscoverCandidates(idx *index.ProgramIndex) []AnalysisCandidate {
	if idx == nil {
		return nil
	}

	var candidates []AnalysisCandidate

	for _, file := range idx.Files {
		filePath := file.RelPath
		if filePath == "" {
			filePath = file.Path
		}

		functions := idx.FindFunctionsInFile(filePath)
		if len(functions) == 0 {
			// If no functions were explicitly declared, treat the file as a single global scope
			functions = []index.FunctionInfo{
				{
					File: filePath,
					Name: "global",
				},
			}
		}

		for _, fn := range functions {
			sinks := idx.FindSinksInFunction(filePath, fn.Name)
			sources := idx.FindSourcesInFunction(filePath, fn.Name)

			// 1. Process Sinks
			for _, s := range sinks {
				vulnClass := mapSinkToVulnClass(s.Sink.Type)
				var sourceRefs []SourceRef
				for _, src := range sources {
					sourceRefs = append(sourceRefs, SourceRef{
						Type:   src.Source.Type,
						Name:   src.Source.Name,
						Line:   src.Source.Line,
						Column: src.Source.Column,
						Detail: src.Source.Detail,
					})
				}

				// If no direct sources were discovered in the function, check parameters
				if len(sourceRefs) == 0 && len(fn.Parameters) > 0 {
					for _, param := range fn.Parameters {
						sourceRefs = append(sourceRefs, SourceRef{
							Type:   analyzer.SourceFuncParam,
							Name:   param,
							Line:   fn.StartLine,
							Column: 1,
							Detail: fmt.Sprintf("Function parameter %q in %s", param, fn.Name),
						})
					}
				}

				candID := fmt.Sprintf("cand-%s-%s-%d", sanitizeID(filepath.Base(filePath)), fn.Name, s.Sink.Line)
				cost := estimateCost(sourceRefs, s.Sink)

				candidates = append(candidates, AnalysisCandidate{
					ID:                   candID,
					Language:             file.Language,
					File:                 filePath,
					Function:             fn.Name,
					VulnerabilityClasses: []string{vulnClass},
					Sources:              sourceRefs,
					Sinks: []SinkRef{
						{
							Type:   s.Sink.Type,
							Name:   s.Sink.Name,
							Line:   s.Sink.Line,
							Column: s.Sink.Column,
							Detail: s.Sink.Detail,
						},
					},
					EstimatedCost: cost,
					Metadata: map[string]any{
						"is_handler": fn.IsHandler,
					},
				})
			}

			// 2. Process Hardcoded Secrets
			for _, src := range sources {
				if src.Source.Type == analyzer.SourceHardcoded {
					candID := fmt.Sprintf("cand-sec-%s-%s-%d", sanitizeID(filepath.Base(filePath)), fn.Name, src.Source.Line)
					candidates = append(candidates, AnalysisCandidate{
						ID:                   candID,
						Language:             file.Language,
						File:                 filePath,
						Function:             fn.Name,
						VulnerabilityClasses: []string{"hardcoded_secret"},
						Sources: []SourceRef{
							{
								Type:   src.Source.Type,
								Name:   src.Source.Name,
								Line:   src.Source.Line,
								Column: src.Source.Column,
								Detail: src.Source.Detail,
							},
						},
						Sinks: nil,
						EstimatedCost: AnalysisCost{
							EstimatedDepth: 1,
							Complexity:     1,
							FilesCrossed:   1,
						},
					})
				}
			}
		}
	}

	return candidates
}

func mapSinkToVulnClass(sinkType analyzer.SinkType) string {
	switch sinkType {
	case analyzer.SinkShell:
		return "command_injection"
	case analyzer.SinkSQL:
		return "sql_injection"
	case analyzer.SinkFilesystem:
		return "path_traversal"
	case analyzer.SinkDeserialization:
		return "insecure_deserialization"
	default:
		return "general_vulnerability"
	}
}

func estimateCost(sources []SourceRef, sink analyzer.Sink) AnalysisCost {
	baseDepth := 4
	complexity := 5

	switch sink.Type {
	case analyzer.SinkShell, analyzer.SinkSQL:
		complexity += 2
	case analyzer.SinkDeserialization:
		complexity += 3
	}

	if len(sources) > 0 {
		minDist := 1000
		for _, src := range sources {
			dist := sink.Line - src.Line
			if dist < 0 {
				dist = -dist
			}
			if dist < minDist {
				minDist = dist
			}
		}

		if minDist <= 5 {
			baseDepth = 2
			complexity -= 2
		} else if minDist <= 15 {
			baseDepth = 3
			complexity -= 1
		} else {
			baseDepth = 5
		}
	} else {
		// When no sources are present in the function, higher interprocedural depth and complexity are estimated
		baseDepth = 5
		complexity += 1
	}

	if complexity < 1 {
		complexity = 1
	} else if complexity > 10 {
		complexity = 10
	}

	return AnalysisCost{
		EstimatedDepth: baseDepth,
		Complexity:     complexity,
		FilesCrossed:   1,
	}
}

func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}
