package scanner

import (
	"context"
	"fmt"

	"haystack/internal/analyzer"
	"haystack/internal/findings"
	"haystack/internal/planning"
)

type analysisCounts struct {
	analyzed int
	skipped  int
	shallow  int
	medium   int
	deep     int
}

func (o *Orchestrator) directivesFor(plan planning.AnalysisPlan, strategy string) (map[string]analyzer.AnalysisDirectives, map[string]*findings.AnalysisMetadata, analysisCounts) {
	directives := make(map[string]analyzer.AnalysisDirectives, len(plan.Candidates))
	metadata := make(map[string]*findings.AnalysisMetadata, len(plan.Candidates))
	var counts analysisCounts

	for _, candidatePlan := range plan.Candidates {
		directives[candidatePlan.CandidateID] = analyzer.AnalysisDirectives{
			Analyze:                 candidatePlan.Analyze,
			Mode:                    string(candidatePlan.Mode),
			MaxDepth:                candidatePlan.Depth,
			MaxInterproceduralDepth: o.cfg.MaxInterproceduralDepth,
			CandidateID:             candidatePlan.CandidateID,
		}
		metadata[candidatePlan.CandidateID] = &findings.AnalysisMetadata{
			Strategy:        strategy,
			Priority:        candidatePlan.Priority,
			Depth:           candidatePlan.Depth,
			Interprocedural: candidatePlan.Interprocedural,
			PlannerProvider: candidatePlan.PlannerProvider,
			PlannerModel:    candidatePlan.PlannerModel,
		}

		if !candidatePlan.Analyze {
			counts.skipped++
			continue
		}
		counts.analyzed++
		switch candidatePlan.Mode {
		case planning.AnalysisDeep:
			counts.deep++
		case planning.AnalysisMedium:
			counts.medium++
		case planning.AnalysisShallow:
			counts.shallow++
		}
	}

	return directives, metadata, counts
}

func (o *Orchestrator) analyzeFiles(ctx context.Context, files []DiscoveredFile, contents map[string][]byte, directives map[string]analyzer.AnalysisDirectives) ([]analyzer.Evidence, error) {
	for _, currentAnalyzer := range o.analyzers {
		if adaptive, ok := currentAnalyzer.(analyzer.AdaptiveAnalyzer); ok {
			adaptive.SetDirectives(directives)
		}
	}

	var evidence []analyzer.Evidence
	for _, file := range files {
		for _, currentAnalyzer := range o.analyzers {
			if !currentAnalyzer.Supports(file.Path) {
				continue
			}
			results, err := currentAnalyzer.Analyze(ctx, contents[file.Path], file.RelPath)
			if err != nil {
				return nil, fmt.Errorf("parser error in %s: %w", file.RelPath, err)
			}
			evidence = append(evidence, results...)
		}
	}
	return evidence, nil
}
