package output

import (
	"encoding/json"
	"io"
	"strings"

	"haystack/internal/findings"
)

// SARIF 2.1.0 data structures
type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     sarifMessage           `json:"shortDescription"`
	FullDescription      sarifMessage           `json:"fullDescription"`
	DefaultConfiguration sarifRuleConfiguration `json:"defaultConfiguration"`
	Help                 sarifMessage           `json:"help"`
	HelpURI              string                 `json:"helpUri,omitempty"`
}

type sarifRuleConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// SARIFFormatter generates SARIF 2.1.0 output for CI/CD platforms.
type SARIFFormatter struct{}

func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

func (sf *SARIFFormatter) Format(w io.Writer, list []findings.Finding, summary ScanSummary) error {
	rulesMap := make(map[string]sarifRule)
	results := make([]sarifResult, 0, len(list))

	for _, f := range list {
		// Map severity to SARIF level
		sarifLevel := "warning"
		switch strings.ToLower(f.Severity) {
		case "critical", "high":
			sarifLevel = "error"
		case "medium":
			sarifLevel = "warning"
		case "low":
			sarifLevel = "note"
		}

		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = sarifRule{
				ID:   f.RuleID,
				Name: f.RuleName,
				ShortDescription: sarifMessage{
					Text: f.CWEName,
				},
				FullDescription: sarifMessage{
					Text: f.Description,
				},
				DefaultConfiguration: sarifRuleConfiguration{
					Level: sarifLevel,
				},
				Help: sarifMessage{
					Text: f.Remediation,
				},
				HelpURI: func() string {
					if len(f.References) > 0 {
						return f.References[0]
					}
					return ""
				}(),
			}
		}

		results = append(results, sarifResult{
			RuleID: f.RuleID,
			Level:  sarifLevel,
			Message: sarifMessage{
				Text: f.RuleName + ": " + f.Remediation,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
		})
	}

	rulesList := make([]sarifRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		rulesList = append(rulesList, r)
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "haystack",
						Version:        "0.1.0",
						InformationURI: "https://github.com/haystack-sec/haystack",
						Rules:          rulesList,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
