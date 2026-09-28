package analyzer

// Source describes the origin of untrusted or sensitive data.
type Source struct {
	Type   SourceType `json:"type"`
	Name   string     `json:"name"`
	Line   int        `json:"line"`
	Column int        `json:"column"`
	Detail string     `json:"detail,omitempty"`
}

// Sink describes a security-sensitive operation receiving data.
type Sink struct {
	Type   SinkType `json:"type"`
	Name   string   `json:"name"`
	Line   int      `json:"line"`
	Column int      `json:"column"`
	Detail string   `json:"detail,omitempty"`
}

// Operation represents an intermediate transformation or data propagation step.
type Operation struct {
	Type   string `json:"type"` // e.g. "assignment", "concatenation", "format_string", "argument_passing"
	Detail string `json:"detail"`
	Line   int    `json:"line,omitempty"`
}

// Evidence captures the deterministic static analysis proof of a security-relevant flow.
type Evidence struct {
	File        string      `json:"file"`
	Line        int         `json:"line"`
	Column      int         `json:"column"`
	Language    string      `json:"language"`
	CandidateID string      `json:"candidate_id,omitempty"`
	Mode        string      `json:"mode,omitempty"`
	Source      Source      `json:"source"`
	Sink        Sink        `json:"sink"`
	Operations  []Operation `json:"operations"`
	FlowSteps   []string    `json:"flow_steps"`
	Code        string      `json:"code"`
	Context     string      `json:"context,omitempty"`
}
