package scanner

// ScanRequest specifies parameters for a scan operation.
type ScanRequest struct {
	Paths         []string `json:"paths,omitempty"`
	GitBase       string   `json:"git_base,omitempty"`
	GitHead       string   `json:"git_head,omitempty"`
	DiffRange     string   `json:"diff_range,omitempty"`
	Languages     []string `json:"languages,omitempty"`
	MinSeverity   string   `json:"min_severity,omitempty"`
	MinConfidence float64  `json:"min_confidence,omitempty"`
	Strategy      string   `json:"strategy,omitempty"`   // "adaptive" or "full"
	AIPlanner     bool     `json:"ai_planner,omitempty"` // enable external AI planner
	NoCache       bool     `json:"-"`                    // bypass all cache reads and writes
}

// ScanCodeRequest describes a scan of in-memory code or one file's contents.
type ScanCodeRequest struct {
	Code          []byte
	Language      string
	Filename      string
	MinSeverity   string
	MinConfidence float64
	NoCache       bool
}
