package issues

import "time"

// IssueID identifies an issue within a provider system.
type IssueID string

// IssueRequest specifies parameters for creating a security issue.
type IssueRequest struct {
	Title       string   `json:"title"`
	Body        string   `json:"body"`
	Labels      []string `json:"labels,omitempty"`
	FindingID   string   `json:"finding_id"`
	Fingerprint string   `json:"fingerprint"`
	Repository  string   `json:"repository,omitempty"` // e.g. "owner/repo"
}

// IssueUpdate specifies modifications to an existing issue.
type IssueUpdate struct {
	Title   string   `json:"title,omitempty"`
	Body    string   `json:"body,omitempty"`
	State   string   `json:"state,omitempty"` // "open" or "closed"
	Comment string   `json:"comment,omitempty"`
	Labels  []string `json:"labels,omitempty"`
}

// Issue represents a tracked security issue.
type Issue struct {
	ID          IssueID   `json:"id"`
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	URL         string    `json:"url"`
	State       string    `json:"state"` // "open", "closed"
	Labels      []string  `json:"labels"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsDuplicate bool      `json:"is_duplicate"`
}
