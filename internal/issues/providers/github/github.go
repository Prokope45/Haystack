package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"haystack/internal/issues"
)

// Config holds GitHub provider client settings.
type Config struct {
	Token       string
	BaseURL     string // defaults to "https://api.github.com"
	DefaultRepo string // "owner/repo"
	HTTPClient  *http.Client
}

// GitHubProvider interacts with GitHub Issues via the REST API.
type GitHubProvider struct {
	cfg Config
}

// NewGitHubProvider creates a GitHubProvider.
func NewGitHubProvider(cfg Config) *GitHubProvider {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("GITHUB_TOKEN")
		if cfg.Token == "" {
			cfg.Token = os.Getenv("GH_TOKEN")
		}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &GitHubProvider{cfg: cfg}
}

func (g *GitHubProvider) Name() string {
	return "github"
}

type ghIssuePayload struct {
	Title  string   `json:"title,omitempty"`
	Body   string   `json:"body,omitempty"`
	State  string   `json:"state,omitempty"`
	Labels []string `json:"labels,omitempty"`
}

type ghIssueResponse struct {
	ID        int64     `json:"id"`
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	HTMLURL   string    `json:"html_url"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Labels    []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

type ghSearchResponse struct {
	TotalCount int               `json:"total_count"`
	Items      []ghIssueResponse `json:"items"`
}

// FindIssueByFingerprint queries GitHub for an existing open issue containing the fingerprint.
func (g *GitHubProvider) FindIssueByFingerprint(ctx context.Context, repo string, fingerprint string) (*issues.Issue, error) {
	if repo == "" {
		repo = g.cfg.DefaultRepo
	}
	if repo == "" || fingerprint == "" {
		return nil, nil
	}

	// 1. First attempt: Search API for repo + fingerprint
	searchQuery := fmt.Sprintf("repo:%s is:issue is:open %s", repo, fingerprint)
	searchURL := fmt.Sprintf("%s/search/issues?q=%s", g.cfg.BaseURL, url.QueryEscape(searchQuery))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	g.setHeaders(req)

	resp, err := g.cfg.HTTPClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		var searchRes ghSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchRes); err == nil {
			for _, item := range searchRes.Items {
				fp := issues.ExtractFingerprint(item.Body)
				if fp == fingerprint {
					return g.toIssue(item, false), nil
				}
			}
		}
	} else if resp != nil {
		_ = resp.Body.Close()
	}

	// 2. Fallback: List recent open issues and scan bodies
	listURL := fmt.Sprintf("%s/repos/%s/issues?state=open&per_page=50", g.cfg.BaseURL, repo)
	listReq, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	g.setHeaders(listReq)

	listResp, err := g.cfg.HTTPClient.Do(listReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = listResp.Body.Close() }()

	if listResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status %d listing issues", listResp.StatusCode)
	}

	var listItems []ghIssueResponse
	if err := json.NewDecoder(listResp.Body).Decode(&listItems); err != nil {
		return nil, err
	}

	for _, item := range listItems {
		fp := issues.ExtractFingerprint(item.Body)
		if fp == fingerprint {
			return g.toIssue(item, false), nil
		}
	}

	return nil, nil
}

// CreateIssue creates a new issue or returns an existing one if the fingerprint matches.
func (g *GitHubProvider) CreateIssue(ctx context.Context, req issues.IssueRequest) (*issues.Issue, error) {
	repo := req.Repository
	if repo == "" {
		repo = g.cfg.DefaultRepo
	}
	if repo == "" {
		return nil, fmt.Errorf("github repository ('owner/repo') is required to create an issue")
	}

	// Deduplication check per DESIGN_PLAN.md Section 40
	if req.Fingerprint != "" {
		existing, err := g.FindIssueByFingerprint(ctx, repo, req.Fingerprint)
		if err == nil && existing != nil {
			dup := *existing
			dup.IsDuplicate = true
			return &dup, nil
		}
	}

	payload := ghIssuePayload{
		Title:  req.Title,
		Body:   req.Body,
		Labels: req.Labels,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/repos/%s/issues", g.cfg.BaseURL, repo)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	g.setHeaders(httpReq)

	resp, err := g.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("github api call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create issue: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ghResp ghIssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return g.toIssue(ghResp, false), nil
}

// UpdateIssue updates an existing issue.
func (g *GitHubProvider) UpdateIssue(ctx context.Context, repo string, id issues.IssueID, update issues.IssueUpdate) error {
	if repo == "" {
		repo = g.cfg.DefaultRepo
	}
	issueNum, err := strconv.Atoi(string(id))
	if err != nil {
		return fmt.Errorf("invalid issue id %q: must be issue number", id)
	}

	payload := ghIssuePayload{
		Title:  update.Title,
		Body:   update.Body,
		State:  update.State,
		Labels: update.Labels,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/repos/%s/issues/%d", g.cfg.BaseURL, repo, issueNum)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, apiURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	g.setHeaders(httpReq)

	resp, err := g.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update issue: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CloseIssue marks an issue as closed.
func (g *GitHubProvider) CloseIssue(ctx context.Context, repo string, id issues.IssueID, reason string) error {
	return g.UpdateIssue(ctx, repo, id, issues.IssueUpdate{
		State: "closed",
	})
}

func (g *GitHubProvider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	}
}

func (g *GitHubProvider) toIssue(resp ghIssueResponse, isDup bool) *issues.Issue {
	var labels []string
	for _, l := range resp.Labels {
		labels = append(labels, l.Name)
	}

	return &issues.Issue{
		ID:          issues.IssueID(strconv.Itoa(resp.Number)),
		Number:      resp.Number,
		Title:       resp.Title,
		Body:        resp.Body,
		URL:         resp.HTMLURL,
		State:       resp.State,
		Labels:      labels,
		Fingerprint: issues.ExtractFingerprint(resp.Body),
		CreatedAt:   resp.CreatedAt,
		UpdatedAt:   resp.UpdatedAt,
		IsDuplicate: isDup,
	}
}
