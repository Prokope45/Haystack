package mock

import (
	"context"
	"fmt"
	"sync"
	"time"

	"haystack/internal/issues"
)

// MockProvider is an in-memory IssueProvider for tests and offline workflows.
type MockProvider struct {
	mu           sync.Mutex
	issues       map[issues.IssueID]*issues.Issue
	fingerprints map[string]issues.IssueID // fingerprint -> IssueID
	nextNumber   int
}

// NewMockProvider creates a new MockProvider.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		issues:       make(map[issues.IssueID]*issues.Issue),
		fingerprints: make(map[string]issues.IssueID),
		nextNumber:   1,
	}
}

func (m *MockProvider) Name() string {
	return "mock"
}

func (m *MockProvider) FindIssueByFingerprint(ctx context.Context, repo string, fingerprint string) (*issues.Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id, exists := m.fingerprints[fingerprint]
	if !exists {
		return nil, nil
	}
	iss, ok := m.issues[id]
	if !ok || iss.State == "closed" {
		return nil, nil
	}
	return iss, nil
}

func (m *MockProvider) CreateIssue(ctx context.Context, req issues.IssueRequest) (*issues.Issue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check deduplication
	if req.Fingerprint != "" {
		if id, exists := m.fingerprints[req.Fingerprint]; exists {
			existing := m.issues[id]
			if existing != nil && existing.State == "open" {
				dup := *existing
				dup.IsDuplicate = true
				return &dup, nil
			}
		}
	}

	num := m.nextNumber
	m.nextNumber++

	id := issues.IssueID(fmt.Sprintf("mock-%d", num))
	url := fmt.Sprintf("https://mock.issues.local/repo/issues/%d", num)

	iss := &issues.Issue{
		ID:          id,
		Number:      num,
		Title:       req.Title,
		Body:        req.Body,
		URL:         url,
		State:       "open",
		Labels:      req.Labels,
		Fingerprint: req.Fingerprint,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsDuplicate: false,
	}

	m.issues[id] = iss
	if req.Fingerprint != "" {
		m.fingerprints[req.Fingerprint] = id
	}

	return iss, nil
}

func (m *MockProvider) UpdateIssue(ctx context.Context, repo string, id issues.IssueID, update issues.IssueUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iss, ok := m.issues[id]
	if !ok {
		return fmt.Errorf("issue %s not found", id)
	}

	if update.Title != "" {
		iss.Title = update.Title
	}
	if update.Body != "" {
		iss.Body = update.Body
	}
	if update.State != "" {
		iss.State = update.State
	}
	if len(update.Labels) > 0 {
		iss.Labels = update.Labels
	}
	iss.UpdatedAt = time.Now()
	return nil
}

func (m *MockProvider) CloseIssue(ctx context.Context, repo string, id issues.IssueID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	iss, ok := m.issues[id]
	if !ok {
		return fmt.Errorf("issue %s not found", id)
	}

	iss.State = "closed"
	iss.UpdatedAt = time.Now()
	return nil
}
