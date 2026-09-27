package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"haystack/internal/issues"
)

func TestGitHubProviderCreateAndDeduplicate(t *testing.T) {
	var createdCount int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", auth)
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/search/issues":
			// If searching for existing issue
			q := r.URL.Query().Get("q")
			if createdCount > 0 && q != "" {
				res := ghSearchResponse{
					TotalCount: 1,
					Items: []ghIssueResponse{
						{
							ID:      101,
							Number:  1,
							Title:   "Security: Vulnerability",
							Body:    "Body\nScanner-Fingerprint: fp-test-123\n",
							HTMLURL: "https://github.com/owner/repo/issues/1",
							State:   "open",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(res)
				return
			}
			_ = json.NewEncoder(w).Encode(ghSearchResponse{TotalCount: 0, Items: []ghIssueResponse{}})

		case r.Method == http.MethodPost && r.URL.Path == "/repos/owner/repo/issues":
			createdCount++
			var payload ghIssuePayload
			_ = json.NewDecoder(r.Body).Decode(&payload)

			res := ghIssueResponse{
				ID:      int64(100 + createdCount),
				Number:  createdCount,
				Title:   payload.Title,
				Body:    payload.Body,
				HTMLURL: "https://github.com/owner/repo/issues/1",
				State:   "open",
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(res)

		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	gh := NewGitHubProvider(Config{
		Token:       "test-token",
		BaseURL:     ts.URL,
		DefaultRepo: "owner/repo",
	})

	ctx := context.Background()

	req := issues.IssueRequest{
		Title:       "Security: Command Injection",
		Body:        "Details\nScanner-Fingerprint: fp-test-123\n",
		Fingerprint: "fp-test-123",
		Repository:  "owner/repo",
	}

	// 1. Create first time
	iss1, err := gh.CreateIssue(ctx, req)
	if err != nil {
		t.Fatalf("first CreateIssue failed: %v", err)
	}
	if iss1.IsDuplicate {
		t.Errorf("first issue should not be marked duplicate")
	}
	if iss1.Number != 1 {
		t.Errorf("expected number 1, got %d", iss1.Number)
	}

	// 2. Create second time with same fingerprint -> should deduplicate
	iss2, err := gh.CreateIssue(ctx, req)
	if err != nil {
		t.Fatalf("second CreateIssue failed: %v", err)
	}
	if !iss2.IsDuplicate {
		t.Errorf("second issue should be marked as duplicate")
	}
	if iss2.Number != 1 {
		t.Errorf("expected duplicate issue number 1, got %d", iss2.Number)
	}
	if createdCount != 1 {
		t.Errorf("expected exactly 1 POST issue call, got %d", createdCount)
	}
}
