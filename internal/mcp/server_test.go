package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef"

func TestAuthenticationAndOriginProtection(t *testing.T) {
	t.Parallel()
	service := New(testStore(t), testToken, "https://errors.example")
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", response.Code)
	}

	request = authorizedRequest(body)
	request.Header.Set("Origin", "https://attacker.example")
	response = httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status = %d", response.Code)
	}

	request = authorizedRequest(body)
	request.Header.Set("Origin", "https://errors.example")
	response = httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid request status = %d", response.Code)
	}
}

func TestInitializeAndListTools(t *testing.T) {
	t.Parallel()
	service := New(testStore(t), testToken, "https://errors.example")

	initialize := call(t, service, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	result := initialize["result"].(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocol version = %v", result["protocolVersion"])
	}

	listed := call(t, service, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	toolsResult := listed["result"].(map[string]any)
	available := toolsResult["tools"].([]any)
	if len(available) != 9 {
		t.Fatalf("tool count = %d, want 9", len(available))
	}
}

func TestIssueAndEventTools(t *testing.T) {
	t.Parallel()
	st := testStore(t)
	seedMCPData(t, st)
	service := New(st, testToken, "https://errors.example")

	listed := call(t, service, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{"project_id":"project","status":"unresolved"}}}`)
	result := listed["result"].(map[string]any)
	if result["isError"] != false {
		t.Fatalf("list_issues returned error: %v", result)
	}
	issues := result["structuredContent"].([]any)
	if len(issues) != 1 || issues[0].(map[string]any)["title"] != "Database unavailable" {
		t.Fatalf("unexpected issues: %#v", issues)
	}

	updated := call(t, service, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"update_issue_status","arguments":{"issue_id":"issue","status":"resolved"}}}`)
	if updated["result"].(map[string]any)["isError"] != false {
		t.Fatalf("update_issue_status returned error: %v", updated)
	}
	var status string
	if err := st.DB.QueryRow(`SELECT status FROM issues WHERE id = 'issue'`).Scan(&status); err != nil || status != "resolved" {
		t.Fatalf("stored status = %q, err = %v", status, err)
	}

	event := call(t, service, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_event","arguments":{"project_id":"project","event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`)
	eventResult := event["result"].(map[string]any)["structuredContent"].(map[string]any)
	payload := eventResult["payload"].(map[string]any)
	if payload["message"] != "database unavailable" {
		t.Fatalf("event payload = %#v", payload)
	}
}

func TestToolErrorsUseMCPResult(t *testing.T) {
	t.Parallel()
	service := New(testStore(t), testToken, "https://errors.example")
	response := call(t, service, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_issue","arguments":{}}}`)
	result := response["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("tool error result = %#v", result)
	}
}

func authorizedRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func call(t *testing.T, service *Service, body string) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	service.ServeHTTP(response, authorizedRequest(body))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedMCPData(t *testing.T, st *store.Store) {
	t.Helper()
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'default', 'Default');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, platform, public_key) VALUES ('project', '1', 'org', 'api', 'API', 'go', 'public-key');
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES ('release', 'org', 'api@1.0.0', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
		INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES ('project', 'release', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
		INSERT INTO issues(id, project_id, fingerprint, title, status, level, first_seen_at, last_seen_at, first_release_id, last_release_id) VALUES ('issue', 'project', 'fingerprint', 'Database unavailable', 'unresolved', 'error', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'release', 'release');
		INSERT INTO events(id, event_id, project_id, issue_id, release_id, environment, platform, level, timestamp, payload) VALUES ('event', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', 'release', 'production', 'go', 'error', '2026-01-01T00:00:00Z', '{"message":"database unavailable"}');
	`)
	if err != nil {
		t.Fatal(err)
	}
}
