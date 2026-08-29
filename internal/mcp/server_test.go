package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/ingest"
	"github.com/barktrace/bark/internal/store"
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
	if len(available) != 37 {
		t.Fatalf("tool count = %d, want 37", len(available))
	}
}

func TestDiscoverAndDashboardToolsAreOrganizationScoped(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	plain := "bark_mcp_discover-write-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('creator', 'creator@example.com', 'Creator');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'creator', 'owner');
		INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes) VALUES ('mcp-discover', 'org', 'creator', 'Discover', ?, 'bark_mcp_scope', '["write"]');
		INSERT INTO logs(id, project_id, timestamp, level, message) VALUES ('log', 'project', CURRENT_TIMESTAMP, 'error', 'database unavailable');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, "", "https://errors.example")

	queried := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_discover","arguments":{"dataset":"logs","fields":["message","severity"],"stats_period":"24h"}}}`)
	queryResult := queried["result"].(map[string]any)
	if queryResult["isError"] != false {
		t.Fatalf("query_discover failed: %#v", queried)
	}
	data := queryResult["structuredContent"].(map[string]any)["data"].([]any)
	if len(data) != 1 || data[0].(map[string]any)["message"] != "database unavailable" {
		t.Fatalf("unexpected discover data: %#v", data)
	}

	created := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_dashboard","arguments":{"project_id":"project","title":"Operations"}}}`)
	createdResult := created["result"].(map[string]any)
	if createdResult["isError"] != false {
		t.Fatalf("create_dashboard failed: %#v", created)
	}
	dashboardID := createdResult["structuredContent"].(map[string]any)["id"].(string)
	added := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add_dashboard_widget","arguments":{"dashboard_id":"`+dashboardID+`","title":"Errors","dataset":"errors","display_type":"number","fields":["count()"],"stats_period":"90d","limit":1}}}`)
	if added["result"].(map[string]any)["isError"] != false {
		t.Fatalf("add_dashboard_widget failed: %#v", added)
	}
	listed := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_dashboards","arguments":{}}}`)
	if dashboards := listed["result"].(map[string]any)["structuredContent"].([]any); len(dashboards) != 1 {
		t.Fatalf("unexpected dashboards: %#v", dashboards)
	}
	var audits int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE organization_id = 'org' AND actor_type = 'mcp'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit count=%d err=%v", audits, err)
	}
}

func TestOrganizationTokenIsScopedAndReadOnly(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	plain := "bark_mcp_scoped-read-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('other-org', 'other', 'Other');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('other-project', '2', 'other-org', 'other', 'Other', 'other-key');
		INSERT INTO users(id, email, name) VALUES ('creator', 'creator@example.com', 'Creator');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'creator', 'owner');
		INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes) VALUES ('mcp-read', 'org', 'creator', 'Read', ?, 'bark_mcp_scope', '["read"]');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, "", "https://errors.example")

	listed := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_projects","arguments":{}}}`)
	projects := listed["result"].(map[string]any)["structuredContent"].([]any)
	if len(projects) != 1 || projects[0].(map[string]any)["id"] != "project" {
		t.Fatalf("scoped projects = %#v", projects)
	}

	foreign := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_project_summary","arguments":{"project_id":"other-project"}}}`)
	if foreign["result"].(map[string]any)["isError"] != true {
		t.Fatalf("foreign project was accessible: %#v", foreign)
	}

	updated := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"update_issue_status","arguments":{"issue_id":"issue","status":"resolved"}}}`)
	if updated["result"].(map[string]any)["isError"] != true {
		t.Fatalf("read-only token changed issue: %#v", updated)
	}
}

func TestOrganizationWriteTokenAuditsMutation(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	plain := "bark_mcp_scoped-write-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('creator', 'creator@example.com', 'Creator');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'creator', 'owner');
		INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes) VALUES ('mcp-write', 'org', 'creator', 'Write', ?, 'bark_mcp_scope', '["write"]');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, "", "https://errors.example")
	updated := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"update_issue_status","arguments":{"issue_id":"issue","status":"resolved"}}}`)
	if updated["result"].(map[string]any)["isError"] != false {
		t.Fatalf("write token mutation failed: %#v", updated)
	}
	var actorType, action, actorID string
	if err := st.DB.QueryRow(`SELECT actor_type, action, actor_user_id FROM audit_logs`).Scan(&actorType, &action, &actorID); err != nil {
		t.Fatal(err)
	}
	if actorType != "mcp" || action != "update_issue_status" || actorID != "creator" {
		t.Fatalf("audit actor=%q action=%q user=%q", actorType, action, actorID)
	}
}

func TestObservabilityToolsExecuteAgainstCurrentSchema(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	_, err := st.DB.Exec(`
		INSERT INTO uptime_monitors(id, project_id, name, url, next_check_at) VALUES ('uptime', 'project', 'API', 'https://example.com/health', '2026-01-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, testToken, "https://errors.example")
	calls := []string{
		`{"name":"list_transactions","arguments":{"project_id":"project"}}`,
		`{"name":"list_logs","arguments":{"project_id":"project"}}`,
		`{"name":"list_uptime_monitors","arguments":{"project_id":"project"}}`,
		`{"name":"list_uptime_checks","arguments":{"project_id":"project","monitor_id":"uptime"}}`,
		`{"name":"list_cron_monitors","arguments":{"project_id":"project"}}`,
		`{"name":"list_cron_checkins","arguments":{"project_id":"project"}}`,
		`{"name":"list_feedback","arguments":{"project_id":"project"}}`,
		`{"name":"list_replays","arguments":{"project_id":"project"}}`,
		`{"name":"list_profiles","arguments":{"project_id":"project"}}`,
		`{"name":"list_metrics","arguments":{"project_id":"project"}}`,
		`{"name":"list_alert_rules","arguments":{"project_id":"project"}}`,
		`{"name":"list_alert_deliveries","arguments":{"project_id":"project"}}`,
		`{"name":"list_artifacts","arguments":{"project_id":"project"}}`,
		`{"name":"list_attachments","arguments":{"project_id":"project"}}`,
		`{"name":"list_deploys","arguments":{"project_id":"project"}}`,
		`{"name":"list_commits","arguments":{"project_id":"project"}}`,
		`{"name":"list_suspect_commits","arguments":{"project_id":"project","issue_id":"issue"}}`,
		`{"name":"list_project_quotas","arguments":{"project_id":"project"}}`,
		`{"name":"list_ingestion_jobs","arguments":{"project_id":"project"}}`,
		`{"name":"list_audit_logs","arguments":{"project_id":"project"}}`,
		`{"name":"get_storage_summary","arguments":{}}`,
	}
	for index, params := range calls {
		response := call(t, service, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		if response["result"].(map[string]any)["isError"] != false {
			t.Fatalf("tool call %d failed: %#v", index, response)
		}
	}
}

func TestTelemetryAnalysisToolsUseStoredReplayAndProfilePayloads(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	ingestion := ingest.New(st, 20<<20, 1000)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "public-key"}
	replayEvent := []byte(`{"replay_id":"12121212121212121212121212121212","segment_id":3,"timestamp":"2026-08-29T10:00:01Z","urls":["https://example.com/checkout"]}`)
	if err := ingestion.StoreReplayEvent(context.Background(), project, replayEvent); err != nil {
		t.Fatal(err)
	}
	recording := []byte("{\"replay_id\":\"12121212121212121212121212121212\",\"segment_id\":3}\n[{\"type\":4,\"timestamp\":1787997600000,\"data\":{\"href\":\"https://example.com/checkout\"}},{\"type\":3,\"timestamp\":1787997600100,\"data\":{\"source\":2,\"type\":2}}]")
	if err := ingestion.StoreReplayRecording(context.Background(), project, "12121212121212121212121212121212", recording); err != nil {
		t.Fatal(err)
	}
	profile := []byte(`{"profile_id":"profile-one","platform":"go","duration_ns":200000000,"profile":{"frames":[{"function":"main"},{"function":"query"}],"stacks":[[0,1]],"samples":[{"stack_id":0,"thread_id":"1"},{"stack_id":0,"thread_id":"1"}]}}`)
	if err := ingestion.StoreProfile(context.Background(), project, profile); err != nil {
		t.Fatal(err)
	}
	var replayID, profileID string
	if err := st.DB.QueryRow(`SELECT id FROM replays WHERE replay_id = '12121212121212121212121212121212' AND segment_id = 3`).Scan(&replayID); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT id FROM profiles WHERE profile_id = 'profile-one'`).Scan(&profileID); err != nil {
		t.Fatal(err)
	}
	service := New(st, testToken, "https://errors.example")
	replay := call(t, service, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analyze_replay","arguments":{"project_id":"project","replay_id":"`+replayID+`"}}}`)
	replayResult := replay["result"].(map[string]any)
	if replayResult["isError"] != false {
		t.Fatalf("analyze_replay failed: %#v", replay)
	}
	replayContent := replayResult["structuredContent"].(map[string]any)
	replayAnalysis := replayContent["analysis"].(map[string]any)
	if replayAnalysis["duration_ms"] != float64(100) || len(replayAnalysis["timeline"].([]any)) != 2 {
		t.Fatalf("unexpected replay analysis: %#v", replayAnalysis)
	}
	profileResult := call(t, service, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_profile","arguments":{"project_id":"project","profile_id":"`+profileID+`"}}}`)["result"].(map[string]any)
	if profileResult["isError"] != false {
		t.Fatalf("analyze_profile failed: %#v", profileResult)
	}
	profileAnalysis := profileResult["structuredContent"].(map[string]any)["analysis"].(map[string]any)
	if profileAnalysis["sample_count"] != float64(2) || len(profileAnalysis["hotspots"].([]any)) != 2 {
		t.Fatalf("unexpected profile analysis: %#v", profileAnalysis)
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
	return callWithToken(t, service, testToken, body)
}

func callWithToken(t *testing.T, service *Service, token, body string) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	service.ServeHTTP(response, request)
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
