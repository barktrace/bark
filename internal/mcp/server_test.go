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
	if version := result["serverInfo"].(map[string]any)["version"]; version != "0.8.0" {
		t.Fatalf("server version = %v", version)
	}

	listed := call(t, service, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	toolsResult := listed["result"].(map[string]any)
	available := toolsResult["tools"].([]any)
	if len(available) != 44 {
		t.Fatalf("tool count = %d, want 44", len(available))
	}
}

func TestAdministrationToolsAreScopedAndAudited(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	plain := "bark_mcp_administration-write-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('creator', 'creator@example.com', 'Creator'), ('member', 'member@example.com', 'Member'), ('outsider', 'outsider@example.com', 'Outsider');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'creator', 'owner'), ('org', 'member', 'viewer');
		INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'member', 'member');
		INSERT INTO organizations(id, slug, name) VALUES ('other-org', 'other', 'Other');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('other-project', '2', 'other-org', 'other', 'Other', 'other-key');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('other-org', 'outsider', 'owner');
		INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes) VALUES ('mcp-admin', 'org', 'creator', 'Administration', ?, 'bark_mcp_admin', '["write"]');
		INSERT INTO ingestion_jobs(id, project_id, category, status, attempts, last_error) VALUES ('retry-job', 'project', 'event', 'dead', 5, 'failed'), ('delete-job', 'project', 'event', 'dead', 5, 'failed');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, "", "https://errors.example")

	membersCall := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_organization_members","arguments":{}}}`)
	members := membersCall["result"].(map[string]any)["structuredContent"].([]any)
	if len(members) != 2 {
		t.Fatalf("scoped members = %#v", members)
	}
	permissionsCall := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_project_permissions","arguments":{"project_id":"project"}}}`)
	permissions := permissionsCall["result"].(map[string]any)["structuredContent"].([]any)
	if len(permissions) != 2 {
		t.Fatalf("project permissions = %#v", permissions)
	}
	var memberPermission map[string]any
	for _, item := range permissions {
		permission := item.(map[string]any)
		if permission["user_id"] == "member" {
			memberPermission = permission
		}
	}
	if memberPermission == nil || memberPermission["organization_role"] != "viewer" || memberPermission["project_role"] != "member" || memberPermission["effective_role"] != "member" {
		t.Fatalf("member permission = %#v", memberPermission)
	}

	updated := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"update_issue","arguments":{"issue_id":"issue","status":"resolved","priority":"critical","assignee_user_id":"member","bookmarked":true,"snoozed_until":"2099-01-01T00:00:00Z"}}}`)
	if updated["result"].(map[string]any)["isError"] != false {
		t.Fatalf("update_issue failed: %#v", updated)
	}
	var status, priority, assignee string
	var bookmarked bool
	if err := st.DB.QueryRow(`SELECT status, priority, assignee_user_id, bookmarked FROM issues WHERE id = 'issue'`).Scan(&status, &priority, &assignee, &bookmarked); err != nil || status != "resolved" || priority != "critical" || assignee != "member" || !bookmarked {
		t.Fatalf("issue state status=%q priority=%q assignee=%q bookmarked=%v err=%v", status, priority, assignee, bookmarked, err)
	}
	var activities int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM issue_activities WHERE issue_id = 'issue'`).Scan(&activities); err != nil || activities != 5 {
		t.Fatalf("issue activities=%d err=%v", activities, err)
	}

	quota := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"set_project_quota","arguments":{"project_id":"project","category":"error","per_minute":60,"per_day":1000,"max_item_bytes":1048576}}}`)
	if quota["result"].(map[string]any)["isError"] != false {
		t.Fatalf("set_project_quota failed: %#v", quota)
	}
	retried := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"retry_ingestion_job","arguments":{"project_id":"project","job_id":"retry-job"}}}`)
	if retried["result"].(map[string]any)["isError"] != false {
		t.Fatalf("retry_ingestion_job failed: %#v", retried)
	}
	deleted := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_ingestion_job","arguments":{"project_id":"project","job_id":"delete-job"}}}`)
	if deleted["result"].(map[string]any)["isError"] != false {
		t.Fatalf("delete_ingestion_job failed: %#v", deleted)
	}
	retention := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"update_retention","arguments":{"days":90}}}`)
	if retention["result"].(map[string]any)["isError"] != false {
		t.Fatalf("update_retention failed: %#v", retention)
	}

	var quotaCount, deletedCount, retentionDays, audits int
	var retryStatus string
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM project_quotas WHERE project_id = 'project' AND category = 'error' AND per_minute = 60 AND per_day = 1000 AND max_item_bytes = 1048576`).Scan(&quotaCount)
	_ = st.DB.QueryRow(`SELECT status FROM ingestion_jobs WHERE id = 'retry-job'`).Scan(&retryStatus)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM ingestion_jobs WHERE id = 'delete-job'`).Scan(&deletedCount)
	_ = st.DB.QueryRow(`SELECT retention_days FROM organizations WHERE id = 'org'`).Scan(&retentionDays)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE organization_id = 'org' AND actor_type = 'mcp'`).Scan(&audits)
	if quotaCount != 1 || retryStatus != "pending" || deletedCount != 0 || retentionDays != 90 || audits != 5 {
		t.Fatalf("quota=%d retry=%q deleted=%d retention=%d audits=%d", quotaCount, retryStatus, deletedCount, retentionDays, audits)
	}
}

func TestAdministrationToolsRejectInvalidAndForeignMutations(t *testing.T) {
	st := testStore(t)
	seedMCPData(t, st)
	plain := "bark_mcp_administration-read-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('creator', 'creator@example.com', 'Creator');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'creator', 'owner');
		INSERT INTO organizations(id, slug, name) VALUES ('other-org', 'other', 'Other');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('other-project', '2', 'other-org', 'other', 'Other', 'other-key');
		INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes) VALUES ('mcp-read-admin', 'org', 'creator', 'Read', ?, 'bark_mcp_read', '["read"]');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, "", "https://errors.example")
	calls := []string{
		`{"name":"list_project_permissions","arguments":{"project_id":"other-project"}}`,
		`{"name":"update_issue","arguments":{"issue_id":"issue","priority":"critical"}}`,
		`{"name":"set_project_quota","arguments":{"project_id":"project","category":"error","per_minute":1,"per_day":0,"max_item_bytes":0}}`,
		`{"name":"update_retention","arguments":{"days":90}}`,
	}
	for index, params := range calls {
		response := callWithToken(t, service, plain, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		if response["result"].(map[string]any)["isError"] != true {
			t.Fatalf("call %d unexpectedly succeeded: %#v", index, response)
		}
	}

	legacy := New(st, testToken, "https://errors.example")
	invalidCalls := []string{
		`{"name":"set_project_quota","arguments":{"project_id":"project","category":"unknown","per_minute":1,"per_day":0,"max_item_bytes":0}}`,
		`{"name":"set_project_quota","arguments":{"project_id":"project","category":"error","per_minute":0,"per_day":0,"max_item_bytes":104857601}}`,
		`{"name":"update_retention","arguments":{"organization_id":"org","days":0}}`,
		`{"name":"retry_ingestion_job","arguments":{"project_id":"project","job_id":"missing"}}`,
	}
	for index, params := range invalidCalls {
		response := call(t, legacy, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`)
		if response["result"].(map[string]any)["isError"] != true {
			t.Fatalf("invalid call %d unexpectedly succeeded: %#v", index, response)
		}
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
