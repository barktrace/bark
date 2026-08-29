package auth

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestRequireAuditsSuccessfulMutations(t *testing.T) {
	st := openAuthStore(t)
	plain := "bark_audit-test-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix) VALUES ('token', 'user', 'org', 'Automation', ?, 'bark_aud');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{store: st}
	mux := http.NewServeMux()
	mux.Handle("PATCH /projects/{project_id}", service.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		w.WriteHeader(http.StatusInternalServerError)
	})))
	request := httptest.NewRequest(http.MethodPatch, "/projects/project", nil)
	request.Header.Set("Authorization", "Bearer "+plain)
	request.RemoteAddr = "192.0.2.10:1234"
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("response status = %d", response.Code)
	}
	var organizationID, projectID, actorID, action, address string
	if err := st.DB.QueryRow(`SELECT organization_id, project_id, actor_user_id, action, ip_address FROM audit_logs`).Scan(&organizationID, &projectID, &actorID, &action, &address); err != nil {
		t.Fatal(err)
	}
	if organizationID != "org" || projectID != "project" || actorID != "user" || action != "patch /projects/{project_id}" || address != "192.0.2.10" {
		t.Fatalf("unexpected audit row: org=%q project=%q actor=%q action=%q address=%q", organizationID, projectID, actorID, action, address)
	}
}

func TestRequireDoesNotAuditFailedMutations(t *testing.T) {
	st := openAuthStore(t)
	plain := "bark_failed-audit-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix) VALUES ('token', 'user', 'org', 'Automation', ?, 'bark_fai');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{store: st}
	handler := service.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	request := httptest.NewRequest(http.MethodPost, "/organizations", nil)
	request.Header.Set("Authorization", "Bearer "+plain)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var count int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed mutation audit rows = %d, want 0", count)
	}
}

func TestRequireResolvesDashboardAuditScope(t *testing.T) {
	st := openAuthStore(t)
	plain := "bark_dashboard-audit-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO dashboards(id, organization_id, project_id, created_by, title) VALUES ('dashboard', 'org', 'project', 'user', 'Operations');
		INSERT INTO dashboard_widgets(id, dashboard_id, title, dataset, fields) VALUES ('widget', 'dashboard', 'Errors', 'errors', '["count()"]');
		INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix) VALUES ('token', 'user', 'org', 'Automation', ?, 'bark_das');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{store: st}
	mux := http.NewServeMux()
	mux.Handle("DELETE /dashboards/{dashboard_id}/widgets/{widget_id}", service.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	request := httptest.NewRequest(http.MethodDelete, "/dashboards/dashboard/widgets/widget", nil)
	request.Header.Set("Authorization", "Bearer "+plain)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	var organizationID, projectID, targetType, targetID string
	if err := st.DB.QueryRow(`SELECT organization_id, project_id, target_type, target_id FROM audit_logs`).Scan(&organizationID, &projectID, &targetType, &targetID); err != nil {
		t.Fatal(err)
	}
	if organizationID != "org" || projectID != "project" || targetType != "dashboard_widget" || targetID != "widget" {
		t.Fatalf("unexpected dashboard audit scope: org=%q project=%q type=%q id=%q", organizationID, projectID, targetType, targetID)
	}
}

func TestRequireResolvesNumericSentryIssueAuditScope(t *testing.T) {
	st := openAuthStore(t)
	plain := "bark_sentry-issue-audit-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO issues(id, project_id, fingerprint, title, first_seen_at, last_seen_at) VALUES ('issue', 'project', 'fingerprint', 'Boom', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
		INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix) VALUES ('token', 'user', 'org', 'Automation', ?, 'bark_sen');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := st.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	service := &Service{store: st}
	mux := http.NewServeMux()
	mux.Handle("PUT /api/0/issues/{issue_id}/", service.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	request := httptest.NewRequest(http.MethodPut, "/api/0/issues/"+strconv.FormatInt(issueID, 10)+"/", nil)
	request.Header.Set("Authorization", "Bearer "+plain)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response status = %d", response.Code)
	}
	var organizationID, projectID, targetType, targetID string
	if err := st.DB.QueryRow(`SELECT organization_id, project_id, target_type, target_id FROM audit_logs`).Scan(&organizationID, &projectID, &targetType, &targetID); err != nil {
		t.Fatal(err)
	}
	if organizationID != "org" || projectID != "project" || targetType != "issue" || targetID != strconv.FormatInt(issueID, 10) {
		t.Fatalf("unexpected Sentry issue audit scope: org=%q project=%q type=%q id=%q", organizationID, projectID, targetType, targetID)
	}
}
