package auth

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
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
