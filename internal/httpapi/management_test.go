package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GhaziBenDahmane/barktrace/internal/auth"
)

func TestIssueUpdateAndCommentCreateActivity(t *testing.T) {
	server, principal := managementFixture(t)
	request := principalRequest(t, principal, http.MethodPatch, "/issues/issue", `{"status":"resolved","priority":"high","bookmarked":true}`)
	request.SetPathValue("issue_id", "issue")
	response := httptest.NewRecorder()
	server.updateIssue(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", response.Code, response.Body.String())
	}
	comment := principalRequest(t, principal, http.MethodPost, "/issues/issue/comments", `{"body":"Fixed in the next deploy"}`)
	comment.SetPathValue("issue_id", "issue")
	response = httptest.NewRecorder()
	server.createIssueComment(response, comment)
	if response.Code != http.StatusCreated {
		t.Fatalf("comment status = %d body=%s", response.Code, response.Body.String())
	}
	var status, priority string
	var bookmarked bool
	if err := server.store.DB.QueryRow(`SELECT status, priority, bookmarked FROM issues WHERE id = 'issue'`).Scan(&status, &priority, &bookmarked); err != nil {
		t.Fatal(err)
	}
	var activities int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issue_activities WHERE issue_id = 'issue'`).Scan(&activities)
	if status != "resolved" || priority != "high" || !bookmarked || activities != 4 {
		t.Fatalf("issue status=%q priority=%q bookmarked=%v activities=%d", status, priority, bookmarked, activities)
	}
}

func TestCreateAPITokenReturnsSecretOnlyOnce(t *testing.T) {
	server, principal := managementFixture(t)
	request := principalRequest(t, principal, http.MethodPost, "/api-tokens", `{"organization_id":"org","name":"CI","expires_in_days":30}`)
	response := httptest.NewRecorder()
	server.createAPIToken(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", response.Code, response.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	secret, _ := created["token"].(string)
	if len(secret) < 20 || secret[:5] != "bark_" {
		t.Fatalf("unexpected token %q", secret)
	}
	list := principalRequest(t, principal, http.MethodGet, "/api-tokens", "")
	response = httptest.NewRecorder()
	server.apiTokens(response, list)
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(secret)) || bytes.Contains(response.Body.Bytes(), []byte(`"token"`)) {
		t.Fatalf("token secret leaked in list response: %s", response.Body.String())
	}
}

func managementFixture(t *testing.T) (*Server, *auth.Principal) {
	t.Helper()
	st := openTestStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'user', 'owner');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO issues(id, project_id, fingerprint, title, first_seen_at, last_seen_at) VALUES ('issue', 'project', 'fingerprint', 'Boom', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatal(err)
	}
	principal := &auth.Principal{UserID: "user", Email: "user@example.com", Name: "User", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", OrganizationName: "Org", Role: "owner"}}}
	return &Server{cfg: configForTest(), store: st}, principal
}

func principalRequest(t *testing.T, principal *auth.Principal, method, target, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	request = request.WithContext(auth.WithPrincipal(request.Context(), principal))
	return request
}
