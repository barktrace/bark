package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryProjectAndIssueTagDistributions(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at)
		VALUES ('release', 'org', 'app@1.0.0', '2026-08-30T08:00:00Z', '2026-08-30T10:00:00Z');
		INSERT INTO issues(id, project_id, fingerprint, title, first_seen_at, last_seen_at)
		VALUES ('other-issue', 'project', 'other', 'Other', '2026-08-30T10:00:00Z', '2026-08-30T10:00:00Z');
		INSERT INTO events(id, event_id, project_id, issue_id, release_id, environment, platform, level, timestamp, payload) VALUES
			('tag-event-1', '11111111111111111111111111111111', 'project', 'issue', 'release', 'production', 'javascript', 'error', '2026-08-30T08:00:00Z', '{"transaction":"/checkout","tags":{"region":"eu-west-1","attempt":1},"user":{"email":"buyer@example.com"},"contexts":{"browser":{"name":"Chrome","version":"140"}}}'),
			('tag-event-2', '22222222222222222222222222222222', 'project', 'issue', 'release', 'production', 'javascript', 'warning', '2026-08-30T09:00:00Z', '{"tags":[["region","eu-west-1"],["attempt",2]],"request":{"url":"https://shop.example/checkout"}}'),
			('tag-event-3', '33333333333333333333333333333333', 'project', 'other-issue', NULL, 'staging', 'go', 'error', '2026-08-30T10:00:00Z', '{"tags":{"region":"us-east-1"}}')
	`)
	if err != nil {
		t.Fatal(err)
	}

	projectTags := serveSentryTags(t, server, principal, "/api/0/projects/org/app/tags/")
	if projectTags.Code != http.StatusOK || !containsAll(projectTags.Body.String(), `"key":"region"`, `"totalValues":3`, `"uniqueValues":2`, `"key":"sentry:environment"`, `"name":"Environment"`) {
		t.Fatalf("project tags status=%d body=%s", projectTags.Code, projectTags.Body.String())
	}
	projectValues := serveSentryTags(t, server, principal, "/api/0/projects/org/app/tags/region/values/?per_page=1")
	var values []struct {
		Value     string `json:"value"`
		Count     int64  `json:"count"`
		FirstSeen string `json:"firstSeen"`
		LastSeen  string `json:"lastSeen"`
	}
	if err := json.Unmarshal(projectValues.Body.Bytes(), &values); err != nil {
		t.Fatal(err)
	}
	if projectValues.Code != http.StatusOK || len(values) != 1 || values[0].Value != "eu-west-1" || values[0].Count != 2 || values[0].FirstSeen != "2026-08-30T08:00:00Z" || values[0].LastSeen != "2026-08-30T09:00:00Z" {
		t.Fatalf("project tag values status=%d values=%+v", projectValues.Code, values)
	}
	searched := serveSentryTags(t, server, principal, "/api/0/projects/org/app/tags/region/values/?query=US-EAST")
	if searched.Code != http.StatusOK || !containsAll(searched.Body.String(), `"value":"us-east-1"`, `"count":1`) || containsAll(searched.Body.String(), `"value":"eu-west-1"`) {
		t.Fatalf("searched tag values status=%d body=%s", searched.Code, searched.Body.String())
	}

	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	issueTags := serveSentryTags(t, server, principal, "/api/0/issues/"+strconv.FormatInt(issueID, 10)+"/tags/")
	if issueTags.Code != http.StatusOK || !containsAll(issueTags.Body.String(), `"key":"region"`, `"totalValues":2`, `"uniqueValues":1`, `"key":"browser"`, `"key":"sentry:user"`) {
		t.Fatalf("issue tags status=%d body=%s", issueTags.Code, issueTags.Body.String())
	}
	issueValues := serveSentryTags(t, server, principal, "/api/0/organizations/org/groups/"+strconv.FormatInt(issueID, 10)+"/tags/sentry:level/values/")
	if issueValues.Code != http.StatusOK || !containsAll(issueValues.Body.String(), `"value":"error"`, `"value":"warning"`) {
		t.Fatalf("issue tag values status=%d body=%s", issueValues.Code, issueValues.Body.String())
	}

	invalidLimit := serveSentryTags(t, server, principal, "/api/0/projects/org/app/tags/region/values/?per_page=0")
	if invalidLimit.Code != http.StatusBadRequest {
		t.Fatalf("invalid per_page status=%d body=%s", invalidLimit.Code, invalidLimit.Body.String())
	}
}

func TestSentryTagsHonorProjectAccess(t *testing.T) {
	server, _ := managementFixture(t)
	outsider := &auth.Principal{UserID: "outsider", Email: "outsider@example.com"}
	response := serveSentryTags(t, server, outsider, "/api/0/projects/org/app/tags/")
	if response.Code != http.StatusNotFound {
		t.Fatalf("outsider tag access status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveSentryTags(t *testing.T, server *Server, principal *auth.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, http.MethodGet, target, "")
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/tags/", server.sentryProjectTags)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/tags/{tag_key}/values/", server.sentryProjectTags)
	for _, prefix := range []string{"/api/0/issues/{issue_id}", "/api/0/organizations/{org_slug}/groups/{issue_id}"} {
		mux.HandleFunc("GET "+prefix+"/tags/", server.sentryIssueTags)
		mux.HandleFunc("GET "+prefix+"/tags/{tag_key}/values/", server.sentryIssueTags)
	}
	mux.ServeHTTP(response, request)
	return response
}
