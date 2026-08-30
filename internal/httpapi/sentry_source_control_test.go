package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryRepositoryCommitAndSuspectAPIs(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO repositories(id, organization_id, name, url, provider) VALUES ('repo', 'org', 'acme/app', 'https://github.com/acme/app', 'integrations:github');
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES ('release', 'org', 'app@1.2.3', '2026-08-29T10:00:00Z', '2026-08-29T10:00:00Z');
		INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES ('project', 'release', '2026-08-29T10:00:00Z', '2026-08-29T10:00:00Z');
		INSERT INTO commits(id, organization_id, repository, external_id, message, author_name, author_email, committed_at) VALUES ('commit', 'org', 'acme/app', 'abcdef123456', 'Fix checkout', 'Ada', 'ada@example.com', '2026-08-29T09:00:00Z');
		INSERT INTO commit_files(commit_id, filename, change_type) VALUES ('commit', 'src/checkout.go', 'M');
		INSERT INTO release_commits(release_id, commit_id, sequence) VALUES ('release', 'commit', 0);
		INSERT INTO issue_suspect_commits(issue_id, commit_id, score, reason) VALUES ('issue', 'commit', 100, 'stacktrace file match');
	`)
	if err != nil {
		t.Fatal(err)
	}

	repository := serveSentrySourceControl(t, server, principal, "/api/0/organizations/org/repos/repo/")
	if repository.Code != http.StatusOK || !containsAll(repository.Body.String(), `"name":"acme/app"`, `"id":"integrations:github"`) {
		t.Fatalf("repository detail status=%d body=%s", repository.Code, repository.Body.String())
	}
	commits := serveSentrySourceControl(t, server, principal, "/api/0/organizations/org/repos/repo/commits/?query=checkout")
	if commits.Code != http.StatusOK || !containsAll(commits.Body.String(), `"id":"abcdef123456"`, `"email":"ada@example.com"`, `"message":"Fix checkout"`) {
		t.Fatalf("commit list status=%d body=%s", commits.Code, commits.Body.String())
	}
	commit := serveSentrySourceControl(t, server, principal, "/api/0/organizations/org/repos/repo/commits/abcdef123456/")
	if commit.Code != http.StatusOK || !containsAll(commit.Body.String(), `"filename":"src/checkout.go"`, `"type":"M"`, `"version":"app@1.2.3"`) {
		t.Fatalf("commit detail status=%d body=%s", commit.Code, commit.Body.String())
	}
	suspects := serveSentrySourceControl(t, server, principal, "/api/0/issues/issue/suspects/")
	if suspects.Code != http.StatusOK || !containsAll(suspects.Body.String(), `"id":"abcdef123456"`, `"score":100`, `"reason":"stacktrace file match"`) {
		t.Fatalf("suspects status=%d body=%s", suspects.Code, suspects.Body.String())
	}
}

func TestSentrySourceControlAuthorizationAndScoping(t *testing.T) {
	server, _ := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('other', 'other', 'Other');
		INSERT INTO repositories(id, organization_id, name) VALUES ('private-repo', 'other', 'other/app');
		INSERT INTO users(id, email, name) VALUES ('outsider', 'outsider@example.com', 'Outsider');
	`)
	if err != nil {
		t.Fatal(err)
	}
	outsider := &auth.Principal{UserID: "outsider"}
	for _, target := range []string{
		"/api/0/organizations/org/repos/private-repo/",
		"/api/0/organizations/org/repos/private-repo/commits/",
		"/api/0/issues/issue/suspects/",
	} {
		response := serveSentrySourceControl(t, server, outsider, target)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unauthorized source-control target exposed: target=%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestSentryRepositoryLifecycleIsAudited(t *testing.T) {
	server, principal := managementFixture(t)
	created := serveSentrySourceControlRequest(t, server, principal, http.MethodPost, "/api/0/organizations/org/repos/", `{"name":"acme/service","url":"https://github.com/acme/service","provider":"integrations:github"}`)
	if created.Code != http.StatusCreated || !containsAll(created.Body.String(), `"name":"acme/service"`, `"url":"https://github.com/acme/service"`) {
		t.Fatalf("repository create status=%d body=%s", created.Code, created.Body.String())
	}
	var repositoryID string
	if err := server.store.DB.QueryRow(`SELECT id FROM repositories WHERE name = 'acme/service'`).Scan(&repositoryID); err != nil {
		t.Fatal(err)
	}
	updated := serveSentrySourceControlRequest(t, server, principal, http.MethodPut, "/api/0/organizations/org/repos/"+repositoryID+"/", `{"name":"acme/service-api"}`)
	if updated.Code != http.StatusOK || !containsAll(updated.Body.String(), `"name":"acme/service-api"`) {
		t.Fatalf("repository update status=%d body=%s", updated.Code, updated.Body.String())
	}
	deleted := serveSentrySourceControlRequest(t, server, principal, http.MethodDelete, "/api/0/organizations/org/repos/"+repositoryID+"/", "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("repository delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	var audits int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE target_type = 'repository' AND target_id = ?`, repositoryID).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("repository audit count=%d err=%v", audits, err)
	}
}

func serveSentrySourceControl(t *testing.T, server *Server, principal *auth.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	return serveSentrySourceControlRequest(t, server, principal, http.MethodGet, target, "")
}

func serveSentrySourceControlRequest(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/repos/", server.sentryOrganizationRepositories)
	mux.HandleFunc("POST /api/0/organizations/{org_slug}/repos/", server.sentryOrganizationRepositories)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/repos/{repo_id}/", server.sentryOrganizationRepositoryDetail)
	mux.HandleFunc("PUT /api/0/organizations/{org_slug}/repos/{repo_id}/", server.sentryOrganizationRepositoryDetail)
	mux.HandleFunc("DELETE /api/0/organizations/{org_slug}/repos/{repo_id}/", server.sentryOrganizationRepositoryDetail)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/repos/{repo_id}/commits/", server.sentryRepositoryCommits)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/repos/{repo_id}/commits/{commit_id}/", server.sentryRepositoryCommitDetail)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/suspects/", server.sentryIssueSuspects)
	mux.ServeHTTP(response, request)
	return response
}
