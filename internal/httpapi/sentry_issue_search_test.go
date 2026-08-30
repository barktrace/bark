package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryOrganizationIssuesSearchAndAuthorization(t *testing.T) {
	server, owner := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		UPDATE issues SET bookmarked = 1, assignee_user_id = 'user', event_count = 2 WHERE id = 'issue';
		INSERT INTO events(id, event_id, project_id, issue_id, environment, platform, level, timestamp, payload)
		VALUES ('event-one', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', 'production', 'go', 'error', '2026-08-30T08:00:00Z', '{"message":"boom"}');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project-two', '2', 'org', 'payments', 'Payments', 'key-two');
		INSERT INTO issues(id, project_id, fingerprint, title, status, level, issue_type, issue_category, priority, event_count, first_seen_at, last_seen_at)
		VALUES ('issue-two', 'project-two', 'payment-timeout', 'Payment timeout', 'resolved', 'warning', 'performance', 'performance', 'high', 7, '2026-08-30T09:00:00Z', '2026-08-30T10:00:00Z');
		INSERT INTO events(id, event_id, project_id, issue_id, environment, platform, level, timestamp, payload)
		VALUES ('event-two', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'project-two', 'issue-two', 'staging', 'javascript', 'warning', '2026-08-30T10:00:00Z', '{"message":"slow payment"}')
	`); err != nil {
		t.Fatal(err)
	}

	all := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/issues/?sort=freq")
	var items []map[string]any
	if all.Code != http.StatusOK || json.Unmarshal(all.Body.Bytes(), &items) != nil || len(items) != 2 {
		t.Fatalf("all issues status=%d body=%s", all.Code, all.Body.String())
	}
	if items[0]["title"] != "Payment timeout" || items[0]["count"] != "7" {
		t.Fatalf("frequency ordering = %#v", items)
	}
	firstPage := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/issues/?sort=freq&per_page=1")
	items = nil
	if firstPage.Code != http.StatusOK || json.Unmarshal(firstPage.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Payment timeout" || !containsAll(firstPage.Header().Get("Link"), `rel="next"; results="true"`, `cursor="offset:1:0"`) {
		t.Fatalf("first issue page status=%d link=%q body=%s", firstPage.Code, firstPage.Header().Get("Link"), firstPage.Body.String())
	}
	secondPage := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/issues/?sort=freq&per_page=1&cursor=offset%3A1%3A0")
	items = nil
	if secondPage.Code != http.StatusOK || json.Unmarshal(secondPage.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Boom" || !containsAll(secondPage.Header().Get("Link"), `rel="previous"; results="true"`, `rel="next"; results="false"`) {
		t.Fatalf("second issue page status=%d link=%q body=%s", secondPage.Code, secondPage.Header().Get("Link"), secondPage.Body.String())
	}

	filtered := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/groups/?project=payments&query=is%3Aresolved+level%3Awarning+issue.type%3Aperformance+Payment&environment=staging")
	items = nil
	if filtered.Code != http.StatusOK || json.Unmarshal(filtered.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Payment timeout" {
		t.Fatalf("filtered issues status=%d body=%s", filtered.Code, filtered.Body.String())
	}

	personal := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/issues/?query=assigned%3Ame+bookmarks%3Ame&project=1")
	items = nil
	if personal.Code != http.StatusOK || json.Unmarshal(personal.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Boom" {
		t.Fatalf("personal issues status=%d body=%s", personal.Code, personal.Body.String())
	}

	timed := serveSentryOrganizationIssues(t, server, owner, "/api/0/organizations/org/issues/?start=2026-08-30T09%3A30%3A00Z&end=2026-08-30T10%3A30%3A00Z")
	items = nil
	if timed.Code != http.StatusOK || json.Unmarshal(timed.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Payment timeout" {
		t.Fatalf("time-filtered issues status=%d body=%s", timed.Code, timed.Body.String())
	}

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('limited', 'limited@example.com', 'Limited');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'limited', 'viewer');
		INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project-two', 'limited', 'none')
	`); err != nil {
		t.Fatal(err)
	}
	limited := &auth.Principal{UserID: "limited", Email: "limited@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", OrganizationName: "Org", Role: "viewer"}}}
	visible := serveSentryOrganizationIssues(t, server, limited, "/api/0/organizations/org/issues/")
	items = nil
	if visible.Code != http.StatusOK || json.Unmarshal(visible.Body.Bytes(), &items) != nil || len(items) != 1 || items[0]["title"] != "Boom" {
		t.Fatalf("project-restricted issues status=%d body=%s", visible.Code, visible.Body.String())
	}

	for _, target := range []string{
		"/api/0/organizations/org/issues/?status=pending",
		"/api/0/organizations/org/issues/?query=assigned%3Ame+unknown%3Avalue",
		"/api/0/organizations/org/issues/?sort=users",
		"/api/0/organizations/org/issues/?per_page=101",
		"/api/0/organizations/org/issues/?cursor=invalid",
	} {
		response := serveSentryOrganizationIssues(t, server, owner, target)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestParseSentryIssueSearch(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?status=all&environment=production&query=is%3Aignored+level%3Aerror+assigned%3Ame+bookmarks%3Ame+database", nil)
	search, err := parseSentryIssueSearch(request, "user")
	if err != nil {
		t.Fatal(err)
	}
	if search.status != "ignored" || search.level != "error" || search.assigned != "user" || !search.bookmarked || len(search.environments) != 1 || len(search.freeText) != 1 {
		t.Fatalf("search = %#v", search)
	}
}

func serveSentryOrganizationIssues(t *testing.T, server *Server, principal *auth.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, http.MethodGet, target, "")
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/issues/", server.sentryOrganizationIssues)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/groups/", server.sentryOrganizationIssues)
	mux.ServeHTTP(response, request)
	if response.Body.Len() > 0 && !json.Valid(response.Body.Bytes()) {
		t.Fatalf("invalid JSON status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}
