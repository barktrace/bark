package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryOrganizationProjectAndKeyDetails(t *testing.T) {
	server, principal := managementFixture(t)

	organization := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/organizations/org/", "")
	if organization.Code != http.StatusOK || !containsAll(organization.Body.String(), `"slug":"org"`, `"role":"owner"`, `"status":{"id":"active"`) {
		t.Fatalf("organization detail status=%d body=%s", organization.Code, organization.Body.String())
	}

	project := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/projects/org/app/", "")
	if project.Code != http.StatusOK || !containsAll(project.Body.String(), `"id":"1"`, `"slug":"app"`, `"dsn":{"public":"https://key@errors.example/1"`) {
		t.Fatalf("project detail status=%d body=%s", project.Code, project.Body.String())
	}

	keys := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/projects/org/app/keys/", "")
	if keys.Code != http.StatusOK || !containsAll(keys.Body.String(), `"public":"key"`, `"projectId":"1"`, `"isActive":true`, `"minidump":"https://key@errors.example/1"`) {
		t.Fatalf("project keys status=%d body=%s", keys.Code, keys.Body.String())
	}

	outsider := &auth.Principal{UserID: "outsider", Email: "outsider@example.com"}
	denied := serveSentryDetail(t, server, outsider, http.MethodGet, "/api/0/projects/org/app/keys/", "")
	if denied.Code != http.StatusNotFound {
		t.Fatalf("outsider key access status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestSentryIssueAndEventDetailWorkflow(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, environment, platform, level, timestamp, payload)
		VALUES (
			'event-internal', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', 'production', 'javascript', 'error',
			'2026-08-29T18:00:00Z',
			'{"message":"checkout failed","exception":{"values":[{"type":"TypeError","value":"boom"}]},"tags":{"region":"eu-west-1"},"user":{"id":"customer-1"}}'
		)
	`)
	if err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	identifier := strconv.FormatInt(issueID, 10)

	issue := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/issues/"+identifier+"/", "")
	if issue.Code != http.StatusOK || !containsAll(issue.Body.String(), `"shortId":"APP-`+identifier+`"`, `"title":"Boom"`, `"count":"1"`) {
		t.Fatalf("issue detail status=%d body=%s", issue.Code, issue.Body.String())
	}

	updated := serveSentryDetail(t, server, principal, http.MethodPut, "/api/0/issues/"+identifier+"/", `{"status":"resolved","priority":"high","isBookmarked":true}`)
	if updated.Code != http.StatusOK || !containsAll(updated.Body.String(), `"status":"resolved"`, `"priority":"high"`, `"isBookmarked":true`) {
		t.Fatalf("issue update status=%d body=%s", updated.Code, updated.Body.String())
	}
	var activities int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM issue_activities WHERE issue_id = 'issue'`).Scan(&activities); err != nil || activities != 3 {
		t.Fatalf("issue activities=%d err=%v, want 3", activities, err)
	}
	queryRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := server.querySentryEvent(queryRequest, sentryEventSelect+` WHERE e.issue_id = ? LIMIT 1`, "issue"); err != nil {
		t.Fatalf("query Sentry event: %v", err)
	}

	list := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/issues/"+identifier+"/events/", "")
	if list.Code != http.StatusOK || !containsAll(list.Body.String(), `"eventID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"groupID":"`+identifier+`"`, `"type":"exception"`, `"key":"region"`) {
		t.Fatalf("issue events status=%d body=%s", list.Code, list.Body.String())
	}

	latest := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/issues/"+identifier+"/events/latest/", "")
	if latest.Code != http.StatusOK || !containsAll(latest.Body.String(), `"message":"checkout failed"`, `"environment":"production"`) {
		t.Fatalf("latest event status=%d body=%s", latest.Code, latest.Body.String())
	}

	event := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/projects/org/app/events/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", "")
	if event.Code != http.StatusOK || !containsAll(event.Body.String(), `"projectID":"1"`, `"projectSlug":"app"`, `"id":"customer-1"`) {
		t.Fatalf("project event status=%d body=%s", event.Code, event.Body.String())
	}
}

func TestSentryIssueMutationHonorsProjectRole(t *testing.T) {
	server, _ := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('viewer', 'viewer@example.com', 'Viewer');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'viewer', 'viewer');
	`); err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	viewer := &auth.Principal{UserID: "viewer", Email: "viewer@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "viewer"}}}
	response := serveSentryDetail(t, server, viewer, http.MethodPut, "/api/0/issues/"+strconv.FormatInt(issueID, 10)+"/", `{"status":"resolved"}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer issue update status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSentryIssueSupportsAssignmentAndSnooze(t *testing.T) {
	server, principal := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('responder', 'responder@example.com', 'Responder');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'responder', 'member');
	`); err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	target := "/api/0/issues/" + strconv.FormatInt(issueID, 10) + "/"
	response := serveSentryDetail(t, server, principal, http.MethodPut, target, `{"status":"ignored","statusDetails":{"ignoreDuration":15},"assignedTo":"user:responder"}`)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"status":"ignored"`, `"ignoreUntil":`, `"id":"responder"`) {
		t.Fatalf("snooze and assignment status=%d body=%s", response.Code, response.Body.String())
	}
	var assignee string
	var snoozed bool
	if err := server.store.DB.QueryRow(`SELECT COALESCE(assignee_user_id, ''), snoozed_until IS NOT NULL FROM issues WHERE id = 'issue'`).Scan(&assignee, &snoozed); err != nil || assignee != "responder" || !snoozed {
		t.Fatalf("stored assignee=%q snoozed=%v err=%v", assignee, snoozed, err)
	}

	response = serveSentryDetail(t, server, principal, http.MethodPut, target, `{"status":"unresolved","assignedTo":null}`)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"status":"unresolved"`, `"assignedTo":null`, `"statusDetails":{}`) {
		t.Fatalf("clear snooze and assignment status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSentryLatestEventReturnsNotFoundForEmptyIssue(t *testing.T) {
	server, principal := managementFixture(t)
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	response := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/issues/"+strconv.FormatInt(issueID, 10)+"/events/latest/", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("empty latest event status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSentryIssueDeleteRequiresProjectAdmin(t *testing.T) {
	server, owner := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'member', 'member');
	`); err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	target := "/api/0/issues/" + strconv.FormatInt(issueID, 10) + "/"
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "member"}}}
	response := serveSentryDetail(t, server, member, http.MethodDelete, target, "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("member issue delete status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveSentryDetail(t, server, owner, http.MethodDelete, target, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("owner issue delete status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues WHERE id = 'issue'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("remaining issues=%d err=%v", count, err)
	}
}

func serveSentryDetail(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/", server.sentryOrganizationDetail)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/", server.sentryProjectDetail)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/keys/", server.sentryProjectKeys)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/events/{event_id}/", server.sentryProjectEventDetail)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("PUT /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("DELETE /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/events/", server.sentryIssueEvents)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/events/latest/", server.sentryIssueLatestEvent)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent && response.Body.Len() > 0 && !json.Valid(response.Body.Bytes()) {
		t.Fatalf("invalid JSON response status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}
