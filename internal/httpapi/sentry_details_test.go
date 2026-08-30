package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/ingest"
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

func TestSentryIssueEventSelectorsAndRawJSON(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, environment, platform, level, timestamp, received_at, payload) VALUES
			('event-old', '11111111111111111111111111111111', 'project', 'issue', 'staging', 'go', 'error', '2026-08-30T08:00:00Z', '2026-08-30T08:00:01Z', '{"message":"old event"}'),
			('event-replay', '22222222222222222222222222222222', 'project', 'issue', 'production', 'go', 'error', '2026-08-30T09:00:00Z', '2026-08-30T09:00:01Z', '{"message":"recommended event","extra":{"safe":true}}'),
			('event-new', '33333333333333333333333333333333', 'project', 'issue', 'production', 'go', 'error', '2026-08-30T10:00:00Z', '2026-08-30T10:00:01Z', '{"message":"latest event"}');
		INSERT INTO replay_error_links(project_id, replay_id, segment_id, event_id) VALUES ('project', '44444444444444444444444444444444', 0, '22222222222222222222222222222222')
	`)
	if err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	identifier := strconv.FormatInt(issueID, 10)

	for name, target := range map[string]string{
		"latest":      "/api/0/issues/" + identifier + "/events/latest/",
		"oldest":      "/api/0/groups/" + identifier + "/events/oldest/",
		"recommended": "/api/0/organizations/org/issues/" + identifier + "/events/recommended/",
		"specific":    "/api/0/organizations/org/groups/" + identifier + "/events/22222222222222222222222222222222/",
	} {
		response := serveSentryDetail(t, server, principal, http.MethodGet, target, "")
		want := map[string]string{"latest": "latest event", "oldest": "old event", "recommended": "recommended event", "specific": "recommended event"}[name]
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"message":"`+want+`"`) {
			t.Fatalf("%s selector status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	filtered := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/issues/"+identifier+"/events/latest/?environment=staging", "")
	if filtered.Code != http.StatusOK || !strings.Contains(filtered.Body.String(), `"message":"old event"`) {
		t.Fatalf("environment selector status=%d body=%s", filtered.Code, filtered.Body.String())
	}
	raw := serveSentryDetail(t, server, principal, http.MethodGet, "/api/0/projects/org/app/events/22222222222222222222222222222222/json/", "")
	if raw.Code != http.StatusOK || raw.Header().Get("Content-Type") != "application/json" || raw.Body.String() != `{"message":"recommended event","extra":{"safe":true}}` {
		t.Fatalf("raw event status=%d content-type=%q body=%s", raw.Code, raw.Header().Get("Content-Type"), raw.Body.String())
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

func TestSentryIssuePublicSharing(t *testing.T) {
	server, owner := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, environment, platform, level, timestamp, payload)
		VALUES ('shared-event', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'project', 'issue', 'production', 'javascript', 'error',
		        '2026-08-29T18:00:00Z', '{"message":"safe public detail","user":{"email":"private@example.com"},"request":{"url":"https://secret.example"}}')
	`); err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	target := "/api/0/issues/" + strconv.FormatInt(issueID, 10) + "/"
	enabled := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"isPublic":true}`)
	var body map[string]any
	if enabled.Code != http.StatusOK || json.Unmarshal(enabled.Body.Bytes(), &body) != nil || body["isPublic"] != true {
		t.Fatalf("enable public sharing status=%d body=%s", enabled.Code, enabled.Body.String())
	}
	shareID, _ := body["shareId"].(string)
	if len(shareID) != 32 {
		t.Fatalf("share ID = %q", shareID)
	}
	repeated := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"isPublic":true}`)
	var repeatedBody map[string]any
	_ = json.Unmarshal(repeated.Body.Bytes(), &repeatedBody)
	if repeatedBody["shareId"] != shareID {
		t.Fatalf("share ID changed from %q to %v", shareID, repeatedBody["shareId"])
	}

	shared := serveSharedIssue(t, server, shareID)
	if shared.Code != http.StatusOK || !containsAll(shared.Body.String(), `"title":"Boom"`, `"message":"safe public detail"`, `"isPublic":true`) || strings.Contains(shared.Body.String(), "private@example.com") || strings.Contains(shared.Body.String(), "secret.example") {
		t.Fatalf("shared issue status=%d body=%s", shared.Code, shared.Body.String())
	}
	if shared.Header().Get("Cache-Control") != "no-store" || shared.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Fatalf("shared issue headers = %#v", shared.Header())
	}

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'member', 'member');
	`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "member"}}}
	denied := serveSentryDetail(t, server, member, http.MethodPut, target, `{"isPublic":false}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("member public-sharing update status=%d body=%s", denied.Code, denied.Body.String())
	}

	disabled := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"isPublic":false}`)
	if disabled.Code != http.StatusOK || !containsAll(disabled.Body.String(), `"isPublic":false`, `"shareId":null`) {
		t.Fatalf("disable public sharing status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	if revoked := serveSharedIssue(t, server, shareID); revoked.Code != http.StatusNotFound {
		t.Fatalf("revoked share status=%d body=%s", revoked.Code, revoked.Body.String())
	} else if revoked.Header().Get("Cache-Control") != "no-store" || revoked.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Fatalf("revoked share headers = %#v", revoked.Header())
	}
}

func TestSentryIssueDiscardSuppressesFutureEvents(t *testing.T) {
	server, owner := managementFixture(t)
	if _, err := server.store.DB.Exec(`DELETE FROM issues`); err != nil {
		t.Fatal(err)
	}
	service := ingest.New(server.store, 20<<20)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}
	first := []byte(`{"event_id":"cccccccccccccccccccccccccccccccc","message":"discard this crash"}`)
	if _, err := service.StoreEvent(t.Context(), project, first, ""); err != nil {
		t.Fatal(err)
	}
	var issueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	target := "/api/0/issues/" + strconv.FormatInt(issueID, 10) + "/"

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'member', 'member');
	`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "member"}}}
	if denied := serveSentryDetail(t, server, member, http.MethodPut, target, `{"discard":true}`); denied.Code != http.StatusForbidden {
		t.Fatalf("member discard status=%d body=%s", denied.Code, denied.Body.String())
	}

	discarded := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"discard":true}`)
	if discarded.Code != http.StatusNoContent {
		t.Fatalf("discard status=%d body=%s", discarded.Code, discarded.Body.String())
	}
	var issues, events, tombstones, audits int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&issues)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM discarded_issue_fingerprints`).Scan(&tombstones)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE action = 'discard_issue'`).Scan(&audits)
	if issues != 0 || events != 0 || tombstones != 1 || audits != 1 {
		t.Fatalf("discarded state issues=%d events=%d tombstones=%d audits=%d", issues, events, tombstones, audits)
	}

	second := []byte(`{"event_id":"dddddddddddddddddddddddddddddddd","message":"discard this crash"}`)
	if id, err := service.StoreEvent(t.Context(), project, second, ""); err != nil || id != "dddddddddddddddddddddddddddddddd" {
		t.Fatalf("suppressed event id=%q err=%v", id, err)
	}
	var filtered int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM ingestion_outcomes WHERE outcome = 'filtered' AND reason = 'discarded_issue'`).Scan(&filtered)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&issues)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
	if issues != 0 || events != 0 || filtered != 1 {
		t.Fatalf("future event state issues=%d events=%d filtered=%d", issues, events, filtered)
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
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/events/{event_id}/json/", server.sentryProjectEventJSON)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("PUT /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("DELETE /api/0/issues/{issue_id}/", server.sentryIssueDetail)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/events/", server.sentryIssueEvents)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/events/latest/", server.sentryIssueLatestEvent)
	mux.HandleFunc("GET /api/0/issues/{issue_id}/events/{event_id}/", server.sentryIssueEventDetail)
	mux.HandleFunc("GET /api/0/groups/{issue_id}/events/{event_id}/", server.sentryIssueEventDetail)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/issues/{issue_id}/events/{event_id}/", server.sentryIssueEventDetail)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/groups/{issue_id}/events/{event_id}/", server.sentryIssueEventDetail)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent && response.Body.Len() > 0 && !json.Valid(response.Body.Bytes()) {
		t.Fatalf("invalid JSON response status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}

func serveSharedIssue(t *testing.T, server *Server, shareID string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/share/issue/"+shareID+"/", nil)
	request.SetPathValue("share_id", shareID)
	response := httptest.NewRecorder()
	server.sentrySharedIssue(response, request)
	if response.Body.Len() > 0 && !json.Valid(response.Body.Bytes()) {
		t.Fatalf("invalid shared issue JSON status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}
