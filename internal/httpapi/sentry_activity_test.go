package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryIssueActivitiesAndCommentLifecycle(t *testing.T) {
	server, owner := managementFixture(t)
	var legacyIssueID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&legacyIssueID); err != nil {
		t.Fatal(err)
	}
	identifier := strconv.FormatInt(legacyIssueID, 10)
	if _, err := server.store.DB.Exec(`INSERT INTO issue_activities(id, issue_id, user_id, kind, value, created_at) VALUES ('status-activity', 'issue', 'user', 'status', 'resolved', '2026-08-30T09:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	activities := serveSentryActivity(t, server, owner, http.MethodGet, "/api/0/issues/"+identifier+"/activities/", "")
	if activities.Code != http.StatusOK || !containsAll(activities.Body.String(), `"type":"set_resolved"`, `"status":"resolved"`, `"type":"first_seen"`, `"id":"user"`) {
		t.Fatalf("issue activities status=%d body=%s", activities.Code, activities.Body.String())
	}

	created := serveSentryActivity(t, server, owner, http.MethodPost, "/api/0/issues/"+identifier+"/comments/", `{"text":"Investigating the deploy"}`)
	if created.Code != http.StatusCreated || !containsAll(created.Body.String(), `"type":"note"`, `"text":"Investigating the deploy"`, `"email":"user@example.com"`) {
		t.Fatalf("comment create status=%d body=%s", created.Code, created.Body.String())
	}
	duplicate := serveSentryActivity(t, server, owner, http.MethodPost, "/api/0/issues/"+identifier+"/notes/", `{"text":"Investigating the deploy"}`)
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate comment status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	var commentID string
	if err := server.store.DB.QueryRow(`SELECT id FROM issue_activities WHERE issue_id = 'issue' AND kind = 'comment'`).Scan(&commentID); err != nil {
		t.Fatal(err)
	}

	comments := serveSentryActivity(t, server, owner, http.MethodGet, "/api/0/organizations/org/groups/"+identifier+"/notes/", "")
	if comments.Code != http.StatusOK || !containsAll(comments.Body.String(), `"id":"`+commentID+`"`, `"text":"Investigating the deploy"`) {
		t.Fatalf("comment list status=%d body=%s", comments.Code, comments.Body.String())
	}
	updated := serveSentryActivity(t, server, owner, http.MethodPut, "/api/0/organizations/org/issues/"+identifier+"/comments/"+commentID+"/", `{"text":"Fixed in the next deploy"}`)
	if updated.Code != http.StatusOK || !containsAll(updated.Body.String(), `"text":"Fixed in the next deploy"`) {
		t.Fatalf("comment update status=%d body=%s", updated.Code, updated.Body.String())
	}

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('member-comments', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'member-comments', 'member')`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member-comments", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "member"}}}
	denied := serveSentryActivity(t, server, member, http.MethodDelete, "/api/0/issues/"+identifier+"/comments/"+commentID+"/", "")
	if denied.Code != http.StatusNotFound {
		t.Fatalf("non-author comment delete status=%d body=%s", denied.Code, denied.Body.String())
	}
	wrongOrganization := serveSentryActivity(t, server, owner, http.MethodGet, "/api/0/organizations/other/issues/"+identifier+"/comments/", "")
	if wrongOrganization.Code != http.StatusNotFound {
		t.Fatalf("cross-organization comment list status=%d body=%s", wrongOrganization.Code, wrongOrganization.Body.String())
	}
	removed := serveSentryActivity(t, server, owner, http.MethodDelete, "/api/0/issues/"+identifier+"/notes/"+commentID+"/", "")
	if removed.Code != http.StatusNoContent {
		t.Fatalf("comment delete status=%d body=%s", removed.Code, removed.Body.String())
	}
}

func serveSentryActivity(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	register := func(prefix string) {
		mux.HandleFunc("GET "+prefix+"/activities/", server.sentryIssueActivities)
		for _, resource := range []string{"comments", "notes"} {
			mux.HandleFunc("GET "+prefix+"/"+resource+"/", server.sentryIssueComments)
			mux.HandleFunc("POST "+prefix+"/"+resource+"/", server.sentryIssueComments)
			mux.HandleFunc("PUT "+prefix+"/"+resource+"/{note_id}/", server.sentryIssueCommentDetail)
			mux.HandleFunc("DELETE "+prefix+"/"+resource+"/{note_id}/", server.sentryIssueCommentDetail)
		}
	}
	register("/api/0/issues/{issue_id}")
	register("/api/0/organizations/{org_slug}/issues/{issue_id}")
	register("/api/0/organizations/{org_slug}/groups/{issue_id}")
	mux.ServeHTTP(response, request)
	return response
}
