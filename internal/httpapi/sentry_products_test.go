package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/ingest"
)

func TestSentryFeedbackAndAttachmentCompatibility(t *testing.T) {
	server, owner := managementFixture(t)
	const eventID = "abababababababababababababababab"
	if _, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, timestamp, payload)
		VALUES ('event-products', ?, 'project', 'issue', '2026-08-30T08:30:00Z', '{}')`, eventID); err != nil {
		t.Fatal(err)
	}
	service := ingest.New(server.store, 20<<20)
	project := ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}
	if err := service.StoreAttachment(context.Background(), project, eventID, "diagnostic.txt", "text/plain", "event.attachment", []byte("useful diagnostics")); err != nil {
		t.Fatal(err)
	}
	if err := service.StoreFeedback(context.Background(), project, []byte(`{"event_id":"`+eventID+`","name":"Ada","email":"ada@example.com","comments":"Checkout failed","url":"https://example.test/checkout"}`)); err != nil {
		t.Fatal(err)
	}
	var attachmentID, feedbackID, storageKey string
	if err := server.store.DB.QueryRow(`SELECT a.id, b.storage_key FROM event_attachments a JOIN blobs b ON b.id = a.blob_id`).Scan(&attachmentID, &storageKey); err != nil {
		t.Fatal(err)
	}
	if err := server.store.DB.QueryRow(`SELECT id FROM user_feedback`).Scan(&feedbackID); err != nil {
		t.Fatal(err)
	}

	feedback := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/user-feedback/?per_page=1")
	if feedback.Code != http.StatusOK || !containsAll(feedback.Body.String(), `"eventID":"`+eventID+`"`, `"name":"Ada"`, `"comments":"Checkout failed"`, `"dateCreated":`) {
		t.Fatalf("feedback list status=%d body=%s", feedback.Code, feedback.Body.String())
	}
	feedbackDetail := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/user-feedback/"+feedbackID+"/")
	if feedbackDetail.Code != http.StatusOK || !containsAll(feedbackDetail.Body.String(), `"id":"`+feedbackID+`"`, `"email":"ada@example.com"`) {
		t.Fatalf("feedback detail status=%d body=%s", feedbackDetail.Code, feedbackDetail.Body.String())
	}

	attachments := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/events/"+eventID+"/attachments/")
	if attachments.Code != http.StatusOK || !containsAll(attachments.Body.String(), `"id":"`+attachmentID+`"`, `"event_id":"`+eventID+`"`, `"name":"diagnostic.txt"`, `"type":"event.attachment"`, `"mimetype":"text/plain"`, `"Content-Type":"text/plain"`) {
		t.Fatalf("attachment list status=%d body=%s", attachments.Code, attachments.Body.String())
	}
	filtered := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/events/"+eventID+"/attachments/?query=diagnostic")
	if filtered.Code != http.StatusOK || !containsAll(filtered.Body.String(), `"name":"diagnostic.txt"`) {
		t.Fatalf("filtered attachment list status=%d body=%s", filtered.Code, filtered.Body.String())
	}
	missingEvent := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/events/missing/attachments/")
	if missingEvent.Code != http.StatusNotFound {
		t.Fatalf("missing event attachment list status=%d body=%s", missingEvent.Code, missingEvent.Body.String())
	}
	metadata := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/events/"+eventID+"/attachments/"+attachmentID+"/")
	if metadata.Code != http.StatusOK || !containsAll(metadata.Body.String(), `"size":18`, `"sha1":null`) {
		t.Fatalf("attachment detail status=%d body=%s", metadata.Code, metadata.Body.String())
	}
	download := serveSentryProduct(t, server, owner, http.MethodGet, "/api/0/projects/org/app/events/"+eventID+"/attachments/"+attachmentID+"/?download=false")
	if download.Code != http.StatusOK || download.Body.String() != "useful diagnostics" || download.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("attachment download status=%d content-type=%q body=%q", download.Code, download.Header().Get("Content-Type"), download.Body.String())
	}

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('viewer-products', 'viewer@example.com', 'Viewer');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'viewer-products', 'viewer')`); err != nil {
		t.Fatal(err)
	}
	viewer := &auth.Principal{UserID: "viewer-products", Email: "viewer@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "viewer"}}}
	denied := serveSentryProduct(t, server, viewer, http.MethodDelete, "/api/0/projects/org/app/events/"+eventID+"/attachments/"+attachmentID+"/")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("viewer attachment delete status=%d body=%s", denied.Code, denied.Body.String())
	}
	removed := serveSentryProduct(t, server, owner, http.MethodDelete, "/api/0/projects/org/app/events/"+eventID+"/attachments/"+attachmentID+"/")
	if removed.Code != http.StatusNoContent {
		t.Fatalf("attachment delete status=%d body=%s", removed.Code, removed.Body.String())
	}
	if _, err := server.store.Blobs.Open(storageKey); err == nil {
		t.Fatal("unreferenced attachment content was not removed")
	}
	removedFeedback := serveSentryProduct(t, server, owner, http.MethodDelete, "/api/0/projects/org/app/user-feedback/"+feedbackID+"/")
	if removedFeedback.Code != http.StatusNoContent {
		t.Fatalf("feedback delete status=%d body=%s", removedFeedback.Code, removedFeedback.Body.String())
	}
}

func serveSentryProduct(t *testing.T, server *Server, principal *auth.Principal, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, "")
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/user-feedback/", server.sentryProjectFeedback)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/user-feedback/{feedback_id}/", server.sentryProjectFeedbackDetail)
	mux.HandleFunc("DELETE /api/0/projects/{org_slug}/{project_slug}/user-feedback/{feedback_id}/", server.sentryProjectFeedbackDetail)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/events/{event_id}/attachments/", server.sentryEventAttachments)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/events/{event_id}/attachments/{attachment_id}/", server.sentryEventAttachmentDetail)
	mux.HandleFunc("DELETE /api/0/projects/{org_slug}/{project_slug}/events/{event_id}/attachments/{attachment_id}/", server.sentryEventAttachmentDetail)
	mux.ServeHTTP(response, request)
	return response
}
