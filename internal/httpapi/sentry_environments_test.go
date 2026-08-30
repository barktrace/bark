package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryEnvironmentDiscoveryAndVisibility(t *testing.T) {
	server, owner := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, environment, timestamp, payload)
		VALUES ('event-environment', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', 'production', '2026-08-30T08:00:00Z', '{}');
		INSERT INTO transactions(id, event_id, project_id, name, environment, started_at, finished_at, duration_ms, payload)
		VALUES ('transaction-environment', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'project', 'checkout', 'staging', '2026-08-30T08:00:00Z', '2026-08-30T08:00:01Z', 1000, '{}');
		INSERT INTO logs(id, project_id, timestamp, message, environment)
		VALUES ('log-environment', 'project', '2026-08-30T08:00:00Z', 'preview log', 'preview');
		INSERT INTO metric_points(project_id, name, metric_type, value, tags, timestamp)
		VALUES ('project', 'queue.depth', 'gauge', 2, '{"sentry.environment":"metrics"}', '2026-08-30T08:00:00Z')
	`)
	if err != nil {
		t.Fatal(err)
	}

	organization := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/organizations/org/environments/", "")
	if organization.Code != http.StatusOK || !containsAll(organization.Body.String(), `"name":"metrics"`, `"name":"preview"`, `"name":"production"`, `"name":"staging"`) {
		t.Fatalf("organization environments status=%d body=%s", organization.Code, organization.Body.String())
	}
	project := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/projects/org/app/environments/", "")
	if project.Code != http.StatusOK || !containsAll(project.Body.String(), `"name":"production"`, `"isHidden":false`) {
		t.Fatalf("project environments status=%d body=%s", project.Code, project.Body.String())
	}

	hidden := serveSentryEnvironment(t, server, owner, http.MethodPut, "/api/0/projects/org/app/environments/", `{"environmentNames":["staging","metrics"],"isHidden":true}`)
	if hidden.Code != http.StatusOK || !containsAll(hidden.Body.String(), `"name":"staging"`, `"name":"metrics"`, `"isHidden":true`) {
		t.Fatalf("bulk environment update status=%d body=%s", hidden.Code, hidden.Body.String())
	}
	visible := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/projects/org/app/environments/", "")
	if visible.Code != http.StatusOK || containsAll(visible.Body.String(), `"name":"staging"`) || !containsAll(visible.Body.String(), `"name":"production"`) {
		t.Fatalf("visible environments status=%d body=%s", visible.Code, visible.Body.String())
	}
	hiddenOnly := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/projects/org/app/environments/?visibility=hidden", "")
	if hiddenOnly.Code != http.StatusOK || !containsAll(hiddenOnly.Body.String(), `"name":"metrics"`, `"name":"staging"`) || containsAll(hiddenOnly.Body.String(), `"name":"production"`) {
		t.Fatalf("hidden environments status=%d body=%s", hiddenOnly.Code, hiddenOnly.Body.String())
	}
	detail := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/projects/org/app/environments/staging/", "")
	if detail.Code != http.StatusOK || !containsAll(detail.Body.String(), `"name":"staging"`, `"isHidden":true`) {
		t.Fatalf("environment detail status=%d body=%s", detail.Code, detail.Body.String())
	}
	restored := serveSentryEnvironment(t, server, owner, http.MethodPut, "/api/0/projects/org/app/environments/staging/", `{"isHidden":false}`)
	if restored.Code != http.StatusOK || !containsAll(restored.Body.String(), `"isHidden":false`) {
		t.Fatalf("environment restore status=%d body=%s", restored.Code, restored.Body.String())
	}
	invalid := serveSentryEnvironment(t, server, owner, http.MethodGet, "/api/0/organizations/org/environments/?visibility=maybe", "")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid visibility status=%d body=%s", invalid.Code, invalid.Body.String())
	}
}

func TestSentryEnvironmentUpdateHonorsProjectRole(t *testing.T) {
	server, _ := managementFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, environment, timestamp, payload)
		VALUES ('event-environment', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', 'production', '2026-08-30T08:00:00Z', '{}');
		INSERT INTO users(id, email, name) VALUES ('viewer-environment', 'viewer@example.com', 'Viewer');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'viewer-environment', 'viewer')
	`); err != nil {
		t.Fatal(err)
	}
	viewer := &auth.Principal{UserID: "viewer-environment", Email: "viewer@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "viewer"}}}
	response := serveSentryEnvironment(t, server, viewer, http.MethodPut, "/api/0/projects/org/app/environments/production/", `{"isHidden":true}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer environment update status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveSentryEnvironment(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/environments/", server.sentryOrganizationEnvironments)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/environments/", server.sentryProjectEnvironments)
	mux.HandleFunc("PUT /api/0/projects/{org_slug}/{project_slug}/environments/", server.sentryProjectEnvironments)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/environments/{environment}/", server.sentryProjectEnvironmentDetail)
	mux.HandleFunc("PUT /api/0/projects/{org_slug}/{project_slug}/environments/{environment}/", server.sentryProjectEnvironmentDetail)
	mux.ServeHTTP(response, request)
	return response
}
