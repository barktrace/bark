package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryMonitorLifecycleAndCheckins(t *testing.T) {
	server, principal := managementFixture(t)
	created := serveSentryMonitors(t, server, principal, http.MethodPost, "/api/0/organizations/org/monitors/", `{
		"name":"Hourly billing","slug":"billing","project":"1",
		"config":{"schedule":{"type":"interval","value":[2,"hour"]},"checkin_margin":10,"max_runtime":45,"timezone":"Europe/Paris"}
	}`)
	if created.Code != http.StatusCreated || !containsAll(created.Body.String(), `"slug":"billing"`, `"status":"active"`, `"lastCheckInStatus":"unknown"`, `"value":[120,"minute"]`, `"id":"1"`) {
		t.Fatalf("create monitor status=%d body=%s", created.Code, created.Body.String())
	}
	var monitorID string
	if err := server.store.DB.QueryRow(`SELECT id FROM cron_monitors WHERE project_id = 'project' AND slug = 'billing'`).Scan(&monitorID); err != nil {
		t.Fatal(err)
	}
	_, err := server.store.DB.Exec(`INSERT INTO cron_checkins(id, checkin_id, monitor_id, status, duration, release, environment, started_at, finished_at, created_at) VALUES ('row', 'check-in', ?, 'ok', 2.5, 'app@1', 'production', '2026-08-30T10:00:00Z', '2026-08-30T10:00:02.5Z', '2026-08-30T10:00:02.5Z')`, monitorID)
	if err != nil {
		t.Fatal(err)
	}

	listed := serveSentryMonitors(t, server, principal, http.MethodGet, "/api/0/organizations/org/monitors/", "")
	if listed.Code != http.StatusOK || !containsAll(listed.Body.String(), `"slug":"billing"`, `"project":{"id":"1"`) {
		t.Fatalf("list monitors status=%d body=%s", listed.Code, listed.Body.String())
	}
	detail := serveSentryMonitors(t, server, principal, http.MethodGet, "/api/0/organizations/org/monitors/billing/", "")
	if detail.Code != http.StatusOK || !containsAll(detail.Body.String(), `"checkin_margin":10`, `"timezone":"Europe/Paris"`) {
		t.Fatalf("monitor detail status=%d body=%s", detail.Code, detail.Body.String())
	}
	updated := serveSentryMonitors(t, server, principal, http.MethodPut, "/api/0/organizations/org/monitors/billing/", `{"name":"Nightly billing","config":{"schedule":{"type":"crontab","value":"0 2 * * *"},"timezone":"UTC"}}`)
	if updated.Code != http.StatusOK || !containsAll(updated.Body.String(), `"name":"Nightly billing"`, `"type":"crontab"`, `"value":"0 2 * * *"`) {
		t.Fatalf("update monitor status=%d body=%s", updated.Code, updated.Body.String())
	}
	checkins := serveSentryMonitors(t, server, principal, http.MethodGet, "/api/0/organizations/org/monitors/billing/checkins/?status=ok", "")
	if checkins.Code != http.StatusOK || !containsAll(checkins.Body.String(), `"id":"check-in"`, `"duration":2.5`, `"environment":"production"`, `"release":"app@1"`) {
		t.Fatalf("check-in list status=%d body=%s", checkins.Code, checkins.Body.String())
	}
	deleted := serveSentryMonitors(t, server, principal, http.MethodDelete, "/api/0/organizations/org/monitors/billing/", "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete monitor status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	var audits int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE target_type = 'cron_monitor' AND target_id = ?`, monitorID).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("monitor audit count=%d err=%v", audits, err)
	}
}

func TestSentryMonitorsEnforceProjectPermissions(t *testing.T) {
	server, _ := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('restricted', 'restricted@example.com', 'Restricted');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'restricted', 'member');
		INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'restricted', 'none');
		INSERT INTO cron_monitors(id, project_id, slug, name, schedule_type, schedule_value) VALUES ('monitor', 'project', 'private', 'Private', 'interval', '5');
	`)
	if err != nil {
		t.Fatal(err)
	}
	principal := &auth.Principal{UserID: "restricted", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", Role: "member"}}}
	listed := serveSentryMonitors(t, server, principal, http.MethodGet, "/api/0/organizations/org/monitors/", "")
	if listed.Code != http.StatusOK || listed.Body.String() != "[]\n" {
		t.Fatalf("restricted monitor leaked from list: status=%d body=%s", listed.Code, listed.Body.String())
	}
	detail := serveSentryMonitors(t, server, principal, http.MethodGet, "/api/0/organizations/org/monitors/private/", "")
	if detail.Code != http.StatusNotFound {
		t.Fatalf("restricted monitor detail leaked: status=%d body=%s", detail.Code, detail.Body.String())
	}
	created := serveSentryMonitors(t, server, principal, http.MethodPost, "/api/0/organizations/org/monitors/", `{"name":"Denied","project":"1"}`)
	if created.Code != http.StatusForbidden {
		t.Fatalf("restricted user created monitor: status=%d body=%s", created.Code, created.Body.String())
	}
}

func TestSentryMonitorValidation(t *testing.T) {
	server, principal := managementFixture(t)
	for _, body := range []string{
		`{"name":"Bad project","project":"missing"}`,
		`{"name":"Bad timezone","project":"1","config":{"timezone":"Mars/Olympus"}}`,
		`{"name":"Bad schedule","project":"1","config":{"schedule":{"type":"crontab","value":"invalid"}}}`,
		`{"name":"Bad margin","project":"1","config":{"checkin_margin":0}}`,
	} {
		response := serveSentryMonitors(t, server, principal, http.MethodPost, "/api/0/organizations/org/monitors/", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid monitor accepted: status=%d body=%s input=%s", response.Code, response.Body.String(), body)
		}
	}
}

func serveSentryMonitors(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/monitors/", server.sentryOrganizationMonitors)
	mux.HandleFunc("POST /api/0/organizations/{org_slug}/monitors/", server.sentryOrganizationMonitors)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/monitors/{monitor_id}/", server.sentryOrganizationMonitorDetail)
	mux.HandleFunc("PUT /api/0/organizations/{org_slug}/monitors/{monitor_id}/", server.sentryOrganizationMonitorDetail)
	mux.HandleFunc("DELETE /api/0/organizations/{org_slug}/monitors/{monitor_id}/", server.sentryOrganizationMonitorDetail)
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/monitors/{monitor_id}/checkins/", server.sentryOrganizationMonitorCheckins)
	mux.ServeHTTP(response, request)
	return response
}
