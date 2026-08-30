package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryOrganizationSessionsAggregatesReleaseHealth(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES
			('release-one', 'org', 'app@1.0.0', '2026-08-30T08:00:00Z', '2026-08-30T11:00:00Z'),
			('release-two', 'org', 'app@2.0.0', '2026-08-30T08:00:00Z', '2026-08-30T11:00:00Z');
		INSERT INTO project_sessions(id, session_id, project_id, release_id, environment, distinct_id, status, started_at, duration, errors) VALUES
			('session-one', 'one', 'project', 'release-one', 'production', 'user-1', 'ok', '2026-08-30T08:15:00Z', 10, 0),
			('session-two', 'two', 'project', 'release-one', 'production', 'user-1', 'ok', '2026-08-30T08:45:00Z', 20, 1),
			('session-three', 'three', 'project', 'release-one', 'production', 'user-2', 'crashed', '2026-08-30T10:15:00Z', 30, 1),
			('session-four', 'four', 'project', 'release-two', 'staging', 'user-3', 'abnormal', '2026-08-30T10:30:00Z', NULL, 0)
	`)
	if err != nil {
		t.Fatal(err)
	}

	query := url.Values{
		"start":    {"2026-08-30T08:00:00Z"},
		"end":      {"2026-08-30T12:00:00Z"},
		"interval": {"2h"},
		"project":  {"1"},
		"groupBy":  {"release"},
		"field":    {"sum(session)", "count_unique(user)", "avg(session.duration)", "crash_free_rate(session)", "crash_free_rate(user)"},
	}
	response := serveSentrySessions(t, server, principal, "/api/0/organizations/org/sessions/?"+query.Encode())
	if response.Code != http.StatusOK {
		t.Fatalf("sessions status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Intervals []string `json:"intervals"`
		Groups    []struct {
			By     map[string]string `json:"by"`
			Totals map[string]any    `json:"totals"`
			Series map[string][]any  `json:"series"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Intervals) != 2 || len(payload.Groups) != 2 {
		t.Fatalf("unexpected release-health shape: %+v", payload)
	}
	var releaseOne map[string]any
	var releaseOneSeries map[string][]any
	for _, group := range payload.Groups {
		if group.By["release"] == "app@1.0.0" {
			releaseOne, releaseOneSeries = group.Totals, group.Series
		}
	}
	if releaseOne == nil || releaseOne["sum(session)"] != float64(3) || releaseOne["count_unique(user)"] != float64(2) || releaseOne["avg(session.duration)"] != float64(20) {
		t.Fatalf("release totals = %#v", releaseOne)
	}
	if releaseOne["crash_free_rate(session)"].(float64) < 66.6 || releaseOne["crash_free_rate(user)"] != float64(50) {
		t.Fatalf("crash-free totals = %#v", releaseOne)
	}
	if values := releaseOneSeries["sum(session)"]; len(values) != 2 || values[0] != float64(2) || values[1] != float64(1) {
		t.Fatalf("session series = %#v", values)
	}

	filteredQuery := url.Values{
		"start": {"2026-08-30T08:00:00Z"}, "end": {"2026-08-30T12:00:00Z"},
		"interval": {"1h"}, "environment": {"staging"}, "groupBy": {"session.status"},
	}
	filtered := serveSentrySessions(t, server, principal, "/api/0/organizations/org/sessions/?"+filteredQuery.Encode())
	if filtered.Code != http.StatusOK || !containsAll(filtered.Body.String(), `"session.status":"abnormal"`, `"sum(session)":1`) || containsAll(filtered.Body.String(), `"session.status":"healthy"`) {
		t.Fatalf("filtered sessions status=%d body=%s", filtered.Code, filtered.Body.String())
	}

	invalid := serveSentrySessions(t, server, principal, "/api/0/organizations/org/sessions/?statsPeriod=24h&interval=1s")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid interval status=%d body=%s", invalid.Code, invalid.Body.String())
	}
}

func TestSentryOrganizationSessionsRequiresMembership(t *testing.T) {
	server, _ := managementFixture(t)
	outsider := &auth.Principal{UserID: "outsider", Email: "outsider@example.com"}
	response := serveSentrySessions(t, server, outsider, "/api/0/organizations/org/sessions/?statsPeriod=24h")
	if response.Code != http.StatusNotFound {
		t.Fatalf("outsider sessions status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveSentrySessions(t *testing.T, server *Server, principal *auth.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, http.MethodGet, target, "")
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/organizations/{org_slug}/sessions/", server.sentryOrganizationSessions)
	mux.ServeHTTP(response, request)
	return response
}
