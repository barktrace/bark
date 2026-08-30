package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryProjectStatsBucketsReceivedAndFilteredEvents(t *testing.T) {
	server, principal := managementFixture(t)
	_, err := server.store.DB.Exec(`
		INSERT INTO events(id, event_id, project_id, issue_id, timestamp, received_at, payload) VALUES
			('event-1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', '2026-08-29T10:02:00Z', '2026-08-29T10:02:00Z', '{}'),
			('event-2', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'project', 'issue', '2026-08-29T10:58:00Z', '2026-08-29T10:58:00Z', '{}'),
			('event-3', 'cccccccccccccccccccccccccccccccc', 'project', 'issue', '2026-08-29T12:05:00Z', '2026-08-29T12:05:00Z', '{}');
		INSERT INTO ingestion_outcomes(project_id, category, outcome, reason, quantity, created_at) VALUES
			('project', 'error', 'filtered', 'discarded_issue', 3, '2026-08-29T11:10:00Z');
	`)
	if err != nil {
		t.Fatal(err)
	}

	received := serveSentryStats(t, server, principal, "/api/0/projects/org/app/stats/?since=1787997600&until=1788008400&resolution=1h")
	if received.Code != http.StatusOK || received.Body.String() != "[[1787997600,2],[1788001200,0],[1788004800,1]]\n" {
		t.Fatalf("unexpected received stats status=%d body=%s", received.Code, received.Body.String())
	}
	filtered := serveSentryStats(t, server, principal, "/api/0/projects/org/app/stats/?stat=blacklisted&since=1787997600&until=1788008400&resolution=1h")
	if filtered.Code != http.StatusOK || filtered.Body.String() != "[[1787997600,0],[1788001200,3],[1788004800,0]]\n" {
		t.Fatalf("unexpected blacklisted stats status=%d body=%s", filtered.Code, filtered.Body.String())
	}
}

func TestSentryProjectStatsValidationAndAuthorization(t *testing.T) {
	server, principal := managementFixture(t)
	for _, target := range []string{
		"/api/0/projects/org/app/stats/?stat=unknown",
		"/api/0/projects/org/app/stats/?since=nope",
		"/api/0/projects/org/app/stats/?since=100&until=50",
		"/api/0/projects/org/app/stats/?since=0&until=10000000&resolution=10s",
		"/api/0/projects/org/app/stats/?resolution=1m",
	} {
		response := serveSentryStats(t, server, principal, target)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected bad request for %s: status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
	denied := &auth.Principal{UserID: "outsider"}
	response := serveSentryStats(t, server, denied, "/api/0/projects/org/app/stats/")
	if response.Code != http.StatusNotFound {
		t.Fatalf("unauthorized project was exposed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestParseSentryStatsRangeDefaults(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 34, 56, 0, time.UTC)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	parsed, err := parseSentryStatsRange(now, request)
	if err != nil || parsed.start != now.Add(-24*time.Hour) || parsed.end != now || parsed.resolution != time.Hour {
		t.Fatalf("unexpected defaults: %#v err=%v", parsed, err)
	}
}

func TestSentryProjectStatsReturnsJSONArrayContract(t *testing.T) {
	server, principal := managementFixture(t)
	response := serveSentryStats(t, server, principal, "/api/0/projects/org/app/stats/?since=1787997600&until=1787997610&resolution=10s")
	var payload [][2]int64
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload) != 1 || payload[0][0] != 1787997600 {
		t.Fatalf("invalid Sentry stats contract: body=%s err=%v", response.Body.String(), err)
	}
}

func serveSentryStats(t *testing.T, server *Server, principal *auth.Principal, target string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, http.MethodGet, target, "")
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/stats/", server.sentryProjectStats)
	mux.ServeHTTP(response, request)
	return response
}
