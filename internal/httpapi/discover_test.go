package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestDiscoverQueryAppliesProjectOverrides(t *testing.T) {
	server, owner := discoverHTTPFixture(t)
	if _, err := server.store.DB.Exec(`INSERT INTO project_memberships(project_id, user_id, role) VALUES ('hidden', 'owner', 'none')`); err != nil {
		t.Fatal(err)
	}
	request := principalRequest(t, owner, http.MethodGet, "/discover?organization_id=org&dataset=logs&field=project&field=count()&stats_period=90d", "")
	response := httptest.NewRecorder()
	server.discoverQuery(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("discover status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 1 || result.Data[0]["project"] != "api" || result.Data[0]["count()"] != float64(1) {
		t.Fatalf("unexpected discover data: %#v", result.Data)
	}
}

func TestSentryOrganizationEventsSupportsDiscoverDatasets(t *testing.T) {
	server, owner := discoverHTTPFixture(t)
	request := principalRequest(t, owner, http.MethodGet, "/api/0/organizations/acme/events/?dataset=transactions&field=transaction&field=p95(duration)&statsPeriod=90d", "")
	request.SetPathValue("org_slug", "acme")
	response := httptest.NewRecorder()
	server.sentryOrganizationEvents(response, request)
	if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("events status=%d body=%s", response.Code, response.Body.String())
	}
	if body := response.Body.String(); !containsAll(body, `"transaction":"checkout"`, `"p95(duration)":420`) {
		t.Fatalf("unexpected Sentry Discover response: %s", body)
	}
}

func TestDashboardCRUDRequiresOrganizationAdmin(t *testing.T) {
	server, owner := discoverHTTPFixture(t)
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", Role: "member"}}}

	denied := principalRequest(t, member, http.MethodPost, "/dashboards", `{"organization_id":"org","project_id":"project","title":"Operations"}`)
	response := httptest.NewRecorder()
	server.dashboards(response, denied)
	if response.Code != http.StatusForbidden {
		t.Fatalf("member create status=%d body=%s", response.Code, response.Body.String())
	}

	create := principalRequest(t, owner, http.MethodPost, "/dashboards", `{"organization_id":"org","project_id":"project","title":"Operations","description":"Production signals"}`)
	response = httptest.NewRecorder()
	server.dashboards(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var dashboard map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &dashboard); err != nil {
		t.Fatal(err)
	}
	id, _ := dashboard["id"].(string)
	if id == "" {
		t.Fatalf("dashboard ID missing: %#v", dashboard)
	}
	invalidWidget := principalRequest(t, owner, http.MethodPost, "/dashboards/"+id+"/widgets", `{"title":"Unsafe","dataset":"errors","fields":["payload"],"stats_period":"7d"}`)
	invalidWidget.SetPathValue("dashboard_id", id)
	response = httptest.NewRecorder()
	server.dashboardWidgets(response, invalidWidget)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid widget status=%d body=%s", response.Code, response.Body.String())
	}

	widget := principalRequest(t, owner, http.MethodPost, "/dashboards/"+id+"/widgets", `{"title":"Error volume","dataset":"errors","display_type":"number","fields":["count()"],"stats_period":"7d","limit":1}`)
	widget.SetPathValue("dashboard_id", id)
	response = httptest.NewRecorder()
	server.dashboardWidgets(response, widget)
	if response.Code != http.StatusCreated || !containsAll(response.Body.String(), `"title":"Error volume"`, `"fields":["count()"]`) {
		t.Fatalf("widget status=%d body=%s", response.Code, response.Body.String())
	}

	list := principalRequest(t, member, http.MethodGet, "/dashboards?organization_id=org", "")
	response = httptest.NewRecorder()
	server.dashboards(response, list)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"title":"Operations"`, `"title":"Error volume"`) {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
}

func discoverHTTPFixture(t *testing.T) (*Server, *auth.Principal) {
	t.Helper()
	st := openTestStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'acme', 'Acme');
		INSERT INTO users(id, email, name) VALUES ('owner', 'owner@example.com', 'Owner'), ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'owner', 'owner'), ('org', 'member', 'member');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES
			('project', '1', 'org', 'api', 'API', 'key-a'), ('hidden', '2', 'org', 'hidden', 'Hidden', 'key-b');
		INSERT INTO logs(id, project_id, timestamp, level, message) VALUES
			('log-a', 'project', CURRENT_TIMESTAMP, 'error', 'visible'), ('log-b', 'hidden', CURRENT_TIMESTAMP, 'error', 'hidden');
		INSERT INTO transactions(id, event_id, project_id, trace_id, span_id, name, started_at, finished_at, duration_ms, payload) VALUES
			('tx-a', 'event-a', 'project', 'trace-a', 'span-a', 'checkout', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 420, '{}');
	`)
	if err != nil {
		t.Fatal(err)
	}
	server := New(configForTest(), st, &auth.Service{})
	owner := &auth.Principal{UserID: "owner", Email: "owner@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "acme", OrganizationName: "Acme", Role: "owner"}}}
	return server, owner
}

func containsAll(value string, pieces ...string) bool {
	for _, piece := range pieces {
		if !strings.Contains(value, piece) {
			return false
		}
	}
	return true
}
