package uptime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
)

func TestCheckNowOpensAndResolvesIncident(t *testing.T) {
	t.Parallel()
	var status atomic.Int64
	status.Store(http.StatusServiceUnavailable)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	defer target.Close()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'default', 'Default');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO uptime_monitors(id, project_id, name, url, interval_seconds, timeout_seconds, expected_status_min, expected_status_max, next_check_at) VALUES ('monitor', 'project', 'API', ?, 60, 3, 200, 399, ?);
	`, target.URL, now)
	if err != nil {
		t.Fatal(err)
	}
	service := New(st, true)
	first, err := service.CheckNow(context.Background(), "monitor")
	if err != nil || first.Status != "down" || first.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("first result = %+v, err=%v", first, err)
	}
	status.Store(http.StatusNoContent)
	second, err := service.CheckNow(context.Background(), "monitor")
	if err != nil || second.Status != "up" {
		t.Fatalf("second result = %+v, err=%v", second, err)
	}
	var checks, openIncidents, resolvedIncidents int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM uptime_checks`).Scan(&checks)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM uptime_incidents WHERE resolved_at IS NULL`).Scan(&openIncidents)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM uptime_incidents WHERE resolved_at IS NOT NULL`).Scan(&resolvedIncidents)
	if checks != 2 || openIncidents != 0 || resolvedIncidents != 1 {
		t.Fatalf("checks=%d open=%d resolved=%d, want 2/0/1", checks, openIncidents, resolvedIncidents)
	}
}

func TestValidateURLBlocksPrivateTargetsByDefault(t *testing.T) {
	t.Parallel()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := New(st, false).ValidateURL(context.Background(), "http://127.0.0.1:8080/healthz"); err == nil {
		t.Fatal("private target unexpectedly accepted")
	}
}
