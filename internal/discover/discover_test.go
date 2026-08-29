package discover_test

import (
	"context"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/discover"
	"github.com/barktrace/bark/internal/store"
)

func TestQueryFiltersAndAggregatesDatasets(t *testing.T) {
	t.Parallel()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	seedDiscover(t, st)

	result, err := discover.Query(context.Background(), st.DB, discover.Request{
		Dataset: "logs", ProjectIDs: []string{"project-a"}, Fields: []string{"message", "severity", "release"},
		Query: `severity:error "connection refused"`, Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 1 || result.Data[0]["message"] != "database connection refused" || result.Data[0]["release"] != "api@1.0" {
		t.Fatalf("unexpected log result: %#v", result.Data)
	}

	result, err = discover.Query(context.Background(), st.DB, discover.Request{
		Dataset: "errors", ProjectIDs: []string{"project-a"}, Fields: []string{"level", "count()"},
		OrderBy: "-count()", Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 2 || result.Data[0]["level"] != "error" || result.Data[0]["count()"] != int64(2) {
		t.Fatalf("unexpected error aggregate: %#v", result.Data)
	}

	result, err = discover.Query(context.Background(), st.DB, discover.Request{
		Dataset: "transactions", ProjectIDs: []string{"project-a"}, Fields: []string{"transaction", "count()", "count_unique(project)", "avg(duration)", "p95(duration)"},
		OrderBy: "-p95(duration)", Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 2 || result.Data[0]["transaction"] != "checkout" || result.Data[0]["p95(duration)"] != float64(900) || result.Data[0]["count_unique(project)"] != int64(1) {
		t.Fatalf("unexpected transaction percentile: %#v", result.Data)
	}

	result, err = discover.Query(context.Background(), st.DB, discover.Request{Dataset: "errors", ProjectIDs: []string{"project-a"}, Fields: []string{"max(timestamp)"}, Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)})
	if err != nil || len(result.Data) != 1 || result.Data[0]["max(timestamp)"] != "2026-08-29T12:00:00Z" {
		t.Fatalf("unexpected max timestamp: %#v err=%v", result.Data, err)
	}

	for _, request := range []discover.Request{
		{Dataset: "spans", ProjectIDs: []string{"project-a"}, Fields: []string{"span.op", "avg(duration)"}, Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)},
		{Dataset: "metrics", ProjectIDs: []string{"project-a"}, Fields: []string{"metric.name", "avg(metric.value)"}, Start: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)},
	} {
		result, err = discover.Query(context.Background(), st.DB, request)
		if err != nil || len(result.Data) != 1 {
			t.Fatalf("%s query result=%#v err=%v", request.Dataset, result.Data, err)
		}
	}
}

func TestQueryIsBoundedAndProjectScoped(t *testing.T) {
	t.Parallel()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	seedDiscover(t, st)
	result, err := discover.Query(context.Background(), st.DB, discover.Request{Dataset: "logs", ProjectIDs: []string{"project-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 0 {
		t.Fatalf("returned another project's rows: %#v", result.Data)
	}
	if _, err := discover.Query(context.Background(), st.DB, discover.Request{Dataset: "logs; DROP TABLE logs", ProjectIDs: []string{"project-a"}}); err == nil {
		t.Fatal("unsafe dataset was accepted")
	}
	if _, err := discover.Query(context.Background(), st.DB, discover.Request{Dataset: "logs", ProjectIDs: []string{"project-a"}, Fields: []string{"message); DROP TABLE logs; --"}}); err == nil {
		t.Fatal("unsafe field was accepted")
	}
}

func seedDiscover(t *testing.T, st *store.Store) {
	t.Helper()
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'acme', 'Acme');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES
			('project-a', '1', 'org', 'api', 'API', 'key-a'), ('project-b', '2', 'org', 'hidden', 'Hidden', 'key-b');
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES ('release', 'org', 'api@1.0', '2026-08-29T09:00:00Z', '2026-08-29T12:00:00Z');
		INSERT INTO issues(id, project_id, fingerprint, title, status, level, first_seen_at, last_seen_at, event_count) VALUES
			('issue-a', 'project-a', 'a', 'Database unavailable', 'unresolved', 'error', '2026-08-29T10:00:00Z', '2026-08-29T12:00:00Z', 2),
			('issue-b', 'project-a', 'b', 'Slow request', 'resolved', 'warning', '2026-08-29T11:00:00Z', '2026-08-29T11:00:00Z', 1);
		INSERT INTO events(id, event_id, project_id, issue_id, release_id, environment, platform, level, timestamp, payload) VALUES
			('event-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project-a', 'issue-a', 'release', 'production', 'go', 'error', '2026-08-29T10:00:00Z', '{}'),
			('event-b', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'project-a', 'issue-a', 'release', 'production', 'go', 'error', '2026-08-29T12:00:00Z', '{}'),
			('event-c', 'cccccccccccccccccccccccccccccccc', 'project-a', 'issue-b', NULL, 'staging', 'go', 'warning', '2026-08-29T11:00:00Z', '{}');
		INSERT INTO logs(id, project_id, release_id, timestamp, level, message, environment, trace_id, span_id) VALUES
			('log-a', 'project-a', 'release', '2026-08-29T10:00:00Z', 'error', 'database connection refused', 'production', 'trace-a', 'span-a'),
			('log-b', 'project-a', NULL, '2026-08-29T11:00:00Z', 'info', 'request complete', 'staging', 'trace-b', 'span-b');
		INSERT INTO transactions(id, event_id, project_id, release_id, trace_id, span_id, name, operation, status, environment, started_at, finished_at, duration_ms, span_count, payload) VALUES
			('tx-a', 'txeventa', 'project-a', 'release', 'trace-a', 'root-a', 'checkout', 'http.server', 'ok', 'production', '2026-08-29T09:59:59Z', '2026-08-29T10:00:00Z', 900, 3, '{}'),
			('tx-b', 'txeventb', 'project-a', 'release', 'trace-b', 'root-b', 'checkout', 'http.server', 'ok', 'production', '2026-08-29T10:59:59Z', '2026-08-29T11:00:00Z', 100, 2, '{}'),
			('tx-c', 'txeventc', 'project-a', NULL, 'trace-c', 'root-c', 'health', 'http.server', 'ok', 'production', '2026-08-29T11:59:59Z', '2026-08-29T12:00:00Z', 20, 1, '{}');
		INSERT INTO spans(id, project_id, transaction_id, trace_id, span_id, operation, description, status, started_at, finished_at, duration_ms) VALUES
			('child-a', 'project-a', 'tx-a', 'trace-a', 'child-a', 'db.sql', 'SELECT checkout', 'ok', '2026-08-29T09:59:59Z', '2026-08-29T10:00:00Z', 120);
		INSERT INTO metric_points(project_id, name, metric_type, value, unit, timestamp) VALUES
			('project-a', 'checkout.duration', 'distribution', 120, 'millisecond', '2026-08-29T10:00:00Z');
	`)
	if err != nil {
		t.Fatal(err)
	}
}
