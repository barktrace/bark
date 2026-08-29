package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
)

func TestCleanupOrganizationDryRunAndDelete(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO issues(id, project_id, fingerprint, title, first_seen_at, last_seen_at) VALUES ('issue', 'project', 'fp', 'Old issue', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z');
		INSERT INTO events(id, event_id, project_id, issue_id, timestamp, received_at, payload) VALUES ('event', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'issue', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z', '{}');
	`)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	dry, err := CleanupOrganization(context.Background(), st.DB, "org", cutoff, []string{"events"}, true)
	if err != nil || dry.Deleted["events"] != 1 {
		t.Fatalf("dry run = %#v, %v", dry, err)
	}
	var count int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count)
	if count != 1 {
		t.Fatal("dry run deleted an event")
	}
	result, err := CleanupOrganization(context.Background(), st.DB, "org", cutoff, []string{"events"}, false)
	if err != nil || result.Deleted["events"] != 1 {
		t.Fatalf("cleanup = %#v, %v", result, err)
	}
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&count)
	if count != 0 {
		t.Fatal("orphaned issue was retained")
	}
}
