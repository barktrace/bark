package maintenance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/barktrace/bark/internal/store"
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

func TestCleanupStoreRemovesReplayBlobAndMetadata(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('user', 'viewer@example.com', 'Viewer');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
	`); err != nil {
		t.Fatal(err)
	}
	stored, err := st.Blobs.Put(strings.NewReader("recording"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`
		INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size) VALUES ('blob', 'org', 'project', 'replay_recording', ?, ?, ?);
		INSERT INTO replays(id, replay_id, project_id, recording_blob_id, started_at, finished_at) VALUES ('replay', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'project', 'blob', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z');
		INSERT INTO issues(id, project_id, fingerprint, title, level, first_seen_at, last_seen_at, issue_type, issue_category) VALUES ('replay-issue', 'project', 'replay-fingerprint', 'Rage click on button#checkout', 'warning', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z', 'rage_click', 'replay');
		INSERT INTO events(id, event_id, project_id, issue_id, level, timestamp, received_at, payload) VALUES ('replay-event', 'cccccccccccccccccccccccccccccccc', 'project', 'replay-issue', 'warning', '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z', '{}');
		INSERT INTO replay_error_links(project_id, replay_id, segment_id, event_id) VALUES ('project', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
		INSERT INTO replay_views(project_id, replay_id, user_id, viewed_at) VALUES ('project', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'user', '2020-01-01T00:00:00Z');
		INSERT INTO replay_clicks(project_id, replay_id, segment_id, sequence, node_id, timestamp, dom_element, element, is_rage) VALUES ('project', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, 1, 42, '2020-01-01T00:00:00Z', 'button#checkout', '{}', 1);
		INSERT INTO replay_issue_occurrences(project_id, replay_id, segment_id, issue_type, dom_element, timestamp, issue_id, event_id) VALUES ('project', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, 'rage_click', 'button#checkout', '2020-01-01T00:00:00Z', 'replay-issue', 'replay-event');
	`, stored.Key, stored.Checksum, stored.Size); err != nil {
		t.Fatal(err)
	}
	result, err := CleanupStore(context.Background(), st, "org", time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC), []string{"replays"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted["replays"] != 1 || result.Deleted["blobs"] != 1 {
		t.Fatalf("cleanup result = %#v", result)
	}
	var blobs, queued, links, views, clicks, occurrences, events, issues int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM blobs`).Scan(&blobs)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM blob_deletion_queue`).Scan(&queued)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM replay_error_links`).Scan(&links)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM replay_views`).Scan(&views)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM replay_clicks`).Scan(&clicks)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM replay_issue_occurrences`).Scan(&occurrences)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&issues)
	if blobs != 0 || queued != 0 || links != 0 || views != 0 || clicks != 0 || occurrences != 0 || events != 0 || issues != 0 {
		t.Fatalf("blobs=%d queued=%d links=%d views=%d clicks=%d occurrences=%d events=%d issues=%d", blobs, queued, links, views, clicks, occurrences, events, issues)
	}
	if file, err := st.Blobs.Open(stored.Key); err == nil {
		_ = file.Close()
		t.Fatal("orphaned replay blob remains in backing storage")
	}
}
