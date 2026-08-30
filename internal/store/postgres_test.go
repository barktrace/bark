package store

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRebindPostgres(t *testing.T) {
	query := `SELECT ?, '?', "?", title FROM issues WHERE title LIKE '%' || ? || '%' AND note = 'it''s ?'`
	want := `SELECT $1, '?', "?", title FROM issues WHERE title LIKE '%' || $2 || '%' AND note = 'it''s ?'`
	if got := rebindPostgres(query); got != want {
		t.Fatalf("unexpected rebound query:\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresQueryCompatibility(t *testing.T) {
	query := postgresQuery(`SELECT rowid, CAST(strftime('%s', timestamp) AS INTEGER), CAST(strftime('%s', created_at) AS INTEGER), MAX(score, excluded.score), CASE WHEN excluded.score > score THEN excluded.reason ELSE reason END FROM issues WHERE title LIKE ? COLLATE NOCASE AND datetime(created_at) >= datetime(?)`)
	for _, expected := range []string{"legacy_id", "ILIKE $1", "created_at::timestamptz >= $2::timestamptz", "CAST(EXTRACT(EPOCH FROM timestamp) AS BIGINT)", "CAST(EXTRACT(EPOCH FROM created_at) AS BIGINT)", "GREATEST(issue_suspect_commits.score, excluded.score)", "excluded.score > issue_suspect_commits.score", "ELSE issue_suspect_commits.reason END"} {
		if !strings.Contains(query, expected) {
			t.Fatalf("expected %q in %q", expected, query)
		}
	}
}

func TestPostgresMigrationCompatibility(t *testing.T) {
	migration := postgresMigration("CREATE TABLE examples (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    payload BLOB NOT NULL DEFAULT '{}',\n    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP\n);")
	for _, expected := range []string{"BIGSERIAL PRIMARY KEY", "BYTEA NOT NULL DEFAULT convert_to('{}', 'UTF8')", "created_at TIMESTAMPTZ"} {
		if !strings.Contains(migration, expected) {
			t.Fatalf("expected %q in %q", expected, migration)
		}
	}
}

func TestInvalidPostgresURLDoesNotLeakPassword(t *testing.T) {
	_, err := OpenWithDatabase(context.Background(), t.TempDir(), nil, "postgres://barktrace:top-secret@%zz", "")
	if err == nil {
		t.Fatal("expected invalid PostgreSQL URL error")
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("error leaked database password: %v", err)
	}
}

func TestPostgresOpenAndMigrate(t *testing.T) {
	databaseURL := os.Getenv("BARKTRACE_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("BARKTRACE_TEST_POSTGRES_URL is not set")
	}
	ctx := context.Background()
	store, err := OpenWithDatabase(ctx, t.TempDir(), nil, databaseURL, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if store.dialect != dialectPostgres {
		t.Fatal("expected PostgreSQL dialect")
	}
	var migrations int
	if err := store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations == 0 {
		t.Fatal("expected applied migrations")
	}
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM organizations WHERE id = ?`, "org-postgres"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = store.DB.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = ?`, "org-postgres")
	})
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO organizations(id, name, slug) VALUES (?, ?, ?)`, "org-postgres", "Postgres", "postgres"); err != nil {
		t.Fatal(err)
	}
	var name string
	if err := store.DB.QueryRowContext(ctx, `SELECT name FROM organizations WHERE slug = ?`, "postgres").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Postgres" {
		t.Fatalf("unexpected organization name %q", name)
	}
}
