package store

import (
	"context"
	"testing"
)

func TestOpenAppliesMigrations(t *testing.T) {
	t.Parallel()

	st, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var migrations int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migrations != 3 {
		t.Fatalf("migration count = %d, want 3", migrations)
	}

	var journalMode string
	if err := st.DB.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}
}
