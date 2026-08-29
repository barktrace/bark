package store

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
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
	if migrations != 17 {
		t.Fatalf("migration count = %d, want 17", migrations)
	}

	var journalMode string
	if err := st.DB.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}
}

func TestRemoteLibSQLSupportsConcurrentReplicas(t *testing.T) {
	databaseURL := os.Getenv("BARKTRACE_TEST_LIBSQL_URL")
	if databaseURL == "" {
		t.Skip("BARKTRACE_TEST_LIBSQL_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const replicas = 2
	stores := make(chan *Store, replicas)
	errors := make(chan error, replicas)
	start := make(chan struct{})
	dataDirs := make([]string, replicas)
	for index := range replicas {
		dataDirs[index] = t.TempDir()
	}
	var workers sync.WaitGroup
	workers.Add(replicas)
	for index := range replicas {
		go func(dataDir string) {
			defer workers.Done()
			<-start
			st, err := OpenWithDatabase(ctx, dataDir, nil, databaseURL, os.Getenv("BARKTRACE_TEST_LIBSQL_TOKEN"))
			if err != nil {
				errors <- err
				return
			}
			stores <- st
		}(dataDirs[index])
	}
	close(start)
	workers.Wait()
	close(stores)
	close(errors)
	for err := range errors {
		t.Errorf("open remote replica: %v", err)
	}
	opened := make([]*Store, 0, replicas)
	for st := range stores {
		opened = append(opened, st)
		defer st.Close()
	}
	if len(opened) != replicas {
		t.Fatalf("opened %d replicas, want %d", len(opened), replicas)
	}
	if _, err := opened[0].DB.ExecContext(ctx, `INSERT INTO organizations(id, slug, name) VALUES ('remote-org', 'remote-org', 'Remote')`); err != nil {
		t.Fatalf("write through first replica: %v", err)
	}
	var name string
	if err := opened[1].DB.QueryRowContext(ctx, `SELECT name FROM organizations WHERE id = 'remote-org'`).Scan(&name); err != nil {
		t.Fatalf("read through second replica: %v", err)
	}
	if name != "Remote" {
		t.Fatalf("remote organization name = %q", name)
	}
}

func TestConcurrentOpenSerializesMigrations(t *testing.T) {
	dataDir := t.TempDir()
	const replicas = 4
	stores := make(chan *Store, replicas)
	errors := make(chan error, replicas)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(replicas)
	for range replicas {
		go func() {
			defer workers.Done()
			<-start
			st, err := Open(context.Background(), dataDir)
			if err != nil {
				errors <- err
				return
			}
			stores <- st
		}()
	}
	close(start)
	workers.Wait()
	close(stores)
	close(errors)
	for err := range errors {
		t.Errorf("concurrent open: %v", err)
	}
	opened := 0
	for st := range stores {
		opened++
		var migrations int
		if err := st.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations); err != nil {
			t.Errorf("count migrations: %v", err)
		} else if migrations != 17 {
			t.Errorf("migration count = %d, want 17", migrations)
		}
		_ = st.Close()
	}
	if opened != replicas {
		t.Fatalf("opened %d stores, want %d", opened, replicas)
	}
}
