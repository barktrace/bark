package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/blobstore"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mattn/go-sqlite3"
	"github.com/tursodatabase/libsql-client-go/libsql"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Store struct {
	DB      *sql.DB
	DataDir string
	Blobs   blobstore.Backend
	dialect databaseDialect
}

type databaseDialect uint8

const (
	dialectSQLite databaseDialect = iota
	dialectPostgres
)

func Open(ctx context.Context, dataDir string) (*Store, error) {
	return OpenWithBlobs(ctx, dataDir, nil)
}

func OpenWithBlobs(ctx context.Context, dataDir string, blobs blobstore.Backend) (*Store, error) {
	return OpenWithDatabase(ctx, dataDir, blobs, "", "")
}

// OpenWithDatabase opens local SQLite by default. Remote libSQL provides a
// SQLite-compatible shared metadata plane; PostgreSQL is also supported for a
// conventional external database deployment.
func OpenWithDatabase(ctx context.Context, dataDir string, blobs blobstore.Backend, databaseURL, authToken string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	var db *sql.DB
	var err error
	dialect := dialectSQLite
	if strings.TrimSpace(databaseURL) == "" {
		path := filepath.Join(dataDir, "barktrace.db")
		dsn := fmt.Sprintf("file:%s?_foreign_keys=on&_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000", path)
		db, err = sql.Open("sqlite3", dsn)
	} else if isPostgresURL(databaseURL) {
		dialect = dialectPostgres
		var config *pgx.ConnConfig
		config, err = pgx.ParseConfig(databaseURL)
		if err != nil {
			return nil, fmt.Errorf("open metadata database: invalid PostgreSQL configuration")
		}
		config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		db = sql.OpenDB(newPostgresConnector(stdlib.GetConnector(*config)))
	} else {
		options := make([]libsql.Option, 0, 1)
		if authToken != "" {
			options = append(options, libsql.WithAuthToken(authToken))
		}
		var connector driver.Connector
		connector, err = libsql.NewConnector(databaseURL, options...)
		if err == nil {
			db = sql.OpenDB(connector)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open metadata database: %w", err)
	}
	// One connection keeps the footprint low, avoids SQLITE_BUSY surprises for
	// local files, and prevents one replica from monopolizing a remote service.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := pingDatabase(ctx, db, dialect); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping metadata database: %w", err)
	}
	if blobs == nil {
		blobs, err = blobstore.New(dataDir)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("open blob store: %w", err)
		}
	}
	s := &Store{DB: db, DataDir: dataDir, Blobs: blobs, dialect: dialect}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Opening a SQLite connection applies the DSN's WAL pragma. SQLite can return
// SQLITE_BUSY immediately for that pragma even when a busy timeout is set, so
// simultaneous first boots need a bounded retry before migrations serialize
// through schema_migration_lock.
func pingDatabase(ctx context.Context, db *sql.DB, dialect databaseDialect) error {
	if dialect != dialectSQLite {
		return db.PingContext(ctx)
	}
	retryContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		err := db.PingContext(retryContext)
		if err == nil || !sqliteBusy(err) {
			return err
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-retryContext.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case <-timer.C:
		}
	}
}

func sqliteBusy(err error) bool {
	var sqliteError sqlite3.Error
	return errors.As(err, &sqliteError) && (sqliteError.Code == sqlite3.ErrBusy || sqliteError.Code == sqlite3.ErrLocked)
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migration_lock (id INTEGER PRIMARY KEY CHECK (id = 1), holder TEXT NOT NULL, expires_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create migration lock: %w", err)
	}
	initializeLock := `INSERT OR IGNORE INTO schema_migration_lock(id, holder, expires_at) VALUES (1, '', '1970-01-01T00:00:00Z')`
	if s.dialect == dialectPostgres {
		initializeLock = `INSERT INTO schema_migration_lock(id, holder, expires_at) VALUES (1, '', '1970-01-01T00:00:00Z') ON CONFLICT DO NOTHING`
	}
	if _, err := s.DB.ExecContext(ctx, initializeLock); err != nil {
		return fmt.Errorf("initialize migration lock: %w", err)
	}
	holder := uuid.NewString()
	for {
		now := time.Now().UTC()
		result, err := s.DB.ExecContext(ctx, `UPDATE schema_migration_lock SET holder = ?, expires_at = ? WHERE id = 1 AND (holder = '' OR expires_at <= ?)`, holder, now.Add(5*time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("acquire migration lock: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected == 1 {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for migration lock: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	defer func() {
		_, _ = s.DB.ExecContext(context.Background(), `UPDATE schema_migration_lock SET holder = '', expires_at = '1970-01-01T00:00:00Z' WHERE id = 1 AND holder = ?`, holder)
	}()
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var applied int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, entry.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", entry.Name(), err)
		}
		if applied != 0 {
			continue
		}
		body, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", entry.Name(), err)
		}
		migration := string(body)
		if s.dialect == dialectPostgres {
			migration = postgresMigration(migration)
		}
		if _, err = tx.ExecContext(ctx, migration); err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version) VALUES (?)`, entry.Name())
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}
