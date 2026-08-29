package coordination

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

const (
	leaseTTL          = 30 * time.Second
	heartbeatInterval = 10 * time.Second
)

type Manager struct {
	db      *sql.DB
	ownerID string
}

func New(db *sql.DB) *Manager {
	return &Manager{db: db, ownerID: uuid.NewString()}
}

// Acquire atomically acquires or renews a named lease. A lease can move to a
// different process only after its previous owner stops renewing it.
func (m *Manager) Acquire(ctx context.Context, name string, now time.Time) (bool, error) {
	expiresAt := now.UTC().Add(leaseTTL).Format(time.RFC3339Nano)
	nowText := now.UTC().Format(time.RFC3339Nano)
	result, err := m.db.ExecContext(ctx, `
		INSERT INTO service_leases(name, owner_id, expires_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			owner_id = excluded.owner_id,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at
		WHERE service_leases.owner_id = excluded.owner_id OR service_leases.expires_at <= ?
	`, name, m.ownerID, expiresAt, nowText, nowText)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected == 1, err
}

func (m *Manager) Release(ctx context.Context, name string) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM service_leases WHERE name = ? AND owner_id = ?`, name, m.ownerID)
	return err
}

// Run invokes task at most once per interval across all processes sharing the
// database. It keeps renewing leadership while a task is running and avoids
// overlapping invocations within one process.
func (m *Manager) Run(ctx context.Context, name string, initialDelay, interval time.Duration, task func(context.Context)) {
	if interval <= 0 {
		interval = time.Minute
	}
	if initialDelay < 0 {
		initialDelay = 0
	}
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	taskTimer := time.NewTimer(initialDelay)
	defer taskTimer.Stop()
	running := make(chan struct{}, 1)
	leader, err := m.Acquire(ctx, name, time.Now())
	if err != nil {
		slog.Error("acquire service lease", "service", name, "error", err)
	}
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = m.Release(releaseCtx, name)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			leader, err = m.Acquire(ctx, name, time.Now())
			if err != nil {
				leader = false
				slog.Error("renew service lease", "service", name, "error", err)
			}
		case <-taskTimer.C:
			if leader {
				select {
				case running <- struct{}{}:
					go func() {
						defer func() { <-running }()
						task(ctx)
					}()
				default:
					slog.Warn("skip overlapping background task", "service", name)
				}
			}
			taskTimer.Reset(interval)
		}
	}
}
