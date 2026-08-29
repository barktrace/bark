package maintenance

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/store"
)

type Service struct{ store *store.Store }

type CleanupResult struct {
	Cutoff  string         `json:"cutoff"`
	DryRun  bool           `json:"dry_run"`
	Deleted map[string]int `json:"deleted"`
}

type cleanupTarget struct {
	name       string
	countQuery string
	deleteSQL  string
}

var targets = map[string]cleanupTarget{
	"events": {
		name:       "events",
		countQuery: `SELECT COUNT(*) FROM events WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
		deleteSQL:  `DELETE FROM events WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
	},
	"transactions": {
		name:       "transactions",
		countQuery: `SELECT COUNT(*) FROM transactions WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
		deleteSQL:  `DELETE FROM transactions WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
	},
	"logs": {
		name:       "logs",
		countQuery: `SELECT COUNT(*) FROM logs WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
		deleteSQL:  `DELETE FROM logs WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
	},
	"sessions": {
		name:       "sessions",
		countQuery: `SELECT COUNT(*) FROM project_sessions WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
		deleteSQL:  `DELETE FROM project_sessions WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND received_at < ?`,
	},
	"spans": {
		name:       "spans",
		countQuery: `SELECT COUNT(*) FROM spans WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND finished_at < ?`,
		deleteSQL:  `DELETE FROM spans WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND finished_at < ?`,
	},
	"uptime": {
		name:       "uptime",
		countQuery: `SELECT COUNT(*) FROM uptime_checks WHERE monitor_id IN (SELECT m.id FROM uptime_monitors m JOIN projects p ON p.id = m.project_id WHERE p.organization_id = ?) AND checked_at < ?`,
		deleteSQL:  `DELETE FROM uptime_checks WHERE monitor_id IN (SELECT m.id FROM uptime_monitors m JOIN projects p ON p.id = m.project_id WHERE p.organization_id = ?) AND checked_at < ?`,
	},
	"replays": {
		name:       "replays",
		countQuery: `SELECT COUNT(*) FROM replays WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND finished_at < ?`,
		deleteSQL:  `DELETE FROM replays WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND finished_at < ?`,
	},
	"profiles": {
		name:       "profiles",
		countQuery: `SELECT COUNT(*) FROM profiles WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND started_at < ?`,
		deleteSQL:  `DELETE FROM profiles WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND started_at < ?`,
	},
	"metrics": {
		name:       "metrics",
		countQuery: `SELECT COUNT(*) FROM metric_points WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND timestamp < ?`,
		deleteSQL:  `DELETE FROM metric_points WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND timestamp < ?`,
	},
}

func New(st *store.Store) *Service { return &Service{store: st} }

func ValidDataType(name string) bool {
	_, ok := targets[name]
	return ok
}

func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.cleanupAll(ctx)
			timer.Reset(6 * time.Hour)
		}
	}
}

func (s *Service) CleanupAll(ctx context.Context) { s.cleanupAll(ctx) }

func (s *Service) cleanupAll(ctx context.Context) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, retention_days FROM organizations`)
	if err != nil {
		slog.Error("load retention policies", "error", err)
		return
	}
	type policy struct {
		id   string
		days int
	}
	policies := make([]policy, 0)
	for rows.Next() {
		var item policy
		if err := rows.Scan(&item.id, &item.days); err == nil {
			policies = append(policies, item)
		}
	}
	_ = rows.Close()
	for _, policy := range policies {
		cutoff := time.Now().UTC().Add(-time.Duration(policy.days) * 24 * time.Hour)
		if result, err := CleanupStore(ctx, s.store, policy.id, cutoff, nil, false); err != nil {
			slog.Error("run retention cleanup", "organization_id", policy.id, "error", err)
		} else {
			slog.Info("retention cleanup", "organization_id", policy.id, "deleted", result.Deleted)
		}
	}
}

func CleanupStore(ctx context.Context, st *store.Store, organizationID string, cutoff time.Time, dataTypes []string, dryRun bool) (CleanupResult, error) {
	result, err := CleanupOrganization(ctx, st.DB, organizationID, cutoff, dataTypes, dryRun)
	if err != nil || dryRun {
		return result, err
	}
	deleted, err := RemoveOrphanedBlobs(ctx, st, organizationID)
	if err != nil {
		return result, err
	}
	result.Deleted["blobs"] = deleted
	return result, nil
}

// RemoveOrphanedBlobs removes metadata and backing objects only after every
// known blob-owning table has released the blob. Storage keys are content
// addressed and may be shared by several metadata rows, so the backing object
// is retained until all rows using that key are orphaned.
func RemoveOrphanedBlobs(ctx context.Context, st *store.Store, organizationID string) (int, error) {
	if st.Blobs == nil {
		return 0, nil
	}
	const orphanPredicate = `
		NOT EXISTS (SELECT 1 FROM project_artifacts x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM event_attachments x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM replays x WHERE x.event_blob_id = b.id OR x.recording_blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM profiles x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM ingestion_jobs x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM upload_chunks x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM preprod_builds x WHERE x.blob_id = b.id) AND
		NOT EXISTS (SELECT 1 FROM snapshot_objects x WHERE x.blob_id = b.id)`
	removed := 0
	for {
		rows, err := st.DB.QueryContext(ctx, `SELECT b.id, b.storage_key FROM blobs b WHERE b.organization_id = ? AND `+orphanPredicate+` ORDER BY b.created_at LIMIT 500`, organizationID)
		if err != nil {
			return removed, err
		}
		type orphan struct{ id, key string }
		items := make([]orphan, 0, 500)
		keyCounts := make(map[string]int)
		for rows.Next() {
			var item orphan
			if err := rows.Scan(&item.id, &item.key); err != nil {
				_ = rows.Close()
				return removed, err
			}
			items = append(items, item)
			keyCounts[item.key]++
		}
		if err := rows.Close(); err != nil {
			return removed, err
		}
		if len(items) == 0 {
			return removed, drainBlobDeletionQueue(ctx, st)
		}
		tx, err := st.DB.BeginTx(ctx, nil)
		if err != nil {
			return removed, err
		}
		for _, item := range items {
			result, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ? AND `+strings.ReplaceAll(orphanPredicate, "b.", "blobs."), item.id)
			if err != nil {
				_ = tx.Rollback()
				return removed, err
			}
			count, _ := result.RowsAffected()
			removed += int(count)
		}
		for key := range keyCounts {
			var remaining int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, key).Scan(&remaining); err != nil {
				_ = tx.Rollback()
				return removed, err
			}
			if remaining == 0 {
				if _, err := tx.ExecContext(ctx, `INSERT INTO blob_deletion_queue(storage_key) VALUES (?) ON CONFLICT(storage_key) DO NOTHING`, key); err != nil {
					_ = tx.Rollback()
					return removed, err
				}
			}
		}
		if err := tx.Commit(); err != nil {
			return removed, err
		}
	}
}

func drainBlobDeletionQueue(ctx context.Context, st *store.Store) error {
	rows, err := st.DB.QueryContext(ctx, `SELECT storage_key FROM blob_deletion_queue ORDER BY created_at LIMIT 500`)
	if err != nil {
		return err
	}
	keys := make([]string, 0, 500)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, key := range keys {
		var references int
		if err := st.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, key).Scan(&references); err != nil {
			return err
		}
		if references == 0 {
			if err := st.Blobs.Remove(key); err != nil {
				_, _ = st.DB.ExecContext(ctx, `UPDATE blob_deletion_queue SET attempts = attempts + 1, last_error = ? WHERE storage_key = ?`, err.Error(), key)
				return fmt.Errorf("remove orphaned blob %q: %w", key, err)
			}
		}
		if _, err := st.DB.ExecContext(ctx, `DELETE FROM blob_deletion_queue WHERE storage_key = ?`, key); err != nil {
			return err
		}
	}
	return nil
}

func CleanupOrganization(ctx context.Context, db *sql.DB, organizationID string, cutoff time.Time, dataTypes []string, dryRun bool) (CleanupResult, error) {
	selected := make([]cleanupTarget, 0)
	if len(dataTypes) == 0 {
		dataTypes = []string{"events", "transactions", "logs", "sessions", "spans", "uptime", "replays", "profiles", "metrics"}
	}
	for _, name := range dataTypes {
		target, ok := targets[name]
		if !ok {
			return CleanupResult{}, fmt.Errorf("unsupported cleanup data type %q", name)
		}
		selected = append(selected, target)
	}
	cutoffText := cutoff.UTC().Format(time.RFC3339Nano)
	result := CleanupResult{Cutoff: cutoffText, DryRun: dryRun, Deleted: make(map[string]int)}
	if dryRun {
		for _, target := range selected {
			var count int
			if err := db.QueryRowContext(ctx, target.countQuery, organizationID, cutoffText).Scan(&count); err != nil {
				return result, err
			}
			result.Deleted[target.name] = count
		}
		return result, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	for _, target := range selected {
		execution, err := tx.ExecContext(ctx, target.deleteSQL, organizationID, cutoffText)
		if err != nil {
			return result, err
		}
		count, _ := execution.RowsAffected()
		result.Deleted[target.name] = int(count)
	}
	if _, includesReplays := result.Deleted["replays"]; includesReplays {
		if _, err := tx.ExecContext(ctx, `DELETE FROM replay_error_links WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND NOT EXISTS (SELECT 1 FROM replays rp WHERE rp.project_id = replay_error_links.project_id AND rp.replay_id = replay_error_links.replay_id)`, organizationID); err != nil {
			return result, err
		}
	}
	if _, includesEvents := result.Deleted["events"]; includesEvents {
		if _, err := tx.ExecContext(ctx, `DELETE FROM issues WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?) AND NOT EXISTS (SELECT 1 FROM events e WHERE e.issue_id = issues.id)`, organizationID); err != nil {
			return result, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE issues SET event_count = (SELECT COUNT(*) FROM events e WHERE e.issue_id = issues.id), first_seen_at = (SELECT MIN(timestamp) FROM events e WHERE e.issue_id = issues.id), last_seen_at = (SELECT MAX(timestamp) FROM events e WHERE e.issue_id = issues.id) WHERE project_id IN (SELECT id FROM projects WHERE organization_id = ?)`, organizationID); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	_, _ = db.ExecContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`)
	return result, nil
}
