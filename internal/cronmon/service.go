package cronmon

import (
	"context"
	"log/slog"
	"time"

	"github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

type Service struct{ store *store.Store }

func New(st *store.Store) *Service { return &Service{store: st} }

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.MarkMissed(ctx, time.Now().UTC())
		}
	}
}

func (s *Service) MarkMissed(ctx context.Context, now time.Time) int {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, project_id, slug, schedule_type, schedule_value, timezone, checkin_margin, next_checkin_at FROM cron_monitors WHERE next_checkin_at IS NOT NULL AND next_checkin_at < ?`, now.Format(time.RFC3339Nano))
	if err != nil {
		slog.Error("load overdue cron monitors", "error", err)
		return 0
	}
	type monitor struct {
		id, projectID, slug, kind, value, timezone, next string
		margin                                           int
	}
	items := make([]monitor, 0)
	for rows.Next() {
		var item monitor
		if rows.Scan(&item.id, &item.projectID, &item.slug, &item.kind, &item.value, &item.timezone, &item.margin, &item.next) == nil {
			items = append(items, item)
		}
	}
	_ = rows.Close()
	missed := 0
	for _, item := range items {
		due, err := time.Parse(time.RFC3339Nano, item.next)
		if err != nil || now.Before(due.Add(time.Duration(item.margin)*time.Minute)) {
			continue
		}
		next := Next(due, item.kind, item.value, item.timezone)
		tx, err := s.store.DB.BeginTx(ctx, nil)
		if err != nil {
			continue
		}
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO cron_checkins(id, checkin_id, monitor_id, status, started_at, finished_at, payload) VALUES (?, ?, ?, 'missed', ?, ?, '{}')`, uuid.NewString(), uuid.NewString(), item.id, due.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		_, updateErr := tx.ExecContext(ctx, `UPDATE cron_monitors SET status = 'missed', next_checkin_at = ? WHERE id = ?`, next.Format(time.RFC3339Nano), item.id)
		if insertErr != nil || updateErr != nil || tx.Commit() != nil {
			_ = tx.Rollback()
			continue
		}
		missed++
		_ = alerts.Queue(ctx, s.store.DB, item.projectID, "cron_missed", map[string]any{"title": "Cron monitor missed", "monitor_id": item.id, "monitor_slug": item.slug, "expected_at": due.Format(time.RFC3339Nano)})
	}
	return missed
}
