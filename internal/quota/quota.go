package quota

import (
	"context"
	"database/sql"
	"time"
)

type Decision struct {
	Allowed    bool
	RetryAfter int
	Reason     string
}

func Check(ctx context.Context, db *sql.DB, projectID, category string, size int64, now time.Time) (Decision, error) {
	var perMinute, perDay int64
	var maxItemBytes int64
	err := db.QueryRowContext(ctx, `SELECT per_minute, per_day, max_item_bytes FROM project_quotas WHERE project_id = ? AND category IN (?, 'all') ORDER BY CASE WHEN category = ? THEN 0 ELSE 1 END LIMIT 1`, projectID, category, category).Scan(&perMinute, &perDay, &maxItemBytes)
	if err != nil && err != sql.ErrNoRows {
		return Decision{}, err
	}
	if maxItemBytes > 0 && size > maxItemBytes {
		return Decision{Reason: "item_size", RetryAfter: 0}, nil
	}
	if perMinute == 0 && perDay == 0 {
		return Decision{Allowed: true}, nil
	}
	minute := now.UTC().Truncate(time.Minute)
	day := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Decision{}, err
	}
	defer tx.Rollback()
	checks := []struct {
		kind       string
		start      time.Time
		limit      int64
		retryAfter int
	}{{"minute", minute, perMinute, int(time.Until(minute.Add(time.Minute)).Seconds()) + 1}, {"day", day, perDay, int(time.Until(day.Add(24*time.Hour)).Seconds()) + 1}}
	for _, check := range checks {
		if check.limit <= 0 {
			continue
		}
		var quantity int64
		err := tx.QueryRowContext(ctx, `SELECT quantity FROM quota_usage WHERE project_id = ? AND category = ? AND window_kind = ? AND window_start = ?`, projectID, category, check.kind, check.start.Format(time.RFC3339)).Scan(&quantity)
		if err != nil && err != sql.ErrNoRows {
			return Decision{}, err
		}
		if quantity >= check.limit {
			return Decision{Reason: check.kind + "_quota", RetryAfter: max(1, check.retryAfter)}, nil
		}
	}
	for _, check := range checks {
		if check.limit <= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO quota_usage(project_id, category, window_kind, window_start, quantity, bytes) VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(project_id, category, window_kind, window_start) DO UPDATE SET quantity = quantity + 1, bytes = bytes + excluded.bytes`, projectID, category, check.kind, check.start.Format(time.RFC3339), size); err != nil {
			return Decision{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: true}, nil
}
