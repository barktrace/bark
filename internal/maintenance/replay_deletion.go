package maintenance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

const replayDeletionBatchSize = 500

// RunReplayDeletionJobs processes one durable Replay deletion batch. The
// coordinator gives this worker a single multi-node lease; the status claim
// additionally makes interrupted work safe to resume after restart.
func (s *Service) RunReplayDeletionJobs(ctx context.Context) {
	var jobID int64
	var projectID, rangeStart, rangeEnd, encodedEnvironments, query string
	err := s.store.DB.QueryRowContext(ctx, `SELECT id, project_id, range_start, range_end, environments, query FROM replay_deletion_jobs WHERE status IN ('pending', 'in_progress') ORDER BY created_at LIMIT 1`).Scan(&jobID, &projectID, &rangeStart, &rangeEnd, &encodedEnvironments, &query)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}
	if err != nil {
		return
	}
	if _, err := s.store.DB.ExecContext(ctx, `UPDATE replay_deletion_jobs SET status = 'in_progress', updated_at = CURRENT_TIMESTAMP, last_error = '' WHERE id = ?`, jobID); err != nil {
		return
	}
	var environments []string
	if err := json.Unmarshal([]byte(encodedEnvironments), &environments); err != nil {
		s.failReplayDeletionJob(ctx, jobID, "invalid stored environments")
		return
	}
	clauses := []string{"project_id = ?", "finished_at >= ?", "started_at <= ?"}
	arguments := []any{projectID, rangeStart, rangeEnd}
	if len(environments) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(environments)), ",")
		clauses = append(clauses, "environment IN ("+placeholders+")")
		for _, environment := range environments {
			arguments = append(arguments, environment)
		}
	}
	freeText := make([]string, 0)
	for _, token := range strings.Fields(strings.TrimSpace(query)) {
		parts := strings.SplitN(token, ":", 2)
		if len(parts) != 2 {
			freeText = append(freeText, token)
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch strings.ToLower(parts[0]) {
		case "environment":
			clauses = append(clauses, "environment = ?")
			arguments = append(arguments, value)
		case "release":
			clauses = append(clauses, "release = ?")
			arguments = append(arguments, value)
		case "user", "user.id", "user.email", "user.username":
			clauses = append(clauses, "user_id = ?")
			arguments = append(arguments, value)
		case "url":
			clauses = append(clauses, "url LIKE ?")
			arguments = append(arguments, "%"+value+"%")
		case "has":
			if value == "error" {
				clauses = append(clauses, "error_count > 0")
			}
		default:
			freeText = append(freeText, token)
		}
	}
	if text := strings.Trim(strings.Join(freeText, " "), `"`); text != "" {
		like := "%" + text + "%"
		clauses = append(clauses, "(url LIKE ? OR user_id LIKE ? OR replay_id LIKE ? OR release LIKE ?)")
		arguments = append(arguments, like, like, like, like)
	}
	arguments = append(arguments, replayDeletionBatchSize)
	rows, err := s.store.DB.QueryContext(ctx, `SELECT DISTINCT replay_id FROM replays WHERE `+strings.Join(clauses, " AND ")+` ORDER BY replay_id LIMIT ?`, arguments...)
	if err != nil {
		s.failReplayDeletionJob(ctx, jobID, err.Error())
		return
	}
	replayIDs := make([]string, 0, replayDeletionBatchSize)
	for rows.Next() {
		var replayID string
		if err := rows.Scan(&replayID); err != nil {
			_ = rows.Close()
			s.failReplayDeletionJob(ctx, jobID, err.Error())
			return
		}
		replayIDs = append(replayIDs, replayID)
	}
	if err := rows.Close(); err != nil {
		s.failReplayDeletionJob(ctx, jobID, err.Error())
		return
	}
	if len(replayIDs) == 0 {
		_, _ = s.store.DB.ExecContext(ctx, `UPDATE replay_deletion_jobs SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`, jobID)
		return
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.failReplayDeletionJob(ctx, jobID, err.Error())
		return
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(replayIDs)), ",")
	deleteArguments := make([]any, 0, len(replayIDs)+1)
	deleteArguments = append(deleteArguments, projectID)
	for _, replayID := range replayIDs {
		deleteArguments = append(deleteArguments, replayID)
	}
	for _, table := range []string{"replay_views", "replay_clicks", "replay_error_links", "replays"} {
		if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE project_id = ? AND replay_id IN (`+marks+`)`, deleteArguments...); err != nil {
			_ = tx.Rollback()
			s.failReplayDeletionJob(ctx, jobID, err.Error())
			return
		}
	}
	nextStatus := "completed"
	if len(replayIDs) == replayDeletionBatchSize {
		nextStatus = "pending"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE replay_deletion_jobs SET status = ?, count_deleted = count_deleted + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, nextStatus, len(replayIDs), jobID); err != nil {
		_ = tx.Rollback()
		s.failReplayDeletionJob(ctx, jobID, err.Error())
		return
	}
	if err := tx.Commit(); err != nil {
		s.failReplayDeletionJob(ctx, jobID, err.Error())
		return
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err == nil {
		_, _ = RemoveOrphanedBlobs(ctx, s.store, organizationID)
	}
}

func (s *Service) failReplayDeletionJob(ctx context.Context, jobID int64, message string) {
	if len(message) > 1000 {
		message = message[:1000]
	}
	_, _ = s.store.DB.ExecContext(ctx, `UPDATE replay_deletion_jobs SET status = 'failed', last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, message, jobID)
}
