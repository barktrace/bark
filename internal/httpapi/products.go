package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/cronmon"
	telemetryanalysis "github.com/barktrace/bark/internal/telemetry"
	"github.com/google/uuid"
)

func (s *Server) cronMonitors(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, status, COALESCE(last_checkin_at, ''), COALESCE(next_checkin_at, ''), created_at FROM cron_monitors WHERE project_id = ? ORDER BY name`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list cron monitors")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, slug, name, scheduleType, scheduleValue, timezone, status, lastCheckin, nextCheckin, createdAt string
		var margin, maxRuntime int
		if err := rows.Scan(&id, &slug, &name, &scheduleType, &scheduleValue, &timezone, &margin, &maxRuntime, &status, &lastCheckin, &nextCheckin, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list cron monitors")
			return
		}
		items = append(items, map[string]any{"id": id, "slug": slug, "name": name, "schedule_type": scheduleType, "schedule_value": scheduleValue, "timezone": timezone, "checkin_margin": margin, "max_runtime": maxRuntime, "status": status, "last_checkin_at": lastCheckin, "next_checkin_at": nextCheckin, "created_at": createdAt})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createCronMonitor(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		ProjectID     string          `json:"project_id"`
		Slug          string          `json:"slug"`
		Name          string          `json:"name"`
		ScheduleType  string          `json:"schedule_type"`
		ScheduleValue json.RawMessage `json:"schedule_value"`
		Timezone      string          `json:"timezone"`
		CheckinMargin int             `json:"checkin_margin"`
		MaxRuntime    int             `json:"max_runtime"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !s.canManageProject(r, principal, input.ProjectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	input.Slug = slug(input.Slug)
	input.Name = strings.TrimSpace(firstNonEmpty(input.Name, input.Slug))
	if input.Slug == "" || input.Name == "" {
		writeError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	kind, value, err := cronmon.NormalizeSchedule(input.ScheduleType, input.ScheduleValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Timezone == "" {
		input.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(input.Timezone); err != nil {
		writeError(w, http.StatusBadRequest, "invalid timezone")
		return
	}
	if input.CheckinMargin <= 0 {
		input.CheckinMargin = 5
	}
	if input.MaxRuntime <= 0 {
		input.MaxRuntime = 30
	}
	next := cronmon.Next(time.Now().UTC(), kind, value, input.Timezone)
	id := uuid.NewString()
	_, err = s.store.DB.ExecContext(r.Context(), `INSERT INTO cron_monitors(id, project_id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, next_checkin_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, input.ProjectID, input.Slug, input.Name, kind, value, input.Timezone, input.CheckinMargin, input.MaxRuntime, next.Format(time.RFC3339Nano))
	if err != nil {
		writeError(w, http.StatusConflict, "cron monitor slug already exists")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": input.Slug, "name": input.Name, "schedule_type": kind, "schedule_value": value, "next_checkin_at": next})
}

func (s *Server) deleteCronMonitor(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	id := r.PathValue("monitor_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM cron_monitors WHERE id = ?`, id).Scan(&projectID); err != nil {
		writeError(w, http.StatusNotFound, "cron monitor not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM cron_monitors WHERE id = ?`, id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) cronCheckins(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	monitorID := r.URL.Query().Get("monitor_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM cron_monitors WHERE id = ?`, monitorID).Scan(&projectID); err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "cron monitor access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, checkin_id, status, COALESCE(duration, 0), release, environment, started_at, COALESCE(finished_at, '') FROM cron_checkins WHERE monitor_id = ? ORDER BY started_at DESC LIMIT 100`, monitorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list check-ins")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, checkinID, status, release, environment, started, finished string
		var duration float64
		if rows.Scan(&id, &checkinID, &status, &duration, &release, &environment, &started, &finished) == nil {
			items = append(items, map[string]any{"id": id, "check_in_id": checkinID, "status": status, "duration": duration, "release": release, "environment": environment, "started_at": started, "finished_at": finished})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) feedback(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, event_id, name, email, comments, url, created_at FROM user_feedback WHERE project_id = ? ORDER BY created_at DESC LIMIT 200`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list feedback")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventID, name, email, comments, targetURL, createdAt string
		if rows.Scan(&id, &eventID, &name, &email, &comments, &targetURL, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "event_id": eventID, "name": name, "email": email, "comments": comments, "url": targetURL, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) eventAttachments(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	eventID, projectID := r.URL.Query().Get("event_id"), r.URL.Query().Get("project_id")
	if eventID == "" || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "event access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT a.id, a.filename, a.attachment_type, b.content_type, b.size, a.created_at FROM event_attachments a JOIN blobs b ON b.id = a.blob_id JOIN events e ON e.id = a.event_id WHERE e.project_id = ? AND (e.id = ? OR e.event_id = ?) ORDER BY a.created_at`, projectID, eventID, eventID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list attachments")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, filename, attachmentType, contentType, createdAt string
		var size int64
		if rows.Scan(&id, &filename, &attachmentType, &contentType, &size, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "filename": filename, "attachment_type": attachmentType, "content_type": contentType, "size": size, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) attachmentContent(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var projectID, key, contentType, filename string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT e.project_id, b.storage_key, b.content_type, a.filename FROM event_attachments a JOIN events e ON e.id = a.event_id JOIN blobs b ON b.id = a.blob_id WHERE a.id = ?`, r.PathValue("attachment_id")).Scan(&projectID, &key, &contentType, &filename)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "attachment not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "attachment access required")
		return
	}
	s.serveBlob(w, r, key, contentType, filename)
}

func (s *Server) replays(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	clauses := []string{"rp.project_id = ?"}
	arguments := []any{projectID}
	for _, filter := range []struct {
		parameter string
		column    string
	}{{"environment", "rp.environment"}, {"release", "rp.release"}, {"user_id", "rp.user_id"}} {
		if value := strings.TrimSpace(r.URL.Query().Get(filter.parameter)); value != "" {
			clauses = append(clauses, filter.column+" = ?")
			arguments = append(arguments, value)
		}
	}
	if query := strings.TrimSpace(r.URL.Query().Get("q")); query != "" {
		like := "%" + query + "%"
		clauses = append(clauses, "(rp.url LIKE ? OR rp.user_id LIKE ? OR rp.replay_id LIKE ?)")
		arguments = append(arguments, like, like, like)
	}
	if value := strings.TrimSpace(r.URL.Query().Get("has_error")); value == "true" || value == "1" {
		clauses = append(clauses, "rp.error_count > 0")
	}
	for _, boundary := range []struct {
		parameter string
		clause    string
	}{{"start", "rp.finished_at >= ?"}, {"end", "rp.started_at <= ?"}} {
		if value := strings.TrimSpace(r.URL.Query().Get(boundary.parameter)); value != "" {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				writeError(w, http.StatusBadRequest, boundary.parameter+" must be RFC3339")
				return
			}
			clauses = append(clauses, boundary.clause)
			arguments = append(arguments, value)
		}
	}
	if issue := strings.TrimSpace(r.URL.Query().Get("issue_id")); issue != "" {
		var issueID string
		err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM issues WHERE project_id = ? AND (id = ? OR CAST(rowid AS TEXT) = ?)`, projectID, issue, issue).Scan(&issueID)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not resolve replay issue")
			return
		}
		clauses = append(clauses, `EXISTS (SELECT 1 FROM replay_error_links rel JOIN events e ON e.project_id = rel.project_id AND e.event_id = rel.event_id WHERE rel.project_id = rp.project_id AND rel.replay_id = rp.replay_id AND e.issue_id = ?)`)
		arguments = append(arguments, issueID)
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT rp.id, rp.replay_id, rp.segment_id, rp.environment, rp.release, rp.user_id, rp.started_at, rp.finished_at, rp.error_count, rp.url, rp.event_blob_id IS NOT NULL, rp.recording_blob_id IS NOT NULL FROM replays rp WHERE `+strings.Join(clauses, " AND ")+` ORDER BY rp.finished_at DESC LIMIT 200`, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replays")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, replayID, environment, release, userID, started, finished, targetURL string
		var segmentID, errorCount int
		var hasEvent, hasRecording bool
		if rows.Scan(&id, &replayID, &segmentID, &environment, &release, &userID, &started, &finished, &errorCount, &targetURL, &hasEvent, &hasRecording) == nil {
			items = append(items, map[string]any{"id": id, "replay_id": replayID, "segment_id": segmentID, "environment": environment, "release": release, "user_id": userID, "started_at": started, "finished_at": finished, "error_count": errorCount, "url": targetURL, "has_event": hasEvent, "has_recording": hasRecording})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) replayContent(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	column, contentType, filename := "event_blob_id", "application/json", "replay-event.json"
	if r.PathValue("content") == "recording" {
		column, contentType, filename = "recording_blob_id", "application/octet-stream", "replay-recording.bin"
	}
	var projectID, key, storedType string
	query := `SELECT rp.project_id, b.storage_key, b.content_type FROM replays rp JOIN blobs b ON b.id = rp.` + column + ` WHERE rp.id = ?`
	if err := s.store.DB.QueryRowContext(r.Context(), query, r.PathValue("replay_id")).Scan(&projectID, &key, &storedType); err != nil {
		writeError(w, http.StatusNotFound, "replay content not found")
		return
	}
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "replay access required")
		return
	}
	if storedType != "" {
		contentType = storedType
	}
	s.serveBlob(w, r, key, contentType, filename)
}

func (s *Server) replayAnalysis(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var projectID, replayID, environment, release, userID, startedAt, finishedAt, targetURL, eventKey, recordingKey string
	var segmentID, errorCount int
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT rp.project_id, rp.replay_id, rp.segment_id, rp.environment, rp.release, rp.user_id,
		       rp.started_at, rp.finished_at, rp.error_count, rp.url,
		       COALESCE(event_blob.storage_key, ''), COALESCE(recording_blob.storage_key, '')
		FROM replays rp
		LEFT JOIN blobs event_blob ON event_blob.id = rp.event_blob_id
		LEFT JOIN blobs recording_blob ON recording_blob.id = rp.recording_blob_id
		WHERE rp.id = ?
	`, r.PathValue("replay_id")).Scan(&projectID, &replayID, &segmentID, &environment, &release, &userID, &startedAt, &finishedAt, &errorCount, &targetURL, &eventKey, &recordingKey)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "replay access required")
		return
	}
	eventPayload, err := s.readAnalysisBlob(eventKey)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	recordingPayload, err := s.readAnalysisBlob(recordingKey)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	analysis, err := telemetryanalysis.AnalyzeReplay(eventPayload, recordingPayload)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": r.PathValue("replay_id"), "replay_id": replayID, "project_id": projectID, "segment_id": segmentID,
		"environment": environment, "release": release, "user_id": userID, "started_at": startedAt,
		"finished_at": finishedAt, "error_count": errorCount, "url": targetURL, "analysis": analysis,
	})
}

func (s *Server) replayPlayback(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var projectID, replayID string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id, replay_id FROM replays WHERE id = ?`, r.PathValue("replay_id")).Scan(&projectID, &replayID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "replay access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT b.storage_key
		FROM replays rp
		JOIN blobs b ON b.id = rp.recording_blob_id
		WHERE rp.project_id = ? AND rp.replay_id = ?
		ORDER BY rp.segment_id
		LIMIT 101
	`, projectID, replayID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load replay segments")
		return
	}
	keys := make([]string, 0, 100)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not load replay segments")
			return
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, http.StatusInternalServerError, "could not load replay segments")
		return
	}
	if err := rows.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load replay segments")
		return
	}
	playback := telemetryanalysis.NewReplayPlayback()
	segmentsTruncated := len(keys) > 100
	if segmentsTruncated {
		keys = keys[:100]
	}
	for _, key := range keys {
		payload, err := s.readAnalysisBlob(key)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if err := playback.AddRecording(payload); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if playback.Truncated {
			break
		}
	}
	if len(playback.Events) == 0 {
		writeError(w, http.StatusNotFound, "replay recording not found")
		return
	}
	if !playback.HasSnapshot {
		writeError(w, http.StatusUnprocessableEntity, "replay does not contain a full snapshot")
		return
	}
	playback.Truncated = playback.Truncated || segmentsTruncated
	writeJSON(w, http.StatusOK, map[string]any{
		"replay_id": replayID, "project_id": projectID, "segment_count": len(keys), "playback": playback,
	})
}

func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.id, p.profile_id, p.transaction_id, p.platform, p.environment, p.release, p.started_at, p.duration_ms, b.size, p.profiler_id, p.chunk_id FROM profiles p JOIN blobs b ON b.id = p.blob_id WHERE p.project_id = ? ORDER BY p.started_at DESC LIMIT 200`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list profiles")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, profileID, transactionID, platform, environment, release, started, profilerID, chunkID string
		var duration float64
		var size int64
		if rows.Scan(&id, &profileID, &transactionID, &platform, &environment, &release, &started, &duration, &size, &profilerID, &chunkID) == nil {
			items = append(items, map[string]any{"id": id, "profile_id": profileID, "profiler_id": profilerID, "chunk_id": chunkID, "transaction_id": transactionID, "platform": platform, "environment": environment, "release": release, "started_at": started, "duration_ms": duration, "size": size})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) profileContent(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var projectID, key, contentType string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT p.project_id, b.storage_key, b.content_type FROM profiles p JOIN blobs b ON b.id = p.blob_id WHERE p.id = ?`, r.PathValue("profile_id")).Scan(&projectID, &key, &contentType); err != nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "profile access required")
		return
	}
	s.serveBlob(w, r, key, contentType, "profile.json")
}

func (s *Server) profileAnalysis(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var projectID, profileID, transactionID, platform, environment, release, startedAt, key string
	var duration float64
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT p.project_id, p.profile_id, p.transaction_id, p.platform, p.environment, p.release,
		       p.started_at, p.duration_ms, b.storage_key
		FROM profiles p JOIN blobs b ON b.id = p.blob_id WHERE p.id = ?
	`, r.PathValue("profile_id")).Scan(&projectID, &profileID, &transactionID, &platform, &environment, &release, &startedAt, &duration, &key)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "profile access required")
		return
	}
	payload, err := s.readAnalysisBlob(key)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	analysis, err := telemetryanalysis.AnalyzeProfile(payload)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": r.PathValue("profile_id"), "profile_id": profileID, "project_id": projectID,
		"transaction_id": transactionID, "platform": platform, "environment": environment, "release": release,
		"started_at": startedAt, "duration_ms": duration, "analysis": analysis,
	})
}

func (s *Server) readAnalysisBlob(key string) ([]byte, error) {
	if strings.TrimSpace(key) == "" {
		return nil, nil
	}
	file, err := s.store.Blobs.Open(key)
	if err != nil {
		return nil, errors.New("telemetry payload is unavailable")
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr == nil && info.Size() > telemetryanalysis.MaxCompressedBytes {
		return nil, errors.New("telemetry payload exceeds analysis size limit")
	}
	payload, err := io.ReadAll(io.LimitReader(file, telemetryanalysis.MaxCompressedBytes+1))
	if err != nil {
		return nil, errors.New("could not read telemetry payload")
	}
	if len(payload) > telemetryanalysis.MaxCompressedBytes {
		return nil, errors.New("telemetry payload exceeds analysis size limit")
	}
	return payload, nil
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	window, label := performanceWindow(r.URL.Query().Get("period"))
	since := time.Now().UTC().Add(-window).Format(time.RFC3339Nano)
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT name, metric_type, unit, COUNT(*), MIN(value), AVG(value), MAX(value), MAX(timestamp) FROM metric_points WHERE project_id = ? AND timestamp >= ? AND (? = '' OR name LIKE '%' || ? || '%') GROUP BY name, metric_type, unit ORDER BY MAX(timestamp) DESC LIMIT 200`, projectID, since, query, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not summarize metrics")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var name, metricType, unit, lastSeen string
		var count int64
		var minimum, average, maximum float64
		if rows.Scan(&name, &metricType, &unit, &count, &minimum, &average, &maximum, &lastSeen) == nil {
			items = append(items, map[string]any{"name": name, "type": metricType, "unit": unit, "count": count, "min": minimum, "average": average, "max": maximum, "last_seen_at": lastSeen})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"period": label, "metrics": items})
}

func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, key, contentType, filename string) {
	file, err := s.store.Blobs.Open(key)
	if err != nil {
		writeError(w, http.StatusNotFound, "blob content not found")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read blob")
		return
	}
	w.Header().Set("Content-Type", firstNonEmpty(contentType, "application/octet-stream"))
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filename, `"`, "")+`"`)
	http.ServeContent(w, r, filename, info.ModTime(), file)
}
