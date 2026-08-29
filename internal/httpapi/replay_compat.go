package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/maintenance"
	telemetryanalysis "github.com/barktrace/bark/internal/telemetry"
)

type replaySession struct {
	ReplayID       string
	ProjectID      string
	SentryProject  string
	ProjectSlug    string
	StartedAt      string
	FinishedAt     string
	Environment    string
	Release        string
	UserID         string
	URL            string
	ErrorCount     int
	SegmentCount   int
	EventSegments  int
	RecordSegments int
}

func (s *Server) sentryOrganizationReplays(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	projects, err := s.authorizedReplayProjects(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay projects")
		return
	}
	items, err := s.loadReplaySessions(r, projects, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items, "meta": map[string]any{"count": len(items), "hasMore": false}})
}

func (s *Server) sentryReplayCount(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	dataSource := strings.TrimSpace(r.URL.Query().Get("data_source"))
	if dataSource != "events" && dataSource != "search_issues" && dataSource != "spans" {
		writeError(w, http.StatusBadRequest, "data_source must be events, search_issues, or spans")
		return
	}
	projects, err := s.authorizedReplayProjects(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay projects")
		return
	}
	items, err := s.loadReplaySessions(r, projects, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	counts := make(map[string]int)
	for _, item := range items {
		projectID, _ := item["project_id"].(string)
		counts[projectID]++
	}
	writeJSON(w, http.StatusOK, counts)
}

func (s *Server) sentryReplaySelectors(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	if _, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug")); !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	// Selector aggregation depends on dead/rage-click classification. Return the
	// canonical empty collection until those heuristics identify selectors.
	writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
}

func (s *Server) sentryReplayDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projects, _, err := s.replayProjectsForRequest(r, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	replayID := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PathValue("replay_id")), "-", ""))
	if r.Method == http.MethodDelete {
		s.deleteReplaySession(w, r, principal, projects, replayID)
		return
	}
	items, err := s.loadReplaySessions(r, projects, replayID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(items) == 0 {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items[0]})
}

func (s *Server) sentryReplaySegments(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projects, _, err := s.replayProjectsForRequest(r, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	replayID := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PathValue("replay_id")), "-", ""))
	projectID, ok := replayProject(projects, replayID, s, r)
	if !ok {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	segmentRaw := strings.TrimSpace(r.PathValue("segment_id"))
	if segmentRaw != "" {
		segmentID, err := strconv.Atoi(segmentRaw)
		if err != nil || segmentID < 0 {
			writeError(w, http.StatusBadRequest, "invalid replay segment")
			return
		}
		var key, contentType, createdAt string
		err = s.store.DB.QueryRowContext(r.Context(), `SELECT b.storage_key, b.content_type, rp.created_at FROM replays rp JOIN blobs b ON b.id = rp.recording_blob_id WHERE rp.project_id = ? AND rp.replay_id = ? AND rp.segment_id = ?`, projectID, replayID, segmentID).Scan(&key, &contentType, &createdAt)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "replay segment not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not load replay segment")
			return
		}
		if r.PathValue("project_slug") != "" {
			var sentryProject string
			_ = s.store.DB.QueryRowContext(r.Context(), `SELECT sentry_id FROM projects WHERE id = ?`, projectID).Scan(&sentryProject)
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"replayId": replayID, "segmentId": segmentID, "projectId": sentryProject, "dateAdded": normalizeAPITime(createdAt)}})
			return
		}
		s.serveBlob(w, r, key, contentType, fmt.Sprintf("replay-%s-%d.bin", replayID, segmentID))
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT rp.segment_id, b.storage_key, b.size, b.content_type FROM replays rp JOIN blobs b ON b.id = rp.recording_blob_id WHERE rp.project_id = ? AND rp.replay_id = ? ORDER BY rp.segment_id LIMIT 1000`, projectID, replayID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay segments")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	decoded := make([][]json.RawMessage, 0)
	playback := telemetryanalysis.NewReplayPlayback()
	for rows.Next() {
		var segmentID int
		var size int64
		var key, contentType string
		if err := rows.Scan(&segmentID, &key, &size, &contentType); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list replay segments")
			return
		}
		if r.PathValue("project_slug") != "" {
			payload, readErr := s.readAnalysisBlob(key)
			if readErr != nil {
				writeError(w, http.StatusInternalServerError, readErr.Error())
				return
			}
			before := len(playback.Events)
			if decodeErr := playback.AddRecording(payload); decodeErr != nil {
				writeError(w, http.StatusUnprocessableEntity, "could not decode replay segment")
				return
			}
			decoded = append(decoded, playback.Events[before:])
			if playback.Truncated {
				break
			}
			continue
		}
		items = append(items, map[string]any{"id": segmentID, "segmentId": segmentID, "replayId": replayID, "size": size, "contentType": contentType})
	}
	if r.PathValue("project_slug") != "" {
		writeJSON(w, http.StatusOK, decoded)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryReplayClicks(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projects, _, err := s.replayProjectsForRequest(r, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	replayID := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PathValue("replay_id")), "-", ""))
	projectID, ok := replayProject(projects, replayID, s, r)
	if !ok {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT b.storage_key FROM replays rp JOIN blobs b ON b.id = rp.recording_blob_id WHERE rp.project_id = ? AND rp.replay_id = ? ORDER BY rp.segment_id LIMIT 1000`, projectID, replayID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay segments")
		return
	}
	keys := make([]string, 0)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list replay segments")
			return
		}
		keys = append(keys, key)
	}
	_ = rows.Close()
	playback := telemetryanalysis.NewReplayPlayback()
	for _, key := range keys {
		payload, readErr := s.readAnalysisBlob(key)
		if readErr != nil {
			writeError(w, http.StatusInternalServerError, readErr.Error())
			return
		}
		if decodeErr := playback.AddRecording(payload); decodeErr != nil {
			writeError(w, http.StatusUnprocessableEntity, "could not decode replay segment")
			return
		}
		if playback.Truncated {
			break
		}
	}
	clicks := make([]map[string]any, 0)
	for _, raw := range playback.Events {
		var event struct {
			Type      int     `json:"type"`
			Timestamp float64 `json:"timestamp"`
			Data      struct {
				Source int `json:"source"`
				Type   int `json:"type"`
				ID     int `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &event) == nil && event.Type == 3 && event.Data.Source == 2 && event.Data.Type == 2 {
			clicks = append(clicks, map[string]any{"node_id": event.Data.ID, "timestamp": replayEventTime(event.Timestamp)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": clicks})
}

func (s *Server) sentryReplayViewedBy(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projects, _, err := s.replayProjectsForRequest(r, principal)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	replayID := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PathValue("replay_id")), "-", ""))
	if _, ok := replayProject(projects, replayID, s, r); !ok {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"viewed_by": []any{}}})
}

func replayEventTime(timestamp float64) string {
	if timestamp > 1e11 {
		return time.Unix(0, int64(timestamp*float64(time.Millisecond))).UTC().Format(time.RFC3339Nano)
	}
	return time.Unix(0, int64(timestamp*float64(time.Second))).UTC().Format(time.RFC3339Nano)
}

func (s *Server) replayProjectsForRequest(r *http.Request, principal *auth.Principal) ([]string, string, error) {
	if r.PathValue("project_slug") != "" {
		projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
		if !ok || !s.canAccessProject(r, principal, projectID) {
			return nil, "", errors.New("project not found")
		}
		return []string{projectID}, organizationID, nil
	}
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		return nil, "", errors.New("organization not found")
	}
	projects, err := s.authorizedReplayProjects(r, principal, organizationID)
	if err != nil {
		return nil, "", errors.New("could not list replay projects")
	}
	return projects, organizationID, nil
}

func (s *Server) authorizedReplayProjects(r *http.Request, principal *auth.Principal, organizationID string) ([]string, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? ORDER BY id`, organizationID)
	if err != nil {
		return nil, err
	}
	candidates := make([]string, 0)
	for rows.Next() {
		var projectID string
		if err := rows.Scan(&projectID); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, projectID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	projects := make([]string, 0, len(candidates))
	for _, projectID := range candidates {
		if s.canAccessProject(r, principal, projectID) {
			projects = append(projects, projectID)
		}
	}
	return projects, nil
}

func (s *Server) loadReplaySessions(r *http.Request, projects []string, replayID string) ([]map[string]any, error) {
	if len(projects) == 0 {
		return []map[string]any{}, nil
	}
	requestedProjects := append([]string(nil), r.URL.Query()["project"]...)
	requestedProjects = append(requestedProjects, r.URL.Query()["project_id"]...)
	clauses := []string{"rp.project_id IN (" + placeholders(len(projects)) + ")"}
	arguments := make([]any, 0, len(projects)+12)
	for _, projectID := range projects {
		arguments = append(arguments, projectID)
	}
	if replayID != "" {
		clauses = append(clauses, "rp.replay_id = ?")
		arguments = append(arguments, replayID)
	}
	if len(requestedProjects) > 0 {
		projectClauses := make([]string, 0, len(requestedProjects))
		for _, project := range requestedProjects {
			projectClauses = append(projectClauses, "(rp.project_id = ? OR p.sentry_id = ? OR p.slug = ?)")
			arguments = append(arguments, project, project, project)
		}
		clauses = append(clauses, "("+strings.Join(projectClauses, " OR ")+")")
	}
	addTextReplayFilter := func(column, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			clauses = append(clauses, column+" = ?")
			arguments = append(arguments, value)
		}
	}
	addTextReplayFilter("rp.environment", r.URL.Query().Get("environment"))
	addTextReplayFilter("rp.release", r.URL.Query().Get("release"))
	addTextReplayFilter("rp.user_id", r.URL.Query().Get("user"))
	if start := strings.TrimSpace(r.URL.Query().Get("start")); start != "" {
		if _, err := time.Parse(time.RFC3339, start); err != nil {
			return nil, errors.New("start must be RFC3339")
		}
		clauses = append(clauses, "rp.finished_at >= ?")
		arguments = append(arguments, start)
	}
	if end := strings.TrimSpace(r.URL.Query().Get("end")); end != "" {
		if _, err := time.Parse(time.RFC3339, end); err != nil {
			return nil, errors.New("end must be RFC3339")
		}
		clauses = append(clauses, "rp.started_at <= ?")
		arguments = append(arguments, end)
	}
	queryText := strings.TrimSpace(r.URL.Query().Get("query"))
	issueFilter := strings.TrimSpace(r.URL.Query().Get("issue_id"))
	freeText := make([]string, 0)
	for _, token := range strings.Fields(queryText) {
		parts := strings.SplitN(token, ":", 2)
		if len(parts) != 2 {
			freeText = append(freeText, token)
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch strings.ToLower(parts[0]) {
		case "environment":
			addTextReplayFilter("rp.environment", value)
		case "release":
			addTextReplayFilter("rp.release", value)
		case "user":
			addTextReplayFilter("rp.user_id", value)
		case "url":
			clauses = append(clauses, "rp.url LIKE ?")
			arguments = append(arguments, "%"+value+"%")
		case "issue":
			issueFilter = value
		case "has":
			if value == "error" {
				clauses = append(clauses, "rp.error_count > 0")
			}
		default:
			freeText = append(freeText, token)
		}
	}
	if text := strings.Trim(strings.Join(freeText, " "), `"`); text != "" {
		clauses = append(clauses, "(rp.url LIKE ? OR rp.user_id LIKE ? OR rp.replay_id LIKE ?)")
		like := "%" + text + "%"
		arguments = append(arguments, like, like, like)
	}
	if issueFilter != "" {
		var issueID string
		err := s.store.DB.QueryRowContext(r.Context(), `SELECT i.id FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.organization_id IN (SELECT organization_id FROM projects WHERE id = ?) AND (i.id = ? OR CAST(i.rowid AS TEXT) = ?) LIMIT 1`, projects[0], issueFilter, issueFilter).Scan(&issueID)
		if errors.Is(err, sql.ErrNoRows) {
			return []map[string]any{}, nil
		}
		if err != nil {
			return nil, err
		}
		clauses = append(clauses, `EXISTS (SELECT 1 FROM replay_error_links rel JOIN events e ON e.project_id = rel.project_id AND e.event_id = rel.event_id WHERE rel.project_id = rp.project_id AND rel.replay_id = rp.replay_id AND e.issue_id = ?)`)
		arguments = append(arguments, issueID)
	}
	limit := 100
	if value, err := strconv.Atoi(r.URL.Query().Get("per_page")); err == nil && value > 0 && value <= 200 {
		limit = value
	}
	arguments = append(arguments, limit)
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT rp.replay_id, rp.project_id, p.sentry_id, p.slug,
		       MIN(rp.started_at), MAX(rp.finished_at), MAX(rp.environment), MAX(rp.release),
		       MAX(rp.user_id), MAX(rp.url), SUM(rp.error_count), COUNT(*),
		       SUM(CASE WHEN rp.event_blob_id IS NOT NULL THEN 1 ELSE 0 END),
		       SUM(CASE WHEN rp.recording_blob_id IS NOT NULL THEN 1 ELSE 0 END)
		FROM replays rp JOIN projects p ON p.id = rp.project_id
		WHERE `+strings.Join(clauses, " AND ")+`
		GROUP BY rp.replay_id, rp.project_id, p.sentry_id, p.slug
		ORDER BY MAX(rp.finished_at) DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]replaySession, 0, limit)
	for rows.Next() {
		var session replaySession
		if err := rows.Scan(&session.ReplayID, &session.ProjectID, &session.SentryProject, &session.ProjectSlug, &session.StartedAt, &session.FinishedAt, &session.Environment, &session.Release, &session.UserID, &session.URL, &session.ErrorCount, &session.SegmentCount, &session.EventSegments, &session.RecordSegments); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(sessions))
	for _, session := range sessions {
		errorIDs, issues, err := s.replayCorrelations(r.Context(), session.ProjectID, session.ReplayID)
		if err != nil {
			return nil, err
		}
		duration := int64(0)
		started, startErr := time.Parse(time.RFC3339Nano, normalizeAPITime(session.StartedAt))
		finished, finishErr := time.Parse(time.RFC3339Nano, normalizeAPITime(session.FinishedAt))
		if startErr == nil && finishErr == nil && finished.After(started) {
			duration = int64(finished.Sub(started).Seconds())
		}
		urls := []string{}
		if session.URL != "" {
			urls = append(urls, session.URL)
		}
		items = append(items, map[string]any{
			"id": session.ReplayID, "replayId": session.ReplayID,
			"projectId": session.SentryProject, "project_id": session.SentryProject, "projectSlug": session.ProjectSlug,
			"started_at": normalizeAPITime(session.StartedAt), "finished_at": normalizeAPITime(session.FinishedAt),
			"startedAt": normalizeAPITime(session.StartedAt), "finishedAt": normalizeAPITime(session.FinishedAt),
			"duration": duration, "environment": nullableText(session.Environment), "release": nullableText(session.Release),
			"releases": replayReleases(session.Release), "dist": nil,
			"user": map[string]any{"id": nullableText(session.UserID), "username": nil, "email": nil, "ip": nil, "display_name": nullableText(session.UserID), "geo": map[string]any{}}, "urls": urls,
			"count_segments": session.RecordSegments, "segmentCount": session.RecordSegments, "count_errors": session.ErrorCount, "error_count": session.ErrorCount,
			"hasRecording": session.RecordSegments > 0, "eventSegmentCount": session.EventSegments,
			"error_ids": errorIDs, "errorIds": errorIDs, "issues": issues,
			"activity": 0, "is_archived": false, "tags": []any{}, "trace_ids": []any{}, "count_urls": len(urls),
			"count_dead_clicks": 0, "count_rage_clicks": 0, "count_warnings": 0, "count_infos": 0,
			"replay_type": "session", "platform": nil, "has_viewed": false,
			"browser": map[string]string{}, "device": map[string]string{}, "os": map[string]string{}, "sdk": map[string]string{},
		})
	}
	return items, nil
}

func replayReleases(release string) []string {
	if strings.TrimSpace(release) == "" {
		return []string{}
	}
	return []string{release}
}

func (s *Server) replayCorrelations(ctx context.Context, projectID, replayID string) ([]string, []map[string]any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT DISTINCT rel.event_id, i.rowid, i.id, i.title, i.status
		FROM replay_error_links rel
		LEFT JOIN events e ON e.project_id = rel.project_id AND e.event_id = rel.event_id
		LEFT JOIN issues i ON i.id = e.issue_id
		WHERE rel.project_id = ? AND rel.replay_id = ? ORDER BY rel.event_id
	`, projectID, replayID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	errorIDs := make([]string, 0)
	issues := make([]map[string]any, 0)
	seenIssues := make(map[string]struct{})
	for rows.Next() {
		var eventID string
		var legacyID sql.NullInt64
		var issueID, title, status sql.NullString
		if err := rows.Scan(&eventID, &legacyID, &issueID, &title, &status); err != nil {
			return nil, nil, err
		}
		errorIDs = append(errorIDs, eventID)
		if issueID.Valid {
			if _, exists := seenIssues[issueID.String]; !exists {
				seenIssues[issueID.String] = struct{}{}
				issues = append(issues, map[string]any{"id": strconv.FormatInt(legacyID.Int64, 10), "internalId": issueID.String, "title": title.String, "status": status.String})
			}
		}
	}
	return errorIDs, issues, rows.Err()
}

func replayProject(projects []string, replayID string, s *Server, r *http.Request) (string, bool) {
	if replayID == "" {
		return "", false
	}
	for _, projectID := range projects {
		var found int
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM replays WHERE project_id = ? AND replay_id = ?`, projectID, replayID).Scan(&found); err == nil && found > 0 {
			return projectID, true
		}
	}
	return "", false
}

func (s *Server) deleteReplaySession(w http.ResponseWriter, r *http.Request, principal *auth.Principal, projects []string, replayID string) {
	projectID, ok := replayProject(projects, replayID, s, r)
	if !ok {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete replay")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'delete_replay', 'replay', ?)`, organizationID, projectID, principal.UserID, replayID)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `DELETE FROM replay_error_links WHERE project_id = ? AND replay_id = ?`, projectID, replayID)
	}
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `DELETE FROM replays WHERE project_id = ? AND replay_id = ?`, projectID, replayID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete replay")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit replay deletion")
		return
	}
	if _, err := maintenance.RemoveOrphanedBlobs(r.Context(), s.store, organizationID); err != nil {
		writeError(w, http.StatusInternalServerError, "replay deleted but blob cleanup failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func placeholders(count int) string {
	if count <= 0 {
		return "NULL"
	}
	return strings.TrimSuffix(strings.Repeat("?,", count), ",")
}
