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
	items, err := s.loadReplaySessions(r, projects, "", principal.UserID)
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
	items, err := s.loadReplaySessions(r, projects, "", principal.UserID)
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
	if len(projects) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
		return
	}
	clauses := []string{"rc.project_id IN (" + placeholders(len(projects)) + ")", "(rc.is_dead = 1 OR rc.is_rage = 1)"}
	arguments := make([]any, 0, len(projects)+10)
	for _, projectID := range projects {
		arguments = append(arguments, projectID)
	}
	requestedProjects := append([]string(nil), r.URL.Query()["project"]...)
	requestedProjects = append(requestedProjects, r.URL.Query()["projectSlug"]...)
	if len(requestedProjects) > 0 {
		parts := make([]string, 0, len(requestedProjects))
		for _, project := range requestedProjects {
			parts = append(parts, "(p.id = ? OR p.sentry_id = ? OR p.slug = ?)")
			arguments = append(arguments, project, project, project)
		}
		clauses = append(clauses, "("+strings.Join(parts, " OR ")+")")
	}
	if environments := r.URL.Query()["environment"]; len(environments) > 0 {
		clauses = append(clauses, "rp.environment IN ("+placeholders(len(environments))+")")
		for _, environment := range environments {
			arguments = append(arguments, environment)
		}
	}
	for parameter, column := range map[string]string{"start": "rc.timestamp >=", "end": "rc.timestamp <="} {
		if value := strings.TrimSpace(r.URL.Query().Get(parameter)); value != "" {
			parsed, parseErr := time.Parse(time.RFC3339, value)
			if parseErr != nil {
				writeError(w, http.StatusBadRequest, parameter+" must be RFC3339")
				return
			}
			clauses = append(clauses, column+" ?")
			arguments = append(arguments, parsed.UTC().Format(time.RFC3339Nano))
		}
	}
	if query := strings.TrimSpace(r.URL.Query().Get("query")); query != "" {
		clauses = append(clauses, "rc.dom_element LIKE ?")
		arguments = append(arguments, "%"+query+"%")
	}
	limit := 100
	if requested, parseErr := strconv.Atoi(r.URL.Query().Get("per_page")); parseErr == nil && requested > 0 && requested <= 100 {
		limit = requested
	}
	order := "SUM(rc.is_dead) + SUM(rc.is_rage) DESC"
	switch firstNonEmpty(r.URL.Query().Get("sortBy"), r.URL.Query().Get("orderBy"), r.URL.Query().Get("sort")) {
	case "count_dead_clicks", "-count_dead_clicks":
		order = "SUM(rc.is_dead) DESC"
	case "count_rage_clicks", "-count_rage_clicks":
		order = "SUM(rc.is_rage) DESC"
	case "dom_element":
		order = "rc.dom_element ASC"
	}
	arguments = append(arguments, limit)
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.sentry_id, rc.dom_element, rc.element, SUM(rc.is_dead), SUM(rc.is_rage) FROM replay_clicks rc JOIN replays rp ON rp.project_id = rc.project_id AND rp.replay_id = rc.replay_id AND rp.segment_id = rc.segment_id JOIN projects p ON p.id = rc.project_id WHERE `+strings.Join(clauses, " AND ")+` GROUP BY p.sentry_id, rc.dom_element, rc.element ORDER BY `+order+` LIMIT ?`, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay selectors")
		return
	}
	items := make([]map[string]any, 0)
	for rows.Next() {
		var projectID, domElement, encodedElement string
		var dead, rage int
		if err := rows.Scan(&projectID, &domElement, &encodedElement, &dead, &rage); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list replay selectors")
			return
		}
		element := map[string]any{}
		_ = json.Unmarshal([]byte(encodedElement), &element)
		items = append(items, map[string]any{"project_id": projectID, "dom_element": domElement, "element": element, "count_dead_clicks": dead, "count_rage_clicks": rage})
	}
	_ = rows.Close()
	writeJSON(w, http.StatusOK, map[string]any{"data": items})
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
	items, err := s.loadReplaySessions(r, projects, replayID, principal.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(items) == 0 {
		writeError(w, http.StatusNotFound, "replay not found")
		return
	}
	projectID, _ := replayProject(projects, replayID, s, r)
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO replay_views(project_id, replay_id, user_id, viewed_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, replay_id, user_id) DO UPDATE SET viewed_at = excluded.viewed_at`, projectID, replayID, principal.UserID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record replay view")
		return
	}
	items[0]["has_viewed"] = true
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
	limit := 1000
	if requested, parseErr := strconv.Atoi(r.URL.Query().Get("per_page")); parseErr == nil && requested > 0 && requested <= 1000 {
		limit = requested
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT node_id, timestamp FROM replay_clicks WHERE project_id = ? AND replay_id = ? ORDER BY timestamp LIMIT ?`, projectID, replayID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay clicks")
		return
	}
	clicks := make([]map[string]any, 0)
	for rows.Next() {
		var nodeID int
		var timestamp string
		if err := rows.Scan(&nodeID, &timestamp); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list replay clicks")
			return
		}
		clicks = append(clicks, map[string]any{"node_id": nodeID, "timestamp": normalizeReplayTime(timestamp)})
	}
	_ = rows.Close()
	writeJSON(w, http.StatusOK, map[string]any{"data": clicks})
}

func normalizeReplayTime(value string) string {
	if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value)); err == nil {
		return parsed.UTC().Format(time.RFC3339Nano)
	}
	return normalizeAPITime(value)
}

func (s *Server) sentryReplayViewedBy(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT u.id, u.name, u.email, COALESCE(u.avatar_url, ''), rv.viewed_at FROM replay_views rv JOIN users u ON u.id = rv.user_id WHERE rv.project_id = ? AND rv.replay_id = ? ORDER BY rv.viewed_at DESC LIMIT 100`, projectID, replayID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list replay viewers")
		return
	}
	viewers := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, email, avatarURL, viewedAt string
		if err := rows.Scan(&id, &name, &email, &avatarURL, &viewedAt); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list replay viewers")
			return
		}
		viewers = append(viewers, map[string]any{"id": id, "name": firstNonEmpty(name, email), "username": email, "email": email, "avatarUrl": avatarURL, "isActive": true, "lastActive": normalizeAPITime(viewedAt), "type": "user"})
	}
	_ = rows.Close()
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"viewed_by": viewers}})
}

func (s *Server) sentryReplayDeletionJob(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projects, organizationID, err := s.replayProjectsForRequest(r, principal)
	if err != nil || len(projects) != 1 {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	projectID := projects[0]
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if r.Method == http.MethodGet {
		jobID, parseErr := strconv.ParseInt(r.PathValue("job_id"), 10, 64)
		if parseErr != nil || jobID <= 0 {
			writeError(w, http.StatusNotFound, "replay deletion job not found")
			return
		}
		job, loadErr := s.loadReplayDeletionJob(r.Context(), projectID, jobID)
		if errors.Is(loadErr, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "replay deletion job not found")
			return
		}
		if loadErr != nil {
			writeError(w, http.StatusInternalServerError, "could not load replay deletion job")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": job})
		return
	}
	var input struct {
		Data struct {
			RangeStart   string   `json:"rangeStart"`
			RangeEnd     string   `json:"rangeEnd"`
			Environments []string `json:"environments"`
			Query        *string  `json:"query"`
		} `json:"data"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	start, startErr := time.Parse(time.RFC3339, strings.TrimSpace(input.Data.RangeStart))
	end, endErr := time.Parse(time.RFC3339, strings.TrimSpace(input.Data.RangeEnd))
	if startErr != nil || endErr != nil || !end.After(start) {
		writeError(w, http.StatusBadRequest, "rangeStart and rangeEnd must be an increasing RFC3339 range")
		return
	}
	if len(input.Data.Environments) > 100 {
		writeError(w, http.StatusBadRequest, "at most 100 environments are allowed")
		return
	}
	environments := make([]string, 0, len(input.Data.Environments))
	seen := make(map[string]struct{})
	for _, value := range input.Data.Environments {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		environments = append(environments, value)
	}
	query := ""
	if input.Data.Query != nil {
		query = strings.TrimSpace(*input.Data.Query)
	}
	if len(query) > 500 {
		writeError(w, http.StatusBadRequest, "query is limited to 500 characters")
		return
	}
	encodedEnvironments, _ := json.Marshal(environments)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create replay deletion job")
		return
	}
	defer tx.Rollback()
	var jobID int64
	err = tx.QueryRowContext(r.Context(), `INSERT INTO replay_deletion_jobs(project_id, range_start, range_end, environments, query) VALUES (?, ?, ?, ?, ?) RETURNING id`, projectID, start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano), string(encodedEnvironments), query).Scan(&jobID)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'create_replay_deletion_job', 'replay_deletion_job', ?)`, organizationID, projectID, principal.UserID, strconv.FormatInt(jobID, 10))
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create replay deletion job")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create replay deletion job")
		return
	}
	job, err := s.loadReplayDeletionJob(r.Context(), projectID, jobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load replay deletion job")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": job})
}

func (s *Server) loadReplayDeletionJob(ctx context.Context, projectID string, jobID int64) (map[string]any, error) {
	var rangeStart, rangeEnd, encodedEnvironments, query, status, createdAt, updatedAt string
	var countDeleted int
	err := s.store.DB.QueryRowContext(ctx, `SELECT range_start, range_end, environments, query, status, count_deleted, created_at, updated_at FROM replay_deletion_jobs WHERE id = ? AND project_id = ?`, jobID, projectID).Scan(&rangeStart, &rangeEnd, &encodedEnvironments, &query, &status, &countDeleted, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	environments := []string{}
	_ = json.Unmarshal([]byte(encodedEnvironments), &environments)
	return map[string]any{
		"id": jobID, "dateCreated": normalizeAPITime(createdAt), "dateUpdated": normalizeAPITime(updatedAt),
		"rangeStart": normalizeAPITime(rangeStart), "rangeEnd": normalizeAPITime(rangeEnd), "environments": environments,
		"status": status, "query": query, "countDeleted": countDeleted,
	}, nil
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

func (s *Server) loadReplaySessions(r *http.Request, projects []string, replayID, viewerID string) ([]map[string]any, error) {
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
		hasViewed := false
		if viewerID != "" {
			var views int
			if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM replay_views WHERE project_id = ? AND replay_id = ? AND user_id = ?`, session.ProjectID, session.ReplayID, viewerID).Scan(&views); err != nil {
				return nil, err
			}
			hasViewed = views > 0
		}
		deadClicks, rageClicks := 0, 0
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COALESCE(SUM(is_dead), 0), COALESCE(SUM(is_rage), 0) FROM replay_clicks WHERE project_id = ? AND replay_id = ?`, session.ProjectID, session.ReplayID).Scan(&deadClicks, &rageClicks); err != nil {
			return nil, err
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
			"count_dead_clicks": deadClicks, "count_rage_clicks": rageClicks, "count_warnings": 0, "count_infos": 0,
			"replay_type": "session", "platform": nil, "has_viewed": hasViewed,
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
		_, err = tx.ExecContext(r.Context(), `DELETE FROM replay_views WHERE project_id = ? AND replay_id = ?`, projectID, replayID)
	}
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `DELETE FROM replay_clicks WHERE project_id = ? AND replay_id = ?`, projectID, replayID)
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
