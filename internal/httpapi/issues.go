package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) issueDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueID := r.PathValue("issue_id")
	var issue map[string]any
	var projectID, title, status, level, priority, firstSeen, lastSeen, firstRelease, lastRelease string
	var assigneeID, assigneeName, snoozedUntil sql.NullString
	var count int64
	var bookmarked bool
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT i.project_id, i.title, i.status, i.level, i.priority, i.event_count,
		       i.first_seen_at, i.last_seen_at, COALESCE(fr.version, ''), COALESCE(lr.version, ''),
		       i.assignee_user_id, u.name, i.bookmarked, i.snoozed_until
		FROM issues i
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		LEFT JOIN users u ON u.id = i.assignee_user_id
		WHERE i.id = ?
	`, issueID).Scan(&projectID, &title, &status, &level, &priority, &count, &firstSeen, &lastSeen, &firstRelease, &lastRelease, &assigneeID, &assigneeName, &bookmarked, &snoozedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "issue access required")
		return
	}
	issue = map[string]any{"id": issueID, "project_id": projectID, "title": title, "status": status, "level": level, "priority": priority, "event_count": count, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "first_release": firstRelease, "last_release": lastRelease, "assignee_user_id": nullString(assigneeID), "assignee_name": nullString(assigneeName), "bookmarked": bookmarked, "snoozed_until": nullString(snoozedUntil)}

	eventRows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT e.id, e.event_id, e.timestamp, e.environment, e.platform, e.level,
		       COALESCE(rel.version, ''), COALESCE(e.processed_payload, e.payload)
		FROM events e LEFT JOIN releases rel ON rel.id = e.release_id
		WHERE e.issue_id = ? ORDER BY e.timestamp DESC LIMIT 100
	`, issueID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issue events")
		return
	}
	events := make([]map[string]any, 0)
	for eventRows.Next() {
		var id, eventID, timestamp, environment, platform, eventLevel, release string
		var payload json.RawMessage
		if err := eventRows.Scan(&id, &eventID, &timestamp, &environment, &platform, &eventLevel, &release, &payload); err != nil {
			_ = eventRows.Close()
			writeError(w, http.StatusInternalServerError, "could not list issue events")
			return
		}
		events = append(events, map[string]any{"id": id, "event_id": eventID, "timestamp": timestamp, "environment": environment, "platform": platform, "level": eventLevel, "release": release, "payload": payload})
	}
	_ = eventRows.Close()

	activityRows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT a.id, a.kind, a.value, a.created_at, COALESCE(u.name, ''), COALESCE(u.email, '')
		FROM issue_activities a LEFT JOIN users u ON u.id = a.user_id
		WHERE a.issue_id = ? ORDER BY a.created_at DESC LIMIT 100
	`, issueID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issue activity")
		return
	}
	defer activityRows.Close()
	activities := make([]map[string]any, 0)
	for activityRows.Next() {
		var id, kind, value, createdAt, userName, userEmail string
		if err := activityRows.Scan(&id, &kind, &value, &createdAt, &userName, &userEmail); err == nil {
			activities = append(activities, map[string]any{"id": id, "kind": kind, "value": value, "created_at": createdAt, "user_name": userName, "user_email": userEmail})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"issue": issue, "events": events, "activities": activities})
}

func (s *Server) eventDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	id := r.PathValue("event_id")
	var projectID, issueID, eventID, timestamp, environment, platform, level, release string
	var payload json.RawMessage
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT e.project_id, e.issue_id, e.event_id, e.timestamp, e.environment, e.platform,
		       e.level, COALESCE(r.version, ''), COALESCE(e.processed_payload, e.payload)
		FROM events e LEFT JOIN releases r ON r.id = e.release_id
		WHERE e.id = ?
	`, id).Scan(&projectID, &issueID, &eventID, &timestamp, &environment, &platform, &level, &release, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "event access required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "event_id": eventID, "issue_id": issueID, "project_id": projectID, "timestamp": timestamp, "environment": environment, "platform": platform, "level": level, "release": release, "payload": payload})
}

func (s *Server) updateIssue(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueID := r.PathValue("issue_id")
	projectID, ok := s.issueProject(r, issueID)
	if !ok {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if !s.canWriteProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project member access required")
		return
	}
	var input struct {
		Status         *string `json:"status"`
		Priority       *string `json:"priority"`
		AssigneeUserID *string `json:"assignee_user_id"`
		Bookmarked     *bool   `json:"bookmarked"`
		SnoozedUntil   *string `json:"snoozed_until"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	var status, priority string
	var assignee, snoozed sql.NullString
	var bookmarked bool
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT status, priority, assignee_user_id, bookmarked, snoozed_until FROM issues WHERE id = ?`, issueID).Scan(&status, &priority, &assignee, &bookmarked, &snoozed); err != nil {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	changes := make([][2]string, 0)
	if input.Status != nil {
		value := strings.ToLower(strings.TrimSpace(*input.Status))
		if value != "unresolved" && value != "resolved" && value != "ignored" {
			writeError(w, http.StatusBadRequest, "invalid issue status")
			return
		}
		if value != status {
			status = value
			changes = append(changes, [2]string{"status", value})
		}
	}
	if input.Priority != nil {
		value := strings.ToLower(strings.TrimSpace(*input.Priority))
		if value != "low" && value != "medium" && value != "high" && value != "critical" {
			writeError(w, http.StatusBadRequest, "invalid issue priority")
			return
		}
		if value != priority {
			priority = value
			changes = append(changes, [2]string{"priority", value})
		}
	}
	if input.AssigneeUserID != nil {
		value := strings.TrimSpace(*input.AssigneeUserID)
		if value != "" && !s.userCanAccessProject(r, value, projectID) {
			writeError(w, http.StatusBadRequest, "assignee is not an organization member")
			return
		}
		if value != assignee.String {
			assignee = sql.NullString{String: value, Valid: value != ""}
			changes = append(changes, [2]string{"assignment", value})
		}
	}
	if input.Bookmarked != nil && *input.Bookmarked != bookmarked {
		bookmarked = *input.Bookmarked
		changes = append(changes, [2]string{"bookmark", map[bool]string{true: "on", false: "off"}[bookmarked]})
	}
	if input.SnoozedUntil != nil {
		value := strings.TrimSpace(*input.SnoozedUntil)
		if value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil || !parsed.After(time.Now()) {
				writeError(w, http.StatusBadRequest, "snooze must be a future RFC3339 timestamp")
				return
			}
			value = parsed.UTC().Format(time.RFC3339Nano)
		}
		if value != snoozed.String {
			snoozed = sql.NullString{String: value, Valid: value != ""}
			changes = append(changes, [2]string{"snooze", value})
		}
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `UPDATE issues SET status = ?, priority = ?, assignee_user_id = ?, bookmarked = ?, snoozed_until = ? WHERE id = ?`, status, priority, nullStringValue(assignee), bookmarked, nullStringValue(snoozed), issueID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return
	}
	for _, change := range changes {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), issueID, principal.UserID, change[0], change[1]); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record issue activity")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit issue update")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": issueID, "status": status, "priority": priority, "assignee_user_id": nullString(assignee), "bookmarked": bookmarked, "snoozed_until": nullString(snoozed)})
}

func (s *Server) createIssueComment(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueID := r.PathValue("issue_id")
	projectID, ok := s.issueProject(r, issueID)
	if !ok || !s.canWriteProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project member access required")
		return
	}
	var input struct {
		Body string `json:"body"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Body = strings.TrimSpace(input.Body)
	if input.Body == "" || len(input.Body) > 4000 {
		writeError(w, http.StatusBadRequest, "comment must contain 1 to 4000 characters")
		return
	}
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, 'comment', ?)`, id, issueID, principal.UserID, input.Body); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create comment")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "body": input.Body, "user_name": principal.Name, "created_at": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) deleteIssue(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueID := r.PathValue("issue_id")
	projectID, ok := s.issueProject(r, issueID)
	if !ok {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM issues WHERE id = ?`, issueID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete issue")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	var input struct {
		Name     string `json:"name"`
		Slug     string `json:"slug"`
		Platform string `json:"platform"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Name, input.Slug, input.Platform = strings.TrimSpace(input.Name), slug(input.Slug), strings.TrimSpace(input.Platform)
	if input.Name == "" || input.Slug == "" {
		writeError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE projects SET name = ?, slug = ?, platform = NULLIF(?, '') WHERE id = ?`, input.Name, input.Slug, input.Platform, projectID); err != nil {
		writeError(w, http.StatusConflict, "project slug already exists")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": projectID, "name": input.Name, "slug": input.Slug, "platform": input.Platform})
}

func (s *Server) rotateProjectKey(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	publicKey := strings.ReplaceAll(uuid.NewString(), "-", "")
	var sentryID string
	if err := s.store.DB.QueryRowContext(r.Context(), `UPDATE projects SET public_key = ? WHERE id = ? RETURNING sentry_id`, publicKey, projectID).Scan(&sentryID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not rotate project key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": publicKey, "dsn": dsnURL(s.cfg.PublicURL, publicKey, sentryID)})
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM projects WHERE id = ?`, projectID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete project")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) issueProject(r *http.Request, issueID string) (string, bool) {
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM issues WHERE id = ?`, issueID).Scan(&projectID); err != nil {
		return "", false
	}
	return projectID, true
}

func (s *Server) userCanAccessProject(r *http.Request, userID, projectID string) bool {
	var organizationRole, projectRole string
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT m.role, COALESCE(pm.role, '')
		FROM projects p JOIN organization_memberships m ON m.organization_id = p.organization_id AND m.user_id = ?
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = m.user_id
		WHERE p.id = ?
	`, userID, projectID).Scan(&organizationRole, &projectRole)
	return err == nil && organizationRole != "" && projectRole != "none"
}

func (s *Server) canWriteProject(r *http.Request, principal *auth.Principal, projectID string) bool {
	role, ok := s.projectRole(r, principal, projectID)
	return ok && (role == "admin" || role == "member")
}

func nullString(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullStringValue(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return nil
}
