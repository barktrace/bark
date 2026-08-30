package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type sentryActivityRecord struct {
	ID        string
	UserID    sql.NullString
	UserName  sql.NullString
	UserEmail sql.NullString
	AvatarURL sql.NullString
	Kind      string
	Value     string
	CreatedAt string
}

func (s *Server) sentryIssueActivities(w http.ResponseWriter, r *http.Request) {
	issue, _, ok := s.authorizedSentryIssue(w, r, false)
	if !ok {
		return
	}
	activities, err := s.listSentryActivities(r, issue.ID, "", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issue activity")
		return
	}
	activities = append(activities, map[string]any{
		"id": "0", "user": nil, "sentry_app": nil, "type": "first_seen",
		"data": map[string]any{"priority": nil}, "dateCreated": normalizeAPITime(issue.FirstSeen),
	})
	writeJSON(w, http.StatusOK, map[string]any{"activity": activities})
}

func (s *Server) sentryIssueComments(w http.ResponseWriter, r *http.Request) {
	issue, principal, ok := s.authorizedSentryIssue(w, r, r.Method == http.MethodPost)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		activities, err := s.listSentryActivities(r, issue.ID, "comment", boundedSentryPageSize(r, 100))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list issue comments")
			return
		}
		writeJSON(w, http.StatusOK, activities)
		return
	}
	text, ok := decodeSentryComment(w, r)
	if !ok {
		return
	}
	var duplicateCreatedAt string
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT created_at FROM issue_activities
		WHERE issue_id = ? AND user_id = ? AND kind = 'comment' AND value = ?
		ORDER BY created_at DESC LIMIT 1`, issue.ID, principal.UserID, text).Scan(&duplicateCreatedAt)
	if err == nil {
		createdAt, _ := time.Parse(time.RFC3339, normalizeAPITime(duplicateCreatedAt))
		if time.Since(createdAt) <= time.Hour {
			writeError(w, http.StatusBadRequest, "you have already posted that comment")
			return
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not check existing comments")
		return
	}
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, 'comment', ?)`, id, issue.ID, principal.UserID, text); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create comment")
		return
	}
	activity, err := s.loadSentryActivity(r, issue.ID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load comment")
		return
	}
	writeJSON(w, http.StatusCreated, sentryActivityResponse(activity))
}

func (s *Server) sentryIssueCommentDetail(w http.ResponseWriter, r *http.Request) {
	issue, principal, ok := s.authorizedSentryIssue(w, r, true)
	if !ok {
		return
	}
	activity, err := s.loadSentryActivity(r, issue.ID, r.PathValue("note_id"))
	if errors.Is(err, sql.ErrNoRows) || err == nil && (activity.Kind != "comment" || !activity.UserID.Valid || activity.UserID.String != principal.UserID) {
		writeError(w, http.StatusNotFound, "comment not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load comment")
		return
	}
	if r.Method == http.MethodDelete {
		result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM issue_activities WHERE id = ? AND issue_id = ? AND kind = 'comment' AND user_id = ?`, activity.ID, issue.ID, principal.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete comment")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "comment not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	text, ok := decodeSentryComment(w, r)
	if !ok {
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE issue_activities SET value = ? WHERE id = ? AND issue_id = ? AND kind = 'comment' AND user_id = ?`, text, activity.ID, issue.ID, principal.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update comment")
		return
	}
	activity.Value = text
	writeJSON(w, http.StatusOK, sentryActivityResponse(activity))
}

func (s *Server) authorizedSentryIssue(w http.ResponseWriter, r *http.Request, write bool) (sentryIssueRecord, *auth.Principal, bool) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issue, err := s.loadSentryIssue(r, r.PathValue("issue_id"))
	if errors.Is(err, sql.ErrNoRows) || err == nil && r.PathValue("org_slug") != "" && r.PathValue("org_slug") != issue.OrganizationSlug && r.PathValue("org_slug") != issue.OrganizationID {
		writeError(w, http.StatusNotFound, "issue not found")
		return sentryIssueRecord{}, principal, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load issue")
		return sentryIssueRecord{}, principal, false
	}
	if !s.canAccessProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusNotFound, "issue not found")
		return sentryIssueRecord{}, principal, false
	}
	if write && !s.canWriteProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusForbidden, "project write access required")
		return sentryIssueRecord{}, principal, false
	}
	return issue, principal, true
}

func (s *Server) listSentryActivities(r *http.Request, issueID, kind string, limit int) ([]map[string]any, error) {
	query := `
		SELECT a.id, a.user_id, u.name, u.email, u.avatar_url, a.kind, a.value, a.created_at
		FROM issue_activities a LEFT JOIN users u ON u.id = a.user_id
		WHERE a.issue_id = ?`
	arguments := []any{issueID}
	if kind != "" {
		query += ` AND a.kind = ?`
		arguments = append(arguments, kind)
	}
	query += ` ORDER BY a.created_at DESC, a.id DESC LIMIT ?`
	arguments = append(arguments, limit)
	rows, err := s.store.DB.QueryContext(r.Context(), query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		activity, err := scanSentryActivity(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, sentryActivityResponse(activity))
	}
	return items, rows.Err()
}

func (s *Server) loadSentryActivity(r *http.Request, issueID, activityID string) (sentryActivityRecord, error) {
	return scanSentryActivity(s.store.DB.QueryRowContext(r.Context(), `
		SELECT a.id, a.user_id, u.name, u.email, u.avatar_url, a.kind, a.value, a.created_at
		FROM issue_activities a LEFT JOIN users u ON u.id = a.user_id
		WHERE a.issue_id = ? AND a.id = ?`, issueID, activityID))
}

func scanSentryActivity(row rowScanner) (sentryActivityRecord, error) {
	var activity sentryActivityRecord
	err := row.Scan(&activity.ID, &activity.UserID, &activity.UserName, &activity.UserEmail, &activity.AvatarURL, &activity.Kind, &activity.Value, &activity.CreatedAt)
	return activity, err
}

func sentryActivityResponse(activity sentryActivityRecord) map[string]any {
	var user any
	if activity.UserID.Valid {
		name := firstNonEmpty(activity.UserName.String, activity.UserEmail.String)
		user = map[string]any{
			"id": activity.UserID.String, "name": name, "email": activity.UserEmail.String,
			"username": activity.UserEmail.String, "isActive": true, "avatarUrl": nullableText(activity.AvatarURL.String),
		}
	}
	activityType := activity.Kind
	data := map[string]any{"value": activity.Value}
	switch activity.Kind {
	case "comment":
		activityType, data = "note", map[string]any{"text": activity.Value}
	case "status":
		activityType, data = sentryStatusActivityType(activity.Value), map[string]any{"status": activity.Value}
	case "priority":
		activityType, data = "set_priority", map[string]any{"priority": activity.Value}
	case "assignment":
		activityType, data = "assigned", map[string]any{"assignee": activity.Value}
	case "bookmark":
		activityType, data = map[bool]string{true: "set_bookmarked", false: "set_unbookmarked"}[activity.Value == "on"], map[string]any{}
	case "snooze":
		activityType, data = "set_ignored", map[string]any{"until": nullableText(activity.Value)}
	}
	return map[string]any{
		"id": activity.ID, "user": user, "sentry_app": nil, "type": activityType,
		"data": data, "dateCreated": normalizeAPITime(activity.CreatedAt),
	}
}

func sentryStatusActivityType(status string) string {
	switch status {
	case "resolved":
		return "set_resolved"
	case "ignored":
		return "set_ignored"
	default:
		return "set_unresolved"
	}
}

func decodeSentryComment(w http.ResponseWriter, r *http.Request) (string, bool) {
	var input struct {
		Text string `json:"text"`
		Body string `json:"body"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return "", false
	}
	text := strings.TrimSpace(firstNonEmpty(input.Text, input.Body))
	if text == "" || len(text) > 4000 {
		writeError(w, http.StatusBadRequest, "text must contain 1 to 4000 characters")
		return "", false
	}
	return text, true
}
