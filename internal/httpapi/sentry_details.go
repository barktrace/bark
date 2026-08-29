package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type sentryIssueRecord struct {
	LegacyID         int64
	ID               string
	ProjectID        string
	SentryProject    string
	ProjectSlug      string
	ProjectName      string
	ProjectPlatform  string
	OrganizationID   string
	OrganizationSlug string
	Title            string
	Status           string
	Level            string
	Priority         string
	EventCount       int64
	FirstSeen        string
	LastSeen         string
	AssigneeID       sql.NullString
	AssigneeName     sql.NullString
	AssigneeEmail    sql.NullString
	Bookmarked       bool
	SnoozedUntil     sql.NullString
}

type sentryEventRecord struct {
	ID              string
	EventID         string
	ProjectID       string
	SentryProject   string
	ProjectSlug     string
	ProjectName     string
	ProjectPlatform string
	IssueLegacyID   int64
	IssueTitle      string
	Timestamp       string
	ReceivedAt      string
	Environment     string
	Platform        string
	Level           string
	Release         string
	Payload         []byte
}

func (s *Server) sentryOrganizationDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var slug, name, createdAt string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT slug, name, created_at FROM organizations WHERE id = ?`, organizationID).Scan(&slug, &name, &createdAt); err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	membership, _ := principal.Membership(organizationID)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": organizationID, "slug": slug, "name": name, "dateCreated": normalizeAPITime(createdAt),
		"status":         map[string]string{"id": "active", "name": "active"},
		"isEarlyAdopter": false, "require2FA": false, "role": membership.Role,
	})
}

func (s *Server) sentryProjectDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	response, err := s.sentryProjectResponse(r, projectID, organizationID)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) sentryProjectKeys(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	var sentryID, publicKey, createdAt string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT sentry_id, public_key, created_at FROM projects WHERE id = ?`, projectID).Scan(&sentryID, &publicKey, &createdAt); err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	dsn := dsnURL(s.cfg.PublicURL, publicKey, sentryID)
	writeJSON(w, http.StatusOK, []map[string]any{{
		"id": publicKey, "name": "Default", "label": "Default", "public": publicKey,
		"secret": nil, "projectId": sentryID, "isActive": true,
		"dateCreated": normalizeAPITime(createdAt),
		"dsn":         map[string]string{"public": dsn, "security": dsn, "csp": dsn, "minidump": dsn, "unreal": dsn},
	}})
}

func (s *Server) sentryIssueDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issue, err := s.loadSentryIssue(r, r.PathValue("issue_id"))
	if errors.Is(err, sql.ErrNoRows) || err == nil && !s.canAccessProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load issue")
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !s.canWriteProject(r, principal, issue.ProjectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		if !s.updateSentryIssue(w, r, principal, &issue) {
			return
		}
		issue, err = s.loadSentryIssue(r, r.PathValue("issue_id"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not reload issue")
			return
		}
	case http.MethodDelete:
		if !s.canManageProject(r, principal, issue.ProjectID) {
			writeError(w, http.StatusForbidden, "project administrator access required")
			return
		}
		if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM issues WHERE id = ?`, issue.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete issue")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, s.sentryIssueResponse(issue))
}

func (s *Server) sentryIssueEvents(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issue, err := s.loadSentryIssue(r, r.PathValue("issue_id"))
	if errors.Is(err, sql.ErrNoRows) || err == nil && !s.canAccessProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load issue")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), sentryEventSelect+` WHERE e.issue_id = ? ORDER BY e.timestamp DESC LIMIT 100`, issue.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issue events")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		record, err := scanSentryEvent(rows)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list issue events")
			return
		}
		items = append(items, s.sentryEventResponse(record))
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issue events")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryIssueLatestEvent(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issue, err := s.loadSentryIssue(r, r.PathValue("issue_id"))
	if errors.Is(err, sql.ErrNoRows) || err == nil && !s.canAccessProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load issue")
		return
	}
	record, err := s.querySentryEvent(r, sentryEventSelect+` WHERE e.issue_id = ? ORDER BY e.timestamp DESC LIMIT 1`, issue.ID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load event")
		return
	}
	writeJSON(w, http.StatusOK, s.sentryEventResponse(record))
}

func (s *Server) sentryProjectEventDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	record, err := s.querySentryEvent(r, sentryEventSelect+` WHERE e.project_id = ? AND (e.event_id = ? OR e.id = ?) LIMIT 1`, projectID, r.PathValue("event_id"), r.PathValue("event_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load event")
		return
	}
	writeJSON(w, http.StatusOK, s.sentryEventResponse(record))
}

func (s *Server) sentryProjectResponse(r *http.Request, projectID, organizationID string) (map[string]any, error) {
	var sentryID, slug, name, platform, publicKey, createdAt, organizationSlug, organizationName string
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), p.public_key, p.created_at, o.slug, o.name
		FROM projects p JOIN organizations o ON o.id = p.organization_id
		WHERE p.id = ? AND p.organization_id = ?
	`, projectID, organizationID).Scan(&sentryID, &slug, &name, &platform, &publicKey, &createdAt, &organizationSlug, &organizationName)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id": sentryID, "slug": slug, "name": name, "platform": platform,
		"dateCreated": normalizeAPITime(createdAt), "isBookmarked": false,
		"organization": map[string]string{"id": organizationID, "slug": organizationSlug, "name": organizationName},
		"team":         nil, "teams": []any{}, "features": []string{},
		"dsn": map[string]string{"public": dsnURL(s.cfg.PublicURL, publicKey, sentryID)},
	}, nil
}

func (s *Server) loadSentryIssue(r *http.Request, identifier string) (sentryIssueRecord, error) {
	legacyID, err := strconv.ParseInt(identifier, 10, 64)
	if err != nil || legacyID <= 0 {
		return sentryIssueRecord{}, sql.ErrNoRows
	}
	var issue sentryIssueRecord
	err = s.store.DB.QueryRowContext(r.Context(), `
		SELECT i.rowid, i.id, i.project_id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''),
		       o.id, o.slug, i.title, i.status, i.level, i.priority, i.event_count,
		       i.first_seen_at, i.last_seen_at, i.assignee_user_id, u.name, u.email,
		       i.bookmarked, i.snoozed_until
		FROM issues i
		JOIN projects p ON p.id = i.project_id
		JOIN organizations o ON o.id = p.organization_id
		LEFT JOIN users u ON u.id = i.assignee_user_id
		WHERE i.rowid = ?
	`, legacyID).Scan(
		&issue.LegacyID, &issue.ID, &issue.ProjectID, &issue.SentryProject, &issue.ProjectSlug,
		&issue.ProjectName, &issue.ProjectPlatform, &issue.OrganizationID, &issue.OrganizationSlug,
		&issue.Title, &issue.Status, &issue.Level, &issue.Priority, &issue.EventCount,
		&issue.FirstSeen, &issue.LastSeen, &issue.AssigneeID, &issue.AssigneeName,
		&issue.AssigneeEmail, &issue.Bookmarked, &issue.SnoozedUntil,
	)
	return issue, err
}

func (s *Server) sentryIssueResponse(issue sentryIssueRecord) map[string]any {
	var assignedTo any
	if issue.AssigneeID.Valid {
		assignedTo = map[string]any{"type": "user", "id": issue.AssigneeID.String, "name": issue.AssigneeName.String, "email": issue.AssigneeEmail.String}
	}
	statusDetails := map[string]any{}
	if issue.SnoozedUntil.Valid {
		statusDetails["ignoreUntil"] = normalizeAPITime(issue.SnoozedUntil.String)
	}
	identifier := strconv.FormatInt(issue.LegacyID, 10)
	return map[string]any{
		"id": identifier, "shareId": nil, "shortId": strings.ToUpper(issue.ProjectSlug) + "-" + identifier,
		"title": issue.Title, "culprit": "", "permalink": strings.TrimRight(s.cfg.PublicURL, "/") + "/ui/issues/",
		"logger": nil, "level": issue.Level, "status": issue.Status, "statusDetails": statusDetails,
		"isPublic": false, "platform": issue.ProjectPlatform, "project": map[string]any{
			"id": issue.SentryProject, "name": issue.ProjectName, "slug": issue.ProjectSlug, "platform": issue.ProjectPlatform,
		},
		"type": "error", "metadata": map[string]string{"title": issue.Title}, "numComments": 0,
		"assignedTo": assignedTo, "isBookmarked": issue.Bookmarked, "isSubscribed": true,
		"subscriptionDetails": nil, "hasSeen": false, "annotations": []any{}, "issueType": "error",
		"issueCategory": "error", "priority": issue.Priority, "priorityLockedAt": nil,
		"count": strconv.FormatInt(issue.EventCount, 10), "userCount": 0,
		"firstSeen": normalizeAPITime(issue.FirstSeen), "lastSeen": normalizeAPITime(issue.LastSeen),
	}
}

func (s *Server) updateSentryIssue(w http.ResponseWriter, r *http.Request, principal *auth.Principal, issue *sentryIssueRecord) bool {
	var input struct {
		Status        *string         `json:"status"`
		StatusDetails map[string]any  `json:"statusDetails"`
		Priority      *string         `json:"priority"`
		AssignedTo    json.RawMessage `json:"assignedTo"`
		IsBookmarked  *bool           `json:"isBookmarked"`
		IsSubscribed  *bool           `json:"isSubscribed"`
		HasSeen       *bool           `json:"hasSeen"`
		IsPublic      *bool           `json:"isPublic"`
		Discard       *bool           `json:"discard"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return false
	}
	changes := make([][2]string, 0, 3)
	if input.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*input.Status))
		if status != "unresolved" && status != "resolved" && status != "ignored" {
			writeError(w, http.StatusBadRequest, "invalid issue status")
			return false
		}
		if status != issue.Status {
			issue.Status = status
			changes = append(changes, [2]string{"status", status})
		}
	}
	if input.Priority != nil {
		priority := strings.ToLower(strings.TrimSpace(*input.Priority))
		if priority != "low" && priority != "medium" && priority != "high" && priority != "critical" {
			writeError(w, http.StatusBadRequest, "invalid issue priority")
			return false
		}
		if priority != issue.Priority {
			issue.Priority = priority
			changes = append(changes, [2]string{"priority", priority})
		}
	}
	if input.IsBookmarked != nil && *input.IsBookmarked != issue.Bookmarked {
		issue.Bookmarked = *input.IsBookmarked
		changes = append(changes, [2]string{"bookmark", map[bool]string{true: "on", false: "off"}[issue.Bookmarked]})
	}
	if input.IsPublic != nil && *input.IsPublic {
		writeError(w, http.StatusBadRequest, "public issue sharing is not supported")
		return false
	}
	if input.Discard != nil && *input.Discard {
		writeError(w, http.StatusBadRequest, "discarding future events is not supported")
		return false
	}
	if len(input.AssignedTo) > 0 {
		assigneeID, err := sentryAssigneeID(input.AssignedTo)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false
		}
		if assigneeID != "" && !s.userCanAccessProject(r, assigneeID, issue.ProjectID) {
			writeError(w, http.StatusBadRequest, "assignee is not a project member")
			return false
		}
		if assigneeID != issue.AssigneeID.String {
			issue.AssigneeID = sql.NullString{String: assigneeID, Valid: assigneeID != ""}
			changes = append(changes, [2]string{"assignment", assigneeID})
		}
	}
	if input.Status != nil {
		snoozedUntil, err := sentrySnoozedUntil(issue.Status, input.StatusDetails)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false
		}
		if snoozedUntil.String != issue.SnoozedUntil.String || snoozedUntil.Valid != issue.SnoozedUntil.Valid {
			issue.SnoozedUntil = snoozedUntil
			changes = append(changes, [2]string{"snooze", snoozedUntil.String})
		}
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return false
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `UPDATE issues SET status = ?, priority = ?, assignee_user_id = ?, bookmarked = ?, snoozed_until = ? WHERE id = ?`, issue.Status, issue.Priority, nullStringValue(issue.AssigneeID), boolInteger(issue.Bookmarked), nullStringValue(issue.SnoozedUntil), issue.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return false
	}
	for _, change := range changes {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), issue.ID, principal.UserID, change[0], change[1]); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record issue activity")
			return false
		}
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit issue update")
		return false
	}
	return true
}

func sentryAssigneeID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", errors.New("assignedTo must be a user identifier or null")
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "team:") {
		return "", errors.New("team assignment is not supported")
	}
	return strings.TrimPrefix(value, "user:"), nil
}

func sentrySnoozedUntil(status string, details map[string]any) (sql.NullString, error) {
	if status != "ignored" {
		return sql.NullString{}, nil
	}
	if value, ok := details["ignoreUntil"].(string); ok && strings.TrimSpace(value) != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || !parsed.After(time.Now()) {
			return sql.NullString{}, errors.New("statusDetails.ignoreUntil must be a future RFC3339 timestamp")
		}
		return sql.NullString{String: parsed.UTC().Format(time.RFC3339Nano), Valid: true}, nil
	}
	if value, ok := details["ignoreDuration"].(float64); ok {
		if value <= 0 || value > 525600 {
			return sql.NullString{}, errors.New("statusDetails.ignoreDuration must be between 1 and 525600 minutes")
		}
		until := time.Now().UTC().Add(time.Duration(value * float64(time.Minute)))
		return sql.NullString{String: until.Format(time.RFC3339Nano), Valid: true}, nil
	}
	return sql.NullString{}, nil
}

const sentryEventSelect = `
	SELECT e.id, e.event_id, e.project_id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''),
	       i.rowid, i.title, e.timestamp, e.received_at, e.environment, e.platform, e.level,
	       COALESCE(rel.version, ''), COALESCE(e.processed_payload, e.payload)
	FROM events e
	JOIN projects p ON p.id = e.project_id
	JOIN issues i ON i.id = e.issue_id
	LEFT JOIN releases rel ON rel.id = e.release_id`

type sentryEventScanner interface {
	Scan(dest ...any) error
}

func scanSentryEvent(scanner sentryEventScanner) (sentryEventRecord, error) {
	var event sentryEventRecord
	err := scanner.Scan(
		&event.ID, &event.EventID, &event.ProjectID, &event.SentryProject, &event.ProjectSlug,
		&event.ProjectName, &event.ProjectPlatform, &event.IssueLegacyID, &event.IssueTitle,
		&event.Timestamp, &event.ReceivedAt, &event.Environment, &event.Platform, &event.Level,
		&event.Release, &event.Payload,
	)
	return event, err
}

func (s *Server) querySentryEvent(r *http.Request, query string, arguments ...any) (sentryEventRecord, error) {
	return scanSentryEvent(s.store.DB.QueryRowContext(r.Context(), query, arguments...))
}

func (s *Server) sentryEventResponse(event sentryEventRecord) map[string]any {
	payload := make(map[string]any)
	_ = json.Unmarshal(event.Payload, &payload)
	entries := make([]map[string]any, 0, 4)
	if value := payload["exception"]; value != nil {
		entries = append(entries, map[string]any{"type": "exception", "data": value})
	}
	if value := payload["message"]; value != nil {
		message := value
		if text, ok := value.(string); ok {
			message = map[string]any{"formatted": text}
		}
		entries = append(entries, map[string]any{"type": "message", "data": message})
	}
	if value := payload["breadcrumbs"]; value != nil {
		entries = append(entries, map[string]any{"type": "breadcrumbs", "data": value})
	}
	if value := payload["request"]; value != nil {
		entries = append(entries, map[string]any{"type": "request", "data": value})
	}
	platform := firstNonEmpty(event.Platform, event.ProjectPlatform)
	return map[string]any{
		"id": event.EventID, "eventID": event.EventID, "groupID": strconv.FormatInt(event.IssueLegacyID, 10),
		"projectID": event.SentryProject, "projectSlug": event.ProjectSlug, "title": event.IssueTitle,
		"message": sentryEventMessage(payload, event.IssueTitle), "location": "", "culprit": "",
		"dateCreated": normalizeAPITime(event.Timestamp), "dateReceived": normalizeAPITime(event.ReceivedAt),
		"platform": platform, "type": "error", "level": event.Level, "environment": event.Environment,
		"release": nullableText(event.Release), "tags": sentryEventTags(payload), "user": payload["user"],
		"contexts": valueOr(payload["contexts"], map[string]any{}), "entries": entries,
		"errors": valueOr(payload["errors"], []any{}), "sdk": payload["sdk"], "packages": valueOr(payload["modules"], map[string]any{}),
		"fingerprints": valueOr(payload["fingerprint"], []any{}), "metadata": map[string]string{"title": event.IssueTitle},
		"size": len(event.Payload),
	}
}

func sentryEventMessage(payload map[string]any, fallback string) string {
	if message, ok := payload["message"].(string); ok && strings.TrimSpace(message) != "" {
		return message
	}
	if message, ok := payload["message"].(map[string]any); ok {
		if formatted, ok := message["formatted"].(string); ok && strings.TrimSpace(formatted) != "" {
			return formatted
		}
	}
	return fallback
}

func valueOr(value, fallback any) any {
	if value == nil {
		return fallback
	}
	return value
}
