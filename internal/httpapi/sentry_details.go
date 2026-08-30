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
	Fingerprint      string
	Title            string
	Status           string
	Level            string
	IssueType        string
	IssueCategory    string
	Priority         string
	EventCount       int64
	FirstSeen        string
	LastSeen         string
	AssigneeID       sql.NullString
	AssigneeName     sql.NullString
	AssigneeEmail    sql.NullString
	AssigneeTeamID   sql.NullString
	AssigneeTeamSlug sql.NullString
	AssigneeTeamName sql.NullString
	Bookmarked       bool
	SnoozedUntil     sql.NullString
	ShareID          sql.NullString
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
		"isEarlyAdopter": false, "require2FA": false, "requireEmailVerification": false, "role": membership.Role,
		"features": []string{},
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
	issue, principal, ok := s.authorizedSentryIssue(w, r, false)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !s.canWriteProject(r, principal, issue.ProjectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		updated, discarded := s.updateSentryIssue(w, r, principal, &issue)
		if !updated {
			return
		}
		if discarded {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var err error
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

func (s *Server) sentrySharedIssue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	shareID := strings.ToLower(strings.TrimSpace(r.PathValue("share_id")))
	if len(shareID) != 32 {
		writeError(w, http.StatusNotFound, "shared issue not found")
		return
	}
	for _, character := range shareID {
		if !strings.ContainsRune("0123456789abcdef", character) {
			writeError(w, http.StatusNotFound, "shared issue not found")
			return
		}
	}
	issue, err := s.loadSentryIssueByShare(r, shareID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "shared issue not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load shared issue")
		return
	}
	response := map[string]any{"issue": s.sentryIssueResponse(issue), "latestEvent": nil}
	event, err := s.querySentryEvent(r, sentryEventSelect+` WHERE e.issue_id = ? ORDER BY e.timestamp DESC LIMIT 1`, issue.ID)
	if err == nil {
		response["latestEvent"] = s.sentryPublicEventResponse(event)
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not load shared event")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) sentryIssueEvents(w http.ResponseWriter, r *http.Request) {
	issue, _, ok := s.authorizedSentryIssue(w, r, false)
	if !ok {
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
	s.sentryIssueEventBySelector(w, r, "latest")
}

func (s *Server) sentryIssueEventDetail(w http.ResponseWriter, r *http.Request) {
	s.sentryIssueEventBySelector(w, r, r.PathValue("event_id"))
}

func (s *Server) sentryIssueEventBySelector(w http.ResponseWriter, r *http.Request, selector string) {
	issue, _, ok := s.authorizedSentryIssue(w, r, false)
	if !ok {
		return
	}
	query := sentryEventSelect + ` WHERE e.issue_id = ?`
	arguments := []any{issue.ID}
	if environments := compactQueryValues(r.URL.Query()["environment"]); len(environments) > 0 {
		query += ` AND e.environment IN (` + queryPlaceholders(len(environments)) + `)`
		for _, environment := range environments {
			arguments = append(arguments, environment)
		}
	}
	for _, boundary := range []struct {
		name   string
		clause string
	}{{"start", " AND e.timestamp >= ?"}, {"end", " AND e.timestamp <= ?"}} {
		if raw := strings.TrimSpace(r.URL.Query().Get(boundary.name)); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid "+boundary.name+" time")
				return
			}
			query += boundary.clause
			arguments = append(arguments, parsed.UTC().Format(time.RFC3339Nano))
		}
	}
	if search := strings.TrimSpace(r.URL.Query().Get("query")); search != "" {
		query += ` AND (LOWER(i.title) LIKE ? OR LOWER(CAST(e.payload AS TEXT)) LIKE ?)`
		pattern := "%" + strings.ToLower(search) + "%"
		arguments = append(arguments, pattern, pattern)
	}
	switch selector {
	case "latest":
		query += ` ORDER BY e.timestamp DESC, e.received_at DESC LIMIT 1`
	case "oldest":
		query += ` ORDER BY e.timestamp, e.received_at LIMIT 1`
	case "recommended":
		query += ` ORDER BY CASE WHEN EXISTS (SELECT 1 FROM replay_error_links rel WHERE rel.project_id = e.project_id AND rel.event_id = e.event_id) THEN 0 ELSE 1 END, e.timestamp DESC, e.received_at DESC LIMIT 1`
	default:
		query += ` AND (e.event_id = ? OR e.id = ?) LIMIT 1`
		arguments = append(arguments, selector, selector)
	}
	record, err := s.querySentryEvent(r, query, arguments...)
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

func (s *Server) sentryProjectEventJSON(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	var payload []byte
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT payload FROM events WHERE project_id = ? AND (event_id = ? OR id = ?) LIMIT 1`, projectID, r.PathValue("event_id"), r.PathValue("event_id")).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil || !json.Valid(payload) {
		writeError(w, http.StatusInternalServerError, "could not load event JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func compactQueryValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func queryPlaceholders(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "?"
	}
	return strings.Join(values, ",")
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

func (s *Server) sentryOrganizationEventID(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	if len(projectIDs) == 0 {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	eventID := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(r.PathValue("event_id")), "-", ""))
	query := sentryEventSelect + ` WHERE p.organization_id = ? AND e.project_id IN (` + queryPlaceholders(len(projectIDs)) + `) AND e.event_id = ? LIMIT 1`
	arguments := make([]any, 0, len(projectIDs)+2)
	arguments = append(arguments, organizationID)
	for _, projectID := range projectIDs {
		arguments = append(arguments, projectID)
	}
	arguments = append(arguments, eventID)
	record, err := s.querySentryEvent(r, query, arguments...)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve event")
		return
	}
	issue, err := s.loadSentryIssue(r, strconv.FormatInt(record.IssueLegacyID, 10))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve event issue")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": s.sentryEventResponse(record), "group": s.sentryIssueResponse(issue)})
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
	teamRows, err := s.store.DB.QueryContext(r.Context(), `SELECT t.id, t.slug, t.name FROM team_projects tp JOIN teams t ON t.id = tp.team_id WHERE tp.project_id = ? ORDER BY t.name`, projectID)
	if err != nil {
		return nil, err
	}
	teams := make([]map[string]string, 0)
	for teamRows.Next() {
		var id, teamSlug, teamName string
		if err := teamRows.Scan(&id, &teamSlug, &teamName); err != nil {
			_ = teamRows.Close()
			return nil, err
		}
		teams = append(teams, map[string]string{"id": id, "slug": teamSlug, "name": teamName})
	}
	if err := teamRows.Close(); err != nil {
		return nil, err
	}
	var primaryTeam any
	if len(teams) > 0 {
		primaryTeam = teams[0]
	}
	return map[string]any{
		"id": sentryID, "slug": slug, "name": name, "platform": platform,
		"dateCreated": normalizeAPITime(createdAt), "isBookmarked": false,
		"organization": map[string]string{"id": organizationID, "slug": organizationSlug, "name": organizationName},
		"team":         primaryTeam, "teams": teams, "features": []string{},
		"dsn": map[string]string{"public": dsnURL(s.cfg.PublicURL, publicKey, sentryID)},
	}, nil
}

func (s *Server) loadSentryIssue(r *http.Request, identifier string) (sentryIssueRecord, error) {
	legacyID, err := strconv.ParseInt(identifier, 10, 64)
	if err != nil || legacyID <= 0 {
		return sentryIssueRecord{}, sql.ErrNoRows
	}
	var issue sentryIssueRecord
	err = s.store.DB.QueryRowContext(r.Context(), sentryIssueSelect+`
		WHERE i.rowid = ?
	`, legacyID).Scan(sentryIssueScanTargets(&issue)...)
	return issue, err
}

func (s *Server) loadSentryIssueByShare(r *http.Request, shareID string) (sentryIssueRecord, error) {
	var issue sentryIssueRecord
	err := s.store.DB.QueryRowContext(r.Context(), sentryIssueSelect+`
		WHERE i.share_id = ?
	`, shareID).Scan(sentryIssueScanTargets(&issue)...)
	return issue, err
}

const sentryIssueSelect = `
		SELECT i.rowid, i.id, i.project_id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''),
		       o.id, o.slug, i.fingerprint, i.title, i.status, i.level, i.issue_type, i.issue_category, i.priority, i.event_count,
		       i.first_seen_at, i.last_seen_at, i.assignee_user_id, u.name, u.email,
		       i.assignee_team_id, at.slug, at.name, i.bookmarked, i.snoozed_until, i.share_id
		FROM issues i
		JOIN projects p ON p.id = i.project_id
		JOIN organizations o ON o.id = p.organization_id
		LEFT JOIN users u ON u.id = i.assignee_user_id
		LEFT JOIN teams at ON at.id = i.assignee_team_id`

func sentryIssueScanTargets(issue *sentryIssueRecord) []any {
	return []any{
		&issue.LegacyID, &issue.ID, &issue.ProjectID, &issue.SentryProject, &issue.ProjectSlug,
		&issue.ProjectName, &issue.ProjectPlatform, &issue.OrganizationID, &issue.OrganizationSlug,
		&issue.Fingerprint, &issue.Title, &issue.Status, &issue.Level, &issue.IssueType, &issue.IssueCategory, &issue.Priority, &issue.EventCount,
		&issue.FirstSeen, &issue.LastSeen, &issue.AssigneeID, &issue.AssigneeName,
		&issue.AssigneeEmail, &issue.AssigneeTeamID, &issue.AssigneeTeamSlug, &issue.AssigneeTeamName,
		&issue.Bookmarked, &issue.SnoozedUntil, &issue.ShareID,
	}
}

func (s *Server) sentryIssueResponse(issue sentryIssueRecord) map[string]any {
	var assignedTo any
	if issue.AssigneeID.Valid {
		assignedTo = map[string]any{"type": "user", "id": issue.AssigneeID.String, "name": issue.AssigneeName.String, "email": issue.AssigneeEmail.String}
	} else if issue.AssigneeTeamID.Valid {
		assignedTo = map[string]any{"type": "team", "id": issue.AssigneeTeamID.String, "slug": issue.AssigneeTeamSlug.String, "name": issue.AssigneeTeamName.String}
	}
	statusDetails := map[string]any{}
	if issue.SnoozedUntil.Valid {
		statusDetails["ignoreUntil"] = normalizeAPITime(issue.SnoozedUntil.String)
	}
	identifier := strconv.FormatInt(issue.LegacyID, 10)
	var shareID any
	if issue.ShareID.Valid {
		shareID = issue.ShareID.String
	}
	return map[string]any{
		"id": identifier, "shareId": shareID, "shortId": strings.ToUpper(issue.ProjectSlug) + "-" + identifier,
		"title": issue.Title, "culprit": "", "permalink": strings.TrimRight(s.cfg.PublicURL, "/") + "/ui/issues/",
		"logger": nil, "level": issue.Level, "status": issue.Status, "statusDetails": statusDetails,
		"isPublic": issue.ShareID.Valid, "platform": issue.ProjectPlatform, "project": map[string]any{
			"id": issue.SentryProject, "name": issue.ProjectName, "slug": issue.ProjectSlug, "platform": issue.ProjectPlatform,
		},
		"type": "error", "metadata": map[string]string{"title": issue.Title}, "numComments": 0,
		"assignedTo": assignedTo, "isBookmarked": issue.Bookmarked, "isSubscribed": true,
		"subscriptionDetails": nil, "hasSeen": false, "annotations": []any{}, "issueType": issue.IssueType,
		"issueCategory": issue.IssueCategory, "priority": issue.Priority, "priorityLockedAt": nil,
		"count": strconv.FormatInt(issue.EventCount, 10), "userCount": 0,
		"firstSeen": normalizeAPITime(issue.FirstSeen), "lastSeen": normalizeAPITime(issue.LastSeen),
	}
}

func (s *Server) updateSentryIssue(w http.ResponseWriter, r *http.Request, principal *auth.Principal, issue *sentryIssueRecord) (bool, bool) {
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
		return false, false
	}
	if input.Discard != nil && *input.Discard {
		if !s.canManageProject(r, principal, issue.ProjectID) {
			writeError(w, http.StatusForbidden, "project administrator access required to discard an issue")
			return false, false
		}
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not discard issue")
			return false, false
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(r.Context(), `INSERT INTO discarded_issue_fingerprints(project_id, fingerprint, discarded_by) VALUES (?, ?, ?) ON CONFLICT(project_id, fingerprint) DO UPDATE SET discarded_by = excluded.discarded_by, discarded_at = CURRENT_TIMESTAMP`, issue.ProjectID, issue.Fingerprint, principal.UserID)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id, metadata) VALUES (?, ?, ?, 'discard_issue', 'issue', ?, ?)`, issue.OrganizationID, issue.ProjectID, principal.UserID, issue.ID, json.RawMessage(`{"fingerprint":`+strconv.Quote(issue.Fingerprint)+`}`))
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM issues WHERE id = ?`, issue.ID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not discard issue")
			return false, false
		}
		if err := tx.Commit(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not commit issue discard")
			return false, false
		}
		return true, true
	}
	changes := make([][2]string, 0, 3)
	sharingChanged := false
	if input.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*input.Status))
		if status != "unresolved" && status != "resolved" && status != "ignored" {
			writeError(w, http.StatusBadRequest, "invalid issue status")
			return false, false
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
			return false, false
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
	if input.IsPublic != nil && *input.IsPublic != issue.ShareID.Valid {
		if !s.canManageProject(r, principal, issue.ProjectID) {
			writeError(w, http.StatusForbidden, "project administrator access required to change public sharing")
			return false, false
		}
		if *input.IsPublic {
			issue.ShareID = sql.NullString{String: strings.ReplaceAll(uuid.NewString(), "-", ""), Valid: true}
		} else {
			issue.ShareID = sql.NullString{}
		}
		sharingChanged = true
	}
	if len(input.AssignedTo) > 0 {
		assigneeType, assigneeID, err := sentryAssignee(input.AssignedTo)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false, false
		}
		switch assigneeType {
		case "user":
			if assigneeID != "" && !s.userCanAccessProject(r, assigneeID, issue.ProjectID) {
				writeError(w, http.StatusBadRequest, "assignee is not a project member")
				return false, false
			}
			if assigneeID != issue.AssigneeID.String || issue.AssigneeTeamID.Valid {
				issue.AssigneeID = sql.NullString{String: assigneeID, Valid: assigneeID != ""}
				issue.AssigneeTeamID = sql.NullString{}
				changes = append(changes, [2]string{"assignment", assigneeID})
			}
		case "team":
			var teamSlug, teamName string
			if err := s.store.DB.QueryRowContext(r.Context(), `SELECT t.slug, t.name FROM teams t JOIN team_projects tp ON tp.team_id = t.id WHERE t.id = ? AND tp.project_id = ?`, assigneeID, issue.ProjectID).Scan(&teamSlug, &teamName); err != nil {
				writeError(w, http.StatusBadRequest, "assignee team is not linked to the project")
				return false, false
			}
			if assigneeID != issue.AssigneeTeamID.String || issue.AssigneeID.Valid {
				issue.AssigneeID = sql.NullString{}
				issue.AssigneeTeamID = sql.NullString{String: assigneeID, Valid: true}
				issue.AssigneeTeamSlug = sql.NullString{String: teamSlug, Valid: true}
				issue.AssigneeTeamName = sql.NullString{String: teamName, Valid: true}
				changes = append(changes, [2]string{"assignment", "team:" + assigneeID})
			}
		}
	}
	if input.Status != nil {
		snoozedUntil, err := sentrySnoozedUntil(issue.Status, input.StatusDetails)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return false, false
		}
		if snoozedUntil.String != issue.SnoozedUntil.String || snoozedUntil.Valid != issue.SnoozedUntil.Valid {
			issue.SnoozedUntil = snoozedUntil
			changes = append(changes, [2]string{"snooze", snoozedUntil.String})
		}
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return false, false
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `UPDATE issues SET status = ?, priority = ?, assignee_user_id = ?, assignee_team_id = ?, bookmarked = ?, snoozed_until = ?, share_id = ? WHERE id = ?`, issue.Status, issue.Priority, nullStringValue(issue.AssigneeID), nullStringValue(issue.AssigneeTeamID), boolInteger(issue.Bookmarked), nullStringValue(issue.SnoozedUntil), nullStringValue(issue.ShareID), issue.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update issue")
		return false, false
	}
	for _, change := range changes {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), issue.ID, principal.UserID, change[0], change[1]); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record issue activity")
			return false, false
		}
	}
	if sharingChanged {
		action := "disable_issue_sharing"
		if issue.ShareID.Valid {
			action = "enable_issue_sharing"
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, ?, 'issue', ?)`, issue.OrganizationID, issue.ProjectID, principal.UserID, action, issue.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record sharing audit")
			return false, false
		}
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit issue update")
		return false, false
	}
	return true, false
}

func sentryAssignee(raw json.RawMessage) (string, string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "user", "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", "", errors.New("assignedTo must be a user or team identifier, or null")
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "team:") {
		value = strings.TrimPrefix(value, "team:")
		if value == "" {
			return "", "", errors.New("assignedTo team identifier is empty")
		}
		return "team", value, nil
	}
	return "user", strings.TrimPrefix(value, "user:"), nil
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

func (s *Server) sentryPublicEventResponse(event sentryEventRecord) map[string]any {
	response := s.sentryEventResponse(event)
	delete(response, "user")
	delete(response, "contexts")
	delete(response, "sdk")
	delete(response, "packages")
	entries, _ := response["entries"].([]map[string]any)
	publicEntries := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if entry["type"] != "request" {
			publicEntries = append(publicEntries, entry)
		}
	}
	response["entries"] = publicEntries
	return response
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
