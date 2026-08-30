package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/releasehealth"
)

type sentryIssueSearch struct {
	status       string
	level        string
	issueType    string
	assigned     string
	bookmarked   bool
	freeText     []string
	environments []string
}

func (s *Server) sentryOrganizationIssues(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	projectIDs, err = s.filterAccessibleProjects(r, projectIDs, compactQueryValues(r.URL.Query()["project"]))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not filter projects")
		return
	}
	if len(projectIDs) == 0 {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	search, err := parseSentryIssueSearch(r, principal.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	query := sentryIssueSelect + ` WHERE i.project_id IN (` + queryPlaceholders(len(projectIDs)) + `)`
	arguments := make([]any, 0, len(projectIDs)+12)
	for _, projectID := range projectIDs {
		arguments = append(arguments, projectID)
	}
	if search.status != "" {
		query += ` AND i.status = ?`
		arguments = append(arguments, search.status)
	}
	if search.level != "" {
		query += ` AND i.level = ?`
		arguments = append(arguments, search.level)
	}
	if search.issueType != "" {
		query += ` AND i.issue_type = ?`
		arguments = append(arguments, search.issueType)
	}
	if search.assigned != "" {
		switch search.assigned {
		case "none":
			query += ` AND i.assignee_user_id IS NULL AND i.assignee_team_id IS NULL`
		default:
			query += ` AND (i.assignee_user_id = ? OR LOWER(COALESCE(u.email, '')) = LOWER(?))`
			arguments = append(arguments, search.assigned, search.assigned)
		}
	}
	if search.bookmarked {
		query += ` AND i.bookmarked = ?`
		arguments = append(arguments, true)
	}
	for _, term := range search.freeText {
		query += ` AND (LOWER(i.title) LIKE ? OR LOWER(i.fingerprint) LIKE ? OR LOWER(i.issue_type) LIKE ?)`
		pattern := "%" + strings.ToLower(term) + "%"
		arguments = append(arguments, pattern, pattern, pattern)
	}
	if len(search.environments) > 0 {
		query += ` AND EXISTS (SELECT 1 FROM events search_event WHERE search_event.issue_id = i.id AND search_event.environment IN (` + queryPlaceholders(len(search.environments)) + `))`
		for _, environment := range search.environments {
			arguments = append(arguments, environment)
		}
	}
	if hasIssueTimeRange(r) {
		start, end, err := releasehealth.ParseRange(time.Now().UTC(), r.URL.Query().Get("start"), r.URL.Query().Get("end"), r.URL.Query().Get("statsPeriod"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		query += ` AND i.last_seen_at >= ? AND i.last_seen_at < ?`
		arguments = append(arguments, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	}
	order, err := sentryIssueOrder(r.URL.Query().Get("sort"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := sentryIssueLimit(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := sentryIssueOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	query += order + ` LIMIT ? OFFSET ?`
	arguments = append(arguments, limit+1, offset)

	rows, err := s.store.DB.QueryContext(r.Context(), query, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issues")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var issue sentryIssueRecord
		if err := rows.Scan(sentryIssueScanTargets(&issue)...); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list issues")
			return
		}
		items = append(items, s.sentryIssueResponse(issue))
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issues")
		return
	}
	hasNext := len(items) > limit
	if hasNext {
		items = items[:limit]
	}
	s.writeSentryIssueLinks(w, r, offset, limit, hasNext)
	writeJSON(w, http.StatusOK, items)
}

func parseSentryIssueSearch(r *http.Request, currentUserID string) (sentryIssueSearch, error) {
	search := sentryIssueSearch{status: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))), environments: compactQueryValues(r.URL.Query()["environment"])}
	if search.status == "all" {
		search.status = ""
	}
	if search.status != "" && search.status != "unresolved" && search.status != "resolved" && search.status != "ignored" {
		return sentryIssueSearch{}, errors.New("unsupported issue status")
	}
	for _, token := range strings.Fields(strings.TrimSpace(r.URL.Query().Get("query"))) {
		key, value, found := strings.Cut(token, ":")
		if !found {
			search.freeText = append(search.freeText, token)
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch key {
		case "is":
			value = strings.ToLower(value)
			if value != "unresolved" && value != "resolved" && value != "ignored" {
				return sentryIssueSearch{}, errors.New("unsupported is: issue filter")
			}
			search.status = value
		case "level":
			search.level = strings.ToLower(value)
		case "issue.type":
			search.issueType = strings.ToLower(value)
		case "assigned":
			if strings.EqualFold(value, "me") {
				value = currentUserID
			} else if strings.EqualFold(value, "none") {
				value = "none"
			}
			search.assigned = value
		case "bookmarks":
			if !strings.EqualFold(value, "me") {
				return sentryIssueSearch{}, errors.New("only bookmarks:me is supported")
			}
			search.bookmarked = true
		case "environment":
			if value != "" {
				search.environments = append(search.environments, value)
			}
		default:
			return sentryIssueSearch{}, errors.New("unsupported issue query filter " + key)
		}
	}
	return search, nil
}

func hasIssueTimeRange(r *http.Request) bool {
	query := r.URL.Query()
	return strings.TrimSpace(query.Get("start")) != "" || strings.TrimSpace(query.Get("end")) != "" || strings.TrimSpace(query.Get("statsPeriod")) != ""
}

func sentryIssueOrder(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "date":
		return ` ORDER BY i.last_seen_at DESC, i.rowid DESC`, nil
	case "new":
		return ` ORDER BY i.first_seen_at DESC, i.rowid DESC`, nil
	case "freq":
		return ` ORDER BY i.event_count DESC, i.last_seen_at DESC, i.rowid DESC`, nil
	case "priority":
		return ` ORDER BY CASE i.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, i.last_seen_at DESC, i.rowid DESC`, nil
	default:
		return "", errors.New("unsupported issue sort")
	}
}

func sentryIssueLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("per_page"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("limit"))
	}
	if raw == "" {
		return 100, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 100 {
		return 0, errors.New("issue limit must be between 1 and 100")
	}
	return limit, nil
}

func sentryIssueOffset(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 3 || parts[0] != "offset" || parts[2] != "0" {
		return 0, errors.New("invalid issue cursor")
	}
	offset, err := strconv.Atoi(parts[1])
	if err != nil || offset < 0 || offset > 1_000_000 {
		return 0, errors.New("invalid issue cursor")
	}
	return offset, nil
}

func (s *Server) writeSentryIssueLinks(w http.ResponseWriter, r *http.Request, offset, limit int, hasNext bool) {
	previousOffset := offset - limit
	if previousOffset < 0 {
		previousOffset = 0
	}
	previousCursor := "offset:" + strconv.Itoa(previousOffset) + ":0"
	nextCursor := "offset:" + strconv.Itoa(offset+limit) + ":0"
	pageURL := func(cursor string) string {
		values := r.URL.Query()
		values.Set("cursor", cursor)
		return strings.TrimRight(s.cfg.PublicURL, "/") + r.URL.Path + "?" + values.Encode()
	}
	w.Header().Set("Link", "<"+pageURL(previousCursor)+">; rel=\"previous\"; results=\""+strconv.FormatBool(offset > 0)+"\"; cursor=\""+previousCursor+"\", <"+pageURL(nextCursor)+">; rel=\"next\"; results=\""+strconv.FormatBool(hasNext)+"\"; cursor=\""+nextCursor+"\"")
}
