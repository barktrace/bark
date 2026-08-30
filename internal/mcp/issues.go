package mcp

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

type organizationIssueSearchArgs struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Status         string `json:"status"`
	Level          string `json:"level"`
	IssueType      string `json:"issue_type"`
	Environment    string `json:"environment"`
	Query          string `json:"query"`
	Sort           string `json:"sort"`
	Limit          int    `json:"limit"`
}

func (s *Service) searchOrganizationIssues(ctx context.Context, projectIDs []string, request organizationIssueSearchArgs) (any, error) {
	if len(projectIDs) == 0 {
		return []any{}, nil
	}
	status := strings.ToLower(strings.TrimSpace(request.Status))
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "unresolved" && status != "resolved" && status != "ignored" {
		return nil, errors.New("status must be all, unresolved, resolved, or ignored")
	}
	statement := `
		SELECT i.id, p.id, p.slug, i.title, i.status, i.level, i.issue_type, i.issue_category, i.priority,
		       i.event_count, i.first_seen_at, i.last_seen_at, COALESCE(fr.version, ''), COALESCE(lr.version, ''),
		       i.assignee_user_id, i.assignee_team_id, i.bookmarked
		FROM issues i JOIN projects p ON p.id = i.project_id
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		WHERE i.project_id IN (` + issuePlaceholders(len(projectIDs)) + `)`
	arguments := make([]any, 0, len(projectIDs)+8)
	for _, projectID := range projectIDs {
		arguments = append(arguments, projectID)
	}
	if status != "all" {
		statement += ` AND i.status = ?`
		arguments = append(arguments, status)
	}
	if level := strings.ToLower(strings.TrimSpace(request.Level)); level != "" {
		statement += ` AND i.level = ?`
		arguments = append(arguments, level)
	}
	if issueType := strings.ToLower(strings.TrimSpace(request.IssueType)); issueType != "" {
		statement += ` AND i.issue_type = ?`
		arguments = append(arguments, issueType)
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		statement += ` AND (LOWER(i.title) LIKE ? OR LOWER(i.fingerprint) LIKE ? OR LOWER(i.issue_type) LIKE ?)`
		pattern := "%" + strings.ToLower(query) + "%"
		arguments = append(arguments, pattern, pattern, pattern)
	}
	if environment := strings.TrimSpace(request.Environment); environment != "" {
		statement += ` AND EXISTS (SELECT 1 FROM events search_event WHERE search_event.issue_id = i.id AND search_event.environment = ?)`
		arguments = append(arguments, environment)
	}
	switch strings.ToLower(strings.TrimSpace(request.Sort)) {
	case "", "date":
		statement += ` ORDER BY i.last_seen_at DESC, i.id DESC`
	case "new":
		statement += ` ORDER BY i.first_seen_at DESC, i.id DESC`
	case "freq":
		statement += ` ORDER BY i.event_count DESC, i.last_seen_at DESC, i.id DESC`
	case "priority":
		statement += ` ORDER BY CASE i.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, i.last_seen_at DESC, i.id DESC`
	default:
		return nil, errors.New("sort must be date, new, freq, or priority")
	}
	statement += ` LIMIT ?`
	arguments = append(arguments, boundedLimit(request.Limit))
	rows, err := s.store.DB.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, projectID, projectSlug, title, issueStatus, level, issueType, issueCategory, priority, firstSeen, lastSeen, firstRelease, lastRelease string
		var assigneeUserID, assigneeTeamID sql.NullString
		var eventCount int64
		var bookmarked bool
		if err := rows.Scan(&id, &projectID, &projectSlug, &title, &issueStatus, &level, &issueType, &issueCategory, &priority, &eventCount, &firstSeen, &lastSeen, &firstRelease, &lastRelease, &assigneeUserID, &assigneeTeamID, &bookmarked); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"id": id, "project_id": projectID, "project_slug": projectSlug, "title": title, "status": issueStatus,
			"level": level, "issue_type": issueType, "issue_category": issueCategory, "priority": priority,
			"event_count": eventCount, "first_seen_at": firstSeen, "last_seen_at": lastSeen,
			"first_release": firstRelease, "last_release": lastRelease, "assignee_user_id": nullableString(assigneeUserID),
			"assignee_team_id": nullableString(assigneeTeamID), "bookmarked": bookmarked,
		})
	}
	return items, rows.Err()
}

func issuePlaceholders(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "?"
	}
	return strings.Join(values, ",")
}
