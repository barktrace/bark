package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var mcpQuotaCategories = map[string]bool{
	"all": true, "error": true, "transaction": true, "span": true, "log": true,
	"session": true, "attachment": true, "feedback": true, "replay": true,
	"profile": true, "metric": true, "check_in": true,
}

func (s *Service) callAdministrationTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	switch name {
	case "list_organization_members":
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		var args struct {
			OrganizationID string `json:"organization_id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		return s.listOrganizationMembers(ctx, organizationID)
	case "list_project_permissions":
		var args projectArgs
		if err := requiredProjectArguments(raw, &args); err != nil {
			return nil, err
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.listProjectPermissions(ctx, args.ProjectID)
	case "list_teams":
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		var args struct {
			OrganizationID string `json:"organization_id"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		return s.listTeams(ctx, organizationID)
	case "create_team":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			OrganizationID string `json:"organization_id"`
			Name           string `json:"name"`
			Slug           string `json:"slug"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.Name) == "" {
			return nil, errors.New("name is required")
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		return s.createTeam(ctx, credential, organizationID, args.Name, args.Slug)
	case "add_team_member", "remove_team_member":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			TeamID string `json:"team_id"`
			UserID string `json:"user_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.TeamID) == "" || strings.TrimSpace(args.UserID) == "" {
			return nil, errors.New("team_id and user_id are required")
		}
		return s.changeTeamMember(ctx, credential, args.TeamID, args.UserID, name == "add_team_member")
	case "link_team_project", "unlink_team_project":
		var args struct {
			TeamID    string `json:"team_id"`
			ProjectID string `json:"project_id"`
			Role      string `json:"role"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.TeamID) == "" || strings.TrimSpace(args.ProjectID) == "" {
			return nil, errors.New("team_id and project_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		return s.changeTeamProject(ctx, credential, args.TeamID, args.ProjectID, args.Role, name == "link_team_project")
	case "update_issue":
		var args issueUpdateArgs
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.IssueID) == "" {
			return nil, errors.New("issue_id is required")
		}
		projectID, err := s.requireIssue(ctx, credential, args.IssueID, "write")
		if err != nil {
			return nil, err
		}
		result, changes, err := s.updateIssue(ctx, credential, projectID, args)
		if err == nil {
			s.recordMutation(ctx, credential, projectID, "update_issue", "issue", args.IssueID, map[string]any{"changes": changes})
		}
		return result, err
	case "set_project_quota":
		var args quotaUpdateArgs
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.Category) == "" {
			return nil, errors.New("project_id and category are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		result, err := s.setProjectQuota(ctx, args)
		if err == nil {
			s.recordMutation(ctx, credential, args.ProjectID, "set_project_quota", "project_quota", strings.ToLower(strings.TrimSpace(args.Category)), result)
		}
		return result, err
	case "retry_ingestion_job", "delete_ingestion_job":
		var args struct {
			ProjectID string `json:"project_id"`
			JobID     string `json:"job_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.JobID) == "" {
			return nil, errors.New("project_id and job_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		var result any
		var err error
		if name == "retry_ingestion_job" {
			result, err = s.retryIngestionJob(ctx, args.ProjectID, args.JobID)
		} else {
			result, err = s.deleteIngestionJob(ctx, args.ProjectID, args.JobID)
		}
		if err == nil {
			s.recordMutation(ctx, credential, args.ProjectID, name, "ingestion_job", args.JobID, nil)
		}
		return result, err
	case "update_retention":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			OrganizationID string `json:"organization_id"`
			Days           int    `json:"days"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		result, err := s.updateRetention(ctx, organizationID, args.Days)
		if err == nil {
			s.recordDiscoverMutation(ctx, credential, organizationID, "", "update_retention", "organization", organizationID, map[string]any{"retention_days": args.Days})
		}
		return result, err
	case "add_issue_comment":
		return s.addIssueCommentTool(ctx, credential, raw)
	case "create_alert_rule", "update_alert_rule", "delete_alert_rule":
		return s.callAlertTool(ctx, credential, name, raw)
	case "create_uptime_monitor", "delete_uptime_monitor":
		return s.callUptimeTool(ctx, credential, name, raw)
	case "create_cron_monitor", "delete_cron_monitor":
		return s.callCronTool(ctx, credential, name, raw)
	default:
		return nil, errors.New("unknown administration tool")
	}
}

func (s *Service) listTeams(ctx context.Context, organizationID string) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT t.id, t.slug, t.name, t.created_at,
		       (SELECT COUNT(*) FROM team_memberships tm WHERE tm.team_id = t.id),
		       (SELECT COUNT(*) FROM team_projects tp WHERE tp.team_id = t.id)
		FROM teams t WHERE t.organization_id = ? ORDER BY t.name, t.slug
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, teamSlug, name, createdAt string
		var members, projects int
		if err := rows.Scan(&id, &teamSlug, &name, &createdAt, &members, &projects); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "slug": teamSlug, "name": name, "member_count": members, "project_count": projects, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) createTeam(ctx context.Context, credential *credential, organizationID, name, rawSlug string) (any, error) {
	name = strings.TrimSpace(name)
	teamSlug := mcpSlug(firstNonEmptyMCP(rawSlug, name))
	if teamSlug == "" {
		return nil, errors.New("valid team name or slug is required")
	}
	id := uuid.NewString()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO teams(id, organization_id, slug, name) VALUES (?, ?, ?, ?)`, id, organizationID, teamSlug, name); err != nil {
		return nil, errors.New("team slug already exists")
	}
	if credential.actorUserID != "" {
		_, err = tx.ExecContext(ctx, `INSERT INTO team_memberships(team_id, user_id) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM organization_memberships WHERE organization_id = ? AND user_id = ?)`, id, credential.actorUserID, organizationID, credential.actorUserID)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.recordDiscoverMutation(ctx, credential, organizationID, "", "create_team", "team", id, map[string]any{"slug": teamSlug, "name": name})
	return map[string]any{"id": id, "organization_id": organizationID, "slug": teamSlug, "name": name}, nil
}

func (s *Service) changeTeamMember(ctx context.Context, credential *credential, teamID, userID string, add bool) (any, error) {
	organizationID, err := s.requireTeam(ctx, credential, teamID)
	if err != nil {
		return nil, err
	}
	if add {
		var member int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, organizationID, userID).Scan(&member); err != nil || member == 0 {
			return nil, errors.New("user is not an organization member")
		}
		_, err = s.store.DB.ExecContext(ctx, `INSERT INTO team_memberships(team_id, user_id) VALUES (?, ?) ON CONFLICT(team_id, user_id) DO NOTHING`, teamID, userID)
	} else {
		var result sql.Result
		result, err = s.store.DB.ExecContext(ctx, `DELETE FROM team_memberships WHERE team_id = ? AND user_id = ?`, teamID, userID)
		if err == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				return nil, errors.New("team membership not found")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	action := "remove_team_member"
	if add {
		action = "add_team_member"
	}
	s.recordDiscoverMutation(ctx, credential, organizationID, "", action, "user", userID, map[string]any{"team_id": teamID})
	return map[string]any{"team_id": teamID, "user_id": userID, "member": add}, nil
}

func (s *Service) changeTeamProject(ctx context.Context, credential *credential, teamID, projectID, role string, link bool) (any, error) {
	organizationID, err := s.requireTeam(ctx, credential, teamID)
	if err != nil {
		return nil, err
	}
	var projectOrganizationID string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&projectOrganizationID); err != nil || projectOrganizationID != organizationID {
		return nil, errors.New("project does not belong to team organization")
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = "member"
	}
	if role != "admin" && role != "member" && role != "viewer" {
		return nil, errors.New("role must be admin, member, or viewer")
	}
	if link {
		_, err = s.store.DB.ExecContext(ctx, `INSERT INTO team_projects(team_id, project_id, role) VALUES (?, ?, ?) ON CONFLICT(team_id, project_id) DO UPDATE SET role = excluded.role`, teamID, projectID, role)
	} else {
		var result sql.Result
		result, err = s.store.DB.ExecContext(ctx, `DELETE FROM team_projects WHERE team_id = ? AND project_id = ?`, teamID, projectID)
		if err == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				return nil, errors.New("team project link not found")
			}
		}
	}
	if err != nil {
		return nil, err
	}
	action := "unlink_team_project"
	if link {
		action = "link_team_project"
	}
	s.recordDiscoverMutation(ctx, credential, organizationID, projectID, action, "team", teamID, map[string]any{"role": role})
	return map[string]any{"team_id": teamID, "project_id": projectID, "role": role, "linked": link}, nil
}

func (s *Service) requireTeam(ctx context.Context, credential *credential, teamID string) (string, error) {
	if !credential.can("write") {
		return "", errors.New("write scope required")
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT organization_id FROM teams WHERE id = ?`, teamID).Scan(&organizationID); err != nil {
		return "", errors.New("team not found")
	}
	if !credential.legacy && organizationID != credential.organizationID {
		return "", errors.New("team not found or not accessible")
	}
	return organizationID, nil
}

func firstNonEmptyMCP(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func (s *Service) listOrganizationMembers(ctx context.Context, organizationID string) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), om.role, om.created_at, COALESCE(u.last_login_at, '')
		FROM organization_memberships om JOIN users u ON u.id = om.user_id
		WHERE om.organization_id = ? ORDER BY u.name, u.email
	`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, email, name, avatarURL, role, joinedAt, lastLoginAt string
		if err := rows.Scan(&id, &email, &name, &avatarURL, &role, &joinedAt, &lastLoginAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"user_id": id, "email": email, "name": name, "avatar_url": avatarURL, "role": role, "joined_at": joinedAt, "last_login_at": lastLoginAt})
	}
	return items, rows.Err()
}

func (s *Service) listProjectPermissions(ctx context.Context, projectID string) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT u.id, u.email, u.name, om.role, COALESCE(pm.role, ''),
		       CASE WHEN pm.role = 'none' THEN 'none'
		            WHEN pm.role != '' THEN pm.role
		            WHEN om.role IN ('owner', 'admin') THEN 'admin'
		            WHEN EXISTS (SELECT 1 FROM team_memberships tm JOIN team_projects tp ON tp.team_id = tm.team_id WHERE tm.user_id = u.id AND tp.project_id = p.id AND tp.role = 'admin') THEN 'admin'
		            WHEN om.role = 'member' OR EXISTS (SELECT 1 FROM team_memberships tm JOIN team_projects tp ON tp.team_id = tm.team_id WHERE tm.user_id = u.id AND tp.project_id = p.id AND tp.role = 'member') THEN 'member'
		            ELSE 'viewer' END
		FROM projects p
		JOIN organization_memberships om ON om.organization_id = p.organization_id
		JOIN users u ON u.id = om.user_id
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
		WHERE p.id = ? ORDER BY u.name, u.email
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var userID, email, name, organizationRole, projectRole, effectiveRole string
		if err := rows.Scan(&userID, &email, &name, &organizationRole, &projectRole, &effectiveRole); err != nil {
			return nil, err
		}
		var override any
		if projectRole != "" {
			override = projectRole
		}
		items = append(items, map[string]any{"user_id": userID, "email": email, "name": name, "organization_role": organizationRole, "project_role": override, "effective_role": effectiveRole})
	}
	return items, rows.Err()
}

type issueUpdateArgs struct {
	IssueID        string  `json:"issue_id"`
	Status         *string `json:"status"`
	Priority       *string `json:"priority"`
	AssigneeUserID *string `json:"assignee_user_id"`
	AssigneeTeamID *string `json:"assignee_team_id"`
	Bookmarked     *bool   `json:"bookmarked"`
	SnoozedUntil   *string `json:"snoozed_until"`
}

func (s *Service) updateIssue(ctx context.Context, credential *credential, projectID string, args issueUpdateArgs) (any, map[string]any, error) {
	if args.Status == nil && args.Priority == nil && args.AssigneeUserID == nil && args.AssigneeTeamID == nil && args.Bookmarked == nil && args.SnoozedUntil == nil {
		return nil, nil, errors.New("at least one issue field is required")
	}
	if args.AssigneeUserID != nil && args.AssigneeTeamID != nil {
		return nil, nil, errors.New("set either assignee_user_id or assignee_team_id")
	}
	var status, priority string
	var assignee, assigneeTeam, snoozed sql.NullString
	var bookmarked bool
	if err := s.store.DB.QueryRowContext(ctx, `SELECT status, priority, assignee_user_id, assignee_team_id, bookmarked, snoozed_until FROM issues WHERE id = ? AND project_id = ?`, args.IssueID, projectID).Scan(&status, &priority, &assignee, &assigneeTeam, &bookmarked, &snoozed); err != nil {
		return nil, nil, errors.New("issue not found")
	}
	changes := make(map[string]any)
	activities := make([][2]string, 0, 5)
	if args.Status != nil {
		value := strings.ToLower(strings.TrimSpace(*args.Status))
		if value != "unresolved" && value != "resolved" && value != "ignored" {
			return nil, nil, errors.New("status must be unresolved, resolved, or ignored")
		}
		if value != status {
			status = value
			changes["status"] = value
			activities = append(activities, [2]string{"status", value})
		}
	}
	if args.Priority != nil {
		value := strings.ToLower(strings.TrimSpace(*args.Priority))
		if value != "low" && value != "medium" && value != "high" && value != "critical" {
			return nil, nil, errors.New("priority must be low, medium, high, or critical")
		}
		if value != priority {
			priority = value
			changes["priority"] = value
			activities = append(activities, [2]string{"priority", value})
		}
	}
	if args.AssigneeUserID != nil {
		value := strings.TrimSpace(*args.AssigneeUserID)
		if value != "" {
			var organizationRole, projectRole string
			err := s.store.DB.QueryRowContext(ctx, `
				SELECT om.role, COALESCE(pm.role, '')
				FROM projects p
				JOIN organization_memberships om ON om.organization_id = p.organization_id AND om.user_id = ?
				LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = om.user_id
				WHERE p.id = ?
			`, value, projectID).Scan(&organizationRole, &projectRole)
			if err != nil || organizationRole == "" || projectRole == "none" {
				return nil, nil, errors.New("assignee is not an accessible organization member")
			}
		}
		if value != assignee.String || assigneeTeam.Valid {
			assignee = sql.NullString{String: value, Valid: value != ""}
			assigneeTeam = sql.NullString{}
			changes["assignee_user_id"] = value
			activities = append(activities, [2]string{"assignment", value})
		}
	}
	if args.AssigneeTeamID != nil {
		value := strings.TrimSpace(*args.AssigneeTeamID)
		if value != "" {
			var linked int
			if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM team_projects WHERE team_id = ? AND project_id = ?`, value, projectID).Scan(&linked); err != nil || linked == 0 {
				return nil, nil, errors.New("assignee team is not linked to the project")
			}
		}
		if value != assigneeTeam.String || assignee.Valid {
			assignee = sql.NullString{}
			assigneeTeam = sql.NullString{String: value, Valid: value != ""}
			changes["assignee_team_id"] = value
			activity := ""
			if value != "" {
				activity = "team:" + value
			}
			activities = append(activities, [2]string{"assignment", activity})
		}
	}
	if args.Bookmarked != nil && *args.Bookmarked != bookmarked {
		bookmarked = *args.Bookmarked
		changes["bookmarked"] = bookmarked
		value := "off"
		if bookmarked {
			value = "on"
		}
		activities = append(activities, [2]string{"bookmark", value})
	}
	if args.SnoozedUntil != nil {
		value := strings.TrimSpace(*args.SnoozedUntil)
		if value != "" {
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil || !parsed.After(time.Now()) {
				return nil, nil, errors.New("snoozed_until must be a future RFC3339 timestamp")
			}
			value = parsed.UTC().Format(time.RFC3339Nano)
		}
		if value != snoozed.String {
			snoozed = sql.NullString{String: value, Valid: value != ""}
			changes["snoozed_until"] = value
			activities = append(activities, [2]string{"snooze", value})
		}
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE issues SET status = ?, priority = ?, assignee_user_id = ?, assignee_team_id = ?, bookmarked = ?, snoozed_until = ? WHERE id = ? AND project_id = ?`, status, priority, nullableString(assignee), nullableString(assigneeTeam), boolInteger(bookmarked), nullableString(snoozed), args.IssueID, projectID); err != nil {
		return nil, nil, err
	}
	var actor any
	if credential.actorUserID != "" {
		actor = credential.actorUserID
	}
	for _, activity := range activities {
		if _, err := tx.ExecContext(ctx, `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), args.IssueID, actor, activity[0], activity[1]); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return map[string]any{"id": args.IssueID, "status": status, "priority": priority, "assignee_user_id": nullableString(assignee), "assignee_team_id": nullableString(assigneeTeam), "bookmarked": bookmarked, "snoozed_until": nullableString(snoozed), "updated": len(changes) > 0}, changes, nil
}

type quotaUpdateArgs struct {
	ProjectID    string `json:"project_id"`
	Category     string `json:"category"`
	PerMinute    int64  `json:"per_minute"`
	PerDay       int64  `json:"per_day"`
	MaxItemBytes int64  `json:"max_item_bytes"`
}

func (s *Service) setProjectQuota(ctx context.Context, args quotaUpdateArgs) (any, error) {
	category := strings.ToLower(strings.TrimSpace(args.Category))
	if !mcpQuotaCategories[category] {
		return nil, errors.New("unsupported quota category")
	}
	if args.PerMinute < 0 || args.PerDay < 0 || args.MaxItemBytes < 0 || args.MaxItemBytes > 100<<20 {
		return nil, errors.New("quota values are outside allowed ranges")
	}
	configured := args.PerMinute != 0 || args.PerDay != 0 || args.MaxItemBytes != 0
	if !configured {
		if _, err := s.store.DB.ExecContext(ctx, `DELETE FROM project_quotas WHERE project_id = ? AND category = ?`, args.ProjectID, category); err != nil {
			return nil, err
		}
	} else if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO project_quotas(project_id, category, per_minute, per_day, max_item_bytes) VALUES (?, ?, ?, ?, ?) ON CONFLICT(project_id, category) DO UPDATE SET per_minute = excluded.per_minute, per_day = excluded.per_day, max_item_bytes = excluded.max_item_bytes`, args.ProjectID, category, args.PerMinute, args.PerDay, args.MaxItemBytes); err != nil {
		return nil, err
	}
	return map[string]any{"project_id": args.ProjectID, "category": category, "per_minute": args.PerMinute, "per_day": args.PerDay, "max_item_bytes": args.MaxItemBytes, "configured": configured}, nil
}

func (s *Service) retryIngestionJob(ctx context.Context, projectID, jobID string) (any, error) {
	result, err := s.store.DB.ExecContext(ctx, `UPDATE ingestion_jobs SET status = 'pending', attempts = 0, available_at = ?, lease_expires_at = NULL, worker_id = '', last_error = '', processed_at = NULL WHERE id = ? AND project_id = ? AND status = 'dead'`, nowUTC(), jobID, projectID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, errors.New("ingestion job not found or is not dead")
	}
	return map[string]any{"id": jobID, "project_id": projectID, "status": "pending"}, nil
}

func (s *Service) deleteIngestionJob(ctx context.Context, projectID, jobID string) (any, error) {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var blobID, storageKey sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT j.blob_id, b.storage_key FROM ingestion_jobs j LEFT JOIN blobs b ON b.id = j.blob_id WHERE j.id = ? AND j.project_id = ? AND j.status IN ('done', 'dead')`, jobID, projectID).Scan(&blobID, &storageKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("ingestion job not found or is not completed or dead")
		}
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ingestion_jobs WHERE id = ? AND project_id = ?`, jobID, projectID); err != nil {
		return nil, err
	}
	if blobID.Valid {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID.String); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if storageKey.Valid {
		var references int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, storageKey.String).Scan(&references); err == nil && references == 0 {
			_ = s.store.Blobs.Remove(storageKey.String)
		}
	}
	return map[string]any{"id": jobID, "project_id": projectID, "deleted": true}, nil
}

func (s *Service) updateRetention(ctx context.Context, organizationID string, days int) (any, error) {
	if days < 1 || days > 3650 {
		return nil, errors.New("retention must be between 1 and 3650 days")
	}
	result, err := s.store.DB.ExecContext(ctx, `UPDATE organizations SET retention_days = ? WHERE id = ?`, days, organizationID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, errors.New("organization not found")
	}
	return map[string]any{"organization_id": organizationID, "retention_days": days}, nil
}

func nullableString(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return nil
}

func boolInteger(value bool) int {
	if value {
		return 1
	}
	return 0
}
