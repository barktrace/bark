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
	default:
		return nil, errors.New("unknown administration tool")
	}
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
		            ELSE om.role END
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
	Bookmarked     *bool   `json:"bookmarked"`
	SnoozedUntil   *string `json:"snoozed_until"`
}

func (s *Service) updateIssue(ctx context.Context, credential *credential, projectID string, args issueUpdateArgs) (any, map[string]any, error) {
	if args.Status == nil && args.Priority == nil && args.AssigneeUserID == nil && args.Bookmarked == nil && args.SnoozedUntil == nil {
		return nil, nil, errors.New("at least one issue field is required")
	}
	var status, priority string
	var assignee, snoozed sql.NullString
	var bookmarked bool
	if err := s.store.DB.QueryRowContext(ctx, `SELECT status, priority, assignee_user_id, bookmarked, snoozed_until FROM issues WHERE id = ? AND project_id = ?`, args.IssueID, projectID).Scan(&status, &priority, &assignee, &bookmarked, &snoozed); err != nil {
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
		if value != assignee.String {
			assignee = sql.NullString{String: value, Valid: value != ""}
			changes["assignee_user_id"] = value
			activities = append(activities, [2]string{"assignment", value})
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
	if _, err := tx.ExecContext(ctx, `UPDATE issues SET status = ?, priority = ?, assignee_user_id = ?, bookmarked = ?, snoozed_until = ? WHERE id = ? AND project_id = ?`, status, priority, nullableString(assignee), boolInteger(bookmarked), nullableString(snoozed), args.IssueID, projectID); err != nil {
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
	return map[string]any{"id": args.IssueID, "status": status, "priority": priority, "assignee_user_id": nullableString(assignee), "bookmarked": bookmarked, "snoozed_until": nullableString(snoozed), "updated": len(changes) > 0}, changes, nil
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
