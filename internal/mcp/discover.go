package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/discover"
	"github.com/google/uuid"
)

type discoverArgs struct {
	OrganizationID string   `json:"organization_id"`
	ProjectID      string   `json:"project_id"`
	Dataset        string   `json:"dataset"`
	Fields         []string `json:"fields"`
	Query          string   `json:"query"`
	Environment    string   `json:"environment"`
	Release        string   `json:"release"`
	Level          string   `json:"level"`
	Status         string   `json:"status"`
	StatsPeriod    string   `json:"stats_period"`
	OrderBy        string   `json:"order_by"`
	Limit          int      `json:"limit"`
}

func (s *Service) callDiscoverTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	switch name {
	case "query_discover":
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		var args discoverArgs
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		projectIDs, err := s.discoverProjects(ctx, credential, organizationID, args.ProjectID)
		if err != nil {
			return nil, err
		}
		period, err := mcpDiscoverPeriod(args.StatsPeriod)
		if err != nil {
			return nil, err
		}
		end := time.Now().UTC()
		return discover.Query(ctx, s.store.DB, discover.Request{Dataset: args.Dataset, Fields: args.Fields, ProjectIDs: projectIDs, Environment: args.Environment, Release: args.Release, Level: args.Level, Status: args.Status, Query: args.Query, Start: end.Add(-period), End: end, OrderBy: args.OrderBy, Limit: boundedLimit(args.Limit)})
	case "list_dashboards":
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
		return s.mcpDashboards(ctx, organizationID)
	case "create_dashboard":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			OrganizationID string `json:"organization_id"`
			ProjectID      string `json:"project_id"`
			Title          string `json:"title"`
			Description    string `json:"description"`
		}
		if err := decodeArguments(raw, &args); err != nil {
			return nil, err
		}
		organizationID, err := s.discoverOrganization(ctx, credential, args.OrganizationID)
		if err != nil {
			return nil, err
		}
		args.Title = strings.TrimSpace(args.Title)
		if args.Title == "" || len(args.Title) > 120 {
			return nil, errors.New("title must contain 1 to 120 characters")
		}
		if len(args.Description) > 1000 {
			return nil, errors.New("description cannot exceed 1000 characters")
		}
		if args.ProjectID != "" {
			if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
				return nil, err
			}
			var belongs int
			if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ? AND organization_id = ?`, args.ProjectID, organizationID).Scan(&belongs); err != nil || belongs == 0 {
				return nil, errors.New("project does not belong to organization")
			}
		}
		var dashboardCount int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboards WHERE organization_id = ?`, organizationID).Scan(&dashboardCount); err != nil {
			return nil, err
		}
		if dashboardCount >= 100 {
			return nil, errors.New("organization cannot contain more than 100 dashboards")
		}
		id := uuid.NewString()
		var actor any
		if credential.actorUserID != "" {
			actor = credential.actorUserID
		}
		if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO dashboards(id, organization_id, project_id, created_by, title, description) VALUES (?, ?, NULLIF(?, ''), ?, ?, ?)`, id, organizationID, args.ProjectID, actor, args.Title, strings.TrimSpace(args.Description)); err != nil {
			return nil, err
		}
		s.recordDiscoverMutation(ctx, credential, organizationID, args.ProjectID, "create_dashboard", "dashboard", id, map[string]any{"title": args.Title})
		return s.mcpDashboard(ctx, organizationID, id)
	case "add_dashboard_widget":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			DashboardID string   `json:"dashboard_id"`
			Title       string   `json:"title"`
			Dataset     string   `json:"dataset"`
			DisplayType string   `json:"display_type"`
			Fields      []string `json:"fields"`
			Query       string   `json:"query"`
			StatsPeriod string   `json:"stats_period"`
			OrderBy     string   `json:"order_by"`
			Limit       int      `json:"limit"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.DashboardID) == "" {
			return nil, errors.New("dashboard_id is required")
		}
		organizationID, projectID, err := s.requireMCPDashboard(ctx, credential, args.DashboardID, "write")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(args.Title) == "" || len(strings.TrimSpace(args.Title)) > 120 {
			return nil, errors.New("title must contain 1 to 120 characters")
		}
		if len(args.Query) > 2048 {
			return nil, errors.New("query cannot exceed 2048 bytes")
		}
		args.Dataset = strings.ToLower(strings.TrimSpace(args.Dataset))
		if args.DisplayType == "" {
			args.DisplayType = "table"
		}
		if !map[string]bool{"table": true, "number": true, "line": true, "bar": true, "area": true}[args.DisplayType] {
			return nil, errors.New("unsupported display_type")
		}
		period, err := mcpDiscoverPeriod(args.StatsPeriod)
		if err != nil {
			return nil, err
		}
		projects, err := s.discoverProjects(ctx, credential, organizationID, projectID)
		if err != nil {
			return nil, err
		}
		end := time.Now().UTC()
		if _, err := discover.Query(ctx, s.store.DB, discover.Request{Dataset: args.Dataset, Fields: args.Fields, ProjectIDs: projects, Query: args.Query, Start: end.Add(-period), End: end, OrderBy: args.OrderBy, Limit: 1}); err != nil {
			return nil, err
		}
		if args.Limit <= 0 {
			args.Limit = 20
		}
		if args.Limit > 100 {
			return nil, errors.New("limit cannot exceed 100")
		}
		if args.StatsPeriod == "" {
			args.StatsPeriod = "24h"
		}
		fields, _ := json.Marshal(args.Fields)
		id := uuid.NewString()
		var widgetCount int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM dashboard_widgets WHERE dashboard_id = ?`, args.DashboardID).Scan(&widgetCount); err != nil {
			return nil, err
		}
		if widgetCount >= 100 {
			return nil, errors.New("dashboard cannot contain more than 100 widgets")
		}
		if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO dashboard_widgets(id, dashboard_id, title, dataset, display_type, fields, query, stats_period, order_by, result_limit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, args.DashboardID, strings.TrimSpace(args.Title), args.Dataset, args.DisplayType, fields, strings.TrimSpace(args.Query), args.StatsPeriod, strings.TrimSpace(args.OrderBy), args.Limit); err != nil {
			return nil, err
		}
		_, _ = s.store.DB.ExecContext(ctx, `UPDATE dashboards SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, args.DashboardID)
		s.recordDiscoverMutation(ctx, credential, organizationID, projectID, "add_dashboard_widget", "dashboard_widget", id, map[string]any{"dashboard_id": args.DashboardID})
		return s.mcpDashboard(ctx, organizationID, args.DashboardID)
	case "delete_dashboard":
		if !credential.can("write") {
			return nil, errors.New("write scope required")
		}
		var args struct {
			DashboardID string `json:"dashboard_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || args.DashboardID == "" {
			return nil, errors.New("dashboard_id is required")
		}
		organizationID, projectID, err := s.requireMCPDashboard(ctx, credential, args.DashboardID, "write")
		if err != nil {
			return nil, err
		}
		if _, err := s.store.DB.ExecContext(ctx, `DELETE FROM dashboards WHERE id = ?`, args.DashboardID); err != nil {
			return nil, err
		}
		s.recordDiscoverMutation(ctx, credential, organizationID, projectID, "delete_dashboard", "dashboard", args.DashboardID, nil)
		return map[string]any{"deleted": true, "id": args.DashboardID}, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (s *Service) discoverOrganization(ctx context.Context, credential *credential, requested string) (string, error) {
	if !credential.legacy {
		if requested != "" && requested != credential.organizationID {
			return "", errors.New("organization not accessible")
		}
		return credential.organizationID, nil
	}
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", errors.New("organization_id is required for the legacy token")
	}
	var exists int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations WHERE id = ?`, requested).Scan(&exists); err != nil || exists == 0 {
		return "", errors.New("organization not found")
	}
	return requested, nil
}

func (s *Service) discoverProjects(ctx context.Context, credential *credential, organizationID, projectID string) ([]string, error) {
	if projectID != "" {
		if err := s.requireProject(ctx, credential, projectID, "read"); err != nil {
			return nil, err
		}
		var belongs int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ? AND organization_id = ?`, projectID, organizationID).Scan(&belongs); err != nil || belongs == 0 {
			return nil, errors.New("project does not belong to organization")
		}
		return []string{projectID}, nil
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id FROM projects WHERE organization_id = ? ORDER BY id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func mcpDiscoverPeriod(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 24 * time.Hour, nil
	}
	if len(value) < 2 {
		return 0, errors.New("stats_period must be between 1h and 90d")
	}
	amount, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || amount <= 0 {
		return 0, errors.New("stats_period must be between 1h and 90d")
	}
	var duration time.Duration
	switch value[len(value)-1] {
	case 'h':
		duration = time.Duration(amount) * time.Hour
	case 'd':
		duration = time.Duration(amount) * 24 * time.Hour
	default:
		return 0, errors.New("stats_period must use h or d")
	}
	if duration < time.Hour || duration > 90*24*time.Hour {
		return 0, errors.New("stats_period must be between 1h and 90d")
	}
	return duration, nil
}

func (s *Service) requireMCPDashboard(ctx context.Context, credential *credential, dashboardID, scope string) (string, string, error) {
	if !credential.can(scope) {
		return "", "", fmt.Errorf("%s scope required", scope)
	}
	var organizationID string
	var projectID sql.NullString
	if err := s.store.DB.QueryRowContext(ctx, `SELECT organization_id, project_id FROM dashboards WHERE id = ?`, dashboardID).Scan(&organizationID, &projectID); err != nil {
		return "", "", errors.New("dashboard not found")
	}
	if !credential.legacy && organizationID != credential.organizationID {
		return "", "", errors.New("dashboard not found or not accessible")
	}
	if projectID.Valid {
		if err := s.requireProject(ctx, credential, projectID.String, scope); err != nil {
			return "", "", err
		}
	}
	return organizationID, projectID.String, nil
}

func (s *Service) mcpDashboards(ctx context.Context, organizationID string) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id FROM dashboards WHERE organization_id = ? ORDER BY updated_at DESC LIMIT 100`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	items := make([]any, 0, len(ids))
	for _, id := range ids {
		item, err := s.mcpDashboard(ctx, organizationID, id)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Service) mcpDashboard(ctx context.Context, organizationID, dashboardID string) (any, error) {
	var title, description, projectID, createdAt, updatedAt string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT title, description, COALESCE(project_id, ''), created_at, updated_at FROM dashboards WHERE id = ? AND organization_id = ?`, dashboardID, organizationID).Scan(&title, &description, &projectID, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, title, dataset, display_type, fields, query, stats_period, order_by, result_limit, position FROM dashboard_widgets WHERE dashboard_id = ? ORDER BY position, created_at LIMIT 100`, dashboardID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	widgets := make([]map[string]any, 0)
	for rows.Next() {
		var id, widgetTitle, dataset, displayType, query, period, orderBy string
		var fields json.RawMessage
		var limit, position int
		if err := rows.Scan(&id, &widgetTitle, &dataset, &displayType, &fields, &query, &period, &orderBy, &limit, &position); err != nil {
			return nil, err
		}
		widgets = append(widgets, map[string]any{"id": id, "title": widgetTitle, "dataset": dataset, "display_type": displayType, "fields": fields, "query": query, "stats_period": period, "order_by": orderBy, "limit": limit, "position": position})
	}
	return map[string]any{"id": dashboardID, "organization_id": organizationID, "project_id": projectID, "title": title, "description": description, "created_at": createdAt, "updated_at": updatedAt, "widgets": widgets}, rows.Err()
}

func (s *Service) recordDiscoverMutation(ctx context.Context, credential *credential, organizationID, projectID, action, targetType, targetID string, metadata any) {
	encoded, _ := json.Marshal(metadata)
	var actor any
	if credential.actorUserID != "" {
		actor = credential.actorUserID
	}
	_, _ = s.store.DB.ExecContext(ctx, `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, actor_type, action, target_type, target_id, metadata) VALUES (?, NULLIF(?, ''), ?, 'mcp', ?, ?, ?, ?)`, organizationID, projectID, actor, action, targetType, targetID, encoded)
}
