package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	alertservice "github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/cronmon"
	"github.com/google/uuid"
)

func (s *Service) addIssueCommentTool(ctx context.Context, credential *credential, raw json.RawMessage) (any, error) {
	var args struct {
		IssueID string `json:"issue_id"`
		Body    string `json:"body"`
	}
	if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.IssueID) == "" {
		return nil, errors.New("issue_id is required")
	}
	projectID, err := s.requireIssue(ctx, credential, args.IssueID, "write")
	if err != nil {
		return nil, err
	}
	body := strings.TrimSpace(args.Body)
	if body == "" || len(body) > 4000 {
		return nil, errors.New("comment must contain 1 to 4000 characters")
	}
	id := uuid.NewString()
	var actor any
	if credential.actorUserID != "" {
		actor = credential.actorUserID
	}
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO issue_activities(id, issue_id, user_id, kind, value) VALUES (?, ?, ?, 'comment', ?)`, id, args.IssueID, actor, body); err != nil {
		return nil, err
	}
	s.recordMutation(ctx, credential, projectID, "add_issue_comment", "issue_comment", id, map[string]any{"issue_id": args.IssueID})
	return map[string]any{"id": id, "issue_id": args.IssueID, "body": body, "actor_user_id": actor, "created_at": nowUTC()}, nil
}

func (s *Service) listIssueActivities(ctx context.Context, issueID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT a.id, a.kind, a.value, a.created_at,
		       COALESCE(a.user_id, ''), COALESCE(u.name, ''), COALESCE(u.email, '')
		FROM issue_activities a LEFT JOIN users u ON u.id = a.user_id
		WHERE a.issue_id = ? ORDER BY a.created_at DESC, a.id DESC LIMIT ?`, issueID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, kind, value, createdAt, actorID, actorName, actorEmail string
		if err := rows.Scan(&id, &kind, &value, &createdAt, &actorID, &actorName, &actorEmail); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"id": id, "issue_id": issueID, "kind": kind, "value": value, "created_at": createdAt,
			"actor_user_id": actorID, "actor_name": actorName, "actor_email": actorEmail,
		})
	}
	return items, rows.Err()
}

type alertRuleCreateArgs struct {
	ProjectID        string          `json:"project_id"`
	Name             string          `json:"name"`
	Trigger          string          `json:"trigger"`
	DestinationType  string          `json:"destination_type"`
	DestinationURL   string          `json:"destination_url"`
	DestinationEmail string          `json:"destination_email"`
	Conditions       json.RawMessage `json:"conditions"`
	FrequencyMinutes int             `json:"frequency_minutes"`
}

type alertRuleUpdateArgs struct {
	ProjectID        string          `json:"project_id"`
	RuleID           string          `json:"rule_id"`
	Name             *string         `json:"name"`
	Trigger          *string         `json:"trigger"`
	DestinationType  *string         `json:"destination_type"`
	DestinationURL   *string         `json:"destination_url"`
	DestinationEmail *string         `json:"destination_email"`
	Conditions       json.RawMessage `json:"conditions"`
	FrequencyMinutes *int            `json:"frequency_minutes"`
	Enabled          *bool           `json:"enabled"`
}

func (s *Service) callAlertTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	switch name {
	case "create_alert_rule":
		var args alertRuleCreateArgs
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" {
			return nil, errors.New("project_id is required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		return s.createAlertRule(ctx, credential, args)
	case "update_alert_rule":
		var args alertRuleUpdateArgs
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.RuleID) == "" {
			return nil, errors.New("project_id and rule_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		return s.updateAlertRule(ctx, credential, args)
	case "delete_alert_rule":
		var args struct {
			ProjectID string `json:"project_id"`
			RuleID    string `json:"rule_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.RuleID) == "" {
			return nil, errors.New("project_id and rule_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		result, err := s.store.DB.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ? AND project_id = ?`, args.RuleID, args.ProjectID)
		if err != nil {
			return nil, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, errors.New("alert rule not found")
		}
		s.recordMutation(ctx, credential, args.ProjectID, name, "alert_rule", args.RuleID, nil)
		return map[string]any{"id": args.RuleID, "project_id": args.ProjectID, "deleted": true}, nil
	default:
		return nil, errors.New("unknown alert tool")
	}
}

func (s *Service) createAlertRule(ctx context.Context, credential *credential, args alertRuleCreateArgs) (any, error) {
	args.Name = strings.TrimSpace(args.Name)
	args.Trigger = strings.ToLower(strings.TrimSpace(args.Trigger))
	args.DestinationType = strings.ToLower(strings.TrimSpace(args.DestinationType))
	args.DestinationURL = strings.TrimSpace(args.DestinationURL)
	args.DestinationEmail = strings.TrimSpace(args.DestinationEmail)
	if args.Name == "" || !alertservice.ValidTrigger(args.Trigger) {
		return nil, errors.New("valid rule name and trigger are required")
	}
	if err := alertservice.ValidateDestination(args.DestinationType, alertDestination(args.DestinationType, args.DestinationURL, args.DestinationEmail)); err != nil {
		return nil, err
	}
	conditions, ok := alertservice.NormalizeConditions(args.Conditions)
	if !ok || args.FrequencyMinutes < 0 || args.FrequencyMinutes > 10080 {
		return nil, errors.New("invalid alert conditions or frequency")
	}
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, args.ProjectID, args.Name, args.Trigger, args.DestinationType, args.DestinationURL, args.DestinationEmail, conditions, args.FrequencyMinutes); err != nil {
		return nil, err
	}
	s.recordMutation(ctx, credential, args.ProjectID, "create_alert_rule", "alert_rule", id, map[string]any{"name": args.Name, "trigger": args.Trigger, "destination_type": args.DestinationType})
	return alertRuleResult(id, args.ProjectID, args.Name, args.Trigger, args.DestinationType, args.DestinationURL, args.DestinationEmail, conditions, args.FrequencyMinutes, true), nil
}

func (s *Service) updateAlertRule(ctx context.Context, credential *credential, args alertRuleUpdateArgs) (any, error) {
	if args.Name == nil && args.Trigger == nil && args.DestinationType == nil && args.DestinationURL == nil && args.DestinationEmail == nil && len(args.Conditions) == 0 && args.FrequencyMinutes == nil && args.Enabled == nil {
		return nil, errors.New("at least one alert rule field is required")
	}
	var name, trigger, destinationType, destinationURL, destinationEmail string
	var conditions json.RawMessage
	var frequency int
	var enabled bool
	if err := s.store.DB.QueryRowContext(ctx, `SELECT name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes, enabled FROM alert_rules WHERE id = ? AND project_id = ?`, args.RuleID, args.ProjectID).Scan(&name, &trigger, &destinationType, &destinationURL, &destinationEmail, &conditions, &frequency, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("alert rule not found")
		}
		return nil, err
	}
	if args.Name != nil {
		name = strings.TrimSpace(*args.Name)
	}
	if args.Trigger != nil {
		trigger = strings.ToLower(strings.TrimSpace(*args.Trigger))
	}
	if args.DestinationType != nil {
		destinationType = strings.ToLower(strings.TrimSpace(*args.DestinationType))
	}
	if args.DestinationURL != nil && strings.TrimSpace(*args.DestinationURL) != "" {
		destinationURL = strings.TrimSpace(*args.DestinationURL)
	}
	if args.DestinationEmail != nil && strings.TrimSpace(*args.DestinationEmail) != "" {
		destinationEmail = strings.TrimSpace(*args.DestinationEmail)
	}
	if len(args.Conditions) > 0 {
		var ok bool
		conditions, ok = alertservice.NormalizeConditions(args.Conditions)
		if !ok {
			return nil, errors.New("invalid alert conditions")
		}
	}
	if args.FrequencyMinutes != nil {
		frequency = *args.FrequencyMinutes
	}
	if args.Enabled != nil {
		enabled = *args.Enabled
	}
	if name == "" || !alertservice.ValidTrigger(trigger) {
		return nil, errors.New("valid rule name and trigger are required")
	}
	if err := alertservice.ValidateDestination(destinationType, alertDestination(destinationType, destinationURL, destinationEmail)); err != nil {
		return nil, err
	}
	if frequency < 0 || frequency > 10080 {
		return nil, errors.New("frequency must be between 0 and 10080 minutes")
	}
	if _, err := s.store.DB.ExecContext(ctx, `UPDATE alert_rules SET name = ?, trigger = ?, destination_type = ?, destination_url = ?, destination_email = ?, conditions = ?, frequency_minutes = ?, enabled = ? WHERE id = ? AND project_id = ?`, name, trigger, destinationType, destinationURL, destinationEmail, conditions, frequency, boolInteger(enabled), args.RuleID, args.ProjectID); err != nil {
		return nil, err
	}
	s.recordMutation(ctx, credential, args.ProjectID, "update_alert_rule", "alert_rule", args.RuleID, map[string]any{"name": name, "trigger": trigger, "enabled": enabled})
	return alertRuleResult(args.RuleID, args.ProjectID, name, trigger, destinationType, destinationURL, destinationEmail, conditions, frequency, enabled), nil
}

func alertDestination(kind, destinationURL, destinationEmail string) string {
	if kind == "email" {
		return destinationEmail
	}
	return destinationURL
}

func alertRuleResult(id, projectID, name, trigger, destinationType, destinationURL, destinationEmail string, conditions json.RawMessage, frequency int, enabled bool) map[string]any {
	destination := alertDestination(destinationType, destinationURL, destinationEmail)
	host := destination
	if strings.Contains(destination, "://") {
		if parsed, err := url.Parse(destination); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
	}
	return map[string]any{"id": id, "project_id": projectID, "name": name, "trigger": trigger, "destination_type": destinationType, "destination_host": host, "conditions": conditions, "frequency_minutes": frequency, "enabled": enabled}
}

type uptimeMonitorArgs struct {
	ProjectID         string `json:"project_id"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	Method            string `json:"method"`
	IntervalSeconds   int    `json:"interval_seconds"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	ExpectedStatusMin int    `json:"expected_status_min"`
	ExpectedStatusMax int    `json:"expected_status_max"`
}

func (s *Service) callUptimeTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	if name == "delete_uptime_monitor" {
		var args struct {
			ProjectID string `json:"project_id"`
			MonitorID string `json:"monitor_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.MonitorID) == "" {
			return nil, errors.New("project_id and monitor_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		result, err := s.store.DB.ExecContext(ctx, `DELETE FROM uptime_monitors WHERE id = ? AND project_id = ?`, args.MonitorID, args.ProjectID)
		if err != nil {
			return nil, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, errors.New("uptime monitor not found")
		}
		s.recordMutation(ctx, credential, args.ProjectID, name, "uptime_monitor", args.MonitorID, nil)
		return map[string]any{"id": args.MonitorID, "project_id": args.ProjectID, "deleted": true}, nil
	}
	var args uptimeMonitorArgs
	if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" {
		return nil, errors.New("project_id is required")
	}
	if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
		return nil, err
	}
	args.Name, args.URL, args.Method = strings.TrimSpace(args.Name), strings.TrimSpace(args.URL), strings.ToUpper(strings.TrimSpace(args.Method))
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	if args.Method == "" {
		args.Method = "GET"
	}
	if args.Method != "GET" && args.Method != "HEAD" {
		return nil, errors.New("method must be GET or HEAD")
	}
	if args.IntervalSeconds == 0 {
		args.IntervalSeconds = 60
	}
	if args.TimeoutSeconds == 0 {
		args.TimeoutSeconds = 10
	}
	if args.ExpectedStatusMin == 0 {
		args.ExpectedStatusMin = 200
	}
	if args.ExpectedStatusMax == 0 {
		args.ExpectedStatusMax = 399
	}
	if args.IntervalSeconds < 30 || args.IntervalSeconds > 86400 || args.TimeoutSeconds < 1 || args.TimeoutSeconds > 30 || args.ExpectedStatusMin < 100 || args.ExpectedStatusMax > 599 || args.ExpectedStatusMin > args.ExpectedStatusMax {
		return nil, errors.New("monitor settings are outside allowed ranges")
	}
	if err := s.uptime.ValidateURL(ctx, args.URL); err != nil {
		return nil, err
	}
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO uptime_monitors(id, project_id, name, url, method, interval_seconds, timeout_seconds, expected_status_min, expected_status_max, next_check_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, args.ProjectID, args.Name, args.URL, args.Method, args.IntervalSeconds, args.TimeoutSeconds, args.ExpectedStatusMin, args.ExpectedStatusMax, nowUTC()); err != nil {
		return nil, err
	}
	s.recordMutation(ctx, credential, args.ProjectID, "create_uptime_monitor", "uptime_monitor", id, map[string]any{"name": args.Name, "url": args.URL})
	return map[string]any{"id": id, "project_id": args.ProjectID, "name": args.Name, "url": args.URL, "method": args.Method, "interval_seconds": args.IntervalSeconds, "timeout_seconds": args.TimeoutSeconds, "expected_status_min": args.ExpectedStatusMin, "expected_status_max": args.ExpectedStatusMax, "last_status": "pending"}, nil
}

type cronMonitorArgs struct {
	ProjectID     string          `json:"project_id"`
	Slug          string          `json:"slug"`
	Name          string          `json:"name"`
	ScheduleType  string          `json:"schedule_type"`
	ScheduleValue json.RawMessage `json:"schedule_value"`
	Timezone      string          `json:"timezone"`
	CheckinMargin int             `json:"checkin_margin"`
	MaxRuntime    int             `json:"max_runtime"`
}

func (s *Service) callCronTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	if name == "delete_cron_monitor" {
		var args struct {
			ProjectID string `json:"project_id"`
			MonitorID string `json:"monitor_id"`
		}
		if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" || strings.TrimSpace(args.MonitorID) == "" {
			return nil, errors.New("project_id and monitor_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
			return nil, err
		}
		result, err := s.store.DB.ExecContext(ctx, `DELETE FROM cron_monitors WHERE id = ? AND project_id = ?`, args.MonitorID, args.ProjectID)
		if err != nil {
			return nil, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, errors.New("cron monitor not found")
		}
		s.recordMutation(ctx, credential, args.ProjectID, name, "cron_monitor", args.MonitorID, nil)
		return map[string]any{"id": args.MonitorID, "project_id": args.ProjectID, "deleted": true}, nil
	}
	var args cronMonitorArgs
	if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" {
		return nil, errors.New("project_id is required")
	}
	if err := s.requireProject(ctx, credential, args.ProjectID, "write"); err != nil {
		return nil, err
	}
	args.Slug = mcpSlug(args.Slug)
	args.Name = strings.TrimSpace(args.Name)
	if args.Name == "" {
		args.Name = args.Slug
	}
	if args.Slug == "" || args.Name == "" {
		return nil, errors.New("name and slug are required")
	}
	kind, value, err := cronmon.NormalizeSchedule(args.ScheduleType, args.ScheduleValue)
	if err != nil {
		return nil, err
	}
	if args.Timezone == "" {
		args.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(args.Timezone); err != nil {
		return nil, errors.New("invalid timezone")
	}
	if args.CheckinMargin <= 0 {
		args.CheckinMargin = 5
	}
	if args.MaxRuntime <= 0 {
		args.MaxRuntime = 30
	}
	next := cronmon.Next(time.Now().UTC(), kind, value, args.Timezone)
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO cron_monitors(id, project_id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, next_checkin_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, args.ProjectID, args.Slug, args.Name, kind, value, args.Timezone, args.CheckinMargin, args.MaxRuntime, next.Format(time.RFC3339Nano)); err != nil {
		return nil, errors.New("cron monitor slug already exists")
	}
	s.recordMutation(ctx, credential, args.ProjectID, "create_cron_monitor", "cron_monitor", id, map[string]any{"slug": args.Slug, "schedule_type": kind, "schedule_value": value})
	return map[string]any{"id": id, "project_id": args.ProjectID, "slug": args.Slug, "name": args.Name, "schedule_type": kind, "schedule_value": value, "timezone": args.Timezone, "checkin_margin": args.CheckinMargin, "max_runtime": args.MaxRuntime, "next_checkin_at": next.Format(time.RFC3339Nano)}, nil
}

func mcpSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			builder.WriteRune(character)
			lastDash = false
		} else if !lastDash && builder.Len() > 0 {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}
