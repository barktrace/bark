// Package mcp exposes a small, stateless Model Context Protocol server over
// Streamable HTTP. It intentionally runs in the main process so deployments do
// not need a sidecar or Node.js runtime.
package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/store"
	"github.com/barktrace/bark/internal/uptime"
)

const (
	protocolVersion = "2025-11-25"
	serverVersion   = "0.21.0"
)

var supportedProtocolVersions = map[string]bool{
	"2025-11-25": true,
	"2025-06-18": true,
	"2025-03-26": true,
}

type Service struct {
	store              *store.Store
	legacyTokenHash    [32]byte
	legacyTokenEnabled bool
	publicURL          string
	publicOrigin       string
	uptime             *uptime.Service
}

type credential struct {
	organizationID string
	tokenID        string
	actorUserID    string
	scopes         map[string]bool
	legacy         bool
}

func (c *credential) can(scope string) bool {
	return c != nil && (c.legacy || c.scopes[scope] || (scope == "read" && c.scopes["write"]))
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func New(st *store.Store, token, publicURL string, allowPrivateUptime ...bool) *Service {
	origin := ""
	if parsed, err := url.Parse(publicURL); err == nil {
		origin = parsed.Scheme + "://" + parsed.Host
	}
	allowPrivate := len(allowPrivateUptime) > 0 && allowPrivateUptime[0]
	return &Service{store: st, legacyTokenHash: sha256.Sum256([]byte(token)), legacyTokenEnabled: strings.TrimSpace(token) != "", publicURL: publicURL, publicOrigin: origin, uptime: uptime.New(st, allowPrivate)}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	credential, ok := s.authorize(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="barktrace-mcp"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.publicOrigin {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	var request rpcRequest
	if err := decoder.Decode(&request); err != nil {
		s.writeRPCError(w, nil, -32700, "Parse error")
		return
	}
	if request.JSONRPC != "2.0" || request.Method == "" {
		s.writeRPCError(w, requestID(request.ID), -32600, "Invalid Request")
		return
	}
	if len(request.ID) == 0 || string(request.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	id := requestID(request.ID)
	switch request.Method {
	case "initialize":
		version := requestedProtocolVersion(request.Params)
		s.writeResult(w, id, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "barktrace", "version": serverVersion},
		})
	case "ping":
		s.writeResult(w, id, map[string]any{})
	case "tools/list":
		s.writeResult(w, id, map[string]any{"tools": tools()})
	case "tools/call":
		result, err := s.callTool(r, credential, request.Params)
		if err != nil {
			s.writeResult(w, id, toolError(err))
			return
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			s.writeRPCError(w, id, -32603, "Internal error")
			return
		}
		s.writeResult(w, id, map[string]any{
			"content":           []map[string]string{{"type": "text", "text": string(encoded)}},
			"structuredContent": result,
			"isError":           false,
		})
	default:
		s.writeRPCError(w, id, -32601, "Method not found")
	}
}

func (s *Service) authorize(r *http.Request) (*credential, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, false
	}
	plain := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if plain == "" {
		return nil, false
	}
	candidate := sha256.Sum256([]byte(plain))
	if s.legacyTokenEnabled && subtle.ConstantTimeCompare(candidate[:], s.legacyTokenHash[:]) == 1 {
		return &credential{legacy: true, scopes: map[string]bool{"read": true, "write": true}}, true
	}
	var id, organizationID, createdBy string
	var scopesJSON []byte
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT id, organization_id, created_by, scopes
		FROM mcp_tokens
		WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)
	`, candidate[:], nowUTC()).Scan(&id, &organizationID, &createdBy, &scopesJSON)
	if err != nil {
		return nil, false
	}
	var names []string
	if json.Unmarshal(scopesJSON, &names) != nil {
		return nil, false
	}
	scopes := make(map[string]bool, len(names))
	for _, name := range names {
		scopes[strings.ToLower(strings.TrimSpace(name))] = true
	}
	if !scopes["read"] && !scopes["write"] {
		return nil, false
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?`, nowUTC(), id)
	return &credential{organizationID: organizationID, tokenID: id, actorUserID: createdBy, scopes: scopes}, true
}

func (s *Service) callTool(r *http.Request, credential *credential, raw json.RawMessage) (any, error) {
	var call struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &call); err != nil || call.Name == "" {
		return nil, errors.New("invalid tool call")
	}
	ctx := r.Context()
	switch call.Name {
	case "list_organizations":
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		return s.listOrganizations(ctx, credential)
	case "list_projects":
		var args struct {
			OrganizationSlug string `json:"organization_slug"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil {
			return nil, err
		}
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		return s.listProjects(ctx, credential, args.OrganizationSlug)
	case "get_project_summary":
		var args projectArgs
		if err := requiredProjectArguments(call.Arguments, &args); err != nil {
			return nil, err
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.projectSummary(ctx, args.ProjectID)
	case "list_issues":
		var args struct {
			ProjectID string `json:"project_id"`
			Status    string `json:"status"`
			Query     string `json:"query"`
			Limit     int    `json:"limit"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.ProjectID == "" {
			return nil, errors.New("project_id is required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.listIssues(ctx, args.ProjectID, args.Status, args.Query, boundedLimit(args.Limit))
	case "get_issue":
		var args struct {
			IssueID string `json:"issue_id"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.IssueID == "" {
			return nil, errors.New("issue_id is required")
		}
		if _, err := s.requireIssue(ctx, credential, args.IssueID, "read"); err != nil {
			return nil, err
		}
		return s.getIssue(ctx, args.IssueID)
	case "update_issue_status":
		var args struct {
			IssueID string `json:"issue_id"`
			Status  string `json:"status"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.IssueID == "" {
			return nil, errors.New("issue_id is required")
		}
		projectID, err := s.requireIssue(ctx, credential, args.IssueID, "write")
		if err != nil {
			return nil, err
		}
		result, err := s.updateIssueStatus(ctx, args.IssueID, args.Status)
		if err == nil {
			s.recordMutation(ctx, credential, projectID, "update_issue_status", "issue", args.IssueID, map[string]any{"status": args.Status})
		}
		return result, err
	case "list_events":
		var args struct {
			ProjectID string `json:"project_id"`
			IssueID   string `json:"issue_id"`
			Limit     int    `json:"limit"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.ProjectID == "" {
			return nil, errors.New("project_id is required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.listEvents(ctx, args.ProjectID, args.IssueID, boundedLimit(args.Limit))
	case "get_event":
		var args struct {
			ProjectID string `json:"project_id"`
			EventID   string `json:"event_id"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.ProjectID == "" || args.EventID == "" {
			return nil, errors.New("project_id and event_id are required")
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.getEvent(ctx, args.ProjectID, args.EventID)
	case "list_releases":
		var args projectArgs
		if err := requiredProjectArguments(call.Arguments, &args); err != nil {
			return nil, err
		}
		if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
			return nil, err
		}
		return s.listReleases(ctx, args.ProjectID, boundedLimit(args.Limit))
	case "query_discover", "list_dashboards", "create_dashboard", "add_dashboard_widget", "delete_dashboard":
		return s.callDiscoverTool(ctx, credential, call.Name, call.Arguments)
	case "list_organization_members", "list_project_permissions", "update_issue", "set_project_quota",
		"retry_ingestion_job", "delete_ingestion_job", "update_retention", "add_issue_comment",
		"create_alert_rule", "update_alert_rule", "delete_alert_rule", "create_uptime_monitor",
		"delete_uptime_monitor", "create_cron_monitor", "delete_cron_monitor":
		return s.callAdministrationTool(ctx, credential, call.Name, call.Arguments)
	case "list_transactions", "list_logs", "list_uptime_monitors", "list_uptime_checks",
		"list_cron_monitors", "list_cron_checkins", "list_feedback", "list_replays",
		"analyze_replay", "list_profiles", "analyze_profile", "list_metrics", "list_alert_rules", "list_alert_deliveries",
		"list_artifacts", "list_attachments", "list_deploys", "list_commits",
		"list_suspect_commits", "list_project_quotas", "list_ingestion_jobs",
		"list_audit_logs", "get_storage_summary":
		return s.callObservabilityTool(ctx, credential, call.Name, call.Arguments)
	default:
		return nil, fmt.Errorf("unknown tool %q", call.Name)
	}
}

type projectArgs struct {
	ProjectID string `json:"project_id"`
	Limit     int    `json:"limit"`
}

func decodeArguments(raw json.RawMessage, destination any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte(`{}`)
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return errors.New("invalid tool arguments")
	}
	return nil
}

func requiredProjectArguments(raw json.RawMessage, args *projectArgs) error {
	if err := decodeArguments(raw, args); err != nil || args.ProjectID == "" {
		return errors.New("project_id is required")
	}
	return nil
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func (s *Service) requireProject(ctx context.Context, credential *credential, projectID, scope string) error {
	if !credential.can(scope) {
		return fmt.Errorf("%s scope required", scope)
	}
	if credential.legacy {
		var exists int
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ?`, projectID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return errors.New("project not found")
		}
		return nil
	}
	var exists int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ? AND organization_id = ?`, projectID, credential.organizationID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return errors.New("project not found or not accessible")
	}
	return nil
}

func (s *Service) requireIssue(ctx context.Context, credential *credential, issueID, scope string) (string, error) {
	var projectID string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT project_id FROM issues WHERE id = ?`, issueID).Scan(&projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("issue not found")
		}
		return "", err
	}
	if err := s.requireProject(ctx, credential, projectID, scope); err != nil {
		return "", err
	}
	return projectID, nil
}

func (s *Service) recordMutation(ctx context.Context, credential *credential, projectID, action, targetType, targetID string, metadata any) {
	var organizationID string
	_ = s.store.DB.QueryRowContext(ctx, `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID)
	encoded, _ := json.Marshal(metadata)
	var actor any
	if credential.actorUserID != "" {
		actor = credential.actorUserID
	}
	_, _ = s.store.DB.ExecContext(ctx, `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, actor_type, action, target_type, target_id, metadata) VALUES (NULLIF(?, ''), NULLIF(?, ''), ?, 'mcp', ?, ?, ?, ?)`, organizationID, projectID, actor, action, targetType, targetID, encoded)
}

func boundedLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func tools() []tool {
	stringProperty := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	limitProperty := map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 50}
	readOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false}
	return []tool{
		{Name: "list_organizations", Description: "List organizations available on this Barktrace instance.", InputSchema: objectSchema(nil), Annotations: readOnly},
		{Name: "list_projects", Description: "List projects, optionally limited to one organization slug. Includes each project's Sentry DSN.", InputSchema: objectSchema(map[string]any{"organization_slug": stringProperty("Optional organization slug")}), Annotations: readOnly},
		{Name: "get_project_summary", Description: "Get issue, event, and release counts for a project.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID")}, "project_id"), Annotations: readOnly},
		{Name: "list_issues", Description: "List grouped issues for a project, optionally filtered by status or title.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"),
			"status":     map[string]any{"type": "string", "enum": []string{"all", "unresolved", "resolved", "ignored"}, "default": "all"},
			"query":      stringProperty("Optional case-insensitive title search"),
			"limit":      limitProperty,
		}, "project_id"), Annotations: readOnly},
		{Name: "get_issue", Description: "Get a grouped issue and its release linkage.", InputSchema: objectSchema(map[string]any{"issue_id": stringProperty("Issue UUID")}, "issue_id"), Annotations: readOnly},
		{Name: "update_issue_status", Description: "Set an issue to unresolved, resolved, or ignored.", InputSchema: objectSchema(map[string]any{
			"issue_id": stringProperty("Issue UUID"),
			"status":   map[string]any{"type": "string", "enum": []string{"unresolved", "resolved", "ignored"}},
		}, "issue_id", "status"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}},
		{Name: "list_events", Description: "List event occurrences for a project, optionally restricted to an issue.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "issue_id": stringProperty("Optional issue UUID"), "limit": limitProperty,
		}, "project_id"), Annotations: readOnly},
		{Name: "get_event", Description: "Get an event including its original Sentry JSON payload.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "event_id": stringProperty("32-character Sentry event ID"),
		}, "project_id", "event_id"), Annotations: readOnly},
		{Name: "list_releases", Description: "List releases linked to a project with event counts.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "limit": limitProperty,
		}, "project_id"), Annotations: readOnly},
		{Name: "query_discover", Description: "Run a bounded Discover query over errors, transactions, spans, logs, or metrics.", InputSchema: objectSchema(map[string]any{
			"organization_id": stringProperty("Organization UUID; only needed by the legacy instance token"),
			"project_id":      stringProperty("Optional project UUID"),
			"dataset":         map[string]any{"type": "string", "enum": []string{"errors", "transactions", "spans", "logs", "metrics"}},
			"fields":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 20},
			"query":           stringProperty("Optional field filters and free-text search"),
			"environment":     stringProperty("Optional environment filter"), "release": stringProperty("Optional release filter"),
			"level": stringProperty("Optional level filter"), "status": stringProperty("Optional status filter"),
			"stats_period": stringProperty("Time range such as 1h, 24h, 7d, or 30d"), "order_by": stringProperty("Selected field, prefixed by - for descending"), "limit": limitProperty,
		}, "dataset", "fields"), Annotations: readOnly},
		{Name: "list_dashboards", Description: "List saved dashboards and widget definitions for an organization.", InputSchema: objectSchema(map[string]any{"organization_id": stringProperty("Organization UUID; only needed by the legacy instance token")}), Annotations: readOnly},
		{Name: "create_dashboard", Description: "Create a saved dashboard, optionally scoped to one project.", InputSchema: objectSchema(map[string]any{
			"organization_id": stringProperty("Organization UUID; only needed by the legacy instance token"), "project_id": stringProperty("Optional project UUID"), "title": stringProperty("Dashboard title"), "description": stringProperty("Optional description"),
		}, "title"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "add_dashboard_widget", Description: "Add a Discover-backed widget to a saved dashboard.", InputSchema: objectSchema(map[string]any{
			"dashboard_id": stringProperty("Dashboard UUID"), "title": stringProperty("Widget title"),
			"dataset":      map[string]any{"type": "string", "enum": []string{"errors", "transactions", "spans", "logs", "metrics"}},
			"display_type": map[string]any{"type": "string", "enum": []string{"table", "number", "line", "bar", "area"}, "default": "table"},
			"fields":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "minItems": 1, "maxItems": 20}, "query": stringProperty("Optional query"), "stats_period": stringProperty("Time range such as 24h or 7d"), "order_by": stringProperty("Optional ordering"), "limit": limitProperty,
		}, "dashboard_id", "title", "dataset", "fields"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "delete_dashboard", Description: "Permanently delete a saved dashboard and its widgets.", InputSchema: objectSchema(map[string]any{"dashboard_id": stringProperty("Dashboard UUID")}, "dashboard_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": true}},
		{Name: "list_transactions", Description: "List performance transactions and latency data for a project.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_logs", Description: "Search structured logs by level or message text.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "level": stringProperty("Optional log level"), "query": stringProperty("Optional message search"), "limit": limitProperty,
		}, "project_id"), Annotations: readOnly},
		{Name: "list_uptime_monitors", Description: "List HTTP uptime monitors and their latest state.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_uptime_checks", Description: "List recent checks and incidents for an uptime monitor.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "monitor_id": stringProperty("Uptime monitor UUID"), "limit": limitProperty}, "project_id", "monitor_id"), Annotations: readOnly},
		{Name: "list_cron_monitors", Description: "List cron/check-in monitors and current status.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_cron_checkins", Description: "List recent cron check-ins, optionally for one monitor.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "monitor_id": stringProperty("Optional cron monitor UUID"), "limit": limitProperty}, "project_id"), Annotations: readOnly},
		{Name: "list_feedback", Description: "List user feedback associated with project events.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_replays", Description: "List replay segments and correlated errors.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "analyze_replay", Description: "Decode a replay segment into navigation, interaction, mutation, and breadcrumb timelines without exposing form input values.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "replay_id": stringProperty("Internal replay segment UUID")}, "project_id", "replay_id"), Annotations: readOnly},
		{Name: "list_profiles", Description: "List profiles and transaction linkage.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "analyze_profile", Description: "Analyze a sampled profile into thread totals, hotspots, and a flamegraph tree.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "profile_id": stringProperty("Internal profile UUID")}, "project_id", "profile_id"), Annotations: readOnly},
		{Name: "list_metrics", Description: "List metric points, optionally filtered by metric name.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "name": stringProperty("Optional metric name"), "limit": limitProperty}, "project_id"), Annotations: readOnly},
		{Name: "list_alert_rules", Description: "List alert rules and advanced conditions.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_alert_deliveries", Description: "List recent alert delivery attempts.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_artifacts", Description: "List source maps and native debug artifacts.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_attachments", Description: "List event attachments and their metadata.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_deploys", Description: "List release deploys for a project.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_commits", Description: "List commits linked to project releases.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_suspect_commits", Description: "List suspect commits calculated for an issue.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "issue_id": stringProperty("Issue UUID"), "limit": limitProperty}, "project_id", "issue_id"), Annotations: readOnly},
		{Name: "list_project_quotas", Description: "List category-specific ingestion quotas for a project.", InputSchema: projectLimitSchema(stringProperty, limitProperty), Annotations: readOnly},
		{Name: "list_ingestion_jobs", Description: "Inspect durable ingestion queue jobs and failures.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "status": stringProperty("Optional pending, processing, done, or dead status"), "limit": limitProperty}, "project_id"), Annotations: readOnly},
		{Name: "list_audit_logs", Description: "List recent organization audit entries.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Optional project UUID"), "limit": limitProperty}), Annotations: readOnly},
		{Name: "get_storage_summary", Description: "Get organization storage usage, retention, queue, and category totals.", InputSchema: objectSchema(nil), Annotations: readOnly},
		{Name: "list_organization_members", Description: "List organization members and their organization roles.", InputSchema: objectSchema(map[string]any{"organization_id": stringProperty("Organization UUID; only needed by the legacy instance token")}), Annotations: readOnly},
		{Name: "list_project_permissions", Description: "List organization roles, explicit project overrides, and effective roles for a project.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID")}, "project_id"), Annotations: readOnly},
		{Name: "update_issue", Description: "Update issue status, priority, assignment, bookmark, or snooze state.", InputSchema: objectSchema(map[string]any{
			"issue_id":         stringProperty("Issue UUID"),
			"status":           map[string]any{"type": "string", "enum": []string{"unresolved", "resolved", "ignored"}},
			"priority":         map[string]any{"type": "string", "enum": []string{"low", "medium", "high", "critical"}},
			"assignee_user_id": stringProperty("Organization user UUID, or an empty string to unassign"),
			"bookmarked":       map[string]any{"type": "boolean"},
			"snoozed_until":    stringProperty("Future RFC3339 timestamp, or an empty string to clear"),
		}, "issue_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}},
		{Name: "set_project_quota", Description: "Set or clear a category-specific project ingestion quota; three zero values clear it.", InputSchema: objectSchema(map[string]any{
			"project_id":     stringProperty("Project UUID"),
			"category":       map[string]any{"type": "string", "enum": []string{"all", "error", "transaction", "span", "log", "session", "attachment", "feedback", "replay", "profile", "metric", "check_in"}},
			"per_minute":     map[string]any{"type": "integer", "minimum": 0},
			"per_day":        map[string]any{"type": "integer", "minimum": 0},
			"max_item_bytes": map[string]any{"type": "integer", "minimum": 0, "maximum": 100 << 20},
		}, "project_id", "category", "per_minute", "per_day", "max_item_bytes"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}},
		{Name: "retry_ingestion_job", Description: "Move a dead-letter ingestion job back to the pending queue.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "job_id": stringProperty("Ingestion job UUID")}, "project_id", "job_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "delete_ingestion_job", Description: "Permanently delete a completed or dead ingestion job and its unreferenced payload.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "job_id": stringProperty("Ingestion job UUID")}, "project_id", "job_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}},
		{Name: "update_retention", Description: "Set organization retention between 1 and 3650 days.", InputSchema: objectSchema(map[string]any{"organization_id": stringProperty("Organization UUID; only needed by the legacy instance token"), "days": map[string]any{"type": "integer", "minimum": 1, "maximum": 3650}}, "days"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}},
		{Name: "add_issue_comment", Description: "Add a triage comment to an issue.", InputSchema: objectSchema(map[string]any{"issue_id": stringProperty("Issue UUID"), "body": stringProperty("Comment text, up to 4000 characters")}, "issue_id", "body"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "create_alert_rule", Description: "Create an email, webhook, or Slack alert rule with bounded conditions.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "name": stringProperty("Rule name"),
			"trigger":          map[string]any{"type": "string", "enum": []string{"new_issue", "regression", "uptime_down", "cron_missed", "metric_threshold", "user_feedback"}},
			"destination_type": map[string]any{"type": "string", "enum": []string{"email", "webhook", "slack"}},
			"destination_url":  stringProperty("HTTPS webhook or Slack URL"), "destination_email": stringProperty("Email recipient"),
			"conditions": map[string]any{"type": "object", "additionalProperties": true}, "frequency_minutes": map[string]any{"type": "integer", "minimum": 0, "maximum": 10080},
		}, "project_id", "name", "trigger", "destination_type"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "update_alert_rule", Description: "Update an alert rule's trigger, destination, conditions, cooldown, or enabled state.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "rule_id": stringProperty("Alert rule UUID"), "name": stringProperty("Rule name"),
			"trigger":          map[string]any{"type": "string", "enum": []string{"new_issue", "regression", "uptime_down", "cron_missed", "metric_threshold", "user_feedback"}},
			"destination_type": map[string]any{"type": "string", "enum": []string{"email", "webhook", "slack"}},
			"destination_url":  stringProperty("HTTPS webhook or Slack URL"), "destination_email": stringProperty("Email recipient"),
			"conditions": map[string]any{"type": "object", "additionalProperties": true}, "frequency_minutes": map[string]any{"type": "integer", "minimum": 0, "maximum": 10080}, "enabled": map[string]any{"type": "boolean"},
		}, "project_id", "rule_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true}},
		{Name: "delete_alert_rule", Description: "Permanently delete an alert rule and its delivery history.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "rule_id": stringProperty("Alert rule UUID")}, "project_id", "rule_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}},
		{Name: "create_uptime_monitor", Description: "Create a bounded GET or HEAD uptime monitor after SSRF-safe URL validation.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "name": stringProperty("Monitor name"), "url": stringProperty("HTTP or HTTPS target"),
			"method":              map[string]any{"type": "string", "enum": []string{"GET", "HEAD"}, "default": "GET"},
			"interval_seconds":    map[string]any{"type": "integer", "minimum": 30, "maximum": 86400, "default": 60},
			"timeout_seconds":     map[string]any{"type": "integer", "minimum": 1, "maximum": 30, "default": 10},
			"expected_status_min": map[string]any{"type": "integer", "minimum": 100, "maximum": 599, "default": 200},
			"expected_status_max": map[string]any{"type": "integer", "minimum": 100, "maximum": 599, "default": 399},
		}, "project_id", "name", "url"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "delete_uptime_monitor", Description: "Permanently delete an uptime monitor, checks, and incidents.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "monitor_id": stringProperty("Uptime monitor UUID")}, "project_id", "monitor_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}},
		{Name: "create_cron_monitor", Description: "Create an interval or five-field crontab check-in monitor.", InputSchema: objectSchema(map[string]any{
			"project_id": stringProperty("Project UUID"), "slug": stringProperty("Monitor slug"), "name": stringProperty("Monitor name; defaults to slug"),
			"schedule_type":  map[string]any{"type": "string", "enum": []string{"interval", "crontab"}, "default": "interval"},
			"schedule_value": map[string]any{"description": "Interval minutes, Sentry interval pair, or five-field crontab expression"},
			"timezone":       stringProperty("IANA timezone, defaults to UTC"), "checkin_margin": map[string]any{"type": "integer", "minimum": 1, "default": 5}, "max_runtime": map[string]any{"type": "integer", "minimum": 1, "default": 30},
		}, "project_id", "slug"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false}},
		{Name: "delete_cron_monitor", Description: "Permanently delete a cron monitor and its check-in history.", InputSchema: objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "monitor_id": stringProperty("Cron monitor UUID")}, "project_id", "monitor_id"), Annotations: map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}},
	}
}

func projectLimitSchema(stringProperty func(string) map[string]any, limitProperty map[string]any) map[string]any {
	return objectSchema(map[string]any{"project_id": stringProperty("Project UUID"), "limit": limitProperty}, "project_id")
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	if properties == nil {
		properties = map[string]any{}
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func (s *Service) listOrganizations(ctx context.Context, credential *credential) (any, error) {
	query := `
		SELECT o.id, o.slug, o.name,
		       (SELECT COUNT(*) FROM projects p WHERE p.organization_id = o.id),
		       (SELECT COUNT(*) FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.organization_id = o.id)
		FROM organizations o`
	args := make([]any, 0, 1)
	if !credential.legacy {
		query += ` WHERE o.id = ?`
		args = append(args, credential.organizationID)
	}
	query += ` ORDER BY o.name`
	rows, err := s.store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, slug, name string
		var projects, issues int64
		if err := rows.Scan(&id, &slug, &name, &projects, &issues); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "slug": slug, "name": name, "projects": projects, "issues": issues})
	}
	return items, rows.Err()
}

func (s *Service) listProjects(ctx context.Context, credential *credential, organizationSlug string) (any, error) {
	query := `
		SELECT p.id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), p.public_key, p.created_at, o.id, o.slug, o.name
		FROM projects p JOIN organizations o ON o.id = p.organization_id`
	conditions := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if !credential.legacy {
		conditions = append(conditions, `o.id = ?`)
		args = append(args, credential.organizationID)
	}
	if organizationSlug != "" {
		conditions = append(conditions, `o.slug = ?`)
		args = append(args, organizationSlug)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY o.name, p.name`
	rows, err := s.store.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, sentryID, slug, name, platform, publicKey, createdAt, orgID, orgSlug, orgName string
		if err := rows.Scan(&id, &sentryID, &slug, &name, &platform, &publicKey, &createdAt, &orgID, &orgSlug, &orgName); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"id": id, "sentry_id": sentryID, "slug": slug, "name": name, "platform": platform, "public_key": publicKey,
			"dsn": dsnURL(s.publicURL, publicKey, sentryID), "created_at": createdAt,
			"organization": map[string]string{"id": orgID, "slug": orgSlug, "name": orgName},
		})
	}
	return items, rows.Err()
}

func (s *Service) projectSummary(ctx context.Context, projectID string) (any, error) {
	var id, slug, name, platform string
	var issues, openIssues, events, releases int64
	err := s.store.DB.QueryRowContext(ctx, `
		SELECT p.id, p.slug, p.name, COALESCE(p.platform, ''),
		       (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id),
		       (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id AND i.status = 'unresolved'),
		       (SELECT COUNT(*) FROM events e WHERE e.project_id = p.id),
		       (SELECT COUNT(*) FROM project_releases pr WHERE pr.project_id = p.id)
		FROM projects p WHERE p.id = ?
	`, projectID).Scan(&id, &slug, &name, &platform, &issues, &openIssues, &events, &releases)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("project not found")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "slug": slug, "name": name, "platform": platform, "issues": issues, "open_issues": openIssues, "events": events, "releases": releases}, nil
}

func (s *Service) listIssues(ctx context.Context, projectID, status, query string, limit int) (any, error) {
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "unresolved" && status != "resolved" && status != "ignored" {
		return nil, errors.New("status must be all, unresolved, resolved, or ignored")
	}
	statement := `
		SELECT i.id, i.title, i.status, i.level, i.event_count, i.first_seen_at, i.last_seen_at,
		       COALESCE(fr.version, ''), COALESCE(lr.version, '')
		FROM issues i
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		WHERE i.project_id = ?`
	args := []any{projectID}
	if status != "all" {
		statement += ` AND i.status = ?`
		args = append(args, status)
	}
	if strings.TrimSpace(query) != "" {
		statement += ` AND i.title LIKE '%' || ? || '%' COLLATE NOCASE`
		args = append(args, strings.TrimSpace(query))
	}
	statement += ` ORDER BY i.last_seen_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, title, issueStatus, level, firstSeen, lastSeen, firstRelease, lastRelease string
		var count int64
		if err := rows.Scan(&id, &title, &issueStatus, &level, &count, &firstSeen, &lastSeen, &firstRelease, &lastRelease); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "title": title, "status": issueStatus, "level": level, "event_count": count, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "first_release": firstRelease, "last_release": lastRelease})
	}
	return items, rows.Err()
}

func (s *Service) getIssue(ctx context.Context, issueID string) (any, error) {
	var id, projectID, projectSlug, title, status, level, fingerprint, firstSeen, lastSeen, firstRelease, lastRelease string
	var count int64
	err := s.store.DB.QueryRowContext(ctx, `
		SELECT i.id, i.project_id, p.slug, i.title, i.status, i.level, i.fingerprint, i.event_count,
		       i.first_seen_at, i.last_seen_at, COALESCE(fr.version, ''), COALESCE(lr.version, '')
		FROM issues i JOIN projects p ON p.id = i.project_id
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		WHERE i.id = ?
	`, issueID).Scan(&id, &projectID, &projectSlug, &title, &status, &level, &fingerprint, &count, &firstSeen, &lastSeen, &firstRelease, &lastRelease)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("issue not found")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "project_id": projectID, "project_slug": projectSlug, "title": title, "status": status, "level": level, "fingerprint": fingerprint, "event_count": count, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "first_release": firstRelease, "last_release": lastRelease}, nil
}

func (s *Service) updateIssueStatus(ctx context.Context, issueID, status string) (any, error) {
	if status != "unresolved" && status != "resolved" && status != "ignored" {
		return nil, errors.New("status must be unresolved, resolved, or ignored")
	}
	result, err := s.store.DB.ExecContext(ctx, `UPDATE issues SET status = ? WHERE id = ?`, status, issueID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed == 0 {
		return nil, errors.New("issue not found")
	}
	return map[string]any{"id": issueID, "status": status, "updated": true}, nil
}

func (s *Service) listEvents(ctx context.Context, projectID, issueID string, limit int) (any, error) {
	statement := `
		SELECT e.event_id, e.issue_id, e.level, e.platform, e.environment, e.timestamp, e.received_at, COALESCE(r.version, '')
		FROM events e LEFT JOIN releases r ON r.id = e.release_id
		WHERE e.project_id = ?`
	args := []any{projectID}
	if issueID != "" {
		statement += ` AND e.issue_id = ?`
		args = append(args, issueID)
	}
	statement += ` ORDER BY e.timestamp DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var eventID, eventIssueID, level, platform, environment, timestamp, receivedAt, release string
		if err := rows.Scan(&eventID, &eventIssueID, &level, &platform, &environment, &timestamp, &receivedAt, &release); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"event_id": eventID, "issue_id": eventIssueID, "level": level, "platform": platform, "environment": environment, "timestamp": timestamp, "received_at": receivedAt, "release": release})
	}
	return items, rows.Err()
}

func (s *Service) getEvent(ctx context.Context, projectID, eventID string) (any, error) {
	var issueID, level, platform, environment, timestamp, receivedAt, release string
	var payload []byte
	err := s.store.DB.QueryRowContext(ctx, `
		SELECT e.issue_id, e.level, e.platform, e.environment, e.timestamp, e.received_at, COALESCE(r.version, ''), e.payload
		FROM events e LEFT JOIN releases r ON r.id = e.release_id
		WHERE e.project_id = ? AND e.event_id = ?
	`, projectID, eventID).Scan(&issueID, &level, &platform, &environment, &timestamp, &receivedAt, &release, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("event not found")
	}
	if err != nil {
		return nil, err
	}
	var eventPayload any
	if err := json.Unmarshal(payload, &eventPayload); err != nil {
		eventPayload = string(payload)
	}
	return map[string]any{"event_id": eventID, "issue_id": issueID, "level": level, "platform": platform, "environment": environment, "timestamp": timestamp, "received_at": receivedAt, "release": release, "payload": eventPayload}, nil
}

func (s *Service) listReleases(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT r.id, r.version, pr.first_seen_at, pr.last_seen_at,
		       (SELECT COUNT(*) FROM events e WHERE e.project_id = pr.project_id AND e.release_id = r.id)
		FROM project_releases pr JOIN releases r ON r.id = pr.release_id
		WHERE pr.project_id = ? ORDER BY pr.last_seen_at DESC LIMIT ?
	`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, version, firstSeen, lastSeen string
		var events int64
		if err := rows.Scan(&id, &version, &firstSeen, &lastSeen, &events); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "version": version, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "events": events})
	}
	return items, rows.Err()
}

func dsnURL(publicURL, publicKey, projectID string) string {
	separator := strings.Index(publicURL, "://")
	if separator < 0 {
		return ""
	}
	return publicURL[:separator+3] + publicKey + "@" + strings.TrimRight(publicURL[separator+3:], "/") + "/" + projectID
}

func requestedProtocolVersion(raw json.RawMessage) string {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(raw, &params) == nil && supportedProtocolVersions[params.ProtocolVersion] {
		return params.ProtocolVersion
	}
	return protocolVersion
}

func requestID(raw json.RawMessage) any {
	var id any
	if json.Unmarshal(raw, &id) != nil {
		return nil
	}
	return id
}

func toolError(err error) map[string]any {
	return map[string]any{
		"content": []map[string]string{{"type": "text", "text": err.Error()}},
		"isError": true,
	}
}

func (s *Service) writeResult(w http.ResponseWriter, id, result any) {
	s.writeResponse(w, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Service) writeRPCError(w http.ResponseWriter, id any, code int, message string) {
	s.writeResponse(w, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}})
}

func (s *Service) writeResponse(w http.ResponseWriter, response rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
