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

	"github.com/GhaziBenDahmane/barktrace/internal/store"
)

const protocolVersion = "2025-11-25"

var supportedProtocolVersions = map[string]bool{
	"2025-11-25": true,
	"2025-06-18": true,
	"2025-03-26": true,
}

type Service struct {
	store        *store.Store
	tokenHash    [32]byte
	publicURL    string
	publicOrigin string
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

func New(st *store.Store, token, publicURL string) *Service {
	origin := ""
	if parsed, err := url.Parse(publicURL); err == nil {
		origin = parsed.Scheme + "://" + parsed.Host
	}
	return &Service{store: st, tokenHash: sha256.Sum256([]byte(token)), publicURL: publicURL, publicOrigin: origin}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
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
			"serverInfo":      map[string]string{"name": "barktrace", "version": "0.1.0"},
		})
	case "ping":
		s.writeResult(w, id, map[string]any{})
	case "tools/list":
		s.writeResult(w, id, map[string]any{"tools": tools()})
	case "tools/call":
		result, err := s.callTool(r, request.Params)
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

func (s *Service) authorized(r *http.Request) bool {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	candidate := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))))
	return subtle.ConstantTimeCompare(candidate[:], s.tokenHash[:]) == 1
}

func (s *Service) callTool(r *http.Request, raw json.RawMessage) (any, error) {
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
		return s.listOrganizations(ctx)
	case "list_projects":
		var args struct {
			OrganizationSlug string `json:"organization_slug"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil {
			return nil, err
		}
		return s.listProjects(ctx, args.OrganizationSlug)
	case "get_project_summary":
		var args projectArgs
		if err := requiredProjectArguments(call.Arguments, &args); err != nil {
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
		return s.listIssues(ctx, args.ProjectID, args.Status, args.Query, boundedLimit(args.Limit))
	case "get_issue":
		var args struct {
			IssueID string `json:"issue_id"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.IssueID == "" {
			return nil, errors.New("issue_id is required")
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
		return s.updateIssueStatus(ctx, args.IssueID, args.Status)
	case "list_events":
		var args struct {
			ProjectID string `json:"project_id"`
			IssueID   string `json:"issue_id"`
			Limit     int    `json:"limit"`
		}
		if err := decodeArguments(call.Arguments, &args); err != nil || args.ProjectID == "" {
			return nil, errors.New("project_id is required")
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
		return s.getEvent(ctx, args.ProjectID, args.EventID)
	case "list_releases":
		var args projectArgs
		if err := requiredProjectArguments(call.Arguments, &args); err != nil {
			return nil, err
		}
		return s.listReleases(ctx, args.ProjectID, boundedLimit(args.Limit))
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
	}
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

func (s *Service) listOrganizations(ctx context.Context) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT o.id, o.slug, o.name,
		       (SELECT COUNT(*) FROM projects p WHERE p.organization_id = o.id),
		       (SELECT COUNT(*) FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.organization_id = o.id)
		FROM organizations o ORDER BY o.name
	`)
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

func (s *Service) listProjects(ctx context.Context, organizationSlug string) (any, error) {
	query := `
		SELECT p.id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), p.public_key, p.created_at, o.id, o.slug, o.name
		FROM projects p JOIN organizations o ON o.id = p.organization_id`
	args := make([]any, 0, 1)
	if organizationSlug != "" {
		query += ` WHERE o.slug = ?`
		args = append(args, organizationSlug)
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
