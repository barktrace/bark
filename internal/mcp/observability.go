package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	telemetryanalysis "github.com/barktrace/bark/internal/telemetry"
)

func (s *Service) callObservabilityTool(ctx context.Context, credential *credential, name string, raw json.RawMessage) (any, error) {
	if name == "get_storage_summary" || name == "list_audit_logs" {
		if !credential.can("read") {
			return nil, errors.New("read scope required")
		}
		if name == "list_audit_logs" {
			var args struct {
				ProjectID string `json:"project_id"`
				Limit     int    `json:"limit"`
			}
			if err := decodeArguments(raw, &args); err != nil {
				return nil, err
			}
			if args.ProjectID != "" {
				if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
					return nil, err
				}
			}
			return s.listAuditLogs(ctx, credential, args.ProjectID, boundedLimit(args.Limit))
		}
		return s.storageSummary(ctx, credential)
	}
	var args struct {
		ProjectID   string `json:"project_id"`
		MonitorID   string `json:"monitor_id"`
		Level       string `json:"level"`
		Query       string `json:"query"`
		Name        string `json:"name"`
		Status      string `json:"status"`
		IssueID     string `json:"issue_id"`
		ReplayID    string `json:"replay_id"`
		ProfileID   string `json:"profile_id"`
		Environment string `json:"environment"`
		Release     string `json:"release"`
		UserID      string `json:"user_id"`
		HasError    bool   `json:"has_error"`
		Limit       int    `json:"limit"`
	}
	if err := decodeArguments(raw, &args); err != nil || strings.TrimSpace(args.ProjectID) == "" {
		return nil, errors.New("project_id is required")
	}
	if err := s.requireProject(ctx, credential, args.ProjectID, "read"); err != nil {
		return nil, err
	}
	limit := boundedLimit(args.Limit)
	switch name {
	case "list_transactions":
		return s.listTransactions(ctx, args.ProjectID, limit)
	case "list_logs":
		return s.listLogs(ctx, args.ProjectID, args.Level, args.Query, limit)
	case "list_uptime_monitors":
		return s.listUptimeMonitors(ctx, args.ProjectID, limit)
	case "list_uptime_checks":
		if args.MonitorID == "" {
			return nil, errors.New("monitor_id is required")
		}
		return s.listUptimeChecks(ctx, args.ProjectID, args.MonitorID, limit)
	case "list_cron_monitors":
		return s.listCronMonitors(ctx, args.ProjectID, limit)
	case "list_cron_checkins":
		return s.listCronCheckins(ctx, args.ProjectID, args.MonitorID, limit)
	case "list_feedback":
		return s.listFeedback(ctx, args.ProjectID, limit)
	case "list_replays":
		return s.listReplays(ctx, args.ProjectID, args.Query, args.Environment, args.Release, args.UserID, args.IssueID, args.HasError, limit)
	case "list_replay_clicks":
		if args.ReplayID == "" {
			return nil, errors.New("replay_id is required")
		}
		return s.listReplayClicks(ctx, args.ProjectID, args.ReplayID, limit)
	case "list_replay_selectors":
		return s.listReplaySelectors(ctx, args.ProjectID, limit)
	case "analyze_replay":
		if args.ReplayID == "" {
			return nil, errors.New("replay_id is required")
		}
		return s.analyzeReplay(ctx, args.ProjectID, args.ReplayID)
	case "list_profiles":
		return s.listProfiles(ctx, args.ProjectID, limit)
	case "analyze_profile":
		if args.ProfileID == "" {
			return nil, errors.New("profile_id is required")
		}
		return s.analyzeProfile(ctx, args.ProjectID, args.ProfileID)
	case "list_metrics":
		return s.listMetrics(ctx, args.ProjectID, args.Name, limit)
	case "list_alert_rules":
		return s.listAlertRules(ctx, args.ProjectID, limit)
	case "list_alert_deliveries":
		return s.listAlertDeliveries(ctx, args.ProjectID, limit)
	case "list_artifacts":
		return s.listArtifacts(ctx, args.ProjectID, limit)
	case "list_attachments":
		return s.listAttachments(ctx, args.ProjectID, limit)
	case "list_deploys":
		return s.listDeploys(ctx, args.ProjectID, limit)
	case "list_commits":
		return s.listCommits(ctx, args.ProjectID, limit)
	case "list_suspect_commits":
		if args.IssueID == "" {
			return nil, errors.New("issue_id is required")
		}
		return s.listSuspectCommits(ctx, args.ProjectID, args.IssueID, limit)
	case "list_project_quotas":
		return s.listProjectQuotas(ctx, args.ProjectID)
	case "list_ingestion_jobs":
		return s.listIngestionJobs(ctx, args.ProjectID, args.Status, limit)
	default:
		return nil, fmt.Errorf("unknown tool %q", name)
	}
}

func (s *Service) listTransactions(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT t.event_id, t.trace_id, t.span_id, t.name, t.operation, t.status, t.environment,
		       t.started_at, t.finished_at, t.duration_ms, t.span_count, COALESCE(r.version, '')
		FROM transactions t LEFT JOIN releases r ON r.id = t.release_id
		WHERE t.project_id = ? ORDER BY t.finished_at DESC LIMIT ?
	`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var eventID, traceID, spanID, name, operation, status, environment, startedAt, finishedAt, release string
		var duration float64
		var spanCount int
		if err := rows.Scan(&eventID, &traceID, &spanID, &name, &operation, &status, &environment, &startedAt, &finishedAt, &duration, &spanCount, &release); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"event_id": eventID, "trace_id": traceID, "span_id": spanID, "name": name, "operation": operation, "status": status, "environment": environment, "started_at": startedAt, "finished_at": finishedAt, "duration_ms": duration, "span_count": spanCount, "release": release})
	}
	return items, rows.Err()
}

func (s *Service) listLogs(ctx context.Context, projectID, level, search string, limit int) (any, error) {
	statement := `SELECT l.id, l.timestamp, l.level, l.message, l.environment, l.trace_id, l.span_id, l.attributes, COALESCE(r.version, '') FROM logs l LEFT JOIN releases r ON r.id = l.release_id WHERE l.project_id = ?`
	args := []any{projectID}
	if level = strings.ToLower(strings.TrimSpace(level)); level != "" && level != "all" {
		statement += ` AND l.level = ?`
		args = append(args, level)
	}
	if search = strings.TrimSpace(search); search != "" {
		statement += ` AND l.message LIKE '%' || ? || '%' COLLATE NOCASE`
		args = append(args, search)
	}
	statement += ` ORDER BY l.timestamp DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, timestamp, logLevel, message, environment, traceID, spanID, release string
		var attributes json.RawMessage
		if err := rows.Scan(&id, &timestamp, &logLevel, &message, &environment, &traceID, &spanID, &attributes, &release); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "timestamp": timestamp, "level": logLevel, "message": message, "environment": environment, "trace_id": traceID, "span_id": spanID, "attributes": attributes, "release": release})
	}
	return items, rows.Err()
}

func (s *Service) listUptimeMonitors(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, name, url, method, interval_seconds, timeout_seconds, expected_status_min, expected_status_max, enabled, last_status, COALESCE(last_checked_at, ''), next_check_at, created_at FROM uptime_monitors WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, targetURL, method, status, lastChecked, nextCheck, createdAt string
		var interval, timeout, statusMin, statusMax int
		var enabled bool
		if err := rows.Scan(&id, &name, &targetURL, &method, &interval, &timeout, &statusMin, &statusMax, &enabled, &status, &lastChecked, &nextCheck, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "url": targetURL, "method": method, "interval_seconds": interval, "timeout_seconds": timeout, "expected_status_min": statusMin, "expected_status_max": statusMax, "enabled": enabled, "last_status": status, "last_checked_at": lastChecked, "next_check_at": nextCheck, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listUptimeChecks(ctx context.Context, projectID, monitorID string, limit int) (any, error) {
	var exists int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM uptime_monitors WHERE id = ? AND project_id = ?`, monitorID, projectID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, errors.New("uptime monitor not found")
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT status, COALESCE(status_code, 0), duration_ms, error, checked_at FROM uptime_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT ?`, monitorID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks := make([]map[string]any, 0)
	for rows.Next() {
		var status, checkError, checkedAt string
		var statusCode int
		var duration int64
		if err := rows.Scan(&status, &statusCode, &duration, &checkError, &checkedAt); err != nil {
			return nil, err
		}
		checks = append(checks, map[string]any{"status": status, "status_code": statusCode, "duration_ms": duration, "error": checkError, "checked_at": checkedAt})
	}
	return checks, rows.Err()
}

func (s *Service) listCronMonitors(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, status, COALESCE(last_checkin_at, ''), COALESCE(next_checkin_at, ''), created_at FROM cron_monitors WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, slug, name, scheduleType, scheduleValue, timezone, status, lastCheckin, nextCheckin, createdAt string
		var margin, maxRuntime int
		if err := rows.Scan(&id, &slug, &name, &scheduleType, &scheduleValue, &timezone, &margin, &maxRuntime, &status, &lastCheckin, &nextCheckin, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "slug": slug, "name": name, "schedule_type": scheduleType, "schedule_value": scheduleValue, "timezone": timezone, "checkin_margin": margin, "max_runtime": maxRuntime, "status": status, "last_checkin_at": lastCheckin, "next_checkin_at": nextCheckin, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listCronCheckins(ctx context.Context, projectID, monitorID string, limit int) (any, error) {
	statement := `SELECT c.checkin_id, c.monitor_id, m.slug, c.status, COALESCE(c.duration, 0), c.release, c.environment, c.started_at, COALESCE(c.finished_at, '') FROM cron_checkins c JOIN cron_monitors m ON m.id = c.monitor_id WHERE m.project_id = ?`
	args := []any{projectID}
	if monitorID != "" {
		statement += ` AND c.monitor_id = ?`
		args = append(args, monitorID)
	}
	statement += ` ORDER BY c.started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var checkinID, id, slug, status, release, environment, startedAt, finishedAt string
		var duration float64
		if err := rows.Scan(&checkinID, &id, &slug, &status, &duration, &release, &environment, &startedAt, &finishedAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"checkin_id": checkinID, "monitor_id": id, "monitor_slug": slug, "status": status, "duration": duration, "release": release, "environment": environment, "started_at": startedAt, "finished_at": finishedAt})
	}
	return items, rows.Err()
}

func (s *Service) listFeedback(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, event_id, name, email, comments, url, created_at FROM user_feedback WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventID, name, email, comments, targetURL, createdAt string
		if err := rows.Scan(&id, &eventID, &name, &email, &comments, &targetURL, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event_id": eventID, "name": name, "email": email, "comments": comments, "url": targetURL, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listReplays(ctx context.Context, projectID, query, environment, release, userID, issueID string, hasError bool, limit int) (any, error) {
	clauses := []string{"rp.project_id = ?"}
	arguments := []any{projectID}
	for _, filter := range []struct{ column, value string }{{"rp.environment", environment}, {"rp.release", release}, {"rp.user_id", userID}} {
		if value := strings.TrimSpace(filter.value); value != "" {
			clauses = append(clauses, filter.column+" = ?")
			arguments = append(arguments, value)
		}
	}
	if query = strings.TrimSpace(query); query != "" {
		like := "%" + query + "%"
		clauses = append(clauses, "(rp.url LIKE ? OR rp.user_id LIKE ? OR rp.replay_id LIKE ?)")
		arguments = append(arguments, like, like, like)
	}
	if hasError {
		clauses = append(clauses, "rp.error_count > 0")
	}
	if issueID = strings.TrimSpace(issueID); issueID != "" {
		clauses = append(clauses, `EXISTS (SELECT 1 FROM replay_error_links rel JOIN events e ON e.project_id = rel.project_id AND e.event_id = rel.event_id WHERE rel.project_id = rp.project_id AND rel.replay_id = rp.replay_id AND e.issue_id = ?)`)
		arguments = append(arguments, issueID)
	}
	arguments = append(arguments, limit)
	rows, err := s.store.DB.QueryContext(ctx, `SELECT rp.replay_id, rp.segment_id, rp.environment, rp.release, rp.user_id, rp.started_at, rp.finished_at, rp.error_count, rp.url, rp.created_at, (SELECT COALESCE(SUM(rc.is_dead), 0) FROM replay_clicks rc WHERE rc.project_id = rp.project_id AND rc.replay_id = rp.replay_id AND rc.segment_id = rp.segment_id), (SELECT COALESCE(SUM(rc.is_rage), 0) FROM replay_clicks rc WHERE rc.project_id = rp.project_id AND rc.replay_id = rp.replay_id AND rc.segment_id = rp.segment_id) FROM replays rp WHERE `+strings.Join(clauses, " AND ")+` ORDER BY rp.finished_at DESC LIMIT ?`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var replayID, environment, release, userID, startedAt, finishedAt, targetURL, createdAt string
		var segmentID, errorCount, deadClicks, rageClicks int
		if err := rows.Scan(&replayID, &segmentID, &environment, &release, &userID, &startedAt, &finishedAt, &errorCount, &targetURL, &createdAt, &deadClicks, &rageClicks); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"replay_id": replayID, "segment_id": segmentID, "environment": environment, "release": release, "user_id": userID, "started_at": startedAt, "finished_at": finishedAt, "error_count": errorCount, "dead_click_count": deadClicks, "rage_click_count": rageClicks, "url": targetURL, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listReplayClicks(ctx context.Context, projectID, replayID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT segment_id, sequence, node_id, timestamp, dom_element, element, is_dead, is_rage FROM replay_clicks WHERE project_id = ? AND replay_id = ? ORDER BY timestamp LIMIT ?`, projectID, strings.ToLower(strings.ReplaceAll(strings.TrimSpace(replayID), "-", "")), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var segmentID, sequence, nodeID, dead, rage int
		var timestamp, selector, encodedElement string
		if err := rows.Scan(&segmentID, &sequence, &nodeID, &timestamp, &selector, &encodedElement, &dead, &rage); err != nil {
			return nil, err
		}
		element := map[string]any{}
		_ = json.Unmarshal([]byte(encodedElement), &element)
		items = append(items, map[string]any{"segment_id": segmentID, "sequence": sequence, "node_id": nodeID, "timestamp": timestamp, "dom_element": selector, "element": element, "is_dead": dead != 0, "is_rage": rage != 0})
	}
	return items, rows.Err()
}

func (s *Service) listReplaySelectors(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT dom_element, element, SUM(is_dead), SUM(is_rage) FROM replay_clicks WHERE project_id = ? AND (is_dead = 1 OR is_rage = 1) GROUP BY dom_element, element ORDER BY SUM(is_dead) + SUM(is_rage) DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var selector, encodedElement string
		var dead, rage int
		if err := rows.Scan(&selector, &encodedElement, &dead, &rage); err != nil {
			return nil, err
		}
		element := map[string]any{}
		_ = json.Unmarshal([]byte(encodedElement), &element)
		items = append(items, map[string]any{"dom_element": selector, "element": element, "count_dead_clicks": dead, "count_rage_clicks": rage})
	}
	return items, rows.Err()
}

func (s *Service) listProfiles(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, profile_id, COALESCE(profiler_id, ''), COALESCE(chunk_id, ''), COALESCE(transaction_id, ''), platform, environment, release, started_at, duration_ms, created_at FROM profiles WHERE project_id = ? ORDER BY started_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, profileID, profilerID, chunkID, transactionID, platform, environment, release, startedAt, createdAt string
		var duration float64
		if err := rows.Scan(&id, &profileID, &profilerID, &chunkID, &transactionID, &platform, &environment, &release, &startedAt, &duration, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "profile_id": profileID, "profiler_id": profilerID, "chunk_id": chunkID, "transaction_id": transactionID, "platform": platform, "environment": environment, "release": release, "started_at": startedAt, "duration_ms": duration, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) analyzeReplay(ctx context.Context, projectID, id string) (any, error) {
	var replayID, eventKey, recordingKey string
	var segmentID int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT rp.replay_id, rp.segment_id, COALESCE(event_blob.storage_key, ''), COALESCE(recording_blob.storage_key, '') FROM replays rp LEFT JOIN blobs event_blob ON event_blob.id = rp.event_blob_id LEFT JOIN blobs recording_blob ON recording_blob.id = rp.recording_blob_id WHERE rp.id = ? AND rp.project_id = ?`, id, projectID).Scan(&replayID, &segmentID, &eventKey, &recordingKey); err != nil {
		return nil, errors.New("replay not found")
	}
	eventPayload, err := s.readTelemetryBlob(eventKey)
	if err != nil {
		return nil, err
	}
	recordingPayload, err := s.readTelemetryBlob(recordingKey)
	if err != nil {
		return nil, err
	}
	analysis, err := telemetryanalysis.AnalyzeReplay(eventPayload, recordingPayload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "replay_id": replayID, "segment_id": segmentID, "analysis": analysis}, nil
}

func (s *Service) analyzeProfile(ctx context.Context, projectID, id string) (any, error) {
	var profileID, key string
	if err := s.store.DB.QueryRowContext(ctx, `SELECT p.profile_id, b.storage_key FROM profiles p JOIN blobs b ON b.id = p.blob_id WHERE p.id = ? AND p.project_id = ?`, id, projectID).Scan(&profileID, &key); err != nil {
		return nil, errors.New("profile not found")
	}
	payload, err := s.readTelemetryBlob(key)
	if err != nil {
		return nil, err
	}
	analysis, err := telemetryanalysis.AnalyzeProfile(payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "profile_id": profileID, "analysis": analysis}, nil
}

func (s *Service) readTelemetryBlob(key string) ([]byte, error) {
	if strings.TrimSpace(key) == "" {
		return nil, nil
	}
	file, err := s.store.Blobs.Open(key)
	if err != nil {
		return nil, errors.New("telemetry payload is unavailable")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, telemetryanalysis.MaxCompressedBytes+1))
	if err != nil {
		return nil, errors.New("could not read telemetry payload")
	}
	if len(payload) > telemetryanalysis.MaxCompressedBytes {
		return nil, errors.New("telemetry payload exceeds analysis size limit")
	}
	return payload, nil
}

func (s *Service) listMetrics(ctx context.Context, projectID, name string, limit int) (any, error) {
	statement := `SELECT id, name, metric_type, value, unit, tags, timestamp FROM metric_points WHERE project_id = ?`
	args := []any{projectID}
	if name = strings.TrimSpace(name); name != "" {
		statement += ` AND name = ?`
		args = append(args, name)
	}
	statement += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var metricName, metricType, unit, timestamp string
		var value float64
		var tags json.RawMessage
		if err := rows.Scan(&id, &metricName, &metricType, &value, &unit, &tags, &timestamp); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": metricName, "type": metricType, "value": value, "unit": unit, "tags": tags, "timestamp": timestamp})
	}
	return items, rows.Err()
}

func (s *Service) listAlertRules(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT id, name, trigger, destination_type, conditions, frequency_minutes, enabled, created_at FROM alert_rules WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, trigger, destinationType, createdAt string
		var conditions json.RawMessage
		var frequency int
		var enabled bool
		if err := rows.Scan(&id, &name, &trigger, &destinationType, &conditions, &frequency, &enabled, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "trigger": trigger, "destination_type": destinationType, "conditions": conditions, "frequency_minutes": frequency, "enabled": enabled, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listAlertDeliveries(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT d.id, d.event_type, d.status, d.attempts, d.last_error, d.created_at, COALESCE(d.delivered_at, ''), r.id, r.name FROM alert_deliveries d JOIN alert_rules r ON r.id = d.rule_id WHERE r.project_id = ? ORDER BY d.created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventType, status, lastError, createdAt, deliveredAt, ruleID, ruleName string
		var attempts int
		if err := rows.Scan(&id, &eventType, &status, &attempts, &lastError, &createdAt, &deliveredAt, &ruleID, &ruleName); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event_type": eventType, "status": status, "attempts": attempts, "last_error": lastError, "created_at": createdAt, "delivered_at": deliveredAt, "rule_id": ruleID, "rule_name": ruleName})
	}
	return items, rows.Err()
}

func (s *Service) listArtifacts(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT a.id, a.name, a.artifact_type, a.debug_id, a.dist, b.size, b.checksum, a.created_at, COALESCE(r.version, '') FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id LEFT JOIN releases r ON r.id = a.release_id WHERE a.project_id = ? ORDER BY a.created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, artifactType, debugID, dist, checksum, createdAt, release string
		var size int64
		if err := rows.Scan(&id, &name, &artifactType, &debugID, &dist, &size, &checksum, &createdAt, &release); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "artifact_type": artifactType, "debug_id": debugID, "dist": dist, "size": size, "checksum": checksum, "created_at": createdAt, "release": release})
	}
	return items, rows.Err()
}

func (s *Service) listAttachments(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT a.id, e.event_id, a.filename, a.attachment_type, b.size, b.content_type, b.checksum, a.created_at FROM event_attachments a JOIN events e ON e.id = a.event_id JOIN blobs b ON b.id = a.blob_id WHERE e.project_id = ? ORDER BY a.created_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventID, filename, attachmentType, contentType, checksum, createdAt string
		var size int64
		if err := rows.Scan(&id, &eventID, &filename, &attachmentType, &size, &contentType, &checksum, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "event_id": eventID, "filename": filename, "attachment_type": attachmentType, "size": size, "content_type": contentType, "checksum": checksum, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listDeploys(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT d.id, r.version, d.environment, d.name, d.url, d.started_at, COALESCE(d.finished_at, ''), d.created_at FROM deploys d JOIN releases r ON r.id = d.release_id LEFT JOIN project_releases pr ON pr.release_id = d.release_id AND pr.project_id = ? WHERE d.project_id = ? OR (d.project_id IS NULL AND pr.project_id IS NOT NULL) ORDER BY d.started_at DESC LIMIT ?`, projectID, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, release, environment, name, targetURL, startedAt, finishedAt, createdAt string
		if err := rows.Scan(&id, &release, &environment, &name, &targetURL, &startedAt, &finishedAt, &createdAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "release": release, "environment": environment, "name": name, "url": targetURL, "started_at": startedAt, "finished_at": finishedAt, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listCommits(ctx context.Context, projectID string, limit int) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT c.id, c.repository, c.external_id, c.message, c.author_name, c.author_email, c.committed_at, GROUP_CONCAT(DISTINCT r.version) FROM commits c JOIN release_commits rc ON rc.commit_id = c.id JOIN releases r ON r.id = rc.release_id JOIN project_releases pr ON pr.release_id = r.id WHERE pr.project_id = ? GROUP BY c.id ORDER BY c.committed_at DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, repository, externalID, message, authorName, authorEmail, committedAt, releases string
		if err := rows.Scan(&id, &repository, &externalID, &message, &authorName, &authorEmail, &committedAt, &releases); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "repository": repository, "external_id": externalID, "message": message, "author_name": authorName, "author_email": authorEmail, "committed_at": committedAt, "releases": strings.Split(releases, ",")})
	}
	return items, rows.Err()
}

func (s *Service) listSuspectCommits(ctx context.Context, projectID, issueID string, limit int) (any, error) {
	var exists int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM issues WHERE id = ? AND project_id = ?`, issueID, projectID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, errors.New("issue not found")
	}
	rows, err := s.store.DB.QueryContext(ctx, `SELECT c.id, c.repository, c.external_id, c.message, c.author_name, c.author_email, c.committed_at, s.score, s.reason FROM issue_suspect_commits s JOIN commits c ON c.id = s.commit_id WHERE s.issue_id = ? ORDER BY s.score DESC, c.committed_at DESC LIMIT ?`, issueID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, repository, externalID, message, authorName, authorEmail, committedAt, reason string
		var score int
		if err := rows.Scan(&id, &repository, &externalID, &message, &authorName, &authorEmail, &committedAt, &score, &reason); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "repository": repository, "external_id": externalID, "message": message, "author_name": authorName, "author_email": authorEmail, "committed_at": committedAt, "score": score, "reason": reason})
	}
	return items, rows.Err()
}

func (s *Service) listProjectQuotas(ctx context.Context, projectID string) (any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT category, per_minute, per_day, max_item_bytes FROM project_quotas WHERE project_id = ? ORDER BY category`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var category string
		var perMinute, perDay, maxItemBytes int64
		if err := rows.Scan(&category, &perMinute, &perDay, &maxItemBytes); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"category": category, "per_minute": perMinute, "per_day": perDay, "max_item_bytes": maxItemBytes})
	}
	return items, rows.Err()
}

func (s *Service) listAuditLogs(ctx context.Context, credential *credential, projectID string, limit int) (any, error) {
	statement := `SELECT a.id, COALESCE(a.project_id, ''), COALESCE(a.actor_user_id, ''), a.actor_type, a.action, a.target_type, a.target_id, a.metadata, a.ip_address, a.created_at, COALESCE(u.email, '') FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id`
	args := make([]any, 0, 3)
	conditions := make([]string, 0, 2)
	if !credential.legacy {
		conditions = append(conditions, `a.organization_id = ?`)
		args = append(args, credential.organizationID)
	}
	if projectID != "" {
		conditions = append(conditions, `a.project_id = ?`)
		args = append(args, projectID)
	}
	if len(conditions) > 0 {
		statement += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	statement += ` ORDER BY a.id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var eventProjectID, actorID, actorType, action, targetType, targetID, address, createdAt, actorEmail string
		var metadata json.RawMessage
		if err := rows.Scan(&id, &eventProjectID, &actorID, &actorType, &action, &targetType, &targetID, &metadata, &address, &createdAt, &actorEmail); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "project_id": eventProjectID, "actor_user_id": actorID, "actor_email": actorEmail, "actor_type": actorType, "action": action, "target_type": targetType, "target_id": targetID, "metadata": metadata, "ip_address": address, "created_at": createdAt})
	}
	return items, rows.Err()
}

func (s *Service) listIngestionJobs(ctx context.Context, projectID, status string, limit int) (any, error) {
	statement := `SELECT id, category, envelope_event_id, status, attempts, available_at, COALESCE(lease_expires_at, ''), last_error, created_at, COALESCE(processed_at, '') FROM ingestion_jobs WHERE project_id = ?`
	args := []any{projectID}
	if status = strings.ToLower(strings.TrimSpace(status)); status != "" && status != "all" {
		if status != "pending" && status != "processing" && status != "done" && status != "dead" {
			return nil, errors.New("status must be pending, processing, done, dead, or all")
		}
		statement += ` AND status = ?`
		args = append(args, status)
	}
	statement += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.store.DB.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, category, eventID, jobStatus, availableAt, leaseExpiresAt, lastError, createdAt, processedAt string
		var attempts int
		if err := rows.Scan(&id, &category, &eventID, &jobStatus, &attempts, &availableAt, &leaseExpiresAt, &lastError, &createdAt, &processedAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "category": category, "event_id": eventID, "status": jobStatus, "attempts": attempts, "available_at": availableAt, "lease_expires_at": leaseExpiresAt, "last_error": lastError, "created_at": createdAt, "processed_at": processedAt})
	}
	return items, rows.Err()
}

func (s *Service) storageSummary(ctx context.Context, credential *credential) (any, error) {
	organizationID := credential.organizationID
	if credential.legacy && organizationID == "" {
		var organizations, projects, blobs, bytes, pending, dead int64
		if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&organizations); err != nil {
			return nil, err
		}
		_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&projects)
		_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM blobs`).Scan(&blobs, &bytes)
		_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingestion_jobs WHERE status = 'pending'`).Scan(&pending)
		_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingestion_jobs WHERE status = 'dead'`).Scan(&dead)
		return map[string]any{"scope": "instance", "organizations": organizations, "projects": projects, "blobs": blobs, "blob_bytes": bytes, "queue_pending": pending, "queue_dead": dead}, nil
	}
	var name string
	var retention int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT name, retention_days FROM organizations WHERE id = ?`, organizationID).Scan(&name, &retention); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("organization not found")
		}
		return nil, err
	}
	var projects, blobs, bytes, pending, dead int64
	_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE organization_id = ?`, organizationID).Scan(&projects)
	_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM blobs WHERE organization_id = ?`, organizationID).Scan(&blobs, &bytes)
	_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingestion_jobs j JOIN projects p ON p.id = j.project_id WHERE p.organization_id = ? AND j.status = 'pending'`, organizationID).Scan(&pending)
	_ = s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingestion_jobs j JOIN projects p ON p.id = j.project_id WHERE p.organization_id = ? AND j.status = 'dead'`, organizationID).Scan(&dead)
	return map[string]any{"scope": "organization", "organization_id": organizationID, "organization_name": name, "retention_days": retention, "projects": projects, "blobs": blobs, "blob_bytes": bytes, "queue_pending": pending, "queue_dead": dead}, nil
}
