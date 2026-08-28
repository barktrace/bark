package httpapi

import (
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/auth"
	"github.com/GhaziBenDahmane/barktrace/internal/uptime"
	"github.com/google/uuid"
)

func (s *Server) performance(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	window, label := performanceWindow(r.URL.Query().Get("period"))
	since := time.Now().UTC().Add(-window).Format(time.RFC3339Nano)
	var count, failed int64
	var average, maximum sql.NullFloat64
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT COUNT(*), AVG(duration_ms), MAX(duration_ms),
		       COALESCE(SUM(CASE WHEN status IN ('internal_error','unknown_error','unavailable','deadline_exceeded','aborted','data_loss') THEN 1 ELSE 0 END), 0)
		FROM transactions WHERE project_id = ? AND finished_at >= ?
	`, projectID, since).Scan(&count, &average, &maximum, &failed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not summarize transactions")
		return
	}
	percentile := func(fraction float64) float64 {
		if count == 0 {
			return 0
		}
		offset := int64(math.Ceil(float64(count)*fraction)) - 1
		var value float64
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT duration_ms FROM transactions WHERE project_id = ? AND finished_at >= ? ORDER BY duration_ms LIMIT 1 OFFSET ?`, projectID, since, offset).Scan(&value)
		return value
	}

	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT t.name, t.operation, COUNT(*), AVG(t.duration_ms), MAX(t.duration_ms),
		       SUM(CASE WHEN t.status IN ('internal_error','unknown_error','unavailable','deadline_exceeded','aborted','data_loss') THEN 1 ELSE 0 END),
		       MAX(t.finished_at)
		FROM transactions t WHERE t.project_id = ? AND t.finished_at >= ?
		GROUP BY t.name, t.operation ORDER BY COUNT(*) DESC, AVG(t.duration_ms) DESC LIMIT 100
	`, projectID, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list transactions")
		return
	}
	items := make([]map[string]any, 0)
	for rows.Next() {
		var name, operation, lastSeen string
		var itemCount, itemFailed int64
		var itemAverage, itemMaximum float64
		if err := rows.Scan(&name, &operation, &itemCount, &itemAverage, &itemMaximum, &itemFailed, &lastSeen); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list transactions")
			return
		}
		items = append(items, map[string]any{"name": name, "operation": operation, "count": itemCount, "average_ms": itemAverage, "max_ms": itemMaximum, "failed": itemFailed, "last_seen_at": lastSeen})
	}
	_ = rows.Close()
	writeJSON(w, http.StatusOK, map[string]any{
		"period":       label,
		"stats":        map[string]any{"count": count, "average_ms": nullFloat(average), "p50_ms": percentile(.50), "p95_ms": percentile(.95), "max_ms": nullFloat(maximum), "failed": failed},
		"transactions": items,
	})
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	limit := 200
	if value, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && value >= 1 && value <= 500 {
		limit = value
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT l.id, l.timestamp, l.level, l.message, l.environment, l.trace_id, l.span_id,
		       l.attributes, COALESCE(r.version, '')
		FROM logs l LEFT JOIN releases r ON r.id = l.release_id
		WHERE l.project_id = ? AND (? = '' OR l.level = ?) AND (? = '' OR l.message LIKE '%' || ? || '%')
		ORDER BY l.timestamp DESC LIMIT ?
	`, projectID, level, level, query, query, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list logs")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, timestamp, itemLevel, message, environment, traceID, spanID, release string
		var attributes []byte
		if err := rows.Scan(&id, &timestamp, &itemLevel, &message, &environment, &traceID, &spanID, &attributes, &release); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list logs")
			return
		}
		var decodedAttributes map[string]any
		_ = json.Unmarshal(attributes, &decodedAttributes)
		items = append(items, map[string]any{"id": id, "timestamp": timestamp, "level": itemLevel, "message": message, "environment": environment, "trace_id": traceID, "span_id": spanID, "release": release, "attributes": decodedAttributes})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) uptimeMonitors(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT m.id, m.name, m.url, m.method, m.interval_seconds, m.timeout_seconds,
		       m.expected_status_min, m.expected_status_max, m.enabled, m.last_status,
		       COALESCE(m.last_checked_at, ''), m.created_at,
		       COALESCE((SELECT ROUND(100.0 * SUM(CASE WHEN c.status = 'up' THEN 1 ELSE 0 END) / COUNT(*), 2) FROM uptime_checks c WHERE c.monitor_id = m.id AND c.checked_at >= datetime('now', '-24 hours')), 0),
		       EXISTS(SELECT 1 FROM uptime_incidents i WHERE i.monitor_id = m.id AND i.resolved_at IS NULL)
		FROM uptime_monitors m WHERE m.project_id = ? ORDER BY m.created_at DESC
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list uptime monitors")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, targetURL, method, status, lastChecked, createdAt string
		var interval, timeout, statusMin, statusMax int
		var enabled, openIncident bool
		var availability float64
		if err := rows.Scan(&id, &name, &targetURL, &method, &interval, &timeout, &statusMin, &statusMax, &enabled, &status, &lastChecked, &createdAt, &availability, &openIncident); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list uptime monitors")
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "url": targetURL, "method": method, "interval_seconds": interval, "timeout_seconds": timeout, "expected_status_min": statusMin, "expected_status_max": statusMax, "enabled": enabled, "last_status": status, "last_checked_at": lastChecked, "availability_24h": availability, "open_incident": openIncident, "created_at": createdAt})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createUptimeMonitor(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		ProjectID         string `json:"project_id"`
		Name              string `json:"name"`
		URL               string `json:"url"`
		Method            string `json:"method"`
		IntervalSeconds   int    `json:"interval_seconds"`
		TimeoutSeconds    int    `json:"timeout_seconds"`
		ExpectedStatusMin int    `json:"expected_status_min"`
		ExpectedStatusMax int    `json:"expected_status_max"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !s.canManageProject(r, principal, input.ProjectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	input.Name, input.URL, input.Method = strings.TrimSpace(input.Name), strings.TrimSpace(input.URL), strings.ToUpper(strings.TrimSpace(input.Method))
	if input.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.Method == "" {
		input.Method = http.MethodGet
	}
	if input.Method != http.MethodGet && input.Method != http.MethodHead {
		writeError(w, http.StatusBadRequest, "method must be GET or HEAD")
		return
	}
	if input.IntervalSeconds == 0 {
		input.IntervalSeconds = 60
	}
	if input.TimeoutSeconds == 0 {
		input.TimeoutSeconds = 10
	}
	if input.ExpectedStatusMin == 0 {
		input.ExpectedStatusMin = 200
	}
	if input.ExpectedStatusMax == 0 {
		input.ExpectedStatusMax = 399
	}
	if input.IntervalSeconds < 30 || input.IntervalSeconds > 86400 || input.TimeoutSeconds < 1 || input.TimeoutSeconds > 30 || input.ExpectedStatusMin < 100 || input.ExpectedStatusMax > 599 || input.ExpectedStatusMin > input.ExpectedStatusMax {
		writeError(w, http.StatusBadRequest, "monitor settings are outside allowed ranges")
		return
	}
	if err := s.uptime.ValidateURL(r.Context(), input.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO uptime_monitors(id, project_id, name, url, method, interval_seconds, timeout_seconds, expected_status_min, expected_status_max, next_check_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, input.ProjectID, input.Name, input.URL, input.Method, input.IntervalSeconds, input.TimeoutSeconds, input.ExpectedStatusMin, input.ExpectedStatusMax, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create uptime monitor")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": input.Name, "url": input.URL, "last_status": "pending"})
}

func (s *Server) deleteUptimeMonitor(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	id := r.PathValue("monitor_id")
	if !s.canManageMonitor(r, principal, id) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM uptime_monitors WHERE id = ?`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete uptime monitor")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) checkUptimeMonitor(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	id := r.PathValue("monitor_id")
	if !s.canManageMonitor(r, principal, id) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	result, err := s.uptime.CheckNow(r.Context(), id)
	if err != nil {
		if uptime.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "monitor not found")
		} else {
			writeError(w, http.StatusInternalServerError, "could not run uptime check")
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) uptimeChecks(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	monitorID := r.URL.Query().Get("monitor_id")
	if !s.canAccessMonitor(r, principal, monitorID) {
		writeError(w, http.StatusForbidden, "monitor access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT status, COALESCE(status_code, 0), duration_ms, error, checked_at FROM uptime_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 100`, monitorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list uptime checks")
		return
	}
	checks := make([]map[string]any, 0)
	for rows.Next() {
		var status, checkError, checkedAt string
		var statusCode int
		var duration int64
		if err := rows.Scan(&status, &statusCode, &duration, &checkError, &checkedAt); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list uptime checks")
			return
		}
		checks = append(checks, map[string]any{"status": status, "status_code": statusCode, "duration_ms": duration, "error": checkError, "checked_at": checkedAt})
	}
	_ = rows.Close()
	incidentRows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, started_at, COALESCE(resolved_at, ''), cause FROM uptime_incidents WHERE monitor_id = ? ORDER BY started_at DESC LIMIT 50`, monitorID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list uptime incidents")
		return
	}
	defer incidentRows.Close()
	incidents := make([]map[string]any, 0)
	for incidentRows.Next() {
		var id, startedAt, resolvedAt, cause string
		if err := incidentRows.Scan(&id, &startedAt, &resolvedAt, &cause); err == nil {
			incidents = append(incidents, map[string]any{"id": id, "started_at": startedAt, "resolved_at": resolvedAt, "cause": cause})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "incidents": incidents})
}

func (s *Server) canManageProject(r *http.Request, principal *auth.Principal, projectID string) bool {
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		return false
	}
	membership, ok := principal.Membership(organizationID)
	return ok && (membership.Role == "owner" || membership.Role == "admin")
}

func (s *Server) canAccessMonitor(r *http.Request, principal *auth.Principal, monitorID string) bool {
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM uptime_monitors WHERE id = ?`, monitorID).Scan(&projectID); err != nil {
		return false
	}
	return s.canAccessProject(r, principal, projectID)
}

func (s *Server) canManageMonitor(r *http.Request, principal *auth.Principal, monitorID string) bool {
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM uptime_monitors WHERE id = ?`, monitorID).Scan(&projectID); err != nil {
		return false
	}
	return s.canManageProject(r, principal, projectID)
}

func performanceWindow(raw string) (time.Duration, string) {
	switch raw {
	case "1h":
		return time.Hour, "1h"
	case "7d":
		return 7 * 24 * time.Hour, "7d"
	case "30d":
		return 30 * 24 * time.Hour, "30d"
	default:
		return 24 * time.Hour, "24h"
	}
}

func nullFloat(value sql.NullFloat64) float64 {
	if value.Valid {
		return value.Float64
	}
	return 0
}
