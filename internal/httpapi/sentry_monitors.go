package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/cronmon"
	"github.com/google/uuid"
)

type sentryMonitorRecord struct {
	ID, ProjectID, ProjectSentryID, ProjectSlug, ProjectName, ProjectPlatform string
	Slug, Name, ScheduleType, ScheduleValue, Timezone, Status                 string
	LastCheckin, NextCheckin, CreatedAt                                       string
	CheckinMargin, MaxRuntime                                                 int
}

type sentryMonitorInput struct {
	Name    *string                   `json:"name"`
	Slug    *string                   `json:"slug"`
	Project string                    `json:"project"`
	Config  *sentryMonitorConfigInput `json:"config"`
}

type sentryMonitorConfigInput struct {
	Schedule      *sentryMonitorScheduleInput `json:"schedule"`
	CheckinMargin *int                        `json:"checkin_margin"`
	MaxRuntime    *int                        `json:"max_runtime"`
	Timezone      *string                     `json:"timezone"`
}

type sentryMonitorScheduleInput struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

func (s *Server) sentryOrganizationMonitors(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	if r.Method == http.MethodPost {
		s.createSentryMonitor(w, r, principal, organizationID)
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err == nil {
		projectIDs, err = s.filterAccessibleProjects(r, projectIDs, compactQueryValues(r.URL.Query()["project"]))
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize monitors")
		return
	}
	if len(projectIDs) == 0 {
		writeJSON(w, http.StatusOK, []map[string]any{})
		return
	}
	arguments := make([]any, 0, len(projectIDs)+2)
	arguments = append(arguments, organizationID)
	for _, projectID := range projectIDs {
		arguments = append(arguments, projectID)
	}
	arguments = append(arguments, boundedSentryPageSize(r, 100))
	rows, err := s.store.DB.QueryContext(r.Context(), sentryMonitorSelect+` WHERE p.organization_id = ? AND m.project_id IN (`+queryPlaceholders(len(projectIDs))+`) ORDER BY m.name, m.id LIMIT ?`, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list monitors")
		return
	}
	monitors := make([]sentryMonitorRecord, 0)
	for rows.Next() {
		monitor, scanErr := scanSentryMonitor(rows)
		if scanErr != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list monitors")
			return
		}
		monitors = append(monitors, monitor)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, http.StatusInternalServerError, "could not list monitors")
		return
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(monitors))
	for _, monitor := range monitors {
		items = append(items, sentryMonitorResponse(monitor))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createSentryMonitor(w http.ResponseWriter, r *http.Request, principal *auth.Principal, organizationID string) {
	var input sentryMonitorInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	projectID, resolvedOrganizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), strings.TrimSpace(input.Project))
	if !ok || resolvedOrganizationID != organizationID {
		writeError(w, http.StatusBadRequest, "project not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	name := ""
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	monitorSlug := slug(name)
	if input.Slug != nil {
		monitorSlug = slug(*input.Slug)
	}
	if name == "" || monitorSlug == "" {
		writeError(w, http.StatusBadRequest, "monitor name is required")
		return
	}
	scheduleType, scheduleValue, timezone, margin, maxRuntime, err := sentryMonitorConfig(input.Config, "interval", "5", "UTC", 5, 30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	next := cronmon.Next(now, scheduleType, scheduleValue, timezone)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create monitor")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO cron_monitors(id, project_id, slug, name, schedule_type, schedule_value, timezone, checkin_margin, max_runtime, next_checkin_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, projectID, monitorSlug, name, scheduleType, scheduleValue, timezone, margin, maxRuntime, next.Format(time.RFC3339Nano))
	if err != nil {
		writeError(w, http.StatusConflict, "monitor slug already exists")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'create_sentry_monitor', 'cron_monitor', ?)`, organizationID, projectID, principal.UserID, id); err != nil || tx.Commit() != nil {
		writeError(w, http.StatusInternalServerError, "could not create monitor")
		return
	}
	monitor, err := s.loadSentryMonitor(r, organizationID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load monitor")
		return
	}
	writeJSON(w, http.StatusCreated, sentryMonitorResponse(monitor))
}

func (s *Server) sentryOrganizationMonitorDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	monitor, err := s.loadSentryMonitor(r, organizationID, r.PathValue("monitor_id"))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.canAccessProject(r, principal, monitor.ProjectID)) {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load monitor")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, sentryMonitorResponse(monitor))
		return
	}
	if !s.canManageProject(r, principal, monitor.ProjectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if r.Method == http.MethodDelete {
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete monitor")
			return
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM cron_monitors WHERE id = ?`, monitor.ID); err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'delete_sentry_monitor', 'cron_monitor', ?)`, organizationID, monitor.ProjectID, principal.UserID, monitor.ID)
		}
		if err != nil || tx.Commit() != nil {
			writeError(w, http.StatusInternalServerError, "could not delete monitor")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input sentryMonitorInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if input.Name != nil {
		monitor.Name = strings.TrimSpace(*input.Name)
	}
	if input.Slug != nil {
		monitor.Slug = slug(*input.Slug)
	}
	if monitor.Name == "" || monitor.Slug == "" {
		writeError(w, http.StatusBadRequest, "monitor name and slug are required")
		return
	}
	monitor.ScheduleType, monitor.ScheduleValue, monitor.Timezone, monitor.CheckinMargin, monitor.MaxRuntime, err = sentryMonitorConfig(input.Config, monitor.ScheduleType, monitor.ScheduleValue, monitor.Timezone, monitor.CheckinMargin, monitor.MaxRuntime)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	next := cronmon.Next(time.Now().UTC(), monitor.ScheduleType, monitor.ScheduleValue, monitor.Timezone)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update monitor")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `UPDATE cron_monitors SET slug = ?, name = ?, schedule_type = ?, schedule_value = ?, timezone = ?, checkin_margin = ?, max_runtime = ?, next_checkin_at = ? WHERE id = ?`, monitor.Slug, monitor.Name, monitor.ScheduleType, monitor.ScheduleValue, monitor.Timezone, monitor.CheckinMargin, monitor.MaxRuntime, next.Format(time.RFC3339Nano), monitor.ID); err != nil {
		writeError(w, http.StatusConflict, "monitor slug already exists")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'update_sentry_monitor', 'cron_monitor', ?)`, organizationID, monitor.ProjectID, principal.UserID, monitor.ID); err != nil || tx.Commit() != nil {
		writeError(w, http.StatusInternalServerError, "could not update monitor")
		return
	}
	monitor, err = s.loadSentryMonitor(r, organizationID, monitor.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load monitor")
		return
	}
	writeJSON(w, http.StatusOK, sentryMonitorResponse(monitor))
}

func (s *Server) sentryOrganizationMonitorCheckins(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	monitor, err := s.loadSentryMonitor(r, organizationID, r.PathValue("monitor_id"))
	if err != nil || !s.canAccessProject(r, principal, monitor.ProjectID) {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	arguments := []any{monitor.ID}
	statusClause := ""
	if status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))); status != "" {
		if status != "in_progress" && status != "ok" && status != "error" && status != "missed" {
			writeError(w, http.StatusBadRequest, "invalid check-in status")
			return
		}
		statusClause = " AND status = ?"
		arguments = append(arguments, status)
	}
	arguments = append(arguments, boundedSentryPageSize(r, 100))
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT checkin_id, status, COALESCE(duration, 0), release, environment, started_at, COALESCE(finished_at, ''), created_at FROM cron_checkins WHERE monitor_id = ?`+statusClause+` ORDER BY started_at DESC, id DESC LIMIT ?`, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list check-ins")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, status, release, environment, startedAt, finishedAt, createdAt string
		var duration float64
		if err := rows.Scan(&id, &status, &duration, &release, &environment, &startedAt, &finishedAt, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list check-ins")
			return
		}
		items = append(items, map[string]any{
			"id": id, "status": status, "duration": duration, "release": nullableText(release),
			"environment": nullableText(environment), "dateCreated": normalizeAPITime(createdAt),
			"dateStarted": normalizeAPITime(startedAt), "dateFinished": nullableAPITime(finishedAt),
		})
	}
	writeJSON(w, http.StatusOK, items)
}

const sentryMonitorSelect = `SELECT m.id, m.project_id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), m.slug, m.name, m.schedule_type, m.schedule_value, m.timezone, m.checkin_margin, m.max_runtime, m.status, COALESCE(m.last_checkin_at, ''), COALESCE(m.next_checkin_at, ''), m.created_at FROM cron_monitors m JOIN projects p ON p.id = m.project_id`

func (s *Server) loadSentryMonitor(r *http.Request, organizationID, selector string) (sentryMonitorRecord, error) {
	return scanSentryMonitor(s.store.DB.QueryRowContext(r.Context(), sentryMonitorSelect+` WHERE p.organization_id = ? AND (m.id = ? OR m.slug = ?) LIMIT 1`, organizationID, selector, selector))
}

func scanSentryMonitor(row rowScanner) (sentryMonitorRecord, error) {
	var monitor sentryMonitorRecord
	err := row.Scan(&monitor.ID, &monitor.ProjectID, &monitor.ProjectSentryID, &monitor.ProjectSlug, &monitor.ProjectName, &monitor.ProjectPlatform, &monitor.Slug, &monitor.Name, &monitor.ScheduleType, &monitor.ScheduleValue, &monitor.Timezone, &monitor.CheckinMargin, &monitor.MaxRuntime, &monitor.Status, &monitor.LastCheckin, &monitor.NextCheckin, &monitor.CreatedAt)
	return monitor, err
}

func sentryMonitorResponse(monitor sentryMonitorRecord) map[string]any {
	var scheduleValue any = monitor.ScheduleValue
	if monitor.ScheduleType == "interval" {
		minutes, _ := strconv.Atoi(monitor.ScheduleValue)
		scheduleValue = []any{minutes, "minute"}
	}
	return map[string]any{
		"id": monitor.ID, "name": monitor.Name, "slug": monitor.Slug, "type": "cron_job", "status": "active", "lastCheckInStatus": monitor.Status,
		"config": map[string]any{
			"schedule":       map[string]any{"type": monitor.ScheduleType, "value": scheduleValue},
			"checkin_margin": monitor.CheckinMargin, "max_runtime": monitor.MaxRuntime, "timezone": monitor.Timezone,
			"failure_issue_threshold": 1, "recovery_threshold": 1,
		},
		"project":      map[string]any{"id": monitor.ProjectSentryID, "slug": monitor.ProjectSlug, "name": monitor.ProjectName, "platform": nullableText(monitor.ProjectPlatform)},
		"environments": []any{}, "dateCreated": normalizeAPITime(monitor.CreatedAt),
		"lastCheckIn": nullableAPITime(monitor.LastCheckin), "nextCheckIn": nullableAPITime(monitor.NextCheckin),
	}
}

func sentryMonitorConfig(input *sentryMonitorConfigInput, scheduleType, scheduleValue, timezone string, margin, maxRuntime int) (string, string, string, int, int, error) {
	if input == nil {
		return scheduleType, scheduleValue, timezone, margin, maxRuntime, nil
	}
	if input.Schedule != nil {
		var err error
		scheduleType, scheduleValue, err = cronmon.NormalizeSchedule(input.Schedule.Type, input.Schedule.Value)
		if err != nil {
			return "", "", "", 0, 0, err
		}
	}
	if input.Timezone != nil {
		timezone = strings.TrimSpace(*input.Timezone)
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return "", "", "", 0, 0, errors.New("invalid timezone")
	}
	if input.CheckinMargin != nil {
		margin = *input.CheckinMargin
	}
	if input.MaxRuntime != nil {
		maxRuntime = *input.MaxRuntime
	}
	if margin < 1 || margin > 10080 || maxRuntime < 1 || maxRuntime > 10080 {
		return "", "", "", 0, 0, errors.New("check-in margin and max runtime must be between 1 and 10080 minutes")
	}
	return scheduleType, scheduleValue, timezone, margin, maxRuntime, nil
}
