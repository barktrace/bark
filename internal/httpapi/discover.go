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
	"github.com/barktrace/bark/internal/discover"
	"github.com/google/uuid"
)

func (s *Server) discoverQuery(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := strings.TrimSpace(r.URL.Query().Get("organization_id"))
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	request, err := discoverRequestFromQuery(r, projectIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := discover.Query(r.Context(), s.store.DB, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func discoverRequestFromQuery(r *http.Request, projectIDs []string) (discover.Request, error) {
	query := r.URL.Query()
	fields := query["field"]
	if len(fields) == 0 && query.Get("fields") != "" {
		fields = splitCommaList(query.Get("fields"))
	}
	start, end, err := discoverTimeRange(query.Get("start"), query.Get("end"), firstNonEmpty(query.Get("statsPeriod"), query.Get("stats_period")))
	if err != nil {
		return discover.Request{}, err
	}
	limit, _ := strconv.Atoi(firstNonEmpty(query.Get("per_page"), query.Get("limit")))
	return discover.Request{
		Dataset: query.Get("dataset"), Fields: fields, ProjectIDs: projectIDs,
		Project: query.Get("project"), Environment: query.Get("environment"), Release: query.Get("release"),
		Level: firstNonEmpty(query.Get("level"), query.Get("severity")), Status: query.Get("status"), Query: query.Get("query"),
		Start: start, End: end, OrderBy: firstNonEmpty(query.Get("orderby"), query.Get("order_by")), Limit: limit,
	}, nil
}

func discoverTimeRange(startRaw, endRaw, period string) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	end := now
	if strings.TrimSpace(endRaw) != "" {
		parsed, err := time.Parse(time.RFC3339, endRaw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("end must be RFC3339")
		}
		end = parsed.UTC()
	}
	if strings.TrimSpace(startRaw) != "" {
		parsed, err := time.Parse(time.RFC3339, startRaw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("start must be RFC3339")
		}
		start := parsed.UTC()
		if !start.Before(end) {
			return time.Time{}, time.Time{}, errors.New("start must be before end")
		}
		if end.Sub(start) > 90*24*time.Hour {
			return time.Time{}, time.Time{}, errors.New("time range cannot exceed 90 days")
		}
		return start, end, nil
	}
	duration, err := discoverPeriod(period)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return end.Add(-duration), end, nil
}

func discoverPeriod(value string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 24 * time.Hour, nil
	}
	if len(value) < 2 {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	amount, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || amount <= 0 {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	var duration time.Duration
	switch value[len(value)-1] {
	case 'h':
		duration = time.Duration(amount) * time.Hour
	case 'd':
		duration = time.Duration(amount) * 24 * time.Hour
	default:
		return 0, errors.New("stats period must use h or d")
	}
	if duration < time.Hour || duration > 90*24*time.Hour {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	return duration, nil
}

func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (s *Server) discoverProjectIDs(r *http.Request, principal *auth.Principal, organizationID string) ([]string, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT p.id FROM projects p
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = ?
		WHERE p.organization_id = ? AND COALESCE(pm.role, '') != 'none'
		ORDER BY p.id
	`, principal.UserID, organizationID)
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

type dashboardInput struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
}

type widgetInput struct {
	Title       string         `json:"title"`
	Dataset     string         `json:"dataset"`
	DisplayType string         `json:"display_type"`
	Fields      []string       `json:"fields"`
	Query       string         `json:"query"`
	Environment string         `json:"environment"`
	Release     string         `json:"release"`
	StatsPeriod string         `json:"stats_period"`
	OrderBy     string         `json:"order_by"`
	Limit       int            `json:"limit"`
	Position    int            `json:"position"`
	Layout      map[string]any `json:"layout"`
}

func (s *Server) dashboards(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	if r.Method == http.MethodPost {
		var input dashboardInput
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if pathOrganizationID := r.PathValue("organization_id"); pathOrganizationID != "" {
			if input.OrganizationID != "" && input.OrganizationID != pathOrganizationID {
				writeError(w, http.StatusBadRequest, "organization does not match request path")
				return
			}
			input.OrganizationID = pathOrganizationID
		}
		input.OrganizationID, input.ProjectID, input.Title = strings.TrimSpace(input.OrganizationID), strings.TrimSpace(input.ProjectID), strings.TrimSpace(input.Title)
		if input.Title == "" || len(input.Title) > 120 {
			writeError(w, http.StatusBadRequest, "title must contain 1 to 120 characters")
			return
		}
		if len(input.Description) > 1000 {
			writeError(w, http.StatusBadRequest, "description cannot exceed 1000 characters")
			return
		}
		if !organizationAdmin(principal, input.OrganizationID) {
			writeError(w, http.StatusForbidden, "organization administrator access required")
			return
		}
		if input.ProjectID != "" {
			var belongs int
			_ = s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM projects WHERE id = ? AND organization_id = ?`, input.ProjectID, input.OrganizationID).Scan(&belongs)
			if belongs == 0 {
				writeError(w, http.StatusBadRequest, "project does not belong to organization")
				return
			}
			if !s.canManageProject(r, principal, input.ProjectID) {
				writeError(w, http.StatusForbidden, "project administrator access required")
				return
			}
		}
		var dashboardCount int
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM dashboards WHERE organization_id = ?`, input.OrganizationID).Scan(&dashboardCount); err != nil {
			writeError(w, http.StatusInternalServerError, "could not count dashboards")
			return
		}
		if dashboardCount >= 100 {
			writeError(w, http.StatusBadRequest, "organization cannot contain more than 100 dashboards")
			return
		}
		id := uuid.NewString()
		_, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO dashboards(id, organization_id, project_id, created_by, title, description) VALUES (?, ?, NULLIF(?, ''), ?, ?, ?)`, id, input.OrganizationID, input.ProjectID, principal.UserID, input.Title, strings.TrimSpace(input.Description))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not create dashboard")
			return
		}
		item, _ := s.dashboardResponse(r, principal, id)
		writeJSON(w, http.StatusCreated, item)
		return
	}
	organizationID := strings.TrimSpace(r.URL.Query().Get("organization_id"))
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT d.id FROM dashboards d
		LEFT JOIN project_memberships pm ON pm.project_id = d.project_id AND pm.user_id = ?
		WHERE d.organization_id = ? AND (d.project_id IS NULL OR COALESCE(pm.role, '') != 'none')
		ORDER BY d.updated_at DESC LIMIT 100
	`, principal.UserID, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list dashboards")
		return
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		if item, err := s.dashboardResponse(r, principal, id); err == nil {
			items = append(items, item)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"dashboards": items})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	id := r.PathValue("dashboard_id")
	organizationID, projectID, ok := s.dashboardScope(r, principal, id)
	if !ok {
		writeError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	if r.Method == http.MethodGet {
		item, err := s.dashboardResponse(r, principal, id)
		if err != nil {
			writeError(w, http.StatusNotFound, "dashboard not found")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if !organizationAdmin(principal, organizationID) || (projectID != "" && !s.canManageProject(r, principal, projectID)) {
		writeError(w, http.StatusForbidden, "dashboard administrator access required")
		return
	}
	if r.Method == http.MethodDelete {
		_, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM dashboards WHERE id = ?`, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete dashboard")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input dashboardInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Title = strings.TrimSpace(input.Title)
	if input.Title == "" || len(input.Title) > 120 {
		writeError(w, http.StatusBadRequest, "title must contain 1 to 120 characters")
		return
	}
	if len(input.Description) > 1000 {
		writeError(w, http.StatusBadRequest, "description cannot exceed 1000 characters")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE dashboards SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, input.Title, strings.TrimSpace(input.Description), id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update dashboard")
		return
	}
	item, _ := s.dashboardResponse(r, principal, id)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) dashboardWidgets(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	dashboardID := r.PathValue("dashboard_id")
	organizationID, projectID, ok := s.dashboardScope(r, principal, dashboardID)
	if !ok {
		writeError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	if !organizationAdmin(principal, organizationID) || (projectID != "" && !s.canManageProject(r, principal, projectID)) {
		writeError(w, http.StatusForbidden, "dashboard administrator access required")
		return
	}
	widgetID := r.PathValue("widget_id")
	if r.Method == http.MethodDelete {
		result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM dashboard_widgets WHERE id = ? AND dashboard_id = ?`, widgetID, dashboardID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete widget")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "widget not found")
			return
		}
		_, _ = s.store.DB.ExecContext(r.Context(), `UPDATE dashboards SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, dashboardID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input widgetInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if err := validateWidget(&input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	if projectID != "" {
		projectIDs = []string{projectID}
	}
	period, _ := discoverPeriod(input.StatsPeriod)
	end := time.Now().UTC()
	if _, err := discover.Query(r.Context(), s.store.DB, discover.Request{Dataset: input.Dataset, Fields: input.Fields, ProjectIDs: projectIDs, Environment: input.Environment, Release: input.Release, Query: input.Query, Start: end.Add(-period), End: end, OrderBy: input.OrderBy, Limit: 1}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fields, _ := json.Marshal(input.Fields)
	layout, _ := json.Marshal(input.Layout)
	if r.Method == http.MethodPost {
		var widgetCount int
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM dashboard_widgets WHERE dashboard_id = ?`, dashboardID).Scan(&widgetCount); err != nil {
			writeError(w, http.StatusInternalServerError, "could not count widgets")
			return
		}
		if widgetCount >= 100 {
			writeError(w, http.StatusBadRequest, "dashboard cannot contain more than 100 widgets")
			return
		}
		widgetID = uuid.NewString()
		_, err = s.store.DB.ExecContext(r.Context(), `INSERT INTO dashboard_widgets(id, dashboard_id, title, dataset, display_type, fields, query, environment, release, stats_period, order_by, result_limit, position, layout) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, widgetID, dashboardID, input.Title, input.Dataset, input.DisplayType, fields, input.Query, input.Environment, input.Release, input.StatsPeriod, input.OrderBy, input.Limit, input.Position, layout)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create widget")
			return
		}
	} else {
		result, err := s.store.DB.ExecContext(r.Context(), `UPDATE dashboard_widgets SET title = ?, dataset = ?, display_type = ?, fields = ?, query = ?, environment = ?, release = ?, stats_period = ?, order_by = ?, result_limit = ?, position = ?, layout = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND dashboard_id = ?`, input.Title, input.Dataset, input.DisplayType, fields, input.Query, input.Environment, input.Release, input.StatsPeriod, input.OrderBy, input.Limit, input.Position, layout, widgetID, dashboardID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not update widget")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "widget not found")
			return
		}
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `UPDATE dashboards SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, dashboardID)
	item, _ := s.dashboardResponse(r, principal, dashboardID)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, item)
}

func validateWidget(input *widgetInput) error {
	input.Title, input.Dataset = strings.TrimSpace(input.Title), strings.ToLower(strings.TrimSpace(input.Dataset))
	input.DisplayType, input.StatsPeriod = strings.ToLower(strings.TrimSpace(input.DisplayType)), strings.TrimSpace(input.StatsPeriod)
	if input.Title == "" || len(input.Title) > 120 {
		return errors.New("widget title must contain 1 to 120 characters")
	}
	validDataset := map[string]bool{"errors": true, "transactions": true, "spans": true, "logs": true, "metrics": true}
	if !validDataset[input.Dataset] {
		return errors.New("unsupported widget dataset")
	}
	if input.DisplayType == "" {
		input.DisplayType = "table"
	}
	validDisplay := map[string]bool{"table": true, "number": true, "line": true, "bar": true, "area": true}
	if !validDisplay[input.DisplayType] {
		return errors.New("unsupported widget display type")
	}
	if len(input.Fields) == 0 || len(input.Fields) > 20 {
		return errors.New("widget requires 1 to 20 fields")
	}
	if len(input.Query) > 2048 {
		return errors.New("widget query cannot exceed 2048 bytes")
	}
	if input.StatsPeriod == "" {
		input.StatsPeriod = "24h"
	}
	if _, err := discoverPeriod(input.StatsPeriod); err != nil {
		return err
	}
	if input.Limit <= 0 {
		input.Limit = 20
	}
	if input.Limit > 100 {
		return errors.New("widget limit cannot exceed 100")
	}
	if input.Layout == nil {
		input.Layout = map[string]any{}
	}
	return nil
}

func (s *Server) dashboardScope(r *http.Request, principal *auth.Principal, dashboardID string) (string, string, bool) {
	var organizationID string
	var projectID sql.NullString
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id, project_id FROM dashboards WHERE id = ?`, dashboardID).Scan(&organizationID, &projectID); err != nil {
		return "", "", false
	}
	if _, ok := principal.Membership(organizationID); !ok {
		return "", "", false
	}
	if projectID.Valid && !s.canAccessProject(r, principal, projectID.String) {
		return "", "", false
	}
	return organizationID, projectID.String, true
}

func (s *Server) dashboardResponse(r *http.Request, principal *auth.Principal, dashboardID string) (map[string]any, error) {
	organizationID, projectID, ok := s.dashboardScope(r, principal, dashboardID)
	if !ok {
		return nil, sql.ErrNoRows
	}
	var title, description, createdBy, createdAt, updatedAt string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT title, description, COALESCE(created_by, ''), created_at, updated_at FROM dashboards WHERE id = ?`, dashboardID).Scan(&title, &description, &createdBy, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, title, dataset, display_type, fields, query, environment, release, stats_period, order_by, result_limit, position, layout, created_at, updated_at FROM dashboard_widgets WHERE dashboard_id = ? ORDER BY position, created_at LIMIT 100`, dashboardID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	widgets := make([]map[string]any, 0)
	for rows.Next() {
		var id, widgetTitle, dataset, displayType, query, environment, release, period, orderBy, widgetCreated, widgetUpdated string
		var fields, layout []byte
		var limit, position int
		if err := rows.Scan(&id, &widgetTitle, &dataset, &displayType, &fields, &query, &environment, &release, &period, &orderBy, &limit, &position, &layout, &widgetCreated, &widgetUpdated); err != nil {
			return nil, err
		}
		widgets = append(widgets, map[string]any{"id": id, "title": widgetTitle, "dataset": dataset, "display_type": displayType, "fields": jsonRaw(fields), "query": query, "environment": environment, "release": release, "stats_period": period, "order_by": orderBy, "limit": limit, "position": position, "layout": jsonRaw(layout), "created_at": widgetCreated, "updated_at": widgetUpdated})
	}
	return map[string]any{"id": dashboardID, "organization_id": organizationID, "project_id": projectID, "title": title, "description": description, "created_by": createdBy, "created_at": createdAt, "updated_at": updatedAt, "widgets": widgets}, rows.Err()
}
