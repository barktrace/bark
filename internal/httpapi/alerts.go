package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	alertservice "github.com/GhaziBenDahmane/barktrace/internal/alerts"
	"github.com/GhaziBenDahmane/barktrace/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) alertRules(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, name, trigger, destination_type, destination_url, enabled, created_at FROM alert_rules WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list alert rules")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, trigger, destinationType, destinationURL, createdAt string
		var enabled bool
		if err := rows.Scan(&id, &name, &trigger, &destinationType, &destinationURL, &enabled, &createdAt); err == nil {
			items = append(items, map[string]any{"id": id, "name": name, "trigger": trigger, "destination_type": destinationType, "destination_host": destinationHost(destinationURL), "enabled": enabled, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		ProjectID       string `json:"project_id"`
		Name            string `json:"name"`
		Trigger         string `json:"trigger"`
		DestinationType string `json:"destination_type"`
		DestinationURL  string `json:"destination_url"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !s.canManageProject(r, principal, input.ProjectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	input.Name, input.Trigger, input.DestinationType, input.DestinationURL = strings.TrimSpace(input.Name), strings.ToLower(strings.TrimSpace(input.Trigger)), strings.ToLower(strings.TrimSpace(input.DestinationType)), strings.TrimSpace(input.DestinationURL)
	if input.Name == "" || !alertTrigger(input.Trigger) {
		writeError(w, http.StatusBadRequest, "valid rule name and trigger are required")
		return
	}
	if err := alertservice.ValidateDestination(input.DestinationType, input.DestinationURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url) VALUES (?, ?, ?, ?, ?, ?)`, id, input.ProjectID, input.Name, input.Trigger, input.DestinationType, input.DestinationURL); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create alert rule")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": input.Name, "trigger": input.Trigger, "destination_type": input.DestinationType, "destination_host": destinationHost(input.DestinationURL), "enabled": true})
}

func (s *Server) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	ruleID := r.PathValue("rule_id")
	var projectID, name, trigger, destinationType, destinationURL string
	var enabled bool
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id, name, trigger, destination_type, destination_url, enabled FROM alert_rules WHERE id = ?`, ruleID).Scan(&projectID, &name, &trigger, &destinationType, &destinationURL, &enabled); err != nil {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	var input struct {
		Name            *string `json:"name"`
		Trigger         *string `json:"trigger"`
		DestinationType *string `json:"destination_type"`
		DestinationURL  *string `json:"destination_url"`
		Enabled         *bool   `json:"enabled"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	if input.Trigger != nil {
		trigger = strings.ToLower(strings.TrimSpace(*input.Trigger))
	}
	if input.DestinationType != nil {
		destinationType = strings.ToLower(strings.TrimSpace(*input.DestinationType))
	}
	if input.DestinationURL != nil && strings.TrimSpace(*input.DestinationURL) != "" {
		destinationURL = strings.TrimSpace(*input.DestinationURL)
	}
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if name == "" || !alertTrigger(trigger) {
		writeError(w, http.StatusBadRequest, "valid rule name and trigger are required")
		return
	}
	if err := alertservice.ValidateDestination(destinationType, destinationURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE alert_rules SET name = ?, trigger = ?, destination_type = ?, destination_url = ?, enabled = ? WHERE id = ?`, name, trigger, destinationType, destinationURL, enabled, ruleID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update alert rule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ruleID, "name": name, "trigger": trigger, "destination_type": destinationType, "destination_host": destinationHost(destinationURL), "enabled": enabled})
}

func (s *Server) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	ruleID := r.PathValue("rule_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM alert_rules WHERE id = ?`, ruleID).Scan(&projectID); err != nil {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM alert_rules WHERE id = ?`, ruleID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	ruleID := r.PathValue("rule_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM alert_rules WHERE id = ?`, ruleID).Scan(&projectID); err != nil {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	payload, _ := json.Marshal(map[string]any{"title": "Barktrace test alert", "event": "test", "project_id": projectID, "sent_at": time.Now().UTC().Format(time.RFC3339Nano)})
	id := uuid.NewString()
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO alert_deliveries(id, rule_id, event_type, payload, status) VALUES (?, ?, 'test', ?, 'pending')`, id, ruleID, payload); err != nil {
		writeError(w, http.StatusInternalServerError, "could not queue test alert")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"delivery_id": id, "status": "pending"})
}

func (s *Server) alertDeliveries(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT d.id, d.event_type, d.status, d.attempts, d.last_error, d.created_at,
		       COALESCE(d.delivered_at, ''), r.name
		FROM alert_deliveries d JOIN alert_rules r ON r.id = d.rule_id
		WHERE r.project_id = ? ORDER BY d.created_at DESC LIMIT 100
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list alert deliveries")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, eventType, status, lastError, createdAt, deliveredAt, ruleName string
		var attempts int
		if err := rows.Scan(&id, &eventType, &status, &attempts, &lastError, &createdAt, &deliveredAt, &ruleName); err == nil {
			items = append(items, map[string]any{"id": id, "event_type": eventType, "status": status, "attempts": attempts, "last_error": lastError, "created_at": createdAt, "delivered_at": deliveredAt, "rule_name": ruleName})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func alertTrigger(value string) bool {
	return value == "new_issue" || value == "regression" || value == "uptime_down"
}

func destinationHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "configured"
	}
	return parsed.Host
}
