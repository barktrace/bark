package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	alertservice "github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) alertRules(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes, enabled, created_at FROM alert_rules WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list alert rules")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, trigger, destinationType, destinationURL, destinationEmail, createdAt string
		var conditions json.RawMessage
		var frequency int
		var enabled bool
		if err := rows.Scan(&id, &name, &trigger, &destinationType, &destinationURL, &destinationEmail, &conditions, &frequency, &enabled, &createdAt); err == nil {
			destination := destinationURL
			if destinationType == "email" {
				destination = destinationEmail
			}
			items = append(items, map[string]any{"id": id, "name": name, "trigger": trigger, "destination_type": destinationType, "destination_host": destinationHost(destination), "conditions": conditions, "frequency_minutes": frequency, "enabled": enabled, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		ProjectID        string          `json:"project_id"`
		Name             string          `json:"name"`
		Trigger          string          `json:"trigger"`
		DestinationType  string          `json:"destination_type"`
		DestinationURL   string          `json:"destination_url"`
		DestinationEmail string          `json:"destination_email"`
		Conditions       json.RawMessage `json:"conditions"`
		FrequencyMinutes int             `json:"frequency_minutes"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !s.canManageProject(r, principal, input.ProjectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	input.Name, input.Trigger, input.DestinationType, input.DestinationURL, input.DestinationEmail = strings.TrimSpace(input.Name), strings.ToLower(strings.TrimSpace(input.Trigger)), strings.ToLower(strings.TrimSpace(input.DestinationType)), strings.TrimSpace(input.DestinationURL), strings.TrimSpace(input.DestinationEmail)
	if input.Name == "" || !alertTrigger(input.Trigger) {
		writeError(w, http.StatusBadRequest, "valid rule name and trigger are required")
		return
	}
	destination := input.DestinationURL
	if input.DestinationType == "email" {
		destination = input.DestinationEmail
	}
	if err := alertservice.ValidateDestination(input.DestinationType, destination); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := uuid.NewString()
	conditions, ok := validAlertConditions(input.Conditions)
	if !ok || input.FrequencyMinutes < 0 || input.FrequencyMinutes > 10080 {
		writeError(w, http.StatusBadRequest, "invalid alert conditions or frequency")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, input.ProjectID, input.Name, input.Trigger, input.DestinationType, input.DestinationURL, input.DestinationEmail, conditions, input.FrequencyMinutes); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create alert rule")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": input.Name, "trigger": input.Trigger, "destination_type": input.DestinationType, "destination_host": destinationHost(destination), "conditions": json.RawMessage(conditions), "frequency_minutes": input.FrequencyMinutes, "enabled": true})
}

func (s *Server) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	ruleID := r.PathValue("rule_id")
	var projectID, name, trigger, destinationType, destinationURL, destinationEmail string
	var conditions json.RawMessage
	var frequency int
	var enabled bool
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id, name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes, enabled FROM alert_rules WHERE id = ?`, ruleID).Scan(&projectID, &name, &trigger, &destinationType, &destinationURL, &destinationEmail, &conditions, &frequency, &enabled); err != nil {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	var input struct {
		Name             *string         `json:"name"`
		Trigger          *string         `json:"trigger"`
		DestinationType  *string         `json:"destination_type"`
		DestinationURL   *string         `json:"destination_url"`
		DestinationEmail *string         `json:"destination_email"`
		Conditions       json.RawMessage `json:"conditions"`
		FrequencyMinutes *int            `json:"frequency_minutes"`
		Enabled          *bool           `json:"enabled"`
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
	if input.DestinationEmail != nil && strings.TrimSpace(*input.DestinationEmail) != "" {
		destinationEmail = strings.TrimSpace(*input.DestinationEmail)
	}
	if len(input.Conditions) > 0 {
		var ok bool
		conditions, ok = validAlertConditions(input.Conditions)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid alert conditions")
			return
		}
	}
	if input.FrequencyMinutes != nil {
		frequency = *input.FrequencyMinutes
	}
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	if name == "" || !alertTrigger(trigger) {
		writeError(w, http.StatusBadRequest, "valid rule name and trigger are required")
		return
	}
	destination := destinationURL
	if destinationType == "email" {
		destination = destinationEmail
	}
	if err := alertservice.ValidateDestination(destinationType, destination); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if frequency < 0 || frequency > 10080 {
		writeError(w, http.StatusBadRequest, "frequency must be between 0 and 10080 minutes")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE alert_rules SET name = ?, trigger = ?, destination_type = ?, destination_url = ?, destination_email = ?, conditions = ?, frequency_minutes = ?, enabled = ? WHERE id = ?`, name, trigger, destinationType, destinationURL, destinationEmail, conditions, frequency, boolInteger(enabled), ruleID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update alert rule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ruleID, "name": name, "trigger": trigger, "destination_type": destinationType, "destination_host": destinationHost(destination), "conditions": conditions, "frequency_minutes": frequency, "enabled": enabled})
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
	return alertservice.ValidTrigger(value)
}

func destinationHost(raw string) string {
	if strings.Contains(raw, "@") && !strings.Contains(raw, "://") {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "configured"
	}
	return parsed.Host
}

func validAlertConditions(raw json.RawMessage) ([]byte, bool) {
	return alertservice.NormalizeConditions(raw)
}
