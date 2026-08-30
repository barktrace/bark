package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	alertservice "github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type sentryAlertInput struct {
	Name             string           `json:"name"`
	ActionMatch      string           `json:"actionMatch"`
	FilterMatch      string           `json:"filterMatch"`
	Frequency        *int             `json:"frequency"`
	Conditions       []map[string]any `json:"conditions"`
	Filters          []map[string]any `json:"filters"`
	Actions          []map[string]any `json:"actions"`
	Environment      any              `json:"environment"`
	Enabled          *bool            `json:"enabled"`
	Status           string           `json:"status"`
	Trigger          string           `json:"trigger"`
	DestinationType  string           `json:"destination_type"`
	DestinationURL   string           `json:"destination_url"`
	DestinationEmail string           `json:"destination_email"`
}

type sentryAlertRecord struct {
	ID               string
	ProjectID        string
	OrganizationID   string
	ProjectSlug      string
	Name             string
	Trigger          string
	DestinationType  string
	DestinationURL   string
	DestinationEmail string
	Conditions       []byte
	Frequency        int
	Enabled          bool
	CreatedAt        string
}

func (s *Server) sentryProjectAlertRules(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if r.Method == http.MethodPost {
		if !s.canManageProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project administrator access required")
			return
		}
		s.createSentryAlertRule(w, r, principal, projectID, organizationID)
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), sentryAlertSelect+` WHERE ar.project_id = ? ORDER BY ar.created_at DESC, ar.id DESC`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list alert rules")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		record, err := scanSentryAlert(rows)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list alert rules")
			return
		}
		items = append(items, sentryAlertResponse(record))
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not list alert rules")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryProjectAlertRuleDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	record, err := s.loadSentryAlert(r, projectID, r.PathValue("rule_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "alert rule not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load alert rule")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, sentryAlertResponse(record))
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if r.Method == http.MethodDelete {
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete alert rule")
			return
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(r.Context(), `DELETE FROM alert_rules WHERE id = ? AND project_id = ?`, record.ID, projectID); err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'delete_sentry_alert_rule', 'alert_rule', ?)`, record.OrganizationID, projectID, principal.UserID, record.ID)
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete alert rule")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input sentryAlertInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	updated, err := s.sentryAlertFromInput(r, principal, input, &record)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update alert rule")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `UPDATE alert_rules SET name = ?, trigger = ?, destination_type = ?, destination_url = ?, destination_email = ?, conditions = ?, frequency_minutes = ?, enabled = ? WHERE id = ? AND project_id = ?`, updated.Name, updated.Trigger, updated.DestinationType, updated.DestinationURL, updated.DestinationEmail, updated.Conditions, updated.Frequency, boolInteger(updated.Enabled), updated.ID, projectID); err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'update_sentry_alert_rule', 'alert_rule', ?)`, updated.OrganizationID, projectID, principal.UserID, updated.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update alert rule")
		return
	}
	writeJSON(w, http.StatusOK, sentryAlertResponse(updated))
}

func (s *Server) createSentryAlertRule(w http.ResponseWriter, r *http.Request, principal *auth.Principal, projectID, organizationID string) {
	var input sentryAlertInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	record, err := s.sentryAlertFromInput(r, principal, input, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	record.ID, record.ProjectID, record.OrganizationID, record.ProjectSlug = uuid.NewString(), projectID, organizationID, r.PathValue("project_slug")
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create alert rule")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url, destination_email, conditions, frequency_minutes, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, record.ID, projectID, record.Name, record.Trigger, record.DestinationType, record.DestinationURL, record.DestinationEmail, record.Conditions, record.Frequency, boolInteger(record.Enabled)); err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'create_sentry_alert_rule', 'alert_rule', ?)`, organizationID, projectID, principal.UserID, record.ID)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create alert rule")
		return
	}
	record, err = s.loadSentryAlert(r, projectID, record.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load alert rule")
		return
	}
	writeJSON(w, http.StatusCreated, sentryAlertResponse(record))
}

func (s *Server) sentryAlertFromInput(r *http.Request, principal *auth.Principal, input sentryAlertInput, existing *sentryAlertRecord) (sentryAlertRecord, error) {
	record := sentryAlertRecord{Frequency: 30, Enabled: true}
	if existing != nil {
		record = *existing
	}
	if name := strings.TrimSpace(input.Name); name != "" {
		record.Name = name
	}
	if record.Name == "" {
		return record, errors.New("alert rule name is required")
	}
	if match := strings.ToLower(strings.TrimSpace(input.ActionMatch)); match != "" && match != "all" {
		return record, errors.New("only actionMatch=all is supported")
	}
	if match := strings.ToLower(strings.TrimSpace(input.FilterMatch)); match != "" && match != "all" {
		return record, errors.New("only filterMatch=all is supported")
	}
	if input.Frequency != nil {
		record.Frequency = *input.Frequency
	}
	if record.Frequency < 0 || record.Frequency > 10080 {
		return record, errors.New("frequency must be between 0 and 10080 minutes")
	}
	if input.Enabled != nil {
		record.Enabled = *input.Enabled
	}
	switch strings.ToLower(strings.TrimSpace(input.Status)) {
	case "disabled", "inactive":
		record.Enabled = false
	case "active", "enabled":
		record.Enabled = true
	case "":
	default:
		return record, errors.New("alert status must be active or disabled")
	}
	trigger := strings.ToLower(strings.TrimSpace(input.Trigger))
	if trigger == "" && len(input.Conditions) > 0 {
		trigger = sentryTrigger(input.Conditions)
	}
	if trigger == "" && existing == nil && len(input.Conditions) == 0 {
		trigger = "new_issue"
	}
	if len(input.Conditions) > 0 && trigger == "" {
		return record, errors.New("unsupported alert trigger")
	}
	if trigger != "" {
		record.Trigger = trigger
	}
	if !alertservice.ValidTrigger(record.Trigger) {
		return record, errors.New("unsupported alert trigger")
	}
	if existing == nil || len(input.Conditions) > 0 || len(input.Filters) > 0 || input.Environment != nil {
		conditions, err := sentryAlertConditions(input)
		if err != nil {
			return record, err
		}
		record.Conditions = conditions
	}
	destinationType, destinationURL, destinationEmail, err := s.sentryAlertDestination(r, principal, input, existing)
	if err != nil {
		return record, err
	}
	record.DestinationType, record.DestinationURL, record.DestinationEmail = destinationType, destinationURL, destinationEmail
	destination := destinationURL
	if destinationType == "email" {
		destination = destinationEmail
	}
	if err := alertservice.ValidateDestination(destinationType, destination); err != nil {
		return record, err
	}
	return record, nil
}

func sentryTrigger(conditions []map[string]any) string {
	for _, condition := range conditions {
		id := strings.ToLower(stringValue(condition["id"]))
		switch {
		case strings.Contains(id, "first_seen"):
			return "new_issue"
		case strings.Contains(id, "regression"):
			return "regression"
		case strings.Contains(id, "user_feedback"):
			return "user_feedback"
		case strings.Contains(id, "uptime"):
			return "uptime_down"
		case strings.Contains(id, "cron") || strings.Contains(id, "checkin"):
			return "cron_missed"
		case strings.Contains(id, "metric"):
			return "metric_threshold"
		}
	}
	return ""
}

func sentryAlertConditions(input sentryAlertInput) ([]byte, error) {
	normalized := make(map[string]any)
	if environment := sentryEnvironmentValue(input.Environment); environment != "" {
		normalized["environment"] = environment
	}
	filters := append(append([]map[string]any{}, input.Conditions...), input.Filters...)
	for _, filter := range filters {
		id := strings.ToLower(stringValue(filter["id"]))
		if strings.Contains(id, "tagged_event") && strings.EqualFold(stringValue(filter["key"]), "environment") {
			normalized["environment"] = stringValue(filter["value"])
		}
		if strings.Contains(id, "level") {
			levels, err := sentryLevels(stringValue(filter["level"]), stringValue(filter["match"]))
			if err != nil {
				return nil, err
			}
			normalized["levels"] = levels
		}
	}
	return json.Marshal(normalized)
}

func sentryLevels(raw, match string) ([]string, error) {
	levels := []string{"debug", "info", "warning", "error", "fatal"}
	aliases := map[string]string{"10": "debug", "20": "info", "30": "warning", "40": "error", "50": "fatal", "warn": "warning"}
	value := strings.ToLower(strings.TrimSpace(raw))
	if alias := aliases[value]; alias != "" {
		value = alias
	}
	index := -1
	for candidate, level := range levels {
		if level == value {
			index = candidate
			break
		}
	}
	if index < 0 {
		return nil, errors.New("unsupported alert level")
	}
	switch strings.ToLower(strings.TrimSpace(match)) {
	case "gte", "greater_or_equal", "":
		return levels[index:], nil
	case "eq", "equal":
		return []string{levels[index]}, nil
	default:
		return nil, errors.New("unsupported alert level comparison")
	}
}

func (s *Server) sentryAlertDestination(r *http.Request, principal *auth.Principal, input sentryAlertInput, existing *sentryAlertRecord) (string, string, string, error) {
	destinationType := strings.ToLower(strings.TrimSpace(input.DestinationType))
	destinationURL, destinationEmail := strings.TrimSpace(input.DestinationURL), strings.TrimSpace(input.DestinationEmail)
	if len(input.Actions) > 1 {
		return "", "", "", errors.New("one alert action is supported per rule")
	}
	if len(input.Actions) == 1 {
		action := input.Actions[0]
		id := strings.ToLower(stringValue(action["id"]))
		switch {
		case strings.Contains(id, "slack"):
			destinationType = "slack"
		case strings.Contains(id, "mail") || strings.Contains(id, "email"):
			destinationType = "email"
		case strings.Contains(id, "webhook") || strings.Contains(id, "notify_event"):
			destinationType = "webhook"
		default:
			return "", "", "", errors.New("unsupported alert action")
		}
		if value := firstNonEmpty(stringValue(action["url"]), stringValue(action["webhook"])); value != "" {
			destinationURL = value
		}
		if value := firstNonEmpty(stringValue(action["email"]), stringValue(action["targetIdentifier"])); strings.Contains(value, "@") {
			destinationEmail = value
		} else if destinationType == "email" && value != "" {
			_ = s.store.DB.QueryRowContext(r.Context(), `SELECT u.email FROM users u JOIN organization_memberships om ON om.user_id = u.id WHERE om.organization_id = ? AND u.id = ?`, projectOrganizationID(r, s, existing), value).Scan(&destinationEmail)
		}
	}
	if existing != nil {
		if destinationType == "" {
			destinationType = existing.DestinationType
		}
		if destinationURL == "" {
			destinationURL = existing.DestinationURL
		}
		if destinationEmail == "" {
			destinationEmail = existing.DestinationEmail
		}
	}
	if destinationType == "email" && destinationEmail == "" {
		destinationEmail = strings.TrimSpace(principal.Email)
	}
	return destinationType, destinationURL, destinationEmail, nil
}

func projectOrganizationID(r *http.Request, s *Server, existing *sentryAlertRecord) string {
	if existing != nil {
		return existing.OrganizationID
	}
	_, organizationID, _ := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	return organizationID
}

func sentryEnvironmentValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		return strings.TrimSpace(stringValue(typed["name"]))
	default:
		return ""
	}
}

const sentryAlertSelect = `
	SELECT ar.id, ar.project_id, p.organization_id, p.slug, ar.name, ar.trigger, ar.destination_type,
	       ar.destination_url, ar.destination_email, ar.conditions, ar.frequency_minutes, ar.enabled, ar.created_at
	FROM alert_rules ar JOIN projects p ON p.id = ar.project_id`

type sentryAlertScanner interface {
	Scan(dest ...any) error
}

func scanSentryAlert(scanner sentryAlertScanner) (sentryAlertRecord, error) {
	var record sentryAlertRecord
	err := scanner.Scan(&record.ID, &record.ProjectID, &record.OrganizationID, &record.ProjectSlug, &record.Name, &record.Trigger, &record.DestinationType, &record.DestinationURL, &record.DestinationEmail, &record.Conditions, &record.Frequency, &record.Enabled, &record.CreatedAt)
	return record, err
}

func (s *Server) loadSentryAlert(r *http.Request, projectID, ruleID string) (sentryAlertRecord, error) {
	return scanSentryAlert(s.store.DB.QueryRowContext(r.Context(), sentryAlertSelect+` WHERE ar.project_id = ? AND ar.id = ?`, projectID, ruleID))
}

func sentryAlertResponse(record sentryAlertRecord) map[string]any {
	var normalized map[string]any
	_ = json.Unmarshal(record.Conditions, &normalized)
	conditions := []map[string]any{{"id": sentryTriggerID(record.Trigger)}}
	filters := make([]map[string]any, 0, 2)
	if environment := stringValue(normalized["environment"]); environment != "" {
		filters = append(filters, map[string]any{"id": "sentry.rules.filters.tagged_event.TaggedEventFilter", "key": "environment", "match": "eq", "value": environment})
	}
	if levels, ok := normalized["levels"].([]any); ok && len(levels) > 0 {
		values := make([]string, 0, len(levels))
		for _, level := range levels {
			values = append(values, stringValue(level))
		}
		filters = append(filters, map[string]any{"id": "barktrace.rules.filters.levels", "levels": values})
	}
	action := map[string]any{"id": sentryActionID(record.DestinationType), "targetType": record.DestinationType}
	switch record.DestinationType {
	case "email":
		action["targetIdentifier"], action["targetDisplay"] = record.DestinationEmail, record.DestinationEmail
	default:
		action["targetIdentifier"], action["targetDisplay"] = nil, destinationHost(record.DestinationURL)
	}
	status := "active"
	if !record.Enabled {
		status = "disabled"
	}
	return map[string]any{
		"id": record.ID, "name": record.Name, "project": record.ProjectSlug, "projects": []string{record.ProjectSlug},
		"actionMatch": "all", "filterMatch": "all", "frequency": record.Frequency, "status": status,
		"conditions": conditions, "filters": filters, "actions": []map[string]any{action},
		"environment": nullableText(stringValue(normalized["environment"])), "dateCreated": normalizeAPITime(record.CreatedAt),
		"owner": nil, "createdBy": nil, "dateModified": normalizeAPITime(record.CreatedAt),
	}
}

func sentryTriggerID(trigger string) string {
	switch trigger {
	case "regression":
		return "sentry.rules.conditions.regression_event.RegressionEventCondition"
	case "user_feedback":
		return "sentry.rules.conditions.user_feedback.UserFeedbackCondition"
	case "uptime_down":
		return "barktrace.rules.conditions.uptime_down"
	case "cron_missed":
		return "barktrace.rules.conditions.cron_missed"
	case "metric_threshold":
		return "barktrace.rules.conditions.metric_threshold"
	default:
		return "sentry.rules.conditions.first_seen_event.FirstSeenEventCondition"
	}
}

func sentryActionID(destinationType string) string {
	switch destinationType {
	case "email":
		return "sentry.mail.actions.NotifyEmailAction"
	case "slack":
		return "sentry.integrations.slack.notify_action.SlackNotifyServiceAction"
	default:
		return "sentry.rules.actions.notify_event.NotifyEventAction"
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}
