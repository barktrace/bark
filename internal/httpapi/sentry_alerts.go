package httpapi

import (
	"context"
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
	Actions          []sentryAlertAction
}

type sentryAlertAction struct {
	Type  string `json:"type"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
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
	records := make([]sentryAlertRecord, 0)
	for rows.Next() {
		record, err := scanSentryAlert(rows)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list alert rules")
			return
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, http.StatusInternalServerError, "could not list alert rules")
		return
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(records))
	for _, record := range records {
		var err error
		if record.Actions, err = s.loadSentryAlertActions(r, record.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list alert rules")
			return
		}
		items = append(items, sentryAlertResponse(record))
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
		err = replaceSentryAlertActions(r, tx, updated.ID, updated.Actions)
	}
	if err == nil {
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
		err = replaceSentryAlertActions(r, tx, record.ID, record.Actions)
	}
	if err == nil {
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
	if match := strings.ToLower(strings.TrimSpace(input.ActionMatch)); match != "" && match != "all" && match != "any" {
		return record, errors.New("actionMatch must be all or any")
	}
	if match := strings.ToLower(strings.TrimSpace(input.FilterMatch)); match != "" && match != "all" && match != "any" {
		return record, errors.New("filterMatch must be all or any")
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
	actions, err := s.sentryAlertDestinations(r, principal, input, existing)
	if err != nil {
		return record, err
	}
	for _, action := range actions {
		destination := action.URL
		if action.Type == "email" {
			destination = action.Email
		}
		if err := alertservice.ValidateDestination(action.Type, destination); err != nil {
			return record, err
		}
	}
	if len(actions) == 0 {
		return record, errors.New("at least one alert action is required")
	}
	record.DestinationType, record.DestinationURL, record.DestinationEmail = actions[0].Type, actions[0].URL, actions[0].Email
	record.Actions = actions
	conditions, err := sentryAlertMetadata(record.Conditions, input)
	if err != nil {
		return record, err
	}
	record.Conditions = conditions
	return record, nil
}

func sentryTrigger(conditions []map[string]any) string {
	triggers := sentryTriggers(conditions)
	if len(triggers) > 0 {
		return triggers[0]
	}
	return ""
}

func sentryTriggers(conditions []map[string]any) []string {
	result := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		id := strings.ToLower(stringValue(condition["id"]))
		trigger := ""
		switch {
		case strings.Contains(id, "first_seen"):
			trigger = "new_issue"
		case strings.Contains(id, "regression"):
			trigger = "regression"
		case strings.Contains(id, "user_feedback"):
			trigger = "user_feedback"
		case strings.Contains(id, "uptime"):
			trigger = "uptime_down"
		case strings.Contains(id, "cron") || strings.Contains(id, "checkin"):
			trigger = "cron_missed"
		case strings.Contains(id, "metric"):
			trigger = "metric_threshold"
		}
		if trigger != "" && !containsString(result, trigger) {
			result = append(result, trigger)
		}
	}
	return result
}

func sentryAlertConditions(input sentryAlertInput) ([]byte, error) {
	normalized := make(map[string]any)
	if match := strings.ToLower(strings.TrimSpace(input.FilterMatch)); match == "any" {
		normalized["filter_match"] = "any"
	}
	if environment := sentryEnvironmentValue(input.Environment); environment != "" {
		normalized["environment"] = environment
	}
	filters := append(append([]map[string]any{}, input.Conditions...), input.Filters...)
	for _, filter := range filters {
		id := strings.ToLower(stringValue(filter["id"]))
		if strings.Contains(id, "tagged_event") && strings.EqualFold(stringValue(filter["key"]), "environment") {
			normalized["environment"] = stringValue(filter["value"])
		} else if strings.Contains(id, "tagged_event") {
			key, value := strings.TrimSpace(stringValue(filter["key"])), stringValue(filter["value"])
			match := strings.ToLower(strings.TrimSpace(stringValue(filter["match"])))
			if key == "" || value == "" || (match != "" && match != "eq" && match != "neq" && match != "contains" && match != "not_contains" && match != "starts_with" && match != "ends_with") {
				return nil, errors.New("invalid tag filter")
			}
			tags, _ := normalized["tags"].([]map[string]string)
			normalized["tags"] = append(tags, map[string]string{"key": key, "match": firstNonEmpty(match, "eq"), "value": value})
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

func (s *Server) sentryAlertDestinations(r *http.Request, principal *auth.Principal, input sentryAlertInput, existing *sentryAlertRecord) ([]sentryAlertAction, error) {
	destinationType := strings.ToLower(strings.TrimSpace(input.DestinationType))
	destinationURL, destinationEmail := strings.TrimSpace(input.DestinationURL), strings.TrimSpace(input.DestinationEmail)
	if len(input.Actions) > 0 {
		actions := make([]sentryAlertAction, 0, len(input.Actions))
		for _, action := range input.Actions {
			destinationType, destinationURL, destinationEmail = "", "", ""
			id := strings.ToLower(stringValue(action["id"]))
			switch {
			case strings.Contains(id, "slack"):
				destinationType = "slack"
			case strings.Contains(id, "mail") || strings.Contains(id, "email"):
				destinationType = "email"
			case strings.Contains(id, "webhook") || strings.Contains(id, "notify_event"):
				destinationType = "webhook"
			default:
				return nil, errors.New("unsupported alert action")
			}
			if value := firstNonEmpty(stringValue(action["url"]), stringValue(action["webhook"])); value != "" {
				destinationURL = value
			}
			if value := firstNonEmpty(stringValue(action["email"]), stringValue(action["targetIdentifier"])); strings.Contains(value, "@") {
				destinationEmail = value
			} else if destinationType == "email" && value != "" {
				_ = s.store.DB.QueryRowContext(r.Context(), `SELECT u.email FROM users u JOIN organization_memberships om ON om.user_id = u.id WHERE om.organization_id = ? AND u.id = ?`, projectOrganizationID(r, s, existing), value).Scan(&destinationEmail)
			}
			if destinationType == "email" && destinationEmail == "" {
				destinationEmail = strings.TrimSpace(principal.Email)
			}
			actions = append(actions, sentryAlertAction{Type: destinationType, URL: destinationURL, Email: destinationEmail})
		}
		return actions, nil
	}
	if destinationType == "" && destinationURL == "" && destinationEmail == "" && existing != nil {
		if len(existing.Actions) > 0 {
			return existing.Actions, nil
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
	return []sentryAlertAction{{Type: destinationType, URL: destinationURL, Email: destinationEmail}}, nil
}

func sentryAlertMetadata(raw []byte, input sentryAlertInput) ([]byte, error) {
	var normalized map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &normalized) != nil {
		normalized = make(map[string]any)
	}
	if len(input.Conditions) > 0 {
		normalized["triggers"] = sentryTriggers(input.Conditions)
	}
	if match := strings.ToLower(strings.TrimSpace(input.ActionMatch)); match != "" {
		normalized["action_match"] = match
	} else if _, ok := normalized["action_match"]; !ok {
		normalized["action_match"] = "all"
	}
	return json.Marshal(normalized)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
	record, err := scanSentryAlert(s.store.DB.QueryRowContext(r.Context(), sentryAlertSelect+` WHERE ar.project_id = ? AND ar.id = ?`, projectID, ruleID))
	if err != nil {
		return record, err
	}
	record.Actions, err = s.loadSentryAlertActions(r, record.ID)
	return record, err
}

func (s *Server) loadSentryAlertActions(r *http.Request, ruleID string) ([]sentryAlertAction, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT destination_type, destination_url, destination_email FROM alert_rule_actions WHERE rule_id = ? ORDER BY position`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	actions := make([]sentryAlertAction, 0, 2)
	for rows.Next() {
		var action sentryAlertAction
		if err := rows.Scan(&action.Type, &action.URL, &action.Email); err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}
	return actions, rows.Err()
}

type sentryAlertExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func replaceSentryAlertActions(r *http.Request, execer sentryAlertExecer, ruleID string, actions []sentryAlertAction) error {
	if _, err := execer.ExecContext(r.Context(), `DELETE FROM alert_rule_actions WHERE rule_id = ?`, ruleID); err != nil {
		return err
	}
	for position, action := range actions {
		if _, err := execer.ExecContext(r.Context(), `INSERT INTO alert_rule_actions(rule_id, position, destination_type, destination_url, destination_email) VALUES (?, ?, ?, ?, ?)`, ruleID, position, action.Type, action.URL, action.Email); err != nil {
			return err
		}
	}
	return nil
}

func sentryAlertResponse(record sentryAlertRecord) map[string]any {
	var normalized map[string]any
	_ = json.Unmarshal(record.Conditions, &normalized)
	conditions := make([]map[string]any, 0, 2)
	if triggers, ok := normalized["triggers"].([]any); ok {
		for _, trigger := range triggers {
			conditions = append(conditions, map[string]any{"id": sentryTriggerID(stringValue(trigger))})
		}
	}
	if len(conditions) == 0 {
		conditions = append(conditions, map[string]any{"id": sentryTriggerID(record.Trigger)})
	}
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
	if tags, ok := normalized["tags"].([]any); ok {
		for _, rawTag := range tags {
			if tag, ok := rawTag.(map[string]any); ok {
				filters = append(filters, map[string]any{"id": "sentry.rules.filters.tagged_event.TaggedEventFilter", "key": stringValue(tag["key"]), "match": stringValue(tag["match"]), "value": stringValue(tag["value"])})
			}
		}
	}
	actions := make([]map[string]any, 0, len(record.Actions))
	for _, action := range record.Actions {
		actions = append(actions, sentryAlertActionResponse(action.Type, action.URL, action.Email))
	}
	if len(actions) == 0 {
		actions = append(actions, sentryAlertActionResponse(record.DestinationType, record.DestinationURL, record.DestinationEmail))
	}
	status := "active"
	if !record.Enabled {
		status = "disabled"
	}
	filterMatch := firstNonEmpty(stringValue(normalized["filter_match"]), "all")
	actionMatch := firstNonEmpty(stringValue(normalized["action_match"]), "all")
	return map[string]any{
		"id": record.ID, "name": record.Name, "project": record.ProjectSlug, "projects": []string{record.ProjectSlug},
		"actionMatch": actionMatch, "filterMatch": filterMatch, "frequency": record.Frequency, "status": status,
		"conditions": conditions, "filters": filters, "actions": actions,
		"environment": nullableText(stringValue(normalized["environment"])), "dateCreated": normalizeAPITime(record.CreatedAt),
		"owner": nil, "createdBy": nil, "dateModified": normalizeAPITime(record.CreatedAt),
	}
}

func sentryAlertActionResponse(destinationType, destinationURL, destinationEmail string) map[string]any {
	action := map[string]any{"id": sentryActionID(destinationType), "targetType": destinationType}
	if destinationType == "email" {
		action["targetIdentifier"], action["targetDisplay"] = destinationEmail, destinationEmail
	} else {
		action["targetIdentifier"], action["targetDisplay"] = nil, destinationHost(destinationURL)
	}
	return action
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
