package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestSentryAlertRuleLifecycle(t *testing.T) {
	server, owner := managementFixture(t)
	created := serveSentryAlert(t, server, owner, http.MethodPost, "/api/0/projects/org/app/rules/", `{
		"name":"Production errors",
		"actionMatch":"all",
		"filterMatch":"all",
		"frequency":30,
		"conditions":[{"id":"sentry.rules.conditions.first_seen_event.FirstSeenEventCondition"}],
		"filters":[
			{"id":"sentry.rules.filters.tagged_event.TaggedEventFilter","key":"environment","match":"eq","value":"production"},
			{"id":"sentry.rules.filters.level.LevelFilter","level":"40","match":"gte"}
		],
		"actions":[{"id":"sentry.mail.actions.NotifyEmailAction","targetType":"Member","targetIdentifier":"user"}]
	}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var rule map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	ruleID, _ := rule["id"].(string)
	if ruleID == "" || rule["name"] != "Production errors" || rule["status"] != "active" || rule["frequency"] != float64(30) {
		t.Fatalf("created rule = %#v", rule)
	}
	if !containsAll(created.Body.String(), `FirstSeenEventCondition`, `"value":"production"`, `"levels":["error","fatal"]`, `"targetIdentifier":"user@example.com"`) {
		t.Fatalf("created Sentry rule shape = %s", created.Body.String())
	}
	var trigger, destinationType, destinationEmail, conditions string
	if err := server.store.DB.QueryRow(`SELECT trigger, destination_type, destination_email, conditions FROM alert_rules WHERE id = ?`, ruleID).Scan(&trigger, &destinationType, &destinationEmail, &conditions); err != nil {
		t.Fatal(err)
	}
	if trigger != "new_issue" || destinationType != "email" || destinationEmail != "user@example.com" || !containsAll(conditions, `"environment":"production"`, `"levels":["error","fatal"]`) {
		t.Fatalf("stored rule trigger=%q destination=%q email=%q conditions=%s", trigger, destinationType, destinationEmail, conditions)
	}

	listed := serveSentryAlert(t, server, owner, http.MethodGet, "/api/0/projects/org/app/rules/", "")
	if listed.Code != http.StatusOK || !containsAll(listed.Body.String(), ruleID, `"name":"Production errors"`) {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	detail := serveSentryAlert(t, server, owner, http.MethodGet, "/api/0/projects/org/app/rules/"+ruleID+"/", "")
	if detail.Code != http.StatusOK || !containsAll(detail.Body.String(), `"status":"active"`, `"project":"app"`) {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}

	updated := serveSentryAlert(t, server, owner, http.MethodPut, "/api/0/projects/org/app/rules/"+ruleID+"/", `{"name":"Paused production errors","frequency":60,"status":"disabled"}`)
	if updated.Code != http.StatusOK || !containsAll(updated.Body.String(), `"name":"Paused production errors"`, `"frequency":60`, `"status":"disabled"`, `"value":"production"`, `"targetIdentifier":"user@example.com"`) {
		t.Fatalf("update status=%d body=%s", updated.Code, updated.Body.String())
	}
	if err := server.store.DB.QueryRow(`SELECT trigger, destination_email, conditions FROM alert_rules WHERE id = ?`, ruleID).Scan(&trigger, &destinationEmail, &conditions); err != nil || trigger != "new_issue" || destinationEmail != "user@example.com" || !containsAll(conditions, `"environment":"production"`) {
		t.Fatalf("preserved rule trigger=%q email=%q conditions=%s err=%v", trigger, destinationEmail, conditions, err)
	}
	reenabled := serveSentryAlert(t, server, owner, http.MethodPut, "/api/0/projects/org/app/rules/"+ruleID+"/", `{"status":"active"}`)
	if reenabled.Code != http.StatusOK || !containsAll(reenabled.Body.String(), `"status":"active"`) {
		t.Fatalf("re-enable status=%d body=%s", reenabled.Code, reenabled.Body.String())
	}

	if _, err := server.store.DB.Exec(`
		INSERT INTO users(id, email, name) VALUES ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'member', 'member')
	`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", OrganizationName: "Org", Role: "member"}}}
	if response := serveSentryAlert(t, server, member, http.MethodGet, "/api/0/projects/org/app/rules/", ""); response.Code != http.StatusOK {
		t.Fatalf("member list status=%d body=%s", response.Code, response.Body.String())
	}
	denied := serveSentryAlert(t, server, member, http.MethodPost, "/api/0/projects/org/app/rules/", `{"name":"Denied"}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("member create status=%d body=%s", denied.Code, denied.Body.String())
	}

	invalid := serveSentryAlert(t, server, owner, http.MethodPost, "/api/0/projects/org/app/rules/", `{"name":"Any filters","filterMatch":"any","destination_type":"email","destination_email":"user@example.com"}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unsupported filter match status=%d body=%s", invalid.Code, invalid.Body.String())
	}

	deleted := serveSentryAlert(t, server, owner, http.MethodDelete, "/api/0/projects/org/app/rules/"+ruleID+"/", "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	var rules, audits int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM alert_rules WHERE id = ?`, ruleID).Scan(&rules)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE target_type = 'alert_rule' AND target_id = ?`, ruleID).Scan(&audits)
	if rules != 0 || audits != 4 {
		t.Fatalf("post-delete rules=%d audits=%d", rules, audits)
	}
}

func TestSentryAlertRuleSupportsWebhookAndRejectsMultipleActions(t *testing.T) {
	server, owner := managementFixture(t)
	webhook := serveSentryAlert(t, server, owner, http.MethodPost, "/api/0/projects/org/app/rules/", `{
		"name":"Regression webhook",
		"conditions":[{"id":"sentry.rules.conditions.regression_event.RegressionEventCondition"}],
		"actions":[{"id":"sentry.rules.actions.notify_event.NotifyEventAction","url":"https://hooks.example.test/sentry"}]
	}`)
	if webhook.Code != http.StatusCreated || !containsAll(webhook.Body.String(), `RegressionEventCondition`, `"targetDisplay":"hooks.example.test"`) || containsAll(webhook.Body.String(), `hooks.example.test/sentry`) {
		t.Fatalf("webhook status=%d body=%s", webhook.Code, webhook.Body.String())
	}
	multiple := serveSentryAlert(t, server, owner, http.MethodPost, "/api/0/projects/org/app/rules/", `{
		"name":"Multiple",
		"actions":[
			{"id":"sentry.mail.actions.NotifyEmailAction","email":"user@example.com"},
			{"id":"sentry.rules.actions.notify_event.NotifyEventAction","url":"https://hooks.example.test/sentry"}
		]
	}`)
	if multiple.Code != http.StatusBadRequest {
		t.Fatalf("multiple actions status=%d body=%s", multiple.Code, multiple.Body.String())
	}
}

func serveSentryAlert(t *testing.T, server *Server, principal *auth.Principal, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := principalRequest(t, principal, method, target, body)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/rules/", server.sentryProjectAlertRules)
	mux.HandleFunc("POST /api/0/projects/{org_slug}/{project_slug}/rules/", server.sentryProjectAlertRules)
	mux.HandleFunc("GET /api/0/projects/{org_slug}/{project_slug}/rules/{rule_id}/", server.sentryProjectAlertRuleDetail)
	mux.HandleFunc("PUT /api/0/projects/{org_slug}/{project_slug}/rules/{rule_id}/", server.sentryProjectAlertRuleDetail)
	mux.HandleFunc("DELETE /api/0/projects/{org_slug}/{project_slug}/rules/{rule_id}/", server.sentryProjectAlertRuleDetail)
	mux.ServeHTTP(response, request)
	if response.Body.Len() > 0 && !json.Valid(response.Body.Bytes()) {
		t.Fatalf("invalid JSON status=%d body=%s", response.Code, response.Body.String())
	}
	return response
}
