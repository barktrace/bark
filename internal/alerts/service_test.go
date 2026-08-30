package alerts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/store"
)

func TestQueueAndDeliverWebhook(t *testing.T) {
	received := make(chan struct{}, 1)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", r.Header.Get("Content-Type"))
		}
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url) VALUES ('rule', 'project', 'New issues', 'new_issue', 'webhook', ?);
	`, destination.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := Queue(context.Background(), st.DB, "project", "new_issue", map[string]string{"title": "Boom"}); err != nil {
		t.Fatal(err)
	}
	service := New(st)
	service.client = destination.Client()
	service.deliverPending(context.Background())
	select {
	case <-received:
	default:
		t.Fatal("webhook was not called")
	}
	var status string
	if err := st.DB.QueryRow(`SELECT status FROM alert_deliveries`).Scan(&status); err != nil || status != "sent" {
		t.Fatalf("delivery status = %q, %v", status, err)
	}
}

func TestMatchesConditionsSupportsAnyAndTags(t *testing.T) {
	payload := map[string]any{"environment": "production", "level": "warning", "tags": map[string]any{"region": "eu-west-1", "tier": "api"}}
	if !matchesConditions(`{"filter_match":"any","environment":"staging","tags":[{"key":"region","match":"starts_with","value":"eu-"}]}`, payload) {
		t.Fatal("any filter did not match a tag predicate")
	}
	if matchesConditions(`{"environment":"production","tags":[{"key":"tier","match":"neq","value":"api"}]}`, payload) {
		t.Fatal("all filters matched despite a failing tag predicate")
	}
	if !matchesConditions(`{"tags":[{"key":"region","match":"contains","value":"west"},{"key":"tier","match":"eq","value":"api"}]}`, payload) {
		t.Fatal("all tag predicates should match")
	}
}

func TestQueueSupportsAnyTriggerAndMultipleActions(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
		INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_email, conditions)
		VALUES ('rule', 'project', 'Several', 'new_issue', 'email', 'first@example.com',
		'{"action_match":"any","triggers":["new_issue","regression"]}');
		INSERT INTO alert_rule_actions(rule_id, position, destination_type, destination_email)
		VALUES ('rule', 0, 'email', 'first@example.com');
		INSERT INTO alert_rule_actions(rule_id, position, destination_type, destination_url)
		VALUES ('rule', 1, 'webhook', 'https://hooks.example.test/alerts');
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := Queue(context.Background(), st.DB, "project", "regression", map[string]string{"title": "Again"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM alert_deliveries WHERE rule_id = 'rule'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("deliveries=%d err=%v", count, err)
	}
	var email, webhook int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM alert_deliveries WHERE destination_email = 'first@example.com'`).Scan(&email)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM alert_deliveries WHERE destination_url = 'https://hooks.example.test/alerts'`).Scan(&webhook)
	if email != 1 || webhook != 1 {
		t.Fatalf("email deliveries=%d webhook deliveries=%d", email, webhook)
	}
}
