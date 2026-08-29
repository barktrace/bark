package alerts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
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
