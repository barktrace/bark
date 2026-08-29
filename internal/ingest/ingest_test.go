package ingest

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestStoreEventGroupsDuplicatesAndLinksReleases(t *testing.T) {
	t.Parallel()
	st, project := testProject(t)
	service := New(st, 20<<20)

	eventOne := []byte(`{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","message":"database unavailable","release":"api@1.0.0","timestamp":"2026-08-27T10:00:00Z"}`)
	eventTwo := []byte(`{"event_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","message":"database unavailable","release":"api@1.1.0","timestamp":"2026-08-28T10:00:00Z"}`)
	if _, err := service.StoreEvent(context.Background(), project, eventOne, ""); err != nil {
		t.Fatalf("store first event: %v", err)
	}
	if _, err := service.StoreEvent(context.Background(), project, eventOne, ""); err != nil {
		t.Fatalf("store duplicate event: %v", err)
	}
	if _, err := service.StoreEvent(context.Background(), project, eventTwo, ""); err != nil {
		t.Fatalf("store second event: %v", err)
	}

	var eventCount, issueCount, issueEvents int
	var firstRelease, lastRelease string
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM issues`).Scan(&issueCount); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`
		SELECT i.event_count, first.version, last.version
		FROM issues i
		JOIN releases first ON first.id = i.first_release_id
		JOIN releases last ON last.id = i.last_release_id
	`).Scan(&issueEvents, &firstRelease, &lastRelease); err != nil {
		t.Fatal(err)
	}
	if eventCount != 2 || issueCount != 1 || issueEvents != 2 {
		t.Fatalf("counts events=%d issues=%d issue_events=%d, want 2/1/2", eventCount, issueCount, issueEvents)
	}
	if firstRelease != "api@1.0.0" || lastRelease != "api@1.1.0" {
		t.Fatalf("release range = %q..%q", firstRelease, lastRelease)
	}
}

func TestStoreEventAcceptsGoSDKExceptionArray(t *testing.T) {
	t.Parallel()
	st, project := testProject(t)
	service := New(st, 20<<20)
	payload := []byte(`{"event_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","platform":"go","exception":[{"type":"*errors.errorString","value":"Go SDK compatibility test"}]}`)
	if _, err := service.StoreEvent(context.Background(), project, payload, ""); err != nil {
		t.Fatalf("store Go SDK event: %v", err)
	}
	var title string
	if err := st.DB.QueryRow(`SELECT title FROM issues`).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title != "*errors.errorString: Go SDK compatibility test" {
		t.Fatalf("title = %q", title)
	}
}

func TestEnvelopeAcceptsEventsAndTransactions(t *testing.T) {
	t.Parallel()
	st, _ := testProject(t)
	service := New(st, 20<<20)
	event := `{"event_id":"cccccccccccccccccccccccccccccccc","message":"boom"}`
	transaction := `{"event_id":"ffffffffffffffffffffffffffffffff","transaction":"GET /checkout","start_timestamp":1787911200.0,"timestamp":1787911200.25,"contexts":{"trace":{"trace_id":"1234","span_id":"5678","op":"http.server","status":"ok"}}}`
	body := fmt.Sprintf("{}\n{\"type\":\"event\",\"length\":%d}\n%s\n{\"type\":\"transaction\",\"length\":%d}\n%s\n", len(event), event, len(transaction), transaction)
	request := httptest.NewRequest(http.MethodPost, "/api/1/envelope/?sentry_key=public-key", bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	service.Envelope(response, request, "1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var events, transactions int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&events)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM transactions`).Scan(&transactions)
	if events != 1 || transactions != 1 {
		t.Fatalf("events=%d transactions=%d, want 1/1", events, transactions)
	}
}

func TestStoreLogsAcceptsBatchAndLinksRelease(t *testing.T) {
	t.Parallel()
	st, project := testProject(t)
	service := New(st, 20<<20)
	payload := []byte(`{"items":[{"timestamp":"2026-08-28T10:00:00Z","level":"warning","body":"queue is backing up","attributes":{"sentry.release":"api@2.0.0","sentry.environment":"production","sentry.trace_id":"abc"}},{"level":"info","message":"worker recovered"}]}`)
	count, err := service.StoreLogs(context.Background(), project, payload)
	if err != nil {
		t.Fatalf("store logs: %v", err)
	}
	if count != 2 {
		t.Fatalf("accepted logs = %d, want 2", count)
	}
	var logs, releases int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&logs)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM releases WHERE version = 'api@2.0.0'`).Scan(&releases)
	if logs != 2 || releases != 1 {
		t.Fatalf("logs=%d releases=%d, want 2/1", logs, releases)
	}
}

func TestEnvelopeAcceptsSDKContentEncodings(t *testing.T) {
	t.Parallel()
	encoders := map[string]func(io.Writer) (io.WriteCloser, error){
		"gzip":    func(w io.Writer) (io.WriteCloser, error) { return gzip.NewWriter(w), nil },
		"deflate": func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, flate.DefaultCompression) },
		"br":      func(w io.Writer) (io.WriteCloser, error) { return brotli.NewWriter(w), nil },
		"zstd":    func(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w) },
	}
	for encoding, newWriter := range encoders {
		encoding, newWriter := encoding, newWriter
		t.Run(encoding, func(t *testing.T) {
			t.Parallel()
			st, _ := testProject(t)
			service := New(st, 20<<20)
			event := `{"event_id":"dddddddddddddddddddddddddddddddd","message":"compressed event"}`
			envelope := fmt.Sprintf("{}\n{\"type\":\"event\",\"length\":%d}\n%s\n", len(event), event)
			var compressed bytes.Buffer
			writer, err := newWriter(&compressed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(envelope)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/1/envelope/?sentry_key=public-key", &compressed)
			request.Header.Set("Content-Encoding", encoding)
			response := httptest.NewRecorder()
			service.Envelope(response, request, "1")
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestIngestionRateLimitUsesSentryHeaders(t *testing.T) {
	st, _ := testProject(t)
	service := New(st, 20<<20, 1)
	payload := `{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","message":"first"}`
	for index, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodPost, "/api/1/store/?sentry_key=public-key", bytes.NewBufferString(payload))
		response := httptest.NewRecorder()
		service.Store(response, request, "1")
		if response.Code != want {
			t.Fatalf("request %d status = %d, want %d", index+1, response.Code, want)
		}
		if want == http.StatusTooManyRequests && (response.Header().Get("Retry-After") == "" || response.Header().Get("X-Sentry-Rate-Limits") == "") {
			t.Fatal("rate-limit response is missing Sentry retry headers")
		}
	}
}

func TestEnvelopeStoresSessionsAndNormalizedSpans(t *testing.T) {
	st, project := testProject(t)
	service := New(st, 20<<20)
	session := []byte(`{"sid":"session-one","did":"user-one","status":"crashed","started":"2026-08-28T10:00:00Z","errors":1,"attrs":{"release":"api@3.0.0","environment":"production"}}`)
	if err := service.StoreSession(context.Background(), project, session); err != nil {
		t.Fatalf("store session: %v", err)
	}
	transaction := []byte(`{"event_id":"12121212121212121212121212121212","transaction":"GET /orders","start_timestamp":1787911200,"timestamp":1787911200.2,"contexts":{"trace":{"trace_id":"trace-one","span_id":"root","op":"http.server","status":"ok"}},"spans":[{"trace_id":"trace-one","span_id":"db-one","parent_span_id":"root","op":"db.sql","description":"SELECT orders","start_timestamp":1787911200.01,"timestamp":1787911200.11}]}`)
	if _, err := service.StoreTransaction(context.Background(), project, transaction, ""); err != nil {
		t.Fatalf("store transaction: %v", err)
	}
	var sessions, spans int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM project_sessions WHERE status = 'crashed'`).Scan(&sessions)
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM spans WHERE trace_id = 'trace-one' AND transaction_id IS NOT NULL`).Scan(&spans)
	if sessions != 1 || spans != 1 {
		t.Fatalf("sessions=%d spans=%d, want 1/1", sessions, spans)
	}
}

func testProject(t *testing.T) (*store.Store, Project) {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'default', 'Default');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'public-key');
	`)
	if err != nil {
		t.Fatal(err)
	}
	return st, Project{ID: "project", OrganizationID: "org", PublicKey: "public-key"}
}
