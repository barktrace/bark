package auth

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/config"
	"github.com/GhaziBenDahmane/barktrace/internal/store"
)

func TestSafeReturnTo(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                               "/ui/",
		"/ui/":                           "/ui/",
		"/ui/issues?project=one":         "/ui/issues?project=one",
		"/ui-pretending-to-be-ui":        "/ui/",
		"/api/0/organizations":           "/ui/",
		"https://attacker.example/ui/":   "/ui/",
		"//attacker.example/ui/redirect": "/ui/",
	}
	for input, want := range tests {
		if got := safeReturnTo(input); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHTTPSOnlyTransport(t *testing.T) {
	t.Parallel()

	recorder := &recordingTransport{}
	transport := &httpsOnlyTransport{base: recorder, allowLoopbackHTTP: true}

	for _, raw := range []string{"https://id.example/token", "http://localhost:1411/token", "http://127.0.0.1/token", "http://[::1]/token"} {
		request := &http.Request{Method: http.MethodGet, URL: mustURL(t, raw)}
		if _, err := transport.RoundTrip(request); err != nil {
			t.Errorf("RoundTrip(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"http://id.example/token", "http://localhost.evil.example/token", "ftp://id.example/token"} {
		request := &http.Request{Method: http.MethodGet, URL: mustURL(t, raw)}
		if _, err := transport.RoundTrip(request); err == nil {
			t.Errorf("RoundTrip(%q) unexpectedly succeeded", raw)
		}
	}
	if recorder.calls != 4 {
		t.Fatalf("base transport calls = %d, want 4", recorder.calls)
	}
}

func TestHTTPSIssuerDoesNotPermitLoopbackHTTPEndpoints(t *testing.T) {
	t.Parallel()
	if err := validateEndpoint("http://localhost/token", isLoopbackHTTP("https://id.example")); err == nil {
		t.Fatal("HTTPS issuer allowed an HTTP loopback endpoint")
	}
}

func TestBearerTokenIsRestrictedToItsOrganization(t *testing.T) {
	st := openAuthStore(t)
	plain := "bark_test-token"
	hash := sha256.Sum256([]byte(plain))
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org-a', 'a', 'A'), ('org-b', 'b', 'B');
		INSERT INTO users(id, email, name) VALUES ('user', 'user@example.com', 'User');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org-a', 'user', 'owner'), ('org-b', 'user', 'admin');
		INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix) VALUES ('token', 'user', 'org-a', 'Automation', ?, 'bark_test');
	`, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	request.Header.Set("Authorization", "Bearer "+plain)
	principal, err := (&Service{store: st}).Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(principal.Memberships) != 1 || principal.Memberships[0].OrganizationID != "org-a" {
		t.Fatalf("token memberships = %#v", principal.Memberships)
	}
}

func TestProvisioningAcceptsEmailInvitation(t *testing.T) {
	st := openAuthStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('invited-org', 'invited', 'Invited');
		INSERT INTO users(id, email, name) VALUES ('owner', 'owner@example.com', 'Owner');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('invited-org', 'owner', 'owner');
		INSERT INTO organization_invitations(id, organization_id, email, role, invited_by, token_hash, expires_at)
		VALUES ('invite', 'invited-org', 'new@example.com', 'member', 'owner', X'01', ?);
	`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{store: st, cfg: config.Config{AutoProvision: true, DefaultOrgName: "Default", DefaultOrgSlug: "default"}}
	userID, err := service.findOrProvision(context.Background(), "https://id.example", claims{Subject: "subject", Email: "new@example.com", Name: "New User"})
	if err != nil {
		t.Fatal(err)
	}
	var role string
	if err := st.DB.QueryRow(`SELECT role FROM organization_memberships WHERE organization_id = 'invited-org' AND user_id = ?`, userID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "member" {
		t.Fatalf("role = %q", role)
	}
	var accepted string
	if err := st.DB.QueryRow(`SELECT accepted_at FROM organization_invitations WHERE id = 'invite'`).Scan(&accepted); err != nil || accepted == "" {
		t.Fatalf("invitation was not accepted: %q, %v", accepted, err)
	}
}

func openAuthStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

type recordingTransport struct{ calls int }

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
