package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/config"
	"github.com/barktrace/bark/internal/store"
)

func TestRouteRegistrationAndRootRedirect(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	server := New(configForTest(), st, &auth.Service{})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTemporaryRedirect || response.Header().Get("Location") != "/ui/" {
		t.Fatalf("root response = %d Location %q", response.Code, response.Header().Get("Location"))
	}
}

func TestDSNURL(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://errors.example":      "https://publickey@errors.example/project-id",
		"https://errors.example/base": "https://publickey@errors.example/base/project-id",
		"invalid":                     "",
	}
	for publicURL, want := range tests {
		if got := dsnURL(publicURL, "publickey", "project-id"); got != want {
			t.Errorf("dsnURL(%q) = %q, want %q", publicURL, got, want)
		}
	}
}

func TestCanAccessProjectUsesOrganizationMembership(t *testing.T) {
	t.Parallel()
	st := openTestStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org-a', 'a', 'A'), ('org-b', 'b', 'B');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project-a', '1', 'org-a', 'app', 'App', 'key');
	`)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: st}
	request := httptest.NewRequest("GET", "/issues", nil)
	allowed := &auth.Principal{Memberships: []auth.Membership{{OrganizationID: "org-a", Role: "member"}}}
	denied := &auth.Principal{Memberships: []auth.Membership{{OrganizationID: "org-b", Role: "owner"}}}
	if !server.canAccessProject(request, allowed, "project-a") {
		t.Fatal("organization member was denied project access")
	}
	if server.canAccessProject(request, denied, "project-a") {
		t.Fatal("member of another organization was granted project access")
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func configForTest() config.Config {
	return config.Config{PublicURL: "https://errors.example", MaxEnvelopeBytes: 20 << 20}
}
