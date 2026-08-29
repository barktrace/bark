package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestProjectRoleOverridesOrganizationRole(t *testing.T) {
	server, owner := permissionsFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/projects/project", nil)

	if role, ok := server.projectRole(request, owner, "project"); !ok || role != "admin" {
		t.Fatalf("owner inherited role = %q, %v", role, ok)
	}
	if _, err := server.store.DB.Exec(`INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'owner', 'none')`); err != nil {
		t.Fatal(err)
	}
	if role, ok := server.projectRole(request, owner, "project"); ok || role != "" {
		t.Fatalf("denied override role = %q, %v", role, ok)
	}

	member := &auth.Principal{UserID: "member", Memberships: []auth.Membership{{OrganizationID: "org", Role: "member"}}}
	if role, ok := server.projectRole(request, member, "project"); !ok || role != "member" {
		t.Fatalf("member inherited role = %q, %v", role, ok)
	}
	if _, err := server.store.DB.Exec(`INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'member', 'admin')`); err != nil {
		t.Fatal(err)
	}
	if role, ok := server.projectRole(request, member, "project"); !ok || role != "admin" {
		t.Fatalf("member override role = %q, %v", role, ok)
	}
}

func TestProjectMembershipManagementAndAuditListing(t *testing.T) {
	server, owner := permissionsFixture(t)

	update := principalRequest(t, owner, http.MethodPut, "/projects/project/memberships/member", `{"role":"viewer"}`)
	update.SetPathValue("project_id", "project")
	update.SetPathValue("user_id", "member")
	response := httptest.NewRecorder()
	server.updateProjectMembership(response, update)
	if response.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", response.Code, response.Body.String())
	}

	list := principalRequest(t, owner, http.MethodGet, "/projects/project/memberships", "")
	list.SetPathValue("project_id", "project")
	response = httptest.NewRecorder()
	server.projectMemberships(response, list)
	if response.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", response.Code, response.Body.String())
	}
	var memberships struct {
		Memberships []struct {
			UserID        string  `json:"user_id"`
			ProjectRole   *string `json:"project_role"`
			EffectiveRole string  `json:"effective_role"`
		} `json:"memberships"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &memberships); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, membership := range memberships.Memberships {
		if membership.UserID == "member" {
			found = membership.ProjectRole != nil && *membership.ProjectRole == "viewer" && membership.EffectiveRole == "viewer"
		}
	}
	if !found {
		t.Fatalf("project override missing from response: %s", response.Body.String())
	}

	if _, err := server.store.DB.Exec(`INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES ('org', 'project', 'owner', 'put /projects/{project_id}/memberships/{user_id}', 'user', 'member')`); err != nil {
		t.Fatal(err)
	}
	audit := principalRequest(t, owner, http.MethodGet, "/organizations/org/audit-logs?project_id=project", "")
	audit.SetPathValue("organization_id", "org")
	response = httptest.NewRecorder()
	server.auditLogs(response, audit)
	if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("audit status = %d body=%s", response.Code, response.Body.String())
	}

	remove := principalRequest(t, owner, http.MethodDelete, "/projects/project/memberships/member", "")
	remove.SetPathValue("project_id", "project")
	remove.SetPathValue("user_id", "member")
	response = httptest.NewRecorder()
	server.deleteProjectMembership(response, remove)
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestProjectMembershipManagementRequiresAdmin(t *testing.T) {
	server, _ := permissionsFixture(t)
	member := &auth.Principal{UserID: "member", Memberships: []auth.Membership{{OrganizationID: "org", Role: "member"}}}
	request := principalRequest(t, member, http.MethodPut, "/projects/project/memberships/owner", `{"role":"none"}`)
	request.SetPathValue("project_id", "project")
	request.SetPathValue("user_id", "owner")
	response := httptest.NewRecorder()
	server.updateProjectMembership(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestProjectListingsApplyEffectiveRolesAndNoneOverrides(t *testing.T) {
	server, _ := permissionsFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project-two', '2', 'org', 'worker', 'Worker', 'key-two');
		INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'member', 'none'), ('project-two', 'member', 'admin');
	`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member", Email: "member@example.com", Memberships: []auth.Membership{{OrganizationID: "org", OrganizationSlug: "org", OrganizationName: "Org", Role: "member"}}}

	native := principalRequest(t, member, http.MethodGet, "/projects?organization_id=org", "")
	response := httptest.NewRecorder()
	server.projects(response, native)
	if response.Code != http.StatusOK {
		t.Fatalf("native list status = %d body=%s", response.Code, response.Body.String())
	}
	var projects []struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &projects); err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].ID != "project-two" || projects[0].Role != "admin" {
		t.Fatalf("native effective project list = %#v", projects)
	}

	sentry := principalRequest(t, member, http.MethodGet, "/api/0/organizations/org/projects/", "")
	sentry.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryOrganizationProjects(response, sentry)
	if response.Code != http.StatusOK {
		t.Fatalf("Sentry list status = %d body=%s", response.Code, response.Body.String())
	}
	var sentryProjects []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &sentryProjects); err != nil {
		t.Fatal(err)
	}
	if len(sentryProjects) != 1 || sentryProjects[0].ID != "2" {
		t.Fatalf("Sentry effective project list = %#v", sentryProjects)
	}
}

func permissionsFixture(t *testing.T) (*Server, *auth.Principal) {
	t.Helper()
	st := openTestStore(t)
	_, err := st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Org');
		INSERT INTO users(id, email, name) VALUES ('owner', 'owner@example.com', 'Owner'), ('member', 'member@example.com', 'Member');
		INSERT INTO organization_memberships(organization_id, user_id, role) VALUES ('org', 'owner', 'owner'), ('org', 'member', 'member');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'key');
	`)
	if err != nil {
		t.Fatal(err)
	}
	principal := &auth.Principal{UserID: "owner", Email: "owner@example.com", Memberships: []auth.Membership{{OrganizationID: "org", Role: "owner"}}}
	return &Server{cfg: configForTest(), store: st}, principal
}
