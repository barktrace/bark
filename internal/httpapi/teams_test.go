package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/barktrace/bark/internal/auth"
)

func TestTeamLifecycleMembershipProjectRoleAndAudit(t *testing.T) {
	server, owner := permissionsFixture(t)

	create := principalRequest(t, owner, http.MethodPost, "/organizations/org/teams", `{"name":"Backend Responders","slug":"backend"}`)
	create.SetPathValue("organization_id", "org")
	response := httptest.NewRecorder()
	server.organizationTeams(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create team status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		Slug     string `json:"slug"`
		IsMember bool   `json:"is_member"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == "" || created.Slug != "backend" || !created.IsMember {
		t.Fatalf("created team=%#v err=%v", created, err)
	}

	addMember := principalRequest(t, owner, http.MethodPut, "/teams/"+created.ID+"/members/member", "")
	addMember.SetPathValue("team_id", created.ID)
	addMember.SetPathValue("user_id", "member")
	response = httptest.NewRecorder()
	server.updateTeamMember(response, addMember)
	if response.Code != http.StatusOK {
		t.Fatalf("add member status=%d body=%s", response.Code, response.Body.String())
	}

	link := principalRequest(t, owner, http.MethodPut, "/teams/"+created.ID+"/projects/project", `{"role":"admin"}`)
	link.SetPathValue("team_id", created.ID)
	link.SetPathValue("project_id", "project")
	response = httptest.NewRecorder()
	server.updateTeamProject(response, link)
	if response.Code != http.StatusOK {
		t.Fatalf("link project status=%d body=%s", response.Code, response.Body.String())
	}

	member := &auth.Principal{UserID: "member", Memberships: []auth.Membership{{OrganizationID: "org", Role: "member"}}}
	request := httptest.NewRequest(http.MethodGet, "/projects/project", nil)
	if role, ok := server.projectRole(request, member, "project"); !ok || role != "admin" {
		t.Fatalf("team-derived project role=%q allowed=%v", role, ok)
	}

	if _, err := server.store.DB.Exec(`INSERT INTO project_memberships(project_id, user_id, role) VALUES ('project', 'member', 'none')`); err != nil {
		t.Fatal(err)
	}
	if role, ok := server.projectRole(request, member, "project"); ok || role != "" {
		t.Fatalf("explicit deny must override team role: role=%q allowed=%v", role, ok)
	}

	members := principalRequest(t, member, http.MethodGet, "/teams/"+created.ID+"/members", "")
	members.SetPathValue("team_id", created.ID)
	response = httptest.NewRecorder()
	server.teamMembers(response, members)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"id":"owner"`, `"id":"member"`) {
		t.Fatalf("team members status=%d body=%s", response.Code, response.Body.String())
	}
	projects := principalRequest(t, member, http.MethodGet, "/teams/"+created.ID+"/projects", "")
	projects.SetPathValue("team_id", created.ID)
	response = httptest.NewRecorder()
	server.teamProjects(response, projects)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"id":"project"`, `"role":"admin"`) {
		t.Fatalf("team projects status=%d body=%s", response.Code, response.Body.String())
	}

	var audits int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE target_type IN ('team', 'user', 'project')`).Scan(&audits); err != nil || audits != 3 {
		t.Fatalf("team audit count=%d err=%v", audits, err)
	}
}

func TestTeamManagementRequiresOrganizationAdminAndIsolation(t *testing.T) {
	server, owner := permissionsFixture(t)
	if _, err := server.store.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('other-org', 'other', 'Other');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('other-project', '2', 'other-org', 'other-app', 'Other App', 'other-key');
		INSERT INTO teams(id, organization_id, slug, name) VALUES ('team', 'org', 'backend', 'Backend');
	`); err != nil {
		t.Fatal(err)
	}
	member := &auth.Principal{UserID: "member", Memberships: []auth.Membership{{OrganizationID: "org", Role: "member"}}}
	denied := principalRequest(t, member, http.MethodPost, "/organizations/org/teams", `{"name":"Nope"}`)
	denied.SetPathValue("organization_id", "org")
	response := httptest.NewRecorder()
	server.organizationTeams(response, denied)
	if response.Code != http.StatusForbidden {
		t.Fatalf("member create status=%d body=%s", response.Code, response.Body.String())
	}

	crossOrg := principalRequest(t, owner, http.MethodPut, "/teams/team/projects/other-project", `{"role":"member"}`)
	crossOrg.SetPathValue("team_id", "team")
	crossOrg.SetPathValue("project_id", "other-project")
	response = httptest.NewRecorder()
	server.updateTeamProject(response, crossOrg)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("cross-organization link status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSentryTeamsAndTeamIssueAssignment(t *testing.T) {
	server, owner := managementFixture(t)

	create := principalRequest(t, owner, http.MethodPost, "/api/0/organizations/org/teams/", `{"name":"Backend","slug":"backend"}`)
	create.SetPathValue("org_slug", "org")
	response := httptest.NewRecorder()
	server.sentryOrganizationTeams(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("Sentry create team status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("Sentry team response=%s err=%v", response.Body.String(), err)
	}

	link := principalRequest(t, owner, http.MethodPost, "/api/0/teams/org/backend/projects/app/", "")
	link.SetPathValue("org_slug", "org")
	link.SetPathValue("team_slug", "backend")
	link.SetPathValue("project_slug", "app")
	response = httptest.NewRecorder()
	server.sentryTeamProjects(response, link)
	if response.Code != http.StatusCreated {
		t.Fatalf("Sentry team project link status=%d body=%s", response.Code, response.Body.String())
	}
	projects := principalRequest(t, owner, http.MethodGet, "/api/0/teams/org/backend/projects/", "")
	projects.SetPathValue("org_slug", "org")
	projects.SetPathValue("team_slug", "backend")
	response = httptest.NewRecorder()
	server.sentryTeamProjects(response, projects)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"id":"1"`, `"slug":"app"`) {
		t.Fatalf("Sentry team projects status=%d body=%s", response.Code, response.Body.String())
	}

	var legacyID int64
	if err := server.store.DB.QueryRow(`SELECT rowid FROM issues WHERE id = 'issue'`).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	target := "/api/0/issues/" + strconv.FormatInt(legacyID, 10) + "/"
	assigned := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"assignedTo":"team:`+created.ID+`"}`)
	if assigned.Code != http.StatusOK || !containsAll(assigned.Body.String(), `"type":"team"`, `"slug":"backend"`, `"name":"Backend"`) {
		t.Fatalf("team assignment status=%d body=%s", assigned.Code, assigned.Body.String())
	}
	var teamID string
	if err := server.store.DB.QueryRow(`SELECT COALESCE(assignee_team_id, '') FROM issues WHERE id = 'issue'`).Scan(&teamID); err != nil || teamID != created.ID {
		t.Fatalf("stored team assignment=%q err=%v", teamID, err)
	}
	unlink := principalRequest(t, owner, http.MethodDelete, "/api/0/teams/org/backend/projects/app/", "")
	unlink.SetPathValue("org_slug", "org")
	unlink.SetPathValue("team_slug", "backend")
	unlink.SetPathValue("project_slug", "app")
	response = httptest.NewRecorder()
	server.sentryTeamProjects(response, unlink)
	if response.Code != http.StatusNoContent {
		t.Fatalf("Sentry team project unlink status=%d body=%s", response.Code, response.Body.String())
	}
	if err := server.store.DB.QueryRow(`SELECT COALESCE(assignee_team_id, '') FROM issues WHERE id = 'issue'`).Scan(&teamID); err != nil || teamID != "" {
		t.Fatalf("assignment after unlink=%q err=%v", teamID, err)
	}
	link = principalRequest(t, owner, http.MethodPost, "/api/0/teams/org/backend/projects/app/", "")
	link.SetPathValue("org_slug", "org")
	link.SetPathValue("team_slug", "backend")
	link.SetPathValue("project_slug", "app")
	response = httptest.NewRecorder()
	server.sentryTeamProjects(response, link)
	if response.Code != http.StatusCreated {
		t.Fatalf("Sentry relink team project status=%d body=%s", response.Code, response.Body.String())
	}

	cleared := serveSentryDetail(t, server, owner, http.MethodPut, target, `{"assignedTo":null}`)
	if cleared.Code != http.StatusOK || !containsAll(cleared.Body.String(), `"assignedTo":null`) {
		t.Fatalf("clear team assignment status=%d body=%s", cleared.Code, cleared.Body.String())
	}

	list := principalRequest(t, owner, http.MethodGet, "/api/0/organizations/org/teams/", "")
	list.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryOrganizationTeams(response, list)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"slug":"backend"`, `"isMember":true`, `"memberCount":1`) {
		t.Fatalf("Sentry team list status=%d body=%s", response.Code, response.Body.String())
	}
	members := principalRequest(t, owner, http.MethodGet, "/api/0/organizations/org/members/", "")
	members.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryOrganizationMembers(response, members)
	if response.Code != http.StatusOK || !containsAll(response.Body.String(), `"email":"user@example.com"`, `"slug":"backend"`) {
		t.Fatalf("Sentry member list status=%d body=%s", response.Code, response.Body.String())
	}
}
