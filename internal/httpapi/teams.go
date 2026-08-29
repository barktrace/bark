package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type teamRecord struct {
	ID             string
	OrganizationID string
	Slug           string
	Name           string
	CreatedAt      string
	MemberCount    int
	ProjectCount   int
	IsMember       bool
}

type organizationMemberRecord struct {
	ID        string
	Email     string
	Name      string
	AvatarURL string
	Role      string
	CreatedAt string
}

func (s *Server) organizationTeams(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	if r.Method == http.MethodPost {
		s.createTeam(w, r, principal, organizationID, false)
		return
	}
	teams, err := s.loadTeams(r.Context(), organizationID, principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list teams")
		return
	}
	items := make([]map[string]any, 0, len(teams))
	for _, team := range teams {
		items = append(items, nativeTeamResponse(team))
	}
	writeJSON(w, http.StatusOK, map[string]any{"teams": items})
}

func (s *Server) teamDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamByID(r.Context(), r.PathValue("team_id"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	if _, ok := principal.Membership(team.OrganizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, nativeTeamResponse(team))
	case http.MethodPatch:
		s.updateTeam(w, r, principal, team, false)
	case http.MethodDelete:
		s.deleteTeam(w, r, principal, team)
	}
}

func (s *Server) teamMembers(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamByID(r.Context(), r.PathValue("team_id"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil || !hasOrganization(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), tm.created_at
		FROM team_memberships tm JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = ? ORDER BY u.name, u.email
	`, team.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list team members")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, email, name, avatarURL, createdAt string
		if rows.Scan(&id, &email, &name, &avatarURL, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "email": email, "name": name, "avatar_url": avatarURL, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": items})
}

func (s *Server) updateTeamMember(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamByID(r.Context(), r.PathValue("team_id"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil || !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	userID := r.PathValue("user_id")
	var member int
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, team.OrganizationID, userID).Scan(&member); err != nil || member == 0 {
		writeError(w, http.StatusBadRequest, "user is not an organization member")
		return
	}
	if r.Method == http.MethodDelete {
		result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM team_memberships WHERE team_id = ? AND user_id = ?`, team.ID, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not remove team member")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "team membership not found")
			return
		}
		s.auditTeamMutation(r.Context(), principal.UserID, team, "remove_team_member", "user", userID, "")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO team_memberships(team_id, user_id) VALUES (?, ?) ON CONFLICT(team_id, user_id) DO NOTHING`, team.ID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not add team member")
		return
	}
	s.auditTeamMutation(r.Context(), principal.UserID, team, "add_team_member", "user", userID, "")
	writeJSON(w, http.StatusOK, map[string]string{"team_id": team.ID, "user_id": userID})
}

func (s *Server) teamProjects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamByID(r.Context(), r.PathValue("team_id"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil || !hasOrganization(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT p.id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), tp.role
		FROM team_projects tp JOIN projects p ON p.id = tp.project_id
		WHERE tp.team_id = ? ORDER BY p.name
	`, team.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list team projects")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, sentryID, projectSlug, name, platform, role string
		if rows.Scan(&id, &sentryID, &projectSlug, &name, &platform, &role) == nil {
			items = append(items, map[string]any{"id": id, "sentry_id": sentryID, "slug": projectSlug, "name": name, "platform": platform, "role": role})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": items})
}

func (s *Server) updateTeamProject(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamByID(r.Context(), r.PathValue("team_id"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil || !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	projectID := r.PathValue("project_id")
	var projectOrganizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&projectOrganizationID); err != nil || projectOrganizationID != team.OrganizationID {
		writeError(w, http.StatusBadRequest, "project does not belong to the team organization")
		return
	}
	if r.Method == http.MethodDelete {
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not unlink team project")
			return
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(r.Context(), `DELETE FROM team_projects WHERE team_id = ? AND project_id = ?`, team.ID, projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not unlink team project")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "team project link not found")
			return
		}
		_, err = tx.ExecContext(r.Context(), `UPDATE issues SET assignee_team_id = NULL WHERE project_id = ? AND assignee_team_id = ?`, projectID, team.ID)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'unlink_team_project', 'project', ?)`, team.OrganizationID, projectID, principal.UserID, projectID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not record team project unlink")
			return
		}
		if err := tx.Commit(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not commit team project unlink")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if input.Role == "" {
		input.Role = "member"
	}
	if !projectTeamRole(input.Role) {
		writeError(w, http.StatusBadRequest, "role must be admin, member, or viewer")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO team_projects(team_id, project_id, role) VALUES (?, ?, ?) ON CONFLICT(team_id, project_id) DO UPDATE SET role = excluded.role`, team.ID, projectID, input.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "could not link team project")
		return
	}
	s.auditTeamMutation(r.Context(), principal.UserID, team, "link_team_project", "project", projectID, projectID)
	writeJSON(w, http.StatusOK, map[string]string{"team_id": team.ID, "project_id": projectID, "role": input.Role})
}

func (s *Server) sentryOrganizationTeams(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	if r.Method == http.MethodPost {
		s.createTeam(w, r, principal, organizationID, true)
		return
	}
	teams, err := s.loadTeams(r.Context(), organizationID, principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list teams")
		return
	}
	items := make([]map[string]any, 0, len(teams))
	for _, team := range teams {
		items = append(items, sentryTeamResponse(team))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	memberID := strings.TrimSpace(r.PathValue("member_id"))
	query := `
		SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), om.role, om.created_at
		FROM organization_memberships om JOIN users u ON u.id = om.user_id
		WHERE om.organization_id = ?`
	arguments := []any{organizationID}
	if memberID != "" {
		query += ` AND u.id = ?`
		arguments = append(arguments, memberID)
	}
	query += ` ORDER BY u.name, u.email LIMIT 100`
	rows, err := s.store.DB.QueryContext(r.Context(), query, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list organization members")
		return
	}
	members := make([]organizationMemberRecord, 0)
	for rows.Next() {
		var member organizationMemberRecord
		if err := rows.Scan(&member.ID, &member.Email, &member.Name, &member.AvatarURL, &member.Role, &member.CreatedAt); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list organization members")
			return
		}
		members = append(members, member)
	}
	_ = rows.Close()
	if memberID != "" && len(members) == 0 {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	items := make([]map[string]any, 0, len(members))
	for _, member := range members {
		teams, err := s.memberTeamSummaries(r.Context(), organizationID, member.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list member teams")
			return
		}
		item := map[string]any{
			"id": member.ID, "email": member.Email, "name": member.Name,
			"user": map[string]any{"id": member.ID, "email": member.Email, "name": member.Name, "username": member.Email, "isActive": true, "avatarUrl": nullableText(member.AvatarURL)},
			"role": member.Role, "orgRole": member.Role, "roleName": member.Role,
			"dateCreated": normalizeAPITime(member.CreatedAt), "pending": false, "expired": false,
			"teams": teams,
		}
		items = append(items, item)
	}
	if memberID != "" {
		writeJSON(w, http.StatusOK, items[0])
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) memberTeamSummaries(ctx context.Context, organizationID, userID string) ([]map[string]any, error) {
	rows, err := s.store.DB.QueryContext(ctx, `SELECT t.id, t.slug, t.name FROM team_memberships tm JOIN teams t ON t.id = tm.team_id WHERE t.organization_id = ? AND tm.user_id = ? ORDER BY t.name`, organizationID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, teamSlug, name string
		if err := rows.Scan(&id, &teamSlug, &name); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "slug": teamSlug, "name": name})
	}
	return items, rows.Err()
}

func (s *Server) sentryTeamDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamBySlugs(r.Context(), r.PathValue("org_slug"), r.PathValue("team_slug"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hasOrganization(principal, team.OrganizationID)) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, sentryTeamResponse(team))
	case http.MethodPut:
		s.updateTeam(w, r, principal, team, true)
	case http.MethodDelete:
		s.deleteTeam(w, r, principal, team)
	}
}

func (s *Server) sentryTeamProjects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamBySlugs(r.Context(), r.PathValue("org_slug"), r.PathValue("team_slug"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hasOrganization(principal, team.OrganizationID)) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	if r.Method == http.MethodGet {
		rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.sentry_id, p.slug, p.name, COALESCE(p.platform, '') FROM team_projects tp JOIN projects p ON p.id = tp.project_id WHERE tp.team_id = ? ORDER BY p.name`, team.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list team projects")
			return
		}
		defer rows.Close()
		items := make([]map[string]any, 0)
		for rows.Next() {
			var id, projectSlug, name, platform string
			if rows.Scan(&id, &projectSlug, &name, &platform) == nil {
				items = append(items, map[string]any{"id": id, "slug": projectSlug, "name": name, "platform": platform})
			}
		}
		writeJSON(w, http.StatusOK, items)
		return
	}
	if !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	request := r.Clone(r.Context())
	request.SetPathValue("team_id", team.ID)
	request.SetPathValue("project_id", projectID)
	if r.Method == http.MethodPost {
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not link team project")
			return
		}
		defer tx.Rollback()
		result, execErr := tx.ExecContext(r.Context(), `INSERT INTO team_projects(team_id, project_id, role) VALUES (?, ?, 'member') ON CONFLICT(team_id, project_id) DO NOTHING`, team.ID, projectID)
		err = execErr
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, 'link_team_project', 'project', ?)`, team.OrganizationID, projectID, principal.UserID, projectID)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not link team project")
			return
		}
		if err := tx.Commit(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not commit team project link")
			return
		}
		if affected, _ := result.RowsAffected(); affected > 0 {
			team.ProjectCount++
		}
		writeJSON(w, http.StatusCreated, sentryTeamResponse(team))
		return
	}
	s.updateTeamProject(w, request)
}

func (s *Server) sentryTeamMembers(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamBySlugs(r.Context(), r.PathValue("org_slug"), r.PathValue("team_slug"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hasOrganization(principal, team.OrganizationID)) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), tm.created_at FROM team_memberships tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = ? ORDER BY u.name, u.email`, team.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list team members")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, email, name, avatarURL, createdAt string
		if rows.Scan(&id, &email, &name, &avatarURL, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "email": email, "name": name, "username": email, "dateCreated": normalizeAPITime(createdAt), "isActive": true, "avatarUrl": nullableText(avatarURL)})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationMemberTeam(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	team, err := s.loadTeamBySlugs(r.Context(), r.PathValue("org_slug"), r.PathValue("team_slug"), principal.UserID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !hasOrganization(principal, team.OrganizationID)) {
		writeError(w, http.StatusNotFound, "team not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	if !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	request := r.Clone(r.Context())
	request.SetPathValue("team_id", team.ID)
	request.SetPathValue("user_id", r.PathValue("member_id"))
	if r.Method == http.MethodPost {
		request.Method = http.MethodPut
	}
	s.updateTeamMember(w, request)
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request, principal *auth.Principal, organizationID string, sentry bool) {
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = slug(firstNonEmpty(input.Slug, input.Name))
	if input.Name == "" || input.Slug == "" {
		writeError(w, http.StatusBadRequest, "team name and slug are required")
		return
	}
	team := teamRecord{ID: uuid.NewString(), OrganizationID: organizationID, Slug: input.Slug, Name: input.Name, IsMember: true, MemberCount: 1}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create team")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO teams(id, organization_id, slug, name) VALUES (?, ?, ?, ?)`, team.ID, organizationID, team.Slug, team.Name); err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO team_memberships(team_id, user_id) VALUES (?, ?)`, team.ID, principal.UserID)
	}
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, 'create_team', 'team', ?)`, organizationID, principal.UserID, team.ID)
	}
	if err != nil {
		writeError(w, http.StatusConflict, "team slug already exists")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit team creation")
		return
	}
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT created_at FROM teams WHERE id = ?`, team.ID).Scan(&team.CreatedAt); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load team")
		return
	}
	if sentry {
		writeJSON(w, http.StatusCreated, sentryTeamResponse(team))
	} else {
		writeJSON(w, http.StatusCreated, nativeTeamResponse(team))
	}
}

func (s *Server) updateTeam(w http.ResponseWriter, r *http.Request, principal *auth.Principal, team teamRecord, sentry bool) {
	if !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input struct {
		Name *string `json:"name"`
		Slug *string `json:"slug"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if input.Name != nil {
		team.Name = strings.TrimSpace(*input.Name)
	}
	if input.Slug != nil {
		team.Slug = slug(*input.Slug)
	}
	if team.Name == "" || team.Slug == "" {
		writeError(w, http.StatusBadRequest, "team name and slug are required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE teams SET name = ?, slug = ? WHERE id = ?`, team.Name, team.Slug, team.ID); err != nil {
		writeError(w, http.StatusConflict, "team slug already exists")
		return
	}
	s.auditTeamMutation(r.Context(), principal.UserID, team, "update_team", "team", team.ID, "")
	if sentry {
		writeJSON(w, http.StatusOK, sentryTeamResponse(team))
	} else {
		writeJSON(w, http.StatusOK, nativeTeamResponse(team))
	}
}

func (s *Server) deleteTeam(w http.ResponseWriter, r *http.Request, principal *auth.Principal, team teamRecord) {
	if !organizationAdmin(principal, team.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete team")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, 'delete_team', 'team', ?)`, team.OrganizationID, principal.UserID, team.ID); err == nil {
		_, err = tx.ExecContext(r.Context(), `DELETE FROM teams WHERE id = ?`, team.ID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete team")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit team deletion")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadTeams(ctx context.Context, organizationID, userID string) ([]teamRecord, error) {
	rows, err := s.store.DB.QueryContext(ctx, `
		SELECT t.id, t.organization_id, t.slug, t.name, t.created_at,
		       (SELECT COUNT(*) FROM team_memberships tm WHERE tm.team_id = t.id),
		       (SELECT COUNT(*) FROM team_projects tp WHERE tp.team_id = t.id),
		       CASE WHEN EXISTS (SELECT 1 FROM team_memberships tm WHERE tm.team_id = t.id AND tm.user_id = ?) THEN 1 ELSE 0 END
		FROM teams t WHERE t.organization_id = ? ORDER BY t.name, t.slug LIMIT 100
	`, userID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]teamRecord, 0)
	for rows.Next() {
		var team teamRecord
		if err := rows.Scan(&team.ID, &team.OrganizationID, &team.Slug, &team.Name, &team.CreatedAt, &team.MemberCount, &team.ProjectCount, &team.IsMember); err != nil {
			return nil, err
		}
		items = append(items, team)
	}
	return items, rows.Err()
}

func (s *Server) loadTeamByID(ctx context.Context, teamID, userID string) (teamRecord, error) {
	return s.loadTeam(ctx, `t.id = ?`, teamID, userID)
}

func (s *Server) loadTeamBySlugs(ctx context.Context, organizationSlug, teamSlug, userID string) (teamRecord, error) {
	return s.loadTeam(ctx, `o.slug = ? AND t.slug = ?`, organizationSlug, teamSlug, userID)
}

func (s *Server) loadTeam(ctx context.Context, predicate string, args ...string) (teamRecord, error) {
	var team teamRecord
	userID := args[len(args)-1]
	queryArgs := make([]any, 0, len(args))
	queryArgs = append(queryArgs, userID)
	for _, argument := range args[:len(args)-1] {
		queryArgs = append(queryArgs, argument)
	}
	err := s.store.DB.QueryRowContext(ctx, `
		SELECT t.id, t.organization_id, t.slug, t.name, t.created_at,
		       (SELECT COUNT(*) FROM team_memberships tm WHERE tm.team_id = t.id),
		       (SELECT COUNT(*) FROM team_projects tp WHERE tp.team_id = t.id),
		       CASE WHEN EXISTS (SELECT 1 FROM team_memberships tm WHERE tm.team_id = t.id AND tm.user_id = ?) THEN 1 ELSE 0 END
		FROM teams t JOIN organizations o ON o.id = t.organization_id WHERE `+predicate, queryArgs...).Scan(
		&team.ID, &team.OrganizationID, &team.Slug, &team.Name, &team.CreatedAt,
		&team.MemberCount, &team.ProjectCount, &team.IsMember,
	)
	return team, err
}

func nativeTeamResponse(team teamRecord) map[string]any {
	return map[string]any{"id": team.ID, "organization_id": team.OrganizationID, "slug": team.Slug, "name": team.Name, "created_at": team.CreatedAt, "member_count": team.MemberCount, "project_count": team.ProjectCount, "is_member": team.IsMember}
}

func sentryTeamResponse(team teamRecord) map[string]any {
	return map[string]any{
		"id": team.ID, "slug": team.Slug, "name": team.Name,
		"dateCreated": normalizeAPITime(team.CreatedAt), "isMember": team.IsMember,
		"memberCount": team.MemberCount, "hasAccess": true, "teamRole": nil,
		"flags":  map[string]bool{"idp:provisioned": false},
		"avatar": map[string]any{"avatarType": "letter_avatar", "avatarUuid": nil},
	}
}

func hasOrganization(principal *auth.Principal, organizationID string) bool {
	if principal == nil {
		return false
	}
	_, ok := principal.Membership(organizationID)
	return ok
}

func projectTeamRole(role string) bool {
	return role == "admin" || role == "member" || role == "viewer"
}

func (s *Server) auditTeamMutation(ctx context.Context, actorID string, team teamRecord, action, targetType, targetID, projectID string) {
	var project any
	if projectID != "" {
		project = projectID
	}
	_, _ = s.store.DB.ExecContext(ctx, `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, ?, ?, ?, ?)`, team.OrganizationID, project, actorID, action, targetType, targetID)
}
