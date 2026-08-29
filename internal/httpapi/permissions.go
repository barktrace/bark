package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/barktrace/bark/internal/auth"
)

func (s *Server) projectMemberships(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT u.id, u.email, u.name, om.role, COALESCE(pm.role, ''),
		       CASE WHEN pm.role = 'none' THEN 'none'
		            WHEN pm.role != '' THEN pm.role
		            WHEN om.role IN ('owner', 'admin') THEN 'admin'
		            WHEN EXISTS (SELECT 1 FROM team_memberships tm JOIN team_projects tp ON tp.team_id = tm.team_id WHERE tm.user_id = u.id AND tp.project_id = p.id AND tp.role = 'admin') THEN 'admin'
		            WHEN om.role = 'member' OR EXISTS (SELECT 1 FROM team_memberships tm JOIN team_projects tp ON tp.team_id = tm.team_id WHERE tm.user_id = u.id AND tp.project_id = p.id AND tp.role = 'member') THEN 'member'
		            ELSE 'viewer' END
		FROM projects p
		JOIN organization_memberships om ON om.organization_id = p.organization_id
		JOIN users u ON u.id = om.user_id
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = u.id
		WHERE p.id = ? ORDER BY u.name, u.email
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list project memberships")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var userID, email, name, organizationRole, projectRole, effectiveRole string
		if rows.Scan(&userID, &email, &name, &organizationRole, &projectRole, &effectiveRole) == nil {
			items = append(items, map[string]any{"user_id": userID, "email": email, "name": name, "organization_role": organizationRole, "project_role": nullableText(projectRole), "effective_role": effectiveRole})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"memberships": items})
}

func (s *Server) updateProjectMembership(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, userID := r.PathValue("project_id"), r.PathValue("user_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	var member int
	_ = s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, organizationID, userID).Scan(&member)
	if member == 0 {
		writeError(w, http.StatusBadRequest, "user is not an organization member")
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if input.Role != "admin" && input.Role != "member" && input.Role != "viewer" && input.Role != "none" {
		writeError(w, http.StatusBadRequest, "role must be admin, member, viewer, or none")
		return
	}
	_, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO project_memberships(project_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role`, projectID, userID, input.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update project membership")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"project_id": projectID, "user_id": userID, "role": input.Role})
}

func (s *Server) deleteProjectMembership(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, userID := r.PathValue("project_id"), r.PathValue("user_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM project_memberships WHERE project_id = ? AND user_id = ?`, projectID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not remove project override")
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		writeError(w, http.StatusNotFound, "project membership override not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auditLogs(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID != "" {
		var belongs int
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM projects WHERE id = ? AND organization_id = ?`, projectID, organizationID).Scan(&belongs)
		if belongs == 0 {
			writeError(w, http.StatusBadRequest, "project does not belong to organization")
			return
		}
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT a.id, COALESCE(a.project_id, ''), COALESCE(a.actor_user_id, ''), a.actor_type, a.action, a.target_type, a.target_id, a.metadata, a.ip_address, a.created_at, COALESCE(u.email, '')
		FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id
		WHERE a.organization_id = ? AND (? = '' OR a.project_id = ?)
		ORDER BY a.id DESC LIMIT 500
	`, organizationID, projectID, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list audit logs")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var eventProjectID, actorID, actorType, action, targetType, targetID, ipAddress, createdAt, actorEmail string
		var metadata []byte
		if rows.Scan(&id, &eventProjectID, &actorID, &actorType, &action, &targetType, &targetID, &metadata, &ipAddress, &createdAt, &actorEmail) == nil {
			items = append(items, map[string]any{"id": id, "project_id": eventProjectID, "actor_user_id": actorID, "actor_email": actorEmail, "actor_type": actorType, "action": action, "target_type": targetType, "target_id": targetID, "metadata": jsonRaw(metadata), "ip_address": ipAddress, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit_logs": items})
}

func jsonRaw(value []byte) any {
	if len(value) == 0 {
		return map[string]any{}
	}
	return json.RawMessage(value)
}
