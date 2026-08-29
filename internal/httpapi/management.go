package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) organizationMembers(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT u.id, u.email, u.name, COALESCE(u.avatar_url, ''), m.role, m.created_at
		FROM organization_memberships m JOIN users u ON u.id = m.user_id
		WHERE m.organization_id = ? ORDER BY u.name, u.email
	`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list members")
		return
	}
	members := make([]map[string]any, 0)
	for rows.Next() {
		var id, email, name, avatarURL, role, createdAt string
		if err := rows.Scan(&id, &email, &name, &avatarURL, &role, &createdAt); err == nil {
			members = append(members, map[string]any{"id": id, "email": email, "name": name, "avatar_url": avatarURL, "role": role, "created_at": createdAt})
		}
	}
	_ = rows.Close()
	invitationRows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, email, role, expires_at, created_at FROM organization_invitations WHERE organization_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY created_at DESC`, organizationID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list invitations")
		return
	}
	defer invitationRows.Close()
	invitations := make([]map[string]any, 0)
	for invitationRows.Next() {
		var id, email, role, expiresAt, createdAt string
		if err := invitationRows.Scan(&id, &email, &role, &expiresAt, &createdAt); err == nil {
			invitations = append(invitations, map[string]any{"id": id, "email": email, "role": role, "expires_at": expiresAt, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members, "invitations": invitations})
}

func (s *Server) createInvitation(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Email, input.Role = strings.ToLower(strings.TrimSpace(input.Email)), strings.ToLower(strings.TrimSpace(input.Role))
	if !strings.Contains(input.Email, "@") || !memberRole(input.Role, false) {
		writeError(w, http.StatusBadRequest, "valid email and role are required")
		return
	}
	var userID string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM users WHERE email = ? COLLATE NOCASE`, input.Email).Scan(&userID)
	if err == nil {
		_, err = s.store.DB.ExecContext(r.Context(), `INSERT INTO organization_memberships(organization_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT(organization_id, user_id) DO UPDATE SET role = excluded.role`, organizationID, userID, input.Role)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not add member")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"status": "joined", "user_id": userID, "email": input.Email, "role": input.Role})
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not check user")
		return
	}
	plain, err := secureToken("invite_", 32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create invitation")
		return
	}
	id := uuid.NewString()
	expires := time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err = s.store.DB.ExecContext(r.Context(), `
		INSERT INTO organization_invitations(id, organization_id, email, role, invited_by, token_hash, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(organization_id, email) WHERE accepted_at IS NULL DO UPDATE SET role = excluded.role, invited_by = excluded.invited_by, token_hash = excluded.token_hash, expires_at = excluded.expires_at, created_at = CURRENT_TIMESTAMP
	`, id, organizationID, input.Email, input.Role, principal.UserID, hashToken(plain), expires)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create invitation")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "pending", "id": id, "email": input.Email, "role": input.Role, "expires_at": expires, "message": "The member will join automatically after signing in with this email through SSO."})
}

func (s *Server) deleteInvitation(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM organization_invitations WHERE id = ? AND organization_id = ? AND accepted_at IS NULL`, r.PathValue("invitation_id"), organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke invitation")
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		writeError(w, http.StatusNotFound, "invitation not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateMember(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, userID := r.PathValue("organization_id"), r.PathValue("user_id")
	membership, ok := principal.Membership(organizationID)
	if !ok || (membership.Role != "owner" && membership.Role != "admin") {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if !memberRole(input.Role, membership.Role == "owner") {
		writeError(w, http.StatusBadRequest, "invalid member role")
		return
	}
	var currentRole string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT role FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, organizationID, userID).Scan(&currentRole); err != nil {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	if currentRole == "owner" && membership.Role != "owner" {
		writeError(w, http.StatusForbidden, "only an owner can change another owner")
		return
	}
	if currentRole == "owner" && input.Role != "owner" && lastOwner(s.store.DB, organizationID) {
		writeError(w, http.StatusConflict, "organization must keep at least one owner")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE organization_memberships SET role = ? WHERE organization_id = ? AND user_id = ?`, input.Role, organizationID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update member")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": userID, "role": input.Role})
}

func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, userID := r.PathValue("organization_id"), r.PathValue("user_id")
	membership, ok := principal.Membership(organizationID)
	if !ok || (membership.Role != "owner" && membership.Role != "admin") {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var targetRole string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT role FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, organizationID, userID).Scan(&targetRole); err != nil {
		writeError(w, http.StatusNotFound, "member not found")
		return
	}
	if targetRole == "owner" && (membership.Role != "owner" || lastOwner(s.store.DB, organizationID)) {
		writeError(w, http.StatusConflict, "organization must keep at least one owner")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM organization_memberships WHERE organization_id = ? AND user_id = ?`, organizationID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not remove member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, organization_id, name, token_prefix, COALESCE(expires_at, ''), COALESCE(last_used_at, ''), created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`, principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list API tokens")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, organizationID, name, prefix, expiresAt, lastUsedAt, createdAt string
		if err := rows.Scan(&id, &organizationID, &name, &prefix, &expiresAt, &lastUsedAt, &createdAt); err == nil {
			if _, allowed := principal.Membership(organizationID); !allowed {
				continue
			}
			items = append(items, map[string]any{"id": id, "organization_id": organizationID, "name": name, "prefix": prefix, "expires_at": expiresAt, "last_used_at": lastUsedAt, "created_at": createdAt})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		OrganizationID string `json:"organization_id"`
		Name           string `json:"name"`
		ExpiresInDays  int    `json:"expires_in_days"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if _, ok := principal.Membership(input.OrganizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || input.ExpiresInDays < 0 || input.ExpiresInDays > 3650 {
		writeError(w, http.StatusBadRequest, "valid token name and expiry are required")
		return
	}
	plain, err := secureToken("bark_", 32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	var expires any
	if input.ExpiresInDays > 0 {
		expires = time.Now().UTC().Add(time.Duration(input.ExpiresInDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	}
	id := uuid.NewString()
	prefix := plain[:min(12, len(plain))]
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO api_tokens(id, user_id, organization_id, name, token_hash, token_prefix, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, id, principal.UserID, input.OrganizationID, input.Name, hashToken(plain), prefix, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": input.Name, "token": plain, "prefix": prefix, "expires_at": expires})
}

func (s *Server) deleteAPIToken(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM api_tokens WHERE id = ? AND user_id = ?`, r.PathValue("token_id"), principal.UserID).Scan(&organizationID); err != nil {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	if _, allowed := principal.Membership(organizationID); !allowed {
		writeError(w, http.StatusForbidden, "token organization access required")
		return
	}
	result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, r.PathValue("token_id"), principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke token")
		return
	}
	if count, _ := result.RowsAffected(); count == 0 {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func organizationAdmin(principal *auth.Principal, organizationID string) bool {
	membership, ok := principal.Membership(organizationID)
	return ok && (membership.Role == "owner" || membership.Role == "admin")
}

func memberRole(role string, allowOwner bool) bool {
	return role == "admin" || role == "member" || role == "viewer" || (allowOwner && role == "owner")
}

func lastOwner(db *sql.DB, organizationID string) bool {
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM organization_memberships WHERE organization_id = ? AND role = 'owner'`, organizationID).Scan(&count)
	return count <= 1
}

func secureToken(prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
