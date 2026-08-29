package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

func (s *Server) mcpTokens(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT t.id, t.name, t.token_prefix, t.scopes, COALESCE(t.expires_at, ''),
		       COALESCE(t.last_used_at, ''), t.created_at, t.created_by, COALESCE(u.email, '')
		FROM mcp_tokens t LEFT JOIN users u ON u.id = t.created_by
		WHERE t.organization_id = ? ORDER BY t.created_at DESC
	`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list MCP tokens")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, prefix, expiresAt, lastUsedAt, createdAt, createdBy, createdByEmail string
		var scopes json.RawMessage
		if err := rows.Scan(&id, &name, &prefix, &scopes, &expiresAt, &lastUsedAt, &createdAt, &createdBy, &createdByEmail); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list MCP tokens")
			return
		}
		items = append(items, map[string]any{
			"id": id, "name": name, "token_prefix": prefix, "scopes": scopes,
			"expires_at": nullableText(expiresAt), "last_used_at": nullableText(lastUsedAt),
			"created_at": createdAt, "created_by": createdBy, "created_by_email": createdByEmail,
		})
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not list MCP tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": items})
}

func (s *Server) createMCPToken(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays int      `json:"expires_in_days"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 120 {
		writeError(w, http.StatusBadRequest, "name must contain between 1 and 120 characters")
		return
	}
	if input.ExpiresInDays < 0 || input.ExpiresInDays > 3650 {
		writeError(w, http.StatusBadRequest, "expires_in_days must be between 0 and 3650")
		return
	}
	scopes, ok := normalizeMCPScopes(input.Scopes)
	if !ok {
		writeError(w, http.StatusBadRequest, "scopes may contain only read and write")
		return
	}
	plain, err := secureToken("bark_mcp_", 32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create MCP token")
		return
	}
	id := uuid.NewString()
	var expiresAt any
	if input.ExpiresInDays > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(input.ExpiresInDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	}
	encodedScopes, _ := json.Marshal(scopes)
	prefix := plain
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO mcp_tokens(id, organization_id, created_by, name, token_hash, token_prefix, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, organizationID, principal.UserID, input.Name, hashToken(plain), prefix, encodedScopes, expiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create MCP token")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": input.Name, "token": plain, "token_prefix": prefix, "scopes": scopes, "expires_at": expiresAt})
}

func (s *Server) deleteMCPToken(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.PathValue("organization_id")
	if !organizationAdmin(principal, organizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM mcp_tokens WHERE id = ? AND organization_id = ?`, r.PathValue("token_id"), organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke MCP token")
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		writeError(w, http.StatusNotFound, "MCP token not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func normalizeMCPScopes(input []string) ([]string, bool) {
	if len(input) == 0 {
		return []string{"read"}, true
	}
	seen := map[string]bool{}
	for _, scope := range input {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "read" && scope != "write" {
			return nil, false
		}
		seen[scope] = true
	}
	result := make([]string, 0, 2)
	if seen["read"] {
		result = append(result, "read")
	}
	if seen["write"] {
		result = append(result, "write")
	}
	return result, true
}
