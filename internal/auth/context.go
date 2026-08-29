package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

type principalKey struct{}

func (s *Service) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := s.Authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"type":"unauthenticated","message":"authentication required"}}`))
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		request := r.WithContext(ctx)
		if !mutatingMethod(r.Method) {
			next.ServeHTTP(w, request)
			return
		}
		organizationID, projectID, targetType, targetID := s.auditScope(request)
		captured := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(captured, request)
		if captured.status < http.StatusBadRequest {
			s.recordMutation(request, principal, organizationID, projectID, targetType, targetID, captured.status)
		}
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func mutatingMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

func (s *Service) auditScope(r *http.Request) (organizationID, projectID, targetType, targetID string) {
	organizationID = firstNonEmpty(r.PathValue("organization_id"), r.URL.Query().Get("organization_id"))
	projectID = firstNonEmpty(r.PathValue("project_id"), r.URL.Query().Get("project_id"))
	if slug := r.PathValue("org_slug"); organizationID == "" && slug != "" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM organizations WHERE slug = ?`, slug).Scan(&organizationID)
	}
	if projectID == "" && r.PathValue("project_slug") != "" && organizationID != "" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? AND slug = ?`, organizationID, r.PathValue("project_slug")).Scan(&projectID)
	}
	for _, candidate := range []struct{ key, kind string }{
		{"job_id", "ingestion_job"}, {"artifact_id", "artifact"}, {"file_id", "artifact"},
		{"issue_id", "issue"}, {"monitor_id", "monitor"}, {"rule_id", "alert_rule"},
		{"widget_id", "dashboard_widget"}, {"dashboard_id", "dashboard"},
		{"invitation_id", "invitation"}, {"token_id", "token"}, {"user_id", "user"},
		{"release_id", "release"}, {"project_id", "project"}, {"organization_id", "organization"},
	} {
		if value := r.PathValue(candidate.key); value != "" {
			targetType, targetID = candidate.kind, value
			break
		}
	}
	if projectID == "" && targetType == "issue" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM issues WHERE id = ?`, targetID).Scan(&projectID)
	}
	if targetType == "dashboard" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id, COALESCE(project_id, '') FROM dashboards WHERE id = ?`, targetID).Scan(&organizationID, &projectID)
	}
	if targetType == "dashboard_widget" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT d.organization_id, COALESCE(d.project_id, '') FROM dashboard_widgets w JOIN dashboards d ON d.id = w.dashboard_id WHERE w.id = ?`, targetID).Scan(&organizationID, &projectID)
	}
	if organizationID == "" && projectID != "" {
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID)
	}
	return organizationID, projectID, targetType, targetID
}

func (s *Service) recordMutation(r *http.Request, principal *Principal, organizationID, projectID, targetType, targetID string, status int) {
	metadata, _ := json.Marshal(map[string]any{"method": r.Method, "path": r.URL.Path, "pattern": r.Pattern, "status": status})
	pattern := strings.TrimSpace(r.Pattern)
	if _, route, found := strings.Cut(pattern, " "); found {
		pattern = route
	}
	address := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	if len(address) > 128 {
		address = address[:128]
	}
	_, _ = s.store.DB.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, project_id, actor_user_id, actor_type, action, target_type, target_id, metadata, ip_address) VALUES (NULLIF(?, ''), NULLIF(?, ''), ?, 'user', ?, ?, ?, ?, ?)`, organizationID, projectID, principal.UserID, strings.ToLower(r.Method)+" "+pattern, targetType, targetID, metadata, address)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(*Principal)
	return principal, ok
}

// WithPrincipal attaches an already authenticated principal to a context.
// It is useful for composing Barktrace handlers without duplicating auth state.
func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func (p Principal) Membership(organizationID string) (Membership, bool) {
	for _, membership := range p.Memberships {
		if membership.OrganizationID == organizationID {
			return membership, true
		}
	}
	return Membership{}, false
}
