package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/auth"
	"github.com/GhaziBenDahmane/barktrace/internal/config"
	"github.com/GhaziBenDahmane/barktrace/internal/ingest"
	"github.com/GhaziBenDahmane/barktrace/internal/mcp"
	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/GhaziBenDahmane/barktrace/internal/uptime"
	webassets "github.com/GhaziBenDahmane/barktrace/internal/web"
	"github.com/google/uuid"
)

type Server struct {
	cfg    config.Config
	store  *store.Store
	auth   *auth.Service
	ingest *ingest.Service
	uptime *uptime.Service
	mux    *http.ServeMux
}

func New(cfg config.Config, st *store.Store, authentication *auth.Service, uptimeServices ...*uptime.Service) *Server {
	uptimeService := uptime.New(st, cfg.UptimeAllowPrivateTargets)
	if len(uptimeServices) > 0 && uptimeServices[0] != nil {
		uptimeService = uptimeServices[0]
	}
	s := &Server{
		cfg:    cfg,
		store:  st,
		auth:   authentication,
		ingest: ingest.New(st, cfg.MaxEnvelopeBytes),
		uptime: uptimeService,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return requestLog(recoverer(securityHeaders(s.mux)))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.DB.PingContext(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	s.mux.HandleFunc("GET /auth/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"oidc": true, "provider_name": s.auth.ProviderName()})
	})
	s.mux.HandleFunc("GET /auth/oidc/start", s.auth.Start)
	s.mux.HandleFunc("GET /auth/oidc/callback", s.auth.Callback)
	s.mux.HandleFunc("POST /auth/logout", s.auth.Logout)
	s.mux.Handle("GET /auth/me", s.auth.Require(http.HandlerFunc(s.me)))

	s.mux.Handle("GET /organizations", s.auth.Require(http.HandlerFunc(s.organizations)))
	s.mux.Handle("POST /organizations", s.auth.Require(http.HandlerFunc(s.createOrganization)))
	s.mux.Handle("GET /projects", s.auth.Require(http.HandlerFunc(s.projects)))
	s.mux.Handle("POST /projects", s.auth.Require(http.HandlerFunc(s.createProject)))
	s.mux.Handle("GET /issues", s.auth.Require(http.HandlerFunc(s.issues)))
	s.mux.Handle("GET /releases", s.auth.Require(http.HandlerFunc(s.releases)))
	s.mux.Handle("GET /performance", s.auth.Require(http.HandlerFunc(s.performance)))
	s.mux.Handle("GET /logs", s.auth.Require(http.HandlerFunc(s.logs)))
	s.mux.Handle("GET /uptime/monitors", s.auth.Require(http.HandlerFunc(s.uptimeMonitors)))
	s.mux.Handle("POST /uptime/monitors", s.auth.Require(http.HandlerFunc(s.createUptimeMonitor)))
	s.mux.Handle("DELETE /uptime/monitors/{monitor_id}", s.auth.Require(http.HandlerFunc(s.deleteUptimeMonitor)))
	s.mux.Handle("POST /uptime/monitors/{monitor_id}/check", s.auth.Require(http.HandlerFunc(s.checkUptimeMonitor)))
	s.mux.Handle("GET /uptime/checks", s.auth.Require(http.HandlerFunc(s.uptimeChecks)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/releases/", s.auth.Require(http.HandlerFunc(s.createSentryRelease)))
	if s.cfg.MCPToken != "" {
		s.mux.Handle("POST /mcp", mcp.New(s.store, s.cfg.MCPToken, s.cfg.PublicURL))
	}

	s.mux.HandleFunc("OPTIONS /api/{project_id}/envelope/", ingestionPreflight)
	s.mux.HandleFunc("OPTIONS /api/{project_id}/store/", ingestionPreflight)
	s.mux.HandleFunc("OPTIONS /api/{project_id}/logs/", ingestionPreflight)
	s.mux.HandleFunc("POST /api/{project_id}/envelope/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.Envelope(w, r, r.PathValue("project_id"))
	})
	s.mux.HandleFunc("POST /api/{project_id}/store/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.Store(w, r, r.PathValue("project_id"))
	})
	s.mux.HandleFunc("POST /api/{project_id}/logs/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.Logs(w, r, r.PathValue("project_id"))
	})

	s.mux.Handle("GET /ui/", webassets.Handler())
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, principal)
}

func (s *Server) organizations(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, principal.Memberships)
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Name, input.Slug = strings.TrimSpace(input.Name), slug(strings.TrimSpace(input.Slug))
	if input.Name == "" || input.Slug == "" {
		writeError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create organization")
		return
	}
	defer tx.Rollback()
	id := uuid.NewString()
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO organizations(id, slug, name) VALUES (?, ?, ?)`, id, input.Slug, input.Name); err != nil {
		writeError(w, http.StatusConflict, "organization slug already exists")
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO organization_memberships(organization_id, user_id, role) VALUES (?, ?, 'owner')`, id, principal.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create membership")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit organization")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "slug": input.Slug, "name": input.Name, "role": "owner"})
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.URL.Query().Get("organization_id")
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, sentry_id, slug, name, COALESCE(platform, ''), public_key, created_at FROM projects WHERE organization_id = ? ORDER BY name`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list projects")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, sentryID, projectSlug, name, platform, publicKey, createdAt string
		if err := rows.Scan(&id, &sentryID, &projectSlug, &name, &platform, &publicKey, &createdAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list projects")
			return
		}
		items = append(items, map[string]any{
			"id": id, "sentry_id": sentryID, "slug": projectSlug, "name": name, "platform": platform,
			"public_key": publicKey, "dsn": dsnURL(s.cfg.PublicURL, publicKey, sentryID), "created_at": createdAt,
		})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		OrganizationID string `json:"organization_id"`
		Name           string `json:"name"`
		Slug           string `json:"slug"`
		Platform       string `json:"platform"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	membership, ok := principal.Membership(input.OrganizationID)
	if !ok || (membership.Role != "owner" && membership.Role != "admin") {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	input.Name, input.Slug = strings.TrimSpace(input.Name), slug(firstNonEmpty(input.Slug, input.Name))
	if input.Name == "" || input.Slug == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create project")
		return
	}
	defer tx.Rollback()
	var sentryID string
	if err := tx.QueryRowContext(r.Context(), `SELECT CAST(COALESCE(MAX(CAST(sentry_id AS INTEGER)), 0) + 1 AS TEXT) FROM projects`).Scan(&sentryID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not allocate Sentry project ID")
		return
	}
	id, publicKey := uuid.NewString(), strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err = tx.ExecContext(r.Context(), `INSERT INTO projects(id, sentry_id, organization_id, slug, name, platform, public_key) VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?)`, id, sentryID, input.OrganizationID, input.Slug, input.Name, input.Platform, publicKey)
	if err != nil {
		writeError(w, http.StatusConflict, "project slug already exists")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit project")
		return
	}
	dsn := dsnURL(s.cfg.PublicURL, publicKey, sentryID)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "sentry_id": sentryID, "slug": input.Slug, "name": input.Name, "public_key": publicKey, "dsn": dsn})
}

func (s *Server) issues(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT i.id, i.title, i.status, i.level, i.event_count, i.first_seen_at, i.last_seen_at,
		       COALESCE(fr.version, ''), COALESCE(lr.version, '')
		FROM issues i
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		WHERE i.project_id = ? ORDER BY i.last_seen_at DESC LIMIT 100
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issues")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, title, status, level, firstSeen, lastSeen, firstRelease, lastRelease string
		var count int64
		if err := rows.Scan(&id, &title, &status, &level, &count, &firstSeen, &lastSeen, &firstRelease, &lastRelease); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list issues")
			return
		}
		items = append(items, map[string]any{"id": id, "title": title, "status": status, "level": level, "event_count": count, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "first_release": firstRelease, "last_release": lastRelease})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) releases(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT r.id, r.version, pr.first_seen_at, pr.last_seen_at,
		       (SELECT COUNT(*) FROM events e WHERE e.project_id = pr.project_id AND e.release_id = r.id)
		FROM project_releases pr JOIN releases r ON r.id = pr.release_id
		WHERE pr.project_id = ? ORDER BY pr.last_seen_at DESC LIMIT 100
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list releases")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, version, firstSeen, lastSeen string
		var events int64
		if err := rows.Scan(&id, &version, &firstSeen, &lastSeen, &events); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list releases")
			return
		}
		items = append(items, map[string]any{"id": id, "version": version, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "events": events})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) createSentryRelease(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	orgSlug := r.PathValue("org_slug")
	var orgID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM organizations WHERE slug = ?`, orgSlug).Scan(&orgID); err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	if _, ok := principal.Membership(orgID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	var input struct {
		Version  string   `json:"version"`
		Projects []string `json:"projects"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Version = strings.TrimSpace(input.Version)
	if input.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create release")
		return
	}
	defer tx.Rollback()
	releaseID := uuid.NewString()
	if err := tx.QueryRowContext(r.Context(), `INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(organization_id, version) DO UPDATE SET last_seen_at = excluded.last_seen_at RETURNING id`, releaseID, orgID, input.Version, now, now).Scan(&releaseID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create release")
		return
	}
	for _, projectSlug := range input.Projects {
		var projectID string
		if err := tx.QueryRowContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? AND slug = ?`, orgID, projectSlug).Scan(&projectID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, http.StatusBadRequest, "unknown project: "+projectSlug)
				return
			}
			writeError(w, http.StatusInternalServerError, "could not link release")
			return
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, release_id) DO UPDATE SET last_seen_at = excluded.last_seen_at`, projectID, releaseID, now, now); err != nil {
			writeError(w, http.StatusInternalServerError, "could not link release")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit release")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": releaseID, "version": input.Version, "projects": input.Projects, "dateCreated": now})
}

func (s *Server) canAccessProject(r *http.Request, principal *auth.Principal, projectID string) bool {
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		return false
	}
	_, ok := principal.Membership(organizationID)
	return ok
}

func ingestionPreflight(w http.ResponseWriter, _ *http.Request) {
	ingestionHeaders(w)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Encoding, X-Sentry-Auth, X-Requested-With")
	w.WriteHeader(http.StatusNoContent)
}

func ingestionHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "X-Sentry-Rate-Limits, Retry-After")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return err
	}
	return nil
}

func dsnURL(publicURL, publicKey, projectID string) string {
	index := strings.Index(publicURL, "://")
	if index < 0 {
		return ""
	}
	return publicURL[:index+3] + publicKey + "@" + publicURL[index+3:] + "/" + projectID
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastDash = false
		} else if !lastDash && builder.Len() > 0 {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"type": strings.ToLower(strings.ReplaceAll(http.StatusText(status), " ", "_")), "message": message}})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("request panic", "error", recovered, "method", r.Method, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}
