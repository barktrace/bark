package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/config"
	"github.com/barktrace/bark/internal/ingest"
	"github.com/barktrace/bark/internal/mcp"
	"github.com/barktrace/bark/internal/store"
	"github.com/barktrace/bark/internal/uptime"
	webassets "github.com/barktrace/bark/internal/web"
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
		ingest: ingest.New(st, cfg.MaxEnvelopeBytes, cfg.RateLimitPerMinute),
		uptime: uptimeService,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return requestLog(recoverer(securityHeaders(s.mux)))
}

func (s *Server) RunIngestion(ctx context.Context) {
	s.ingest.Run(ctx)
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
	s.mux.Handle("GET /organizations/{organization_id}/members", s.auth.Require(http.HandlerFunc(s.organizationMembers)))
	s.mux.Handle("POST /organizations/{organization_id}/invitations", s.auth.Require(http.HandlerFunc(s.createInvitation)))
	s.mux.Handle("DELETE /organizations/{organization_id}/invitations/{invitation_id}", s.auth.Require(http.HandlerFunc(s.deleteInvitation)))
	s.mux.Handle("PATCH /organizations/{organization_id}/members/{user_id}", s.auth.Require(http.HandlerFunc(s.updateMember)))
	s.mux.Handle("DELETE /organizations/{organization_id}/members/{user_id}", s.auth.Require(http.HandlerFunc(s.deleteMember)))
	s.mux.Handle("GET /organizations/{organization_id}/audit-logs", s.auth.Require(http.HandlerFunc(s.auditLogs)))
	s.mux.Handle("GET /discover", s.auth.Require(http.HandlerFunc(s.discoverQuery)))
	s.mux.Handle("GET /dashboards", s.auth.Require(http.HandlerFunc(s.dashboards)))
	s.mux.Handle("POST /organizations/{organization_id}/dashboards", s.auth.Require(http.HandlerFunc(s.dashboards)))
	s.mux.Handle("GET /dashboards/{dashboard_id}", s.auth.Require(http.HandlerFunc(s.dashboard)))
	s.mux.Handle("PATCH /dashboards/{dashboard_id}", s.auth.Require(http.HandlerFunc(s.dashboard)))
	s.mux.Handle("DELETE /dashboards/{dashboard_id}", s.auth.Require(http.HandlerFunc(s.dashboard)))
	s.mux.Handle("POST /dashboards/{dashboard_id}/widgets", s.auth.Require(http.HandlerFunc(s.dashboardWidgets)))
	s.mux.Handle("PATCH /dashboards/{dashboard_id}/widgets/{widget_id}", s.auth.Require(http.HandlerFunc(s.dashboardWidgets)))
	s.mux.Handle("DELETE /dashboards/{dashboard_id}/widgets/{widget_id}", s.auth.Require(http.HandlerFunc(s.dashboardWidgets)))
	s.mux.Handle("GET /organizations/{organization_id}/mcp-tokens", s.auth.Require(http.HandlerFunc(s.mcpTokens)))
	s.mux.Handle("POST /organizations/{organization_id}/mcp-tokens", s.auth.Require(http.HandlerFunc(s.createMCPToken)))
	s.mux.Handle("DELETE /organizations/{organization_id}/mcp-tokens/{token_id}", s.auth.Require(http.HandlerFunc(s.deleteMCPToken)))
	s.mux.Handle("GET /api-tokens", s.auth.Require(http.HandlerFunc(s.apiTokens)))
	s.mux.Handle("POST /api-tokens", s.auth.Require(http.HandlerFunc(s.createAPIToken)))
	s.mux.Handle("DELETE /api-tokens/{token_id}", s.auth.Require(http.HandlerFunc(s.deleteAPIToken)))
	s.mux.Handle("GET /storage", s.auth.Require(http.HandlerFunc(s.storageUsage)))
	s.mux.Handle("PATCH /storage/retention", s.auth.Require(http.HandlerFunc(s.updateRetention)))
	s.mux.Handle("POST /storage/cleanup", s.auth.Require(http.HandlerFunc(s.cleanupStorage)))
	s.mux.Handle("GET /alerts", s.auth.Require(http.HandlerFunc(s.alertRules)))
	s.mux.Handle("POST /alerts", s.auth.Require(http.HandlerFunc(s.createAlertRule)))
	s.mux.Handle("PATCH /alerts/{rule_id}", s.auth.Require(http.HandlerFunc(s.updateAlertRule)))
	s.mux.Handle("DELETE /alerts/{rule_id}", s.auth.Require(http.HandlerFunc(s.deleteAlertRule)))
	s.mux.Handle("POST /alerts/{rule_id}/test", s.auth.Require(http.HandlerFunc(s.testAlertRule)))
	s.mux.Handle("GET /alert-deliveries", s.auth.Require(http.HandlerFunc(s.alertDeliveries)))
	s.mux.Handle("GET /cron/monitors", s.auth.Require(http.HandlerFunc(s.cronMonitors)))
	s.mux.Handle("POST /cron/monitors", s.auth.Require(http.HandlerFunc(s.createCronMonitor)))
	s.mux.Handle("DELETE /cron/monitors/{monitor_id}", s.auth.Require(http.HandlerFunc(s.deleteCronMonitor)))
	s.mux.Handle("GET /cron/checkins", s.auth.Require(http.HandlerFunc(s.cronCheckins)))
	s.mux.Handle("GET /feedback", s.auth.Require(http.HandlerFunc(s.feedback)))
	s.mux.Handle("GET /attachments", s.auth.Require(http.HandlerFunc(s.eventAttachments)))
	s.mux.Handle("GET /attachments/{attachment_id}", s.auth.Require(http.HandlerFunc(s.attachmentContent)))
	s.mux.Handle("GET /replays", s.auth.Require(http.HandlerFunc(s.replays)))
	s.mux.Handle("GET /replays/{replay_id}/{content}", s.auth.Require(http.HandlerFunc(s.replayContent)))
	s.mux.Handle("GET /profiles", s.auth.Require(http.HandlerFunc(s.profiles)))
	s.mux.Handle("GET /profiles/{profile_id}", s.auth.Require(http.HandlerFunc(s.profileContent)))
	s.mux.Handle("GET /metrics", s.auth.Require(http.HandlerFunc(s.metrics)))
	s.mux.Handle("GET /projects", s.auth.Require(http.HandlerFunc(s.projects)))
	s.mux.Handle("POST /projects", s.auth.Require(http.HandlerFunc(s.createProject)))
	s.mux.Handle("PATCH /projects/{project_id}", s.auth.Require(http.HandlerFunc(s.updateProject)))
	s.mux.Handle("DELETE /projects/{project_id}", s.auth.Require(http.HandlerFunc(s.deleteProject)))
	s.mux.Handle("GET /projects/{project_id}/memberships", s.auth.Require(http.HandlerFunc(s.projectMemberships)))
	s.mux.Handle("PUT /projects/{project_id}/memberships/{user_id}", s.auth.Require(http.HandlerFunc(s.updateProjectMembership)))
	s.mux.Handle("DELETE /projects/{project_id}/memberships/{user_id}", s.auth.Require(http.HandlerFunc(s.deleteProjectMembership)))
	s.mux.Handle("POST /projects/{project_id}/rotate-key", s.auth.Require(http.HandlerFunc(s.rotateProjectKey)))
	s.mux.Handle("GET /artifacts", s.auth.Require(http.HandlerFunc(s.projectArtifacts)))
	s.mux.Handle("POST /artifacts", s.auth.Require(http.HandlerFunc(s.uploadProjectArtifact)))
	s.mux.Handle("GET /artifacts/{artifact_id}", s.auth.Require(http.HandlerFunc(s.artifactFile)))
	s.mux.Handle("DELETE /artifacts/{artifact_id}", s.auth.Require(http.HandlerFunc(s.artifactFile)))
	s.mux.Handle("POST /projects/{project_id}/reprocess", s.auth.Require(http.HandlerFunc(s.reprocessProject)))
	s.mux.Handle("GET /projects/{project_id}/quotas", s.auth.Require(http.HandlerFunc(s.projectQuotas)))
	s.mux.Handle("PUT /projects/{project_id}/quotas/{category}", s.auth.Require(http.HandlerFunc(s.updateProjectQuota)))
	s.mux.Handle("GET /projects/{project_id}/ingestion-jobs", s.auth.Require(http.HandlerFunc(s.ingestionJobs)))
	s.mux.Handle("POST /projects/{project_id}/ingestion-jobs/{job_id}/retry", s.auth.Require(http.HandlerFunc(s.retryIngestionJob)))
	s.mux.Handle("DELETE /projects/{project_id}/ingestion-jobs/{job_id}", s.auth.Require(http.HandlerFunc(s.deleteIngestionJob)))
	s.mux.Handle("GET /issues", s.auth.Require(http.HandlerFunc(s.issues)))
	s.mux.Handle("GET /issues/{issue_id}", s.auth.Require(http.HandlerFunc(s.issueDetail)))
	s.mux.Handle("GET /issues/{issue_id}/suspects", s.auth.Require(http.HandlerFunc(s.issueSuspects)))
	s.mux.Handle("PATCH /issues/{issue_id}", s.auth.Require(http.HandlerFunc(s.updateIssue)))
	s.mux.Handle("DELETE /issues/{issue_id}", s.auth.Require(http.HandlerFunc(s.deleteIssue)))
	s.mux.Handle("POST /issues/{issue_id}/comments", s.auth.Require(http.HandlerFunc(s.createIssueComment)))
	s.mux.Handle("GET /events/{event_id}", s.auth.Require(http.HandlerFunc(s.eventDetail)))
	s.mux.Handle("GET /releases", s.auth.Require(http.HandlerFunc(s.releases)))
	s.mux.Handle("GET /releases/{release_id}/metadata", s.auth.Require(http.HandlerFunc(s.releaseMetadata)))
	s.mux.Handle("GET /performance", s.auth.Require(http.HandlerFunc(s.performance)))
	s.mux.Handle("GET /transactions/{transaction_id}", s.auth.Require(http.HandlerFunc(s.transactionDetail)))
	s.mux.Handle("GET /logs", s.auth.Require(http.HandlerFunc(s.logs)))
	s.mux.Handle("GET /uptime/monitors", s.auth.Require(http.HandlerFunc(s.uptimeMonitors)))
	s.mux.Handle("POST /uptime/monitors", s.auth.Require(http.HandlerFunc(s.createUptimeMonitor)))
	s.mux.Handle("DELETE /uptime/monitors/{monitor_id}", s.auth.Require(http.HandlerFunc(s.deleteUptimeMonitor)))
	s.mux.Handle("POST /uptime/monitors/{monitor_id}/check", s.auth.Require(http.HandlerFunc(s.checkUptimeMonitor)))
	s.mux.Handle("GET /uptime/checks", s.auth.Require(http.HandlerFunc(s.uptimeChecks)))
	s.mux.Handle("GET /api/0/", s.auth.Require(http.HandlerFunc(s.sentryAuthInfo)))
	s.mux.Handle("GET /api/0/organizations/", s.auth.Require(http.HandlerFunc(s.sentryOrganizations)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/projects/", s.auth.Require(http.HandlerFunc(s.sentryOrganizationProjects)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/monitors/", s.auth.Require(http.HandlerFunc(s.sentryOrganizationMonitors)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/repos/", s.auth.Require(http.HandlerFunc(s.sentryOrganizationRepositories)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/code-mappings/bulk/", s.auth.Require(http.HandlerFunc(s.sentryBulkCodeMappings)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/events/", s.auth.Require(http.HandlerFunc(s.sentryOrganizationEvents)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/releases/", s.auth.Require(http.HandlerFunc(s.sentryOrganizationReleases)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/releases/", s.auth.Require(http.HandlerFunc(s.createSentryRelease)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/", s.auth.Require(http.HandlerFunc(s.sentryReleaseDetail)))
	s.mux.Handle("PUT /api/0/organizations/{org_slug}/releases/{version}/", s.auth.Require(http.HandlerFunc(s.sentryReleaseDetail)))
	s.mux.Handle("DELETE /api/0/organizations/{org_slug}/releases/{version}/", s.auth.Require(http.HandlerFunc(s.deleteSentryRelease)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/commits/", s.auth.Require(http.HandlerFunc(s.sentryReleaseCommits)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/releases/{version}/commits/", s.auth.Require(http.HandlerFunc(s.sentryReleaseCommits)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/previous-with-commits/", s.auth.Require(http.HandlerFunc(s.sentryPreviousRelease)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/deploys/", s.auth.Require(http.HandlerFunc(s.sentryReleaseDeployList)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/releases/{version}/deploys/", s.auth.Require(http.HandlerFunc(s.sentryReleaseDeploys)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/releases/", s.auth.Require(http.HandlerFunc(s.sentryProjectReleases)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/events/", s.auth.Require(http.HandlerFunc(s.sentryProjectEvents)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/issues/", s.auth.Require(http.HandlerFunc(s.sentryProjectIssues)))
	s.mux.Handle("PUT /api/0/projects/{org_slug}/{project_slug}/issues/", s.auth.Require(http.HandlerFunc(s.sentryProjectIssues)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/releases/{version}/files/", s.auth.Require(http.HandlerFunc(s.sentryReleaseArtifacts)))
	s.mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/releases/{version}/files/", s.auth.Require(http.HandlerFunc(s.sentryReleaseArtifacts)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/releases/{version}/files/{file_id}/", s.auth.Require(http.HandlerFunc(s.sentryReleaseArtifactDetail)))
	s.mux.Handle("PUT /api/0/projects/{org_slug}/{project_slug}/releases/{version}/files/{file_id}/", s.auth.Require(http.HandlerFunc(s.sentryReleaseArtifactDetail)))
	s.mux.Handle("DELETE /api/0/projects/{org_slug}/{project_slug}/releases/{version}/files/{file_id}/", s.auth.Require(http.HandlerFunc(s.sentryReleaseArtifactDetail)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/chunk-upload/", s.auth.Require(http.HandlerFunc(s.sentryChunkUpload)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/chunk-upload/", s.auth.Require(http.HandlerFunc(s.sentryChunkUpload)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/artifactbundle/assemble/", s.auth.Require(http.HandlerFunc(s.assembleArtifactBundle)))
	s.mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/files/difs/assemble/", s.auth.Require(http.HandlerFunc(s.assembleDebugFiles)))
	s.mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/files/preprodartifacts/assemble/", s.auth.Require(http.HandlerFunc(s.assemblePreprodBuild)))
	s.mux.Handle("GET /api/0/organizations/{org_slug}/preprodartifacts/{preprod_path...}", s.auth.Require(http.HandlerFunc(s.preprodOrganizationRoute)))
	s.mux.Handle("POST /api/0/organizations/{org_slug}/preprodartifacts/{preprod_path...}", s.auth.Require(http.HandlerFunc(s.preprodOrganizationRoute)))
	s.mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/preprodartifacts/snapshots/upload-options/", s.auth.Require(http.HandlerFunc(s.snapshotUploadOptions)))
	s.mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/preprodartifacts/snapshots/", s.auth.Require(http.HandlerFunc(s.createPreprodSnapshot)))
	s.mux.HandleFunc("HEAD /api/0/objectstore/v1/objects/preprod/{scope}/{object_key...}", s.snapshotObject)
	s.mux.HandleFunc("PUT /api/0/objectstore/v1/objects/preprod/{scope}/{object_key...}", s.snapshotObject)
	s.mux.HandleFunc("POST /api/0/objectstore/v1/objects:batch/preprod/{scope}/{$}", s.snapshotObjectBatch)
	s.mux.Handle("POST /mcp", mcp.New(s.store, s.cfg.MCPToken, s.cfg.PublicURL))

	s.mux.HandleFunc("OPTIONS /api/{project_id}/envelope/", ingestionPreflight)
	s.mux.HandleFunc("OPTIONS /api/{project_id}/store/", ingestionPreflight)
	s.mux.HandleFunc("OPTIONS /api/{project_id}/logs/", ingestionPreflight)
	s.mux.HandleFunc("OPTIONS /api/{project_id}/user-report/", ingestionPreflight)
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
	s.mux.HandleFunc("POST /api/{project_id}/user-report/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.Feedback(w, r, r.PathValue("project_id"))
	})
	s.mux.HandleFunc("POST /api/{project_id}/cron/{monitor_slug}/{checkin_id}/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.CheckIn(w, r, r.PathValue("project_id"), r.PathValue("monitor_slug"), r.PathValue("checkin_id"))
	})
	s.mux.HandleFunc("POST /api/{project_id}/cron/{monitor_slug}/", func(w http.ResponseWriter, r *http.Request) {
		ingestionHeaders(w)
		s.ingest.CheckIn(w, r, r.PathValue("project_id"), r.PathValue("monitor_slug"), "")
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
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT p.id, p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''), p.public_key, p.created_at,
		       CASE WHEN pm.role != '' THEN pm.role WHEN om.role IN ('owner', 'admin') THEN 'admin' ELSE om.role END
		FROM projects p
		JOIN organization_memberships om ON om.organization_id = p.organization_id AND om.user_id = ?
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = om.user_id
		WHERE p.organization_id = ? AND COALESCE(pm.role, '') != 'none'
		ORDER BY p.name
	`, principal.UserID, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list projects")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, sentryID, projectSlug, name, platform, publicKey, createdAt, effectiveRole string
		if err := rows.Scan(&id, &sentryID, &projectSlug, &name, &platform, &publicKey, &createdAt, &effectiveRole); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list projects")
			return
		}
		items = append(items, map[string]any{
			"id": id, "sentry_id": sentryID, "slug": projectSlug, "name": name, "platform": platform,
			"public_key": publicKey, "dsn": dsnURL(s.cfg.PublicURL, publicKey, sentryID), "created_at": createdAt, "role": effectiveRole,
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
		       COALESCE(fr.version, ''), COALESCE(lr.version, ''), i.priority,
		       COALESCE(i.assignee_user_id, ''), COALESCE(u.name, ''), i.bookmarked,
		       COALESCE(i.snoozed_until, '')
		FROM issues i
		LEFT JOIN releases fr ON fr.id = i.first_release_id
		LEFT JOIN releases lr ON lr.id = i.last_release_id
		LEFT JOIN users u ON u.id = i.assignee_user_id
		WHERE i.project_id = ? ORDER BY i.last_seen_at DESC LIMIT 100
	`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issues")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, title, status, level, firstSeen, lastSeen, firstRelease, lastRelease, priority, assigneeID, assigneeName, snoozedUntil string
		var count int64
		var bookmarked bool
		if err := rows.Scan(&id, &title, &status, &level, &count, &firstSeen, &lastSeen, &firstRelease, &lastRelease, &priority, &assigneeID, &assigneeName, &bookmarked, &snoozedUntil); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list issues")
			return
		}
		items = append(items, map[string]any{"id": id, "title": title, "status": status, "level": level, "event_count": count, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "first_release": firstRelease, "last_release": lastRelease, "priority": priority, "assignee_user_id": assigneeID, "assignee_name": assigneeName, "bookmarked": bookmarked, "snoozed_until": snoozedUntil})
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
		       (SELECT COUNT(*) FROM events e WHERE e.project_id = pr.project_id AND e.release_id = r.id),
		       (SELECT COUNT(*) FROM project_sessions s WHERE s.project_id = pr.project_id AND s.release_id = r.id),
		       (SELECT COUNT(*) FROM project_sessions s WHERE s.project_id = pr.project_id AND s.release_id = r.id AND (s.status IN ('crashed', 'abnormal') OR s.errors > 0)),
		       (SELECT COUNT(DISTINCT s.distinct_id) FROM project_sessions s WHERE s.project_id = pr.project_id AND s.release_id = r.id AND s.distinct_id != ''),
		       (SELECT COUNT(DISTINCT s.distinct_id) FROM project_sessions s WHERE s.project_id = pr.project_id AND s.release_id = r.id AND s.distinct_id != '' AND (s.status IN ('crashed', 'abnormal') OR s.errors > 0))
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
		var events, sessions, crashedSessions, users, crashedUsers int64
		if err := rows.Scan(&id, &version, &firstSeen, &lastSeen, &events, &sessions, &crashedSessions, &users, &crashedUsers); err != nil {
			writeError(w, http.StatusInternalServerError, "could not list releases")
			return
		}
		crashFreeSessions, crashFreeUsers := 100.0, 100.0
		if sessions > 0 {
			crashFreeSessions = 100 * (1 - float64(crashedSessions)/float64(sessions))
		}
		if users > 0 {
			crashFreeUsers = 100 * (1 - float64(crashedUsers)/float64(users))
		}
		items = append(items, map[string]any{"id": id, "version": version, "first_seen_at": firstSeen, "last_seen_at": lastSeen, "events": events, "sessions": sessions, "crash_free_sessions": crashFreeSessions, "users": users, "crash_free_users": crashFreeUsers})
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
	membership, ok := principal.Membership(orgID)
	if !ok || membership.Role == "viewer" {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	var input struct {
		Version      string   `json:"version"`
		Projects     []string `json:"projects"`
		URL          string   `json:"url"`
		DateStarted  string   `json:"dateStarted"`
		DateReleased string   `json:"dateReleased"`
		Status       string   `json:"status"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Version = strings.TrimSpace(input.Version)
	if input.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	if input.Status == "" {
		input.Status = "open"
	}
	if input.Status != "open" && input.Status != "archived" {
		writeError(w, http.StatusBadRequest, "status must be open or archived")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	started := now
	if input.DateStarted != "" {
		parsed, err := time.Parse(time.RFC3339, input.DateStarted)
		if err != nil {
			writeError(w, http.StatusBadRequest, "dateStarted must be RFC3339")
			return
		}
		started = parsed.UTC().Format(time.RFC3339Nano)
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create release")
		return
	}
	defer tx.Rollback()
	releaseID := uuid.NewString()
	if input.DateReleased != "" {
		if _, err := time.Parse(time.RFC3339, input.DateReleased); err != nil {
			writeError(w, http.StatusBadRequest, "dateReleased must be RFC3339")
			return
		}
	}
	if err := tx.QueryRowContext(r.Context(), `INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at, released_at, status) VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?) ON CONFLICT(organization_id, version) DO UPDATE SET last_seen_at = excluded.last_seen_at, released_at = COALESCE(excluded.released_at, releases.released_at), status = excluded.status RETURNING id`, releaseID, orgID, input.Version, started, now, input.DateReleased, input.Status).Scan(&releaseID); err != nil {
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
	item, err := s.sentryReleaseResponse(r, releaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load release")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) canAccessProject(r *http.Request, principal *auth.Principal, projectID string) bool {
	_, ok := s.projectRole(r, principal, projectID)
	return ok
}

func (s *Server) projectRole(r *http.Request, principal *auth.Principal, projectID string) (string, bool) {
	if principal == nil {
		return "", false
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		return "", false
	}
	membership, ok := principal.Membership(organizationID)
	if !ok {
		return "", false
	}
	var override string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT role FROM project_memberships WHERE project_id = ? AND user_id = ?`, projectID, principal.UserID).Scan(&override)
	if err == nil {
		if override == "none" {
			return "", false
		}
		return override, true
	}
	if err != sql.ErrNoRows {
		return "", false
	}
	switch membership.Role {
	case "owner", "admin":
		return "admin", true
	case "member":
		return "member", true
	case "viewer":
		return "viewer", true
	default:
		return "", false
	}
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
