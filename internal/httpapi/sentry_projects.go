package httpapi

import (
	"net/http"
	"strings"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type sentryProjectInput struct {
	Name     *string `json:"name"`
	Slug     *string `json:"slug"`
	Platform *string `json:"platform"`
	Team     string  `json:"team"`
}

func (s *Server) createSentryProject(w http.ResponseWriter, r *http.Request, principal *auth.Principal, organizationID string) {
	membership, ok := principal.Membership(organizationID)
	if !ok || (membership.Role != "owner" && membership.Role != "admin") {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input sentryProjectInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	name := ""
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	projectSlug := slug(name)
	if input.Slug != nil {
		projectSlug = slug(*input.Slug)
	}
	if name == "" || projectSlug == "" {
		writeError(w, http.StatusBadRequest, "project name is required")
		return
	}
	platform := ""
	if input.Platform != nil {
		platform = strings.TrimSpace(*input.Platform)
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create project")
		return
	}
	defer tx.Rollback()
	var sentryID string
	if err = tx.QueryRowContext(r.Context(), `SELECT CAST(COALESCE(MAX(CAST(sentry_id AS INTEGER)), 0) + 1 AS TEXT) FROM projects`).Scan(&sentryID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not allocate Sentry project ID")
		return
	}
	projectID, publicKey := uuid.NewString(), strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO projects(id, sentry_id, organization_id, slug, name, platform, public_key) VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?)`, projectID, sentryID, organizationID, projectSlug, name, platform, publicKey); err != nil {
		writeError(w, http.StatusConflict, "project slug already exists")
		return
	}
	if teamSlug := slug(input.Team); teamSlug != "" {
		var teamID string
		if err = tx.QueryRowContext(r.Context(), `SELECT id FROM teams WHERE organization_id = ? AND slug = ?`, organizationID, teamSlug).Scan(&teamID); err != nil {
			writeError(w, http.StatusBadRequest, "team not found")
			return
		}
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO team_projects(team_id, project_id) VALUES (?, ?)`, teamID, projectID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not link project team")
			return
		}
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create project")
		return
	}
	response, err := s.sentryProjectResponse(r, projectID, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load project")
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) updateSentryProject(w http.ResponseWriter, r *http.Request, projectID string) bool {
	var input sentryProjectInput
	if err := decodeJSON(w, r, &input); err != nil {
		return false
	}
	var name, projectSlug, platform string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT name, slug, COALESCE(platform, '') FROM projects WHERE id = ?`, projectID).Scan(&name, &projectSlug, &platform); err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return false
	}
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	if input.Slug != nil {
		projectSlug = slug(*input.Slug)
	}
	if input.Platform != nil {
		platform = strings.TrimSpace(*input.Platform)
	}
	if name == "" || projectSlug == "" {
		writeError(w, http.StatusBadRequest, "project name and slug are required")
		return false
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE projects SET name = ?, slug = ?, platform = NULLIF(?, '') WHERE id = ?`, name, projectSlug, platform, projectID); err != nil {
		writeError(w, http.StatusConflict, "project slug already exists")
		return false
	}
	return true
}
