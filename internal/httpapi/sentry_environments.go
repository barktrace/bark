package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/environments"
)

type sentryEnvironment = environments.Environment

func (s *Server) sentryOrganizationEnvironments(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	visibility, ok := sentryEnvironmentVisibility(w, r)
	if !ok {
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	visibleNames, hiddenNames := make(map[string]bool), make(map[string]bool)
	for _, projectID := range projectIDs {
		environments, err := environments.List(r.Context(), s.store.DB, projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list environments")
			return
		}
		for _, environment := range environments {
			if environment.IsHidden {
				hiddenNames[environment.Name] = true
			} else {
				visibleNames[environment.Name] = true
			}
		}
	}
	names := make([]string, 0, len(visibleNames)+len(hiddenNames))
	seen := make(map[string]bool)
	appendNames := func(source map[string]bool) {
		for name := range source {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	switch visibility {
	case "visible":
		appendNames(visibleNames)
	case "hidden":
		appendNames(hiddenNames)
	default:
		appendNames(visibleNames)
		appendNames(hiddenNames)
	}
	sort.Strings(names)
	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		items = append(items, map[string]any{"id": sentryEnvironmentID(organizationID, name), "name": name})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryProjectEnvironments(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if r.Method == http.MethodPut {
		if !s.canWriteProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		var input struct {
			EnvironmentNames []string `json:"environmentNames"`
			IsHidden         *bool    `json:"isHidden"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if input.IsHidden == nil || len(input.EnvironmentNames) == 0 || len(input.EnvironmentNames) > 100 {
			writeError(w, http.StatusBadRequest, "environmentNames and isHidden are required")
			return
		}
		observed, err := environments.List(r.Context(), s.store.DB, projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list environments")
			return
		}
		known := make(map[string]bool, len(observed))
		for _, environment := range observed {
			known[environment.Name] = true
		}
		names := make([]string, 0, len(input.EnvironmentNames))
		seen := make(map[string]bool, len(input.EnvironmentNames))
		for _, name := range input.EnvironmentNames {
			name = strings.TrimSpace(name)
			if name == "" || !known[name] || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not update environments")
			return
		}
		defer func() { _ = tx.Rollback() }()
		updated := make([]map[string]any, 0, len(names))
		for _, name := range names {
			if _, err := tx.ExecContext(r.Context(), `
				INSERT INTO project_environment_settings(project_id, name, is_hidden)
				VALUES (?, ?, ?) ON CONFLICT(project_id, name) DO UPDATE SET is_hidden = excluded.is_hidden, updated_at = CURRENT_TIMESTAMP`, projectID, name, boolInteger(*input.IsHidden)); err != nil {
				writeError(w, http.StatusInternalServerError, "could not update environments")
				return
			}
			updated = append(updated, sentryProjectEnvironmentResponse(organizationID, sentryEnvironment{Name: name, IsHidden: *input.IsHidden}))
		}
		if err := tx.Commit(); err != nil {
			writeError(w, http.StatusInternalServerError, "could not update environments")
			return
		}
		writeJSON(w, http.StatusOK, updated)
		return
	}
	visibility, ok := sentryEnvironmentVisibility(w, r)
	if !ok {
		return
	}
	environments, err := environments.List(r.Context(), s.store.DB, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list environments")
		return
	}
	items := make([]map[string]any, 0, len(environments))
	for _, environment := range environments {
		if visibility == "visible" && environment.IsHidden || visibility == "hidden" && !environment.IsHidden {
			continue
		}
		items = append(items, sentryProjectEnvironmentResponse(organizationID, environment))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryProjectEnvironmentDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "environment not found")
		return
	}
	name := strings.TrimSpace(r.PathValue("environment"))
	environments, err := environments.List(r.Context(), s.store.DB, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load environment")
		return
	}
	var selected sentryEnvironment
	found := false
	for _, environment := range environments {
		if environment.Name == name {
			selected, found = environment, true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "environment not found")
		return
	}
	if r.Method == http.MethodPut {
		if !s.canWriteProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		var input struct {
			IsHidden *bool `json:"isHidden"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if input.IsHidden == nil {
			writeError(w, http.StatusBadRequest, "isHidden is required")
			return
		}
		if _, err := s.store.DB.ExecContext(r.Context(), `
			INSERT INTO project_environment_settings(project_id, name, is_hidden)
			VALUES (?, ?, ?) ON CONFLICT(project_id, name) DO UPDATE SET is_hidden = excluded.is_hidden, updated_at = CURRENT_TIMESTAMP`, projectID, name, boolInteger(*input.IsHidden)); err != nil {
			writeError(w, http.StatusInternalServerError, "could not update environment")
			return
		}
		selected.IsHidden = *input.IsHidden
	}
	writeJSON(w, http.StatusOK, sentryProjectEnvironmentResponse(organizationID, selected))
}

func sentryEnvironmentVisibility(w http.ResponseWriter, r *http.Request) (string, bool) {
	visibility := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("visibility")))
	if visibility == "" {
		visibility = "visible"
	}
	if visibility != "visible" && visibility != "hidden" && visibility != "all" {
		writeError(w, http.StatusBadRequest, "visibility must be visible, hidden, or all")
		return "", false
	}
	return visibility, true
}

func sentryEnvironmentID(organizationID, name string) string {
	digest := sha256.Sum256([]byte(organizationID + "\x00" + name))
	return hex.EncodeToString(digest[:16])
}

func sentryProjectEnvironmentResponse(organizationID string, environment sentryEnvironment) map[string]any {
	return map[string]any{"id": sentryEnvironmentID(organizationID, environment.Name), "name": environment.Name, "isHidden": environment.IsHidden}
}
