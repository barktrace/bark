package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/eventtags"
)

func (s *Server) sentryProjectTags(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	s.writeSentryTags(w, r, projectID, "")
}

func (s *Server) sentryIssueTags(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issue, err := s.loadSentryIssue(r, r.PathValue("issue_id"))
	if err != nil || !s.canAccessProject(r, principal, issue.ProjectID) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if organizationSlug := strings.TrimSpace(r.PathValue("org_slug")); organizationSlug != "" && organizationSlug != issue.OrganizationSlug && organizationSlug != issue.OrganizationID {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	s.writeSentryTags(w, r, issue.ProjectID, issue.ID)
}

func (s *Server) writeSentryTags(w http.ResponseWriter, r *http.Request, projectID, issueID string) {
	tags, err := eventtags.List(r.Context(), s.store.DB, projectID, issueID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not aggregate event tags")
		return
	}
	key := strings.TrimSpace(r.PathValue("tag_key"))
	if key == "" {
		items := make([]map[string]any, 0, len(tags))
		for _, tag := range tags {
			items = append(items, map[string]any{
				"key": tag.Key, "name": tag.Name, "totalValues": tag.TotalValues, "uniqueValues": len(tag.Values),
			})
		}
		writeJSON(w, http.StatusOK, items)
		return
	}

	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("per_page")); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "per_page must be between 1 and 100")
			return
		}
		limit = parsed
	}
	items := make([]map[string]any, 0)
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
	for _, tag := range tags {
		if tag.Key != key {
			continue
		}
		for _, value := range tag.Values {
			if search != "" && !strings.Contains(strings.ToLower(value.Value), search) {
				continue
			}
			if len(items) == limit {
				break
			}
			items = append(items, map[string]any{
				"key": value.Value, "value": value.Value, "name": value.Value, "count": value.Count,
				"firstSeen": normalizeAPITime(value.FirstSeen), "lastSeen": normalizeAPITime(value.LastSeen),
			})
		}
		break
	}
	writeJSON(w, http.StatusOK, items)
}
