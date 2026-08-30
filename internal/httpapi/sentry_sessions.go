package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/releasehealth"
)

func (s *Server) sentryOrganizationSessions(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	projectIDs, err = s.filterSessionProjects(r, projectIDs, compactQueryValues(r.URL.Query()["project"]))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not filter projects")
		return
	}
	start, end, err := releasehealth.ParseRange(time.Now().UTC(), r.URL.Query().Get("start"), r.URL.Query().Get("end"), r.URL.Query().Get("statsPeriod"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	interval, err := releasehealth.ParseInterval(r.URL.Query().Get("interval"), end.Sub(start))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := releasehealth.Query(r.Context(), s.store.DB, releasehealth.Request{
		ProjectIDs: projectIDs, Environments: compactQueryValues(r.URL.Query()["environment"]),
		Releases: compactQueryValues(r.URL.Query()["release"]), Fields: compactQueryValues(r.URL.Query()["field"]),
		GroupBy: compactQueryValues(r.URL.Query()["groupBy"]), Start: start, End: end, Interval: interval,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	intervals := make([]string, len(result.Intervals))
	for index, value := range result.Intervals {
		intervals[index] = value.UTC().Format(time.RFC3339)
	}
	groups := make([]map[string]any, 0, len(result.Groups))
	for _, group := range result.Groups {
		groups = append(groups, map[string]any{"by": group.By, "totals": group.Totals, "series": group.Series})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"start": result.Start.UTC().Format(time.RFC3339), "end": result.End.UTC().Format(time.RFC3339),
		"query": strings.TrimSpace(r.URL.Query().Get("query")), "intervals": intervals, "groups": groups,
	})
}

func (s *Server) filterSessionProjects(r *http.Request, accessible, selectors []string) ([]string, error) {
	if len(selectors) == 0 || len(accessible) == 0 {
		return accessible, nil
	}
	wanted := make(map[string]bool, len(selectors))
	for _, selector := range selectors {
		wanted[selector] = true
	}
	query := `SELECT id, sentry_id, slug FROM projects WHERE id IN (` + queryPlaceholders(len(accessible)) + `)`
	arguments := make([]any, len(accessible))
	for index, projectID := range accessible {
		arguments[index] = projectID
	}
	rows, err := s.store.DB.QueryContext(r.Context(), query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	selected := make([]string, 0, len(accessible))
	for rows.Next() {
		var id, sentryID, slug string
		if err := rows.Scan(&id, &sentryID, &slug); err != nil {
			return nil, err
		}
		if wanted[id] || wanted[sentryID] || wanted[slug] {
			selected = append(selected, id)
		}
	}
	return selected, rows.Err()
}
