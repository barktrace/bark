package httpapi

import (
	"net/http"
	"strings"

	"github.com/barktrace/bark/internal/auth"
)

var quotaCategories = map[string]bool{
	"all": true, "error": true, "transaction": true, "span": true, "log": true,
	"session": true, "attachment": true, "feedback": true, "replay": true,
	"profile": true, "metric": true, "check_in": true,
}

func (s *Server) projectQuotas(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT category, per_minute, per_day, max_item_bytes FROM project_quotas WHERE project_id = ? ORDER BY category`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list quotas")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var category string
		var perMinute, perDay, maxItemBytes int64
		if rows.Scan(&category, &perMinute, &perDay, &maxItemBytes) == nil {
			items = append(items, map[string]any{"category": category, "per_minute": perMinute, "per_day": perDay, "max_item_bytes": maxItemBytes})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"default_per_minute": s.cfg.RateLimitPerMinute, "quotas": items})
}

func (s *Server) updateProjectQuota(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, category := r.PathValue("project_id"), strings.ToLower(r.PathValue("category"))
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if !quotaCategories[category] {
		writeError(w, http.StatusBadRequest, "unsupported quota category")
		return
	}
	var input struct {
		PerMinute    int64 `json:"per_minute"`
		PerDay       int64 `json:"per_day"`
		MaxItemBytes int64 `json:"max_item_bytes"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if input.PerMinute < 0 || input.PerDay < 0 || input.MaxItemBytes < 0 || input.MaxItemBytes > 100<<20 {
		writeError(w, http.StatusBadRequest, "quota values are outside allowed ranges")
		return
	}
	if input.PerMinute == 0 && input.PerDay == 0 && input.MaxItemBytes == 0 {
		_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM project_quotas WHERE project_id = ? AND category = ?`, projectID, category)
	} else {
		_, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO project_quotas(project_id, category, per_minute, per_day, max_item_bytes) VALUES (?, ?, ?, ?, ?) ON CONFLICT(project_id, category) DO UPDATE SET per_minute = excluded.per_minute, per_day = excluded.per_day, max_item_bytes = excluded.max_item_bytes`, projectID, category, input.PerMinute, input.PerDay, input.MaxItemBytes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not update quota")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"project_id": projectID, "category": category, "per_minute": input.PerMinute, "per_day": input.PerDay, "max_item_bytes": input.MaxItemBytes})
}
