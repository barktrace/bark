package httpapi

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/auth"
)

func (s *Server) ingestionJobs(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && status != "pending" && status != "processing" && status != "done" && status != "dead" {
		writeError(w, http.StatusBadRequest, "unsupported ingestion status")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT j.id, j.category, j.status, j.attempts, j.available_at, COALESCE(j.lease_expires_at, ''), j.last_error, j.created_at, COALESCE(j.processed_at, ''), COALESCE(b.size, 0)
		FROM ingestion_jobs j LEFT JOIN blobs b ON b.id = j.blob_id
		WHERE j.project_id = ? AND (? = '' OR j.status = ?)
		ORDER BY j.created_at DESC LIMIT ?
	`, projectID, status, status, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list ingestion jobs")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, category, itemStatus, availableAt, leaseExpiresAt, lastError, createdAt, processedAt string
		var attempts, size int64
		if rows.Scan(&id, &category, &itemStatus, &attempts, &availableAt, &leaseExpiresAt, &lastError, &createdAt, &processedAt, &size) == nil {
			items = append(items, map[string]any{"id": id, "category": category, "status": itemStatus, "attempts": attempts, "available_at": availableAt, "lease_expires_at": leaseExpiresAt, "last_error": lastError, "created_at": createdAt, "processed_at": processedAt, "payload_bytes": size})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": items})
}

func (s *Server) retryIngestionJob(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	jobID := r.PathValue("job_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM ingestion_jobs WHERE id = ?`, jobID).Scan(&projectID); err != nil {
		writeError(w, http.StatusNotFound, "ingestion job not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if err := s.ingest.RetryJob(r.Context(), jobID); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusConflict, "only dead ingestion jobs can be retried")
		} else {
			writeError(w, http.StatusInternalServerError, "could not retry ingestion job")
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": jobID, "status": "pending"})
}

func (s *Server) deleteIngestionJob(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	jobID := r.PathValue("job_id")
	var projectID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id FROM ingestion_jobs WHERE id = ?`, jobID).Scan(&projectID); err != nil {
		writeError(w, http.StatusNotFound, "ingestion job not found")
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if err := s.ingest.DeleteJob(r.Context(), jobID); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusConflict, "only completed or dead ingestion jobs can be deleted")
		} else {
			writeError(w, http.StatusInternalServerError, "could not delete ingestion job")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
