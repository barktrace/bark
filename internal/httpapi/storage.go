package httpapi

import (
	"net/http"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/maintenance"
)

func (s *Server) storageUsage(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID := r.URL.Query().Get("organization_id")
	if _, ok := principal.Membership(organizationID); !ok {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	var retentionDays int
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT retention_days FROM organizations WHERE id = ?`, organizationID).Scan(&retentionDays); err != nil {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT p.id, p.name,
		       (SELECT COUNT(*) FROM events e WHERE e.project_id = p.id),
		       (SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM events e WHERE e.project_id = p.id),
		       (SELECT COUNT(*) FROM transactions t WHERE t.project_id = p.id),
		       (SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM transactions t WHERE t.project_id = p.id),
		       (SELECT COUNT(*) FROM logs l WHERE l.project_id = p.id),
		       (SELECT COALESCE(SUM(LENGTH(message) + LENGTH(attributes)), 0) FROM logs l WHERE l.project_id = p.id),
		       (SELECT COUNT(*) FROM project_sessions ps WHERE ps.project_id = p.id),
		       (SELECT COUNT(*) FROM spans sp WHERE sp.project_id = p.id)
		FROM projects p WHERE p.organization_id = ? ORDER BY p.name
	`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not calculate storage usage")
		return
	}
	projects := make([]map[string]any, 0)
	totals := map[string]int64{"events": 0, "transactions": 0, "logs": 0, "sessions": 0, "spans": 0, "estimated_bytes": 0}
	for rows.Next() {
		var id, name string
		var events, eventBytes, transactions, transactionBytes, logs, logBytes, sessions, spans int64
		if err := rows.Scan(&id, &name, &events, &eventBytes, &transactions, &transactionBytes, &logs, &logBytes, &sessions, &spans); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not calculate storage usage")
			return
		}
		estimated := eventBytes + transactionBytes + logBytes
		projects = append(projects, map[string]any{"id": id, "name": name, "events": events, "transactions": transactions, "logs": logs, "sessions": sessions, "spans": spans, "estimated_bytes": estimated})
		totals["events"] += events
		totals["transactions"] += transactions
		totals["logs"] += logs
		totals["sessions"] += sessions
		totals["spans"] += spans
		totals["estimated_bytes"] += estimated
	}
	_ = rows.Close()
	var pageCount, pageSize int64
	_ = s.store.DB.QueryRowContext(r.Context(), `PRAGMA page_count`).Scan(&pageCount)
	_ = s.store.DB.QueryRowContext(r.Context(), `PRAGMA page_size`).Scan(&pageSize)
	queue := map[string]int64{"pending": 0, "processing": 0, "dead": 0, "payload_bytes": 0}
	queueRows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT j.status, COUNT(*), COALESCE(SUM(b.size), 0)
		FROM ingestion_jobs j JOIN projects p ON p.id = j.project_id LEFT JOIN blobs b ON b.id = j.blob_id
		WHERE p.organization_id = ? AND j.status != 'done' GROUP BY j.status
	`, organizationID)
	if err == nil {
		for queueRows.Next() {
			var status string
			var count, size int64
			if queueRows.Scan(&status, &count, &size) == nil {
				queue[status] = count
				queue["payload_bytes"] += size
			}
		}
		_ = queueRows.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"retention_days": retentionDays, "database_bytes": pageCount * pageSize, "totals": totals, "ingestion_queue": queue, "projects": projects})
}

func (s *Server) updateRetention(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		OrganizationID string `json:"organization_id"`
		Days           int    `json:"days"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !organizationAdmin(principal, input.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	if input.Days < 1 || input.Days > 3650 {
		writeError(w, http.StatusBadRequest, "retention must be between 1 and 3650 days")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE organizations SET retention_days = ? WHERE id = ?`, input.Days, input.OrganizationID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update retention")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organization_id": input.OrganizationID, "retention_days": input.Days})
}

func (s *Server) cleanupStorage(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	var input struct {
		OrganizationID string   `json:"organization_id"`
		OlderThanDays  int      `json:"older_than_days"`
		DataTypes      []string `json:"data_types"`
		DryRun         bool     `json:"dry_run"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if !organizationAdmin(principal, input.OrganizationID) {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	if input.OlderThanDays < 1 || input.OlderThanDays > 3650 {
		writeError(w, http.StatusBadRequest, "cleanup age must be between 1 and 3650 days")
		return
	}
	for _, dataType := range input.DataTypes {
		if !maintenance.ValidDataType(dataType) {
			writeError(w, http.StatusBadRequest, "unsupported cleanup data type")
			return
		}
	}
	result, err := maintenance.CleanupStore(r.Context(), s.store, input.OrganizationID, time.Now().UTC().Add(-time.Duration(input.OlderThanDays)*24*time.Hour), input.DataTypes, input.DryRun)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not clean storage")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
