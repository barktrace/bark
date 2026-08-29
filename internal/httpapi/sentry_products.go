package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/auth"
)

type sentryAttachmentRecord struct {
	ID             string
	EventID        string
	BlobID         string
	StorageKey     string
	Filename       string
	AttachmentType string
	ContentType    string
	Checksum       string
	Size           int64
	CreatedAt      string
}

func (s *Server) sentryProjectFeedback(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	limit := boundedSentryPageSize(r, 100)
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT id, event_id, name, email, comments, url, created_at
		FROM user_feedback WHERE project_id = ?
		ORDER BY created_at DESC, id DESC LIMIT ?`, projectID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list user feedback")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		item, scanErr := scanSentryFeedback(rows)
		if scanErr != nil {
			writeError(w, http.StatusInternalServerError, "could not list user feedback")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryProjectFeedbackDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "feedback not found")
		return
	}
	if r.Method == http.MethodDelete {
		if !s.canWriteProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		result, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM user_feedback WHERE id = ? AND project_id = ?`, r.PathValue("feedback_id"), projectID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete user feedback")
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			writeError(w, http.StatusNotFound, "feedback not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	row := s.store.DB.QueryRowContext(r.Context(), `
		SELECT id, event_id, name, email, comments, url, created_at
		FROM user_feedback WHERE id = ? AND project_id = ?`, r.PathValue("feedback_id"), projectID)
	item, err := scanSentryFeedback(row)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "feedback not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load user feedback")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type rowScanner interface {
	Scan(...any) error
}

func scanSentryFeedback(row rowScanner) (map[string]any, error) {
	var id, eventID, name, email, comments, targetURL, createdAt string
	if err := row.Scan(&id, &eventID, &name, &email, &comments, &targetURL, &createdAt); err != nil {
		return nil, err
	}
	return map[string]any{
		"id": id, "eventID": eventID, "name": name, "email": email,
		"comments": comments, "url": targetURL, "dateCreated": normalizeAPITime(createdAt),
	}, nil
}

func (s *Server) sentryEventAttachments(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	var canonicalEventID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT event_id FROM events WHERE project_id = ? AND (id = ? OR event_id = ?) LIMIT 1`, projectID, r.PathValue("event_id"), r.PathValue("event_id")).Scan(&canonicalEventID); err != nil {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	filterClause := ""
	arguments := []any{projectID, canonicalEventID}
	if strings.EqualFold(query, "is:screenshot") {
		filterClause = " AND a.attachment_type = ?"
		arguments = append(arguments, "event.screenshot")
	} else if query != "" {
		if strings.Contains(query, ":") {
			writeJSON(w, http.StatusOK, []map[string]any{})
			return
		}
		filterClause = " AND LOWER(a.filename) LIKE ?"
		arguments = append(arguments, "%"+strings.ToLower(query)+"%")
	}
	arguments = append(arguments, boundedSentryPageSize(r, 100))
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT a.id, e.event_id, a.blob_id, b.storage_key, a.filename, a.attachment_type,
		       b.content_type, b.checksum, b.size, a.created_at
		FROM event_attachments a
		JOIN blobs b ON b.id = a.blob_id
		JOIN events e ON e.id = a.event_id
		WHERE e.project_id = ? AND e.event_id = ?`+filterClause+`
		ORDER BY a.filename, a.id LIMIT ?`, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list attachments")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		attachment, scanErr := scanSentryAttachment(rows)
		if scanErr != nil {
			writeError(w, http.StatusInternalServerError, "could not list attachments")
			return
		}
		items = append(items, sentryAttachmentResponse(attachment))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryEventAttachmentDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "attachment not found")
		return
	}
	attachment, err := scanSentryAttachment(s.store.DB.QueryRowContext(r.Context(), `
		SELECT a.id, e.event_id, a.blob_id, b.storage_key, a.filename, a.attachment_type,
		       b.content_type, b.checksum, b.size, a.created_at
		FROM event_attachments a
		JOIN blobs b ON b.id = a.blob_id
		JOIN events e ON e.id = a.event_id
		WHERE a.id = ? AND e.project_id = ? AND (e.id = ? OR e.event_id = ?)`,
		r.PathValue("attachment_id"), projectID, r.PathValue("event_id"), r.PathValue("event_id")))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "attachment not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load attachment")
		return
	}
	if r.Method == http.MethodDelete {
		if !s.canWriteProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		tx, txErr := s.store.DB.BeginTx(r.Context(), nil)
		if txErr == nil {
			_, txErr = tx.ExecContext(r.Context(), `DELETE FROM event_attachments WHERE id = ?`, attachment.ID)
		}
		if txErr == nil {
			_, txErr = tx.ExecContext(r.Context(), `DELETE FROM blobs WHERE id = ?`, attachment.BlobID)
		}
		if txErr == nil {
			txErr = tx.Commit()
		} else if tx != nil {
			_ = tx.Rollback()
		}
		if txErr != nil {
			writeError(w, http.StatusInternalServerError, "could not delete attachment")
			return
		}
		s.removeBlobIfUnreferenced(r.Context(), attachment.StorageKey)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if requestedAttachmentDownload(r) {
		s.serveBlob(w, r, attachment.StorageKey, attachment.ContentType, attachment.Filename)
		return
	}
	writeJSON(w, http.StatusOK, sentryAttachmentResponse(attachment))
}

func scanSentryAttachment(row rowScanner) (sentryAttachmentRecord, error) {
	var attachment sentryAttachmentRecord
	err := row.Scan(&attachment.ID, &attachment.EventID, &attachment.BlobID, &attachment.StorageKey, &attachment.Filename,
		&attachment.AttachmentType, &attachment.ContentType, &attachment.Checksum, &attachment.Size, &attachment.CreatedAt)
	return attachment, err
}

func sentryAttachmentResponse(attachment sentryAttachmentRecord) map[string]any {
	return map[string]any{
		"id": attachment.ID, "event_id": attachment.EventID, "name": attachment.Filename, "type": attachment.AttachmentType,
		"mimetype": attachment.ContentType, "size": attachment.Size, "sha1": nil, "dateCreated": normalizeAPITime(attachment.CreatedAt),
		"headers": map[string]string{"Content-Type": attachment.ContentType},
	}
}

func boundedSentryPageSize(r *http.Request, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("per_page")))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > 200 {
		return 200
	}
	return value
}

func requestedAttachmentDownload(r *http.Request) bool {
	_, present := r.URL.Query()["download"]
	return present
}
