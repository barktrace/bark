package httpapi

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/blobstore"
	"github.com/barktrace/bark/internal/symbolicate"
	"github.com/google/uuid"
)

func (s *Server) projectArtifacts(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	items, err := s.listArtifacts(r, projectID, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list artifacts")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) uploadProjectArtifact(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	s.uploadArtifact(w, r, projectID, strings.TrimSpace(r.URL.Query().Get("release")))
}

func (s *Server) sentryReleaseArtifacts(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if _, allowed := principal.Membership(organizationID); !allowed {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	version := r.PathValue("version")
	if r.Method == http.MethodGet {
		items, err := s.listArtifacts(r, projectID, version)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list release files")
			return
		}
		writeJSON(w, http.StatusOK, items)
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	s.uploadArtifact(w, r, projectID, version)
}

func (s *Server) sentryReleaseArtifactDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	artifactID := r.PathValue("file_id")
	var blobID, storageKey, name, contentType, checksum, dist, createdAt string
	var size int64
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT a.blob_id, b.storage_key, a.name, b.content_type, b.checksum, b.size, a.dist, a.created_at
		FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id JOIN releases rel ON rel.id = a.release_id
		WHERE a.id = ? AND a.project_id = ? AND rel.version = ?
	`, artifactID, projectID, r.PathValue("version")).Scan(&blobID, &storageKey, &name, &contentType, &checksum, &size, &dist, &createdAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "release file not found")
		return
	}
	if r.Method == http.MethodGet {
		if _, download := r.URL.Query()["download"]; download {
			file, err := s.store.Blobs.Open(storageKey)
			if err != nil {
				writeError(w, http.StatusNotFound, "release file content not found")
				return
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not read release file")
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filepath.Base(name), `"`, "")+`"`)
			http.ServeContent(w, r, name, info.ModTime(), file)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": artifactID, "name": name, "sha1": checksum, "size": size, "dist": dist, "dateCreated": normalizeAPITime(createdAt), "headers": map[string]string{}})
		return
	}
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	if r.Method == http.MethodPut {
		var input struct {
			Name string `json:"name"`
			Dist string `json:"dist"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		input.Name = strings.TrimSpace(input.Name)
		if input.Name == "" || len(input.Name) > 2048 {
			writeError(w, http.StatusBadRequest, "valid file name is required")
			return
		}
		if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE project_artifacts SET name = ?, dist = ? WHERE id = ?`, input.Name, strings.TrimSpace(input.Dist), artifactID); err != nil {
			writeError(w, http.StatusConflict, "could not update release file")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": artifactID, "name": input.Name, "sha1": checksum, "size": size, "dist": strings.TrimSpace(input.Dist), "dateCreated": normalizeAPITime(createdAt), "headers": map[string]string{}})
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM blobs WHERE id = ?`, blobID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete release file")
		return
	}
	s.removeBlobIfUnreferenced(r.Context(), storageKey)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) uploadArtifact(w http.ResponseWriter, r *http.Request, projectID, version string) {
	r.Body = http.MaxBytesReader(w, r.Body, blobstore.MaxBlobBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart artifact upload")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()
	name := strings.TrimSpace(firstNonEmpty(r.FormValue("name"), header.Filename))
	if name == "" || len(name) > 2048 {
		writeError(w, http.StatusBadRequest, "artifact name is required and limited to 2048 characters")
		return
	}
	kind := artifactType(firstNonEmpty(r.FormValue("artifact_type"), r.FormValue("type")), name)
	if kind == "" {
		writeError(w, http.StatusBadRequest, "unsupported artifact type")
		return
	}
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID); err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	releaseID, err := s.ensureArtifactRelease(r, organizationID, projectID, version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not link artifact release")
		return
	}
	result, err := s.store.Blobs.Put(file, blobstore.MaxBlobBytes)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	contentType := strings.TrimSpace(header.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	blobID, artifactID := uuid.NewString(), uuid.NewString()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store artifact")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, 'artifact', ?, ?, ?, ?)`, blobID, organizationID, projectID, result.Key, result.Checksum, result.Size, contentType); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store artifact metadata")
		return
	}
	var oldBlobID sql.NullString
	_ = tx.QueryRowContext(r.Context(), `SELECT blob_id FROM project_artifacts WHERE project_id = ? AND COALESCE(release_id, '') = ? AND name = ? AND dist = ?`, projectID, releaseID, name, r.FormValue("dist")).Scan(&oldBlobID)
	debugID := strings.TrimSpace(firstNonEmpty(r.FormValue("debug_id"), r.FormValue("proguard_uuid"), r.FormValue("uuid")))
	err = tx.QueryRowContext(r.Context(), `
		INSERT INTO project_artifacts(id, project_id, release_id, blob_id, name, artifact_type, debug_id, dist)
		VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?)
		ON CONFLICT (project_id, (COALESCE(release_id, '')), name, dist)
		DO UPDATE SET blob_id = excluded.blob_id, artifact_type = excluded.artifact_type, debug_id = excluded.debug_id, created_at = CURRENT_TIMESTAMP
		RETURNING id
	`, artifactID, projectID, releaseID, blobID, name, kind, debugID, strings.TrimSpace(r.FormValue("dist"))).Scan(&artifactID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not index artifact")
		return
	}
	if oldBlobID.Valid && oldBlobID.String != blobID {
		_, _ = tx.ExecContext(r.Context(), `DELETE FROM blobs WHERE id = ?`, oldBlobID.String)
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit artifact")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": artifactID, "name": name, "artifact_type": kind, "sha1": result.Checksum, "size": result.Size, "dist": r.FormValue("dist"), "dateCreated": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) sentryDebugArtifactUpload(w http.ResponseWriter, r *http.Request, kind string) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, blobstore.MaxBlobBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart artifact upload")
		return
	}
	r.Form.Set("artifact_type", kind)
	if r.FormValue("debug_id") == "" {
		r.Form.Set("debug_id", firstNonEmpty(r.FormValue("proguard_uuid"), r.FormValue("uuid")))
	}
	s.uploadArtifact(w, r, projectID, strings.TrimSpace(r.FormValue("version")))
}

func (s *Server) ensureArtifactRelease(r *http.Request, organizationID, projectID, version string) (string, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return "", nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	releaseID := uuid.NewString()
	if err := tx.QueryRowContext(r.Context(), `INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(organization_id, version) DO UPDATE SET last_seen_at = excluded.last_seen_at RETURNING id`, releaseID, organizationID, version, now, now).Scan(&releaseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?) ON CONFLICT(project_id, release_id) DO UPDATE SET last_seen_at = excluded.last_seen_at`, projectID, releaseID, now, now); err != nil {
		return "", err
	}
	return releaseID, tx.Commit()
}

func (s *Server) listArtifacts(r *http.Request, projectID, version string) ([]map[string]any, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT a.id, a.name, a.artifact_type, a.debug_id, a.dist, b.checksum, b.size, b.content_type, a.created_at, COALESCE(rel.version, '')
		FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id LEFT JOIN releases rel ON rel.id = a.release_id
		WHERE a.project_id = ? AND (? = '' OR rel.version = ?) ORDER BY a.created_at DESC
	`, projectID, version, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, kind, debugID, dist, checksum, contentType, createdAt, release string
		var size int64
		if err := rows.Scan(&id, &name, &kind, &debugID, &dist, &checksum, &size, &contentType, &createdAt, &release); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "name": name, "artifact_type": kind, "debug_id": debugID, "dist": dist, "sha1": checksum, "size": size, "content_type": contentType, "dateCreated": createdAt, "release": release})
	}
	return items, rows.Err()
}

func (s *Server) artifactFile(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	artifactID := r.PathValue("artifact_id")
	var projectID, blobID, storageKey, name, contentType string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT a.project_id, a.blob_id, b.storage_key, a.name, b.content_type FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id WHERE a.id = ?`, artifactID).Scan(&projectID, &blobID, &storageKey, &name, &contentType); err != nil {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}
	if !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project access required")
		return
	}
	if r.Method == http.MethodDelete {
		if !s.canManageProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project administrator access required")
			return
		}
		if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM blobs WHERE id = ?`, blobID); err != nil {
			writeError(w, http.StatusInternalServerError, "could not delete artifact")
			return
		}
		var references int
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, storageKey).Scan(&references)
		if references == 0 {
			_ = s.store.Blobs.Remove(storageKey)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	file, err := s.store.Blobs.Open(storageKey)
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact content not found")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read artifact")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filepath.Base(name), `"`, "")+`"`)
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func (s *Server) reprocessProject(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID := r.PathValue("project_id")
	if !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "project administrator access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, COALESCE(release_id, ''), payload FROM events WHERE project_id = ? ORDER BY received_at DESC LIMIT 10000`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load events")
		return
	}
	type event struct {
		id, releaseID string
		raw           []byte
	}
	events := make([]event, 0)
	for rows.Next() {
		var item event
		if err := rows.Scan(&item.id, &item.releaseID, &item.raw); err == nil {
			events = append(events, item)
		}
	}
	_ = rows.Close()
	updated := 0
	for _, item := range events {
		processed, changed, err := symbolicate.ProcessEvent(r.Context(), s.store, projectID, item.releaseID, item.raw)
		if err == nil && changed {
			if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE events SET processed_payload = ? WHERE id = ?`, processed, item.id); err == nil {
				updated++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"processed": len(events), "symbolicated": updated})
}

func (s *Server) projectBySlugs(r *http.Request, organizationSlug, projectSlug string) (string, string, bool) {
	var projectID, organizationID string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT p.id, p.organization_id FROM projects p JOIN organizations o ON o.id = p.organization_id WHERE o.slug = ? AND p.slug = ?`, organizationSlug, projectSlug).Scan(&projectID, &organizationID)
	return projectID, organizationID, err == nil
}

func artifactType(requested, name string) string {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested == "source" || requested == "sourcemap" || requested == "debug_file" || requested == "proguard" {
		return requested
	}
	extension := strings.ToLower(filepath.Ext(name))
	switch extension {
	case ".map":
		return "sourcemap"
	case ".js", ".css":
		return "source"
	case ".sym", ".debug", ".dwarf", ".elf", ".so", ".dylib", ".dsym", ".exe", ".dll", ".pdb":
		return "debug_file"
	case ".txt":
		return "proguard"
	default:
		return ""
	}
}
