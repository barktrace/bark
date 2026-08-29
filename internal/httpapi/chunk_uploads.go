package httpapi

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/blobstore"
	"github.com/google/uuid"
)

const (
	chunkSize       = 1 << 20
	chunkRequestMax = 32 << 20
)

func (s *Server) sentryChunkUpload(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"url":              strings.TrimRight(s.cfg.PublicURL, "/") + "/api/0/organizations/" + r.PathValue("org_slug") + "/chunk-upload/",
			"chunksPerRequest": 32,
			"maxRequestSize":   chunkRequestMax,
			"maxFileSize":      blobstore.MaxBlobBytes,
			"maxWait":          30,
			"hashAlgorithm":    "sha1",
			"chunkSize":        chunkSize,
			"concurrency":      2,
			"compression":      []string{"gzip"},
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, chunkRequestMax+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "multipart chunk upload required")
		return
	}
	uploaded := 0
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid multipart chunk upload")
			return
		}
		checksum := strings.ToLower(strings.TrimSpace(part.FileName()))
		if !validSHA1(checksum) || (part.FormName() != "file" && part.FormName() != "file_gzip") {
			_ = part.Close()
			writeError(w, http.StatusBadRequest, "chunk filename must be its SHA1 checksum")
			return
		}
		var source io.Reader = part
		var compressed *gzip.Reader
		if part.FormName() == "file_gzip" {
			compressed, err = gzip.NewReader(part)
			if err != nil {
				_ = part.Close()
				writeError(w, http.StatusBadRequest, "invalid gzip chunk")
				return
			}
			source = compressed
		}
		payload, readErr := io.ReadAll(io.LimitReader(source, chunkSize+1))
		if compressed != nil {
			_ = compressed.Close()
		}
		_ = part.Close()
		if readErr != nil || len(payload) > chunkSize {
			writeError(w, http.StatusRequestEntityTooLarge, "chunk exceeds advertised size")
			return
		}
		digest := sha1.Sum(payload)
		if hex.EncodeToString(digest[:]) != checksum {
			writeError(w, http.StatusBadRequest, "chunk checksum does not match filename")
			return
		}
		if err := s.storeUploadChunk(r.Context(), organizationID, checksum, payload); err != nil {
			writeError(w, http.StatusInternalServerError, "could not store chunk")
			return
		}
		uploaded++
	}
	writeJSON(w, http.StatusOK, map[string]int{"uploaded": uploaded})
}

func (s *Server) storeUploadChunk(ctx context.Context, organizationID, checksum string, payload []byte) error {
	var exists int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_chunks WHERE organization_id = ? AND checksum = ?`, organizationID, checksum).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	stored, err := s.store.Blobs.Put(bytes.NewReader(payload), chunkSize)
	if err != nil {
		return err
	}
	blobID := uuid.NewString()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, 'upload_chunk', ?, ?, ?, 'application/octet-stream')`, blobID, organizationID, stored.Key, stored.Checksum, stored.Size); err == nil {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `INSERT INTO upload_chunks(organization_id, checksum, blob_id, size) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`, organizationID, checksum, blobID, stored.Size)
		if err == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				_, err = tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID)
			}
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
	}
	return err
}

type chunkAssemblyRequest struct {
	Checksum string   `json:"checksum"`
	Chunks   []string `json:"chunks"`
	Projects []string `json:"projects"`
	Version  string   `json:"version"`
	Dist     string   `json:"dist"`
}

func (s *Server) assembleArtifactBundle(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var input chunkAssemblyRequest
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Checksum = strings.ToLower(strings.TrimSpace(input.Checksum))
	if !validSHA1(input.Checksum) || len(input.Chunks) == 0 || len(input.Chunks) > 1000 || len(input.Projects) == 0 {
		writeError(w, http.StatusBadRequest, "valid checksum, chunks, and projects are required")
		return
	}
	projectIDs, ok := s.authorizedProjectSlugs(r, principal, organizationID, input.Projects)
	if !ok {
		writeError(w, http.StatusBadRequest, "one or more projects are unknown or not writable")
		return
	}
	payload, missing, err := s.assembleChunks(r.Context(), organizationID, input.Chunks)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": err.Error()})
		return
	}
	if len(missing) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"state": "not_found", "missingChunks": missing, "detail": nil})
		return
	}
	digest := sha1.Sum(payload)
	if hex.EncodeToString(digest[:]) != input.Checksum {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": "assembled artifact checksum mismatch"})
		return
	}
	files, err := parseArtifactBundle(payload)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": err.Error()})
		return
	}
	for _, projectID := range projectIDs {
		releaseID, err := s.ensureArtifactRelease(r, organizationID, projectID, input.Version)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": "could not link artifact release"})
			return
		}
		for _, file := range files {
			if _, err := s.storeArtifactBytes(r.Context(), organizationID, projectID, releaseID, file.Name, file.Kind, file.DebugID, input.Dist, file.ContentType, file.Payload); err != nil {
				writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": "could not index artifact bundle"})
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "ok", "missingChunks": []string{}, "detail": nil})
}

type artifactBundleFile struct {
	Name, Kind, DebugID, ContentType string
	Payload                          []byte
}

func parseArtifactBundle(payload []byte) ([]artifactBundleFile, error) {
	archivePayload := payload
	if len(payload) >= 8 && string(payload[:4]) == "SYSB" {
		archivePayload = payload[8:]
	}
	archive, err := zip.NewReader(bytes.NewReader(archivePayload), int64(len(archivePayload)))
	if err != nil {
		return nil, errors.New("artifact bundle is not a valid source bundle")
	}
	manifestFile, err := archive.Open("manifest.json")
	if err != nil {
		return nil, errors.New("artifact bundle has no manifest")
	}
	var manifest struct {
		DebugID string `json:"debug_id"`
		Files   map[string]struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"files"`
	}
	err = json.NewDecoder(io.LimitReader(manifestFile, 4<<20)).Decode(&manifest)
	_ = manifestFile.Close()
	if err != nil || len(manifest.Files) == 0 || len(manifest.Files) > 10000 {
		return nil, errors.New("artifact bundle manifest is invalid")
	}
	files := make([]artifactBundleFile, 0, len(manifest.Files))
	var total int64
	for archiveName, info := range manifest.Files {
		if path.Clean(archiveName) != archiveName || strings.HasPrefix(archiveName, "/") || strings.HasPrefix(archiveName, "../") {
			return nil, errors.New("artifact bundle contains an unsafe path")
		}
		entry, err := archive.Open(archiveName)
		if err != nil {
			return nil, errors.New("artifact bundle manifest references a missing file")
		}
		contents, readErr := io.ReadAll(io.LimitReader(entry, (20<<20)+1))
		_ = entry.Close()
		if readErr != nil || len(contents) > 20<<20 {
			return nil, errors.New("artifact bundle file is too large")
		}
		total += int64(len(contents))
		if total > blobstore.MaxBlobBytes {
			return nil, errors.New("artifact bundle expands beyond the storage limit")
		}
		kind := "source"
		if info.Type == "source_map" {
			kind = "sourcemap"
		}
		name := strings.TrimSpace(info.URL)
		if name == "" {
			name = strings.TrimPrefix(archiveName, "files/")
		}
		contentType := "application/javascript"
		if kind == "sourcemap" {
			contentType = "application/json"
		}
		files = append(files, artifactBundleFile{Name: name, Kind: kind, DebugID: manifest.DebugID, ContentType: contentType, Payload: contents})
	}
	return files, nil
}

func (s *Server) assembleDebugFiles(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	var input map[string]struct {
		Name    string   `json:"name"`
		DebugID string   `json:"debug_id"`
		Chunks  []string `json:"chunks"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if len(input) == 0 || len(input) > 1000 {
		writeError(w, http.StatusBadRequest, "one to 1000 debug files are required")
		return
	}
	response := make(map[string]any, len(input))
	for checksum, file := range input {
		checksum = strings.ToLower(checksum)
		payload, missing, err := s.assembleChunks(r.Context(), organizationID, file.Chunks)
		if err != nil {
			response[checksum] = map[string]any{"state": "error", "missingChunks": []string{}, "detail": err.Error(), "dif": nil}
			continue
		}
		if len(missing) > 0 {
			response[checksum] = map[string]any{"state": "not_found", "missingChunks": missing, "detail": nil, "dif": nil}
			continue
		}
		digest := sha1.Sum(payload)
		if !validSHA1(checksum) || hex.EncodeToString(digest[:]) != checksum {
			response[checksum] = map[string]any{"state": "error", "missingChunks": []string{}, "detail": "assembled debug file checksum mismatch", "dif": nil}
			continue
		}
		artifact, err := s.storeArtifactBytes(r.Context(), organizationID, projectID, "", file.Name, "debug_file", file.DebugID, "", "application/octet-stream", payload)
		if err != nil {
			response[checksum] = map[string]any{"state": "error", "missingChunks": []string{}, "detail": "could not index debug file", "dif": nil}
			continue
		}
		dif := map[string]any{"objectName": file.Name, "cpuName": "unknown", "sha1": checksum, "data": map[string]any{}}
		if file.DebugID != "" {
			dif["debugId"] = file.DebugID
		}
		response[checksum] = map[string]any{"state": "ok", "missingChunks": []string{}, "detail": nil, "dif": dif, "artifactId": artifact["id"]}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) assembleChunks(ctx context.Context, organizationID string, checksums []string) ([]byte, []string, error) {
	if len(checksums) == 0 || len(checksums) > 1000 {
		return nil, nil, errors.New("invalid chunk list")
	}
	type chunk struct{ checksum, key string }
	chunks := make([]chunk, 0, len(checksums))
	missing := make([]string, 0)
	for _, rawChecksum := range checksums {
		checksum := strings.ToLower(strings.TrimSpace(rawChecksum))
		if !validSHA1(checksum) {
			return nil, nil, errors.New("invalid chunk checksum")
		}
		var key string
		err := s.store.DB.QueryRowContext(ctx, `SELECT b.storage_key FROM upload_chunks c JOIN blobs b ON b.id = c.blob_id WHERE c.organization_id = ? AND c.checksum = ?`, organizationID, checksum).Scan(&key)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, checksum)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		chunks = append(chunks, chunk{checksum: checksum, key: key})
	}
	if len(missing) > 0 {
		return nil, missing, nil
	}
	var assembled bytes.Buffer
	for _, item := range chunks {
		file, err := s.store.Blobs.Open(item.key)
		if err != nil {
			return nil, nil, fmt.Errorf("open chunk %s: %w", item.checksum, err)
		}
		_, copyErr := io.Copy(&assembled, io.LimitReader(file, chunkSize+1))
		_ = file.Close()
		if copyErr != nil || int64(assembled.Len()) > blobstore.MaxBlobBytes {
			return nil, nil, errors.New("assembled upload exceeds storage limit")
		}
	}
	return assembled.Bytes(), nil, nil
}

func (s *Server) storeArtifactBytes(ctx context.Context, organizationID, projectID, releaseID, name, kind, debugID, dist, contentType string, payload []byte) (map[string]any, error) {
	name = strings.TrimSpace(name)
	kind = artifactType(kind, name)
	if name == "" || len(name) > 2048 || kind == "" {
		return nil, errors.New("invalid artifact metadata")
	}
	stored, err := s.store.Blobs.Put(bytes.NewReader(payload), blobstore.MaxBlobBytes)
	if err != nil {
		return nil, err
	}
	blobID, artifactID := uuid.NewString(), uuid.NewString()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return nil, err
	}
	defer tx.Rollback()
	var oldBlobID, oldStorageKey, oldChecksum sql.NullString
	_ = tx.QueryRowContext(ctx, `SELECT a.blob_id, b.storage_key, b.checksum FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id WHERE a.project_id = ? AND COALESCE(a.release_id, '') = ? AND a.name = ? AND a.dist = ?`, projectID, releaseID, name, dist).Scan(&oldBlobID, &oldStorageKey, &oldChecksum)
	if oldChecksum.Valid && oldChecksum.String == stored.Checksum {
		if err := tx.QueryRowContext(ctx, `SELECT id FROM project_artifacts WHERE project_id = ? AND COALESCE(release_id, '') = ? AND name = ? AND dist = ?`, projectID, releaseID, name, dist).Scan(&artifactID); err != nil {
			return nil, err
		}
		_ = tx.Rollback()
		return map[string]any{"id": artifactID, "name": name, "artifact_type": kind, "sha1": stored.Checksum, "size": stored.Size, "dist": dist}, nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, 'artifact', ?, ?, ?, ?)`, blobID, organizationID, projectID, stored.Key, stored.Checksum, stored.Size, contentType); err == nil {
		err = tx.QueryRowContext(ctx, `INSERT INTO project_artifacts(id, project_id, release_id, blob_id, name, artifact_type, debug_id, dist) VALUES (?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?) ON CONFLICT (project_id, (COALESCE(release_id, '')), name, dist) DO UPDATE SET blob_id = excluded.blob_id, artifact_type = excluded.artifact_type, debug_id = excluded.debug_id, created_at = CURRENT_TIMESTAMP RETURNING id`, artifactID, projectID, releaseID, blobID, name, kind, strings.TrimSpace(debugID), strings.TrimSpace(dist)).Scan(&artifactID)
	}
	if err == nil && oldBlobID.Valid {
		_, err = tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, oldBlobID.String)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return nil, err
	}
	if oldStorageKey.Valid {
		s.removeBlobIfUnreferenced(context.Background(), oldStorageKey.String)
	}
	return map[string]any{"id": artifactID, "name": name, "artifact_type": kind, "sha1": stored.Checksum, "size": stored.Size, "dist": dist, "dateCreated": time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func (s *Server) removeBlobIfUnreferenced(ctx context.Context, storageKey string) {
	var references int
	if err := s.store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE storage_key = ?`, storageKey).Scan(&references); err == nil && references == 0 {
		_ = s.store.Blobs.Remove(storageKey)
	}
}

func (s *Server) authorizedOrganizationSlug(r *http.Request, principal *auth.Principal, slug string) (string, bool) {
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM organizations WHERE slug = ?`, slug).Scan(&organizationID); err != nil {
		return "", false
	}
	_, ok := principal.Membership(organizationID)
	return organizationID, ok
}

func (s *Server) authorizedProjectSlugs(r *http.Request, principal *auth.Principal, organizationID string, slugs []string) ([]string, bool) {
	projectIDs := make([]string, 0, len(slugs))
	seen := make(map[string]bool)
	for _, slug := range slugs {
		if seen[slug] {
			continue
		}
		seen[slug] = true
		var projectID string
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? AND slug = ?`, organizationID, slug).Scan(&projectID); err != nil || !s.canManageProject(r, principal, projectID) {
			return nil, false
		}
		projectIDs = append(projectIDs, projectID)
	}
	return projectIDs, len(projectIDs) > 0
}

func validSHA1(value string) bool {
	if len(value) != sha1.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
