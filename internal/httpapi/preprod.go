package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/blobstore"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
)

const (
	snapshotManifestMax = 4 << 20
	snapshotBatchMax    = 128 << 20
	snapshotTokenTTL    = time.Hour
)

type preprodBuildRequest struct {
	Checksum           string   `json:"checksum"`
	Chunks             []string `json:"chunks"`
	BuildConfiguration string   `json:"build_configuration"`
	ReleaseNotes       string   `json:"release_notes"`
	InstallGroups      []string `json:"install_groups"`
	HeadSHA            string   `json:"head_sha"`
	BaseSHA            string   `json:"base_sha"`
	Provider           string   `json:"provider"`
	HeadRepoName       string   `json:"head_repo_name"`
	BaseRepoName       string   `json:"base_repo_name"`
	HeadRef            string   `json:"head_ref"`
	BaseRef            string   `json:"base_ref"`
	PRNumber           *uint32  `json:"pr_number"`
}

// Sentry's build and snapshot routes overlap in a way that Go's ServeMux
// deliberately rejects as ambiguous. Keep one wildcard route and dispatch only
// the small set of documented endpoint shapes here.
func (s *Server) preprodOrganizationRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.PathValue("preprod_path"), "/"), "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "install-details":
		r.SetPathValue("build_id", parts[0])
		s.preprodBuildInstallDetails(w, r)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "download":
		r.SetPathValue("build_id", parts[0])
		s.downloadPreprodBuild(w, r)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "snapshots" && parts[1] == "latest-base":
		s.latestBaseSnapshot(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && len(parts) == 3 && parts[0] == "snapshots" && parts[2] == "archive":
		r.SetPathValue("snapshot_id", parts[1])
		s.snapshotArchive(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) assemblePreprodBuild(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	var input preprodBuildRequest
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Checksum = strings.ToLower(strings.TrimSpace(input.Checksum))
	if !validSHA1(input.Checksum) || len(input.Chunks) == 0 || len(input.Chunks) > 1000 {
		writeError(w, http.StatusBadRequest, "valid checksum and chunks are required")
		return
	}
	payload, missing, err := s.assembleChunks(r.Context(), organizationID, input.Chunks)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": err.Error(), "artifactUrl": nil})
		return
	}
	if len(missing) != 0 {
		writeJSON(w, http.StatusOK, map[string]any{"state": "not_found", "missingChunks": missing, "detail": nil, "artifactUrl": nil})
		return
	}
	digest := sha1.Sum(payload)
	if hex.EncodeToString(digest[:]) != input.Checksum {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": "assembled build checksum mismatch", "artifactUrl": nil})
		return
	}
	buildID, err := s.storePreprodBuild(r.Context(), organizationID, projectID, input, payload)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "error", "missingChunks": []string{}, "detail": "could not store build", "artifactUrl": nil})
		return
	}
	artifactURL := strings.TrimRight(s.cfg.PublicURL, "/") + "/api/0/organizations/" + url.PathEscape(r.PathValue("org_slug")) + "/preprodartifacts/" + buildID + "/install-details/"
	writeJSON(w, http.StatusOK, map[string]any{"state": "ok", "missingChunks": []string{}, "detail": nil, "artifactUrl": artifactURL})
}

func (s *Server) storePreprodBuild(ctx context.Context, organizationID, projectID string, input preprodBuildRequest, payload []byte) (string, error) {
	var existing string
	err := s.store.DB.QueryRowContext(ctx, `SELECT id FROM preprod_builds WHERE project_id = ? AND checksum = ?`, projectID, input.Checksum).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	stored, err := s.store.Blobs.Put(bytes.NewReader(payload), blobstore.MaxBlobBytes)
	if err != nil {
		return "", err
	}
	buildID, blobID := uuid.NewString(), uuid.NewString()
	groups, _ := json.Marshal(input.InstallGroups)
	vcs, _ := json.Marshal(map[string]any{
		"head_sha": input.HeadSHA, "base_sha": input.BaseSHA, "provider": input.Provider,
		"head_repo_name": input.HeadRepoName, "base_repo_name": input.BaseRepoName,
		"head_ref": input.HeadRef, "base_ref": input.BaseRef, "pr_number": input.PRNumber,
	})
	format := detectPreprodBuildFormat(payload)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, 'preprod_build', ?, ?, ?, 'application/zip')`, blobID, organizationID, projectID, stored.Key, stored.Checksum, stored.Size); err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO preprod_builds(id, organization_id, project_id, blob_id, checksum, format, build_configuration, release_notes, install_groups, vcs_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, buildID, organizationID, projectID, blobID, input.Checksum, format, strings.TrimSpace(input.BuildConfiguration), strings.TrimSpace(input.ReleaseNotes), groups, vcs)
	}
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", err
	}
	if err := tx.Commit(); err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", err
	}
	return buildID, nil
}

func detectPreprodBuildFormat(payload []byte) string {
	archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return ""
	}
	for _, extension := range []string{".apk", ".ipa", ".aab"} {
		for _, file := range archive.File {
			if !file.FileInfo().IsDir() && strings.EqualFold(path.Ext(file.Name), extension) {
				return strings.TrimPrefix(extension, ".")
			}
		}
	}
	return ""
}

func (s *Server) preprodBuildInstallDetails(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var format string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT format FROM preprod_builds WHERE id = ? AND organization_id = ?`, r.PathValue("build_id"), organizationID).Scan(&format); err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	installable := format == "apk" || format == "ipa"
	var installURL any
	if installable {
		installURL = strings.TrimRight(s.cfg.PublicURL, "/") + "/api/0/organizations/" + url.PathEscape(r.PathValue("org_slug")) + "/preprodartifacts/" + r.PathValue("build_id") + "/download/?response_format=" + format
	}
	writeJSON(w, http.StatusOK, map[string]any{"isInstallable": installable, "installUrl": installURL})
}

func (s *Server) downloadPreprodBuild(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var storageKey, format string
	var size int64
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT b.storage_key, pb.format, b.size FROM preprod_builds pb JOIN blobs b ON b.id = pb.blob_id WHERE pb.id = ? AND pb.organization_id = ?`, r.PathValue("build_id"), organizationID).Scan(&storageKey, &format, &size); err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	requested := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("response_format")))
	if (format != "apk" && format != "ipa") || (requested != "" && requested != format) {
		writeError(w, http.StatusBadRequest, "build is not available in the requested format")
		return
	}
	file, err := s.store.Blobs.Open(storageKey)
	if err != nil {
		writeError(w, http.StatusNotFound, "build content not found")
		return
	}
	defer file.Close()
	archive, err := zip.NewReader(file, size)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stored build is invalid")
		return
	}
	archive.RegisterDecompressor(93, func(reader io.Reader) io.ReadCloser {
		decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
		if err != nil {
			return io.NopCloser(&errorReader{err: err})
		}
		return &zstdReadCloser{Decoder: decoder}
	})
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() || !strings.EqualFold(path.Ext(entry.Name), "."+format) {
			continue
		}
		content, err := entry.Open()
		if err != nil {
			break
		}
		defer content.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatUint(entry.UncompressedSize64, 10))
		w.Header().Set("Content-Disposition", `attachment; filename="build.`+format+`"`)
		_, _ = io.Copy(w, content)
		return
	}
	writeError(w, http.StatusNotFound, "installable build content not found")
}

type zstdReadCloser struct{ *zstd.Decoder }

func (r *zstdReadCloser) Close() error {
	r.Decoder.Close()
	return nil
}

type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }

type snapshotManifest struct {
	AppID             string                     `json:"app_id"`
	Images            map[string]json.RawMessage `json:"images"`
	DiffThreshold     *float64                   `json:"diff_threshold"`
	Selective         bool                       `json:"selective"`
	AllImageFileNames []string                   `json:"all_image_file_names"`
	HeadSHA           string                     `json:"head_sha"`
	BaseSHA           string                     `json:"base_sha"`
	Provider          string                     `json:"provider"`
	HeadRepoName      string                     `json:"head_repo_name"`
	BaseRepoName      string                     `json:"base_repo_name"`
	HeadRef           string                     `json:"head_ref"`
	BaseRef           string                     `json:"base_ref"`
	PRNumber          *uint32                    `json:"pr_number"`
}

func (s *Server) snapshotUploadOptions(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create upload token")
		return
	}
	token := "bark_os_" + base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().UTC().Add(snapshotTokenTTL).Format(time.RFC3339Nano)
	_, _ = s.store.DB.ExecContext(r.Context(), `DELETE FROM snapshot_upload_tokens WHERE expires_at <= ?`, time.Now().UTC().Format(time.RFC3339Nano))
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO snapshot_upload_tokens(id, token_hash, organization_id, project_id, expires_at) VALUES (?, ?, ?, ?, ?)`, uuid.NewString(), hash[:], organizationID, projectID, expires); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create upload token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"objectstore": map[string]any{
		"url":       strings.TrimRight(s.cfg.PublicURL, "/") + "/api/0/objectstore",
		"scopes":    [][]string{{"org", organizationID}, {"project", projectID}},
		"authToken": token, "expirationPolicy": "manual",
	}})
}

func (s *Server) createPreprodSnapshot(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, organizationID, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	raw, err := readEncodedBody(w, r, snapshotManifestMax)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid snapshot manifest")
		return
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || strings.TrimSpace(manifest.AppID) == "" || len(manifest.Images) > 5000 {
		writeError(w, http.StatusBadRequest, "invalid snapshot manifest")
		return
	}
	for name, metadata := range manifest.Images {
		if !safeArchiveName(name) {
			writeError(w, http.StatusBadRequest, "snapshot contains an invalid image name")
			return
		}
		var image struct {
			ContentHash string `json:"content_hash"`
		}
		if json.Unmarshal(metadata, &image) != nil || !validSHA256(image.ContentHash) {
			writeError(w, http.StatusBadRequest, "snapshot image content_hash is required")
			return
		}
		objectKey := organizationID + "/" + projectID + "/" + strings.ToLower(image.ContentHash)
		var exists int
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM snapshot_objects WHERE project_id = ? AND object_key = ?`, projectID, objectKey).Scan(&exists); err != nil || exists != 1 {
			writeError(w, http.StatusConflict, "snapshot references an image that was not uploaded")
			return
		}
	}
	snapshotID := uuid.NewString()
	if _, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO preprod_snapshots(id, organization_id, project_id, app_id, image_count, manifest, head_sha, base_sha, head_ref, base_ref, pr_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshotID, organizationID, projectID, strings.TrimSpace(manifest.AppID), len(manifest.Images), raw, manifest.HeadSHA, manifest.BaseSHA, manifest.HeadRef, manifest.BaseRef, manifest.PRNumber); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create snapshot")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"artifactId": snapshotID, "imageCount": len(manifest.Images)})
}

func (s *Server) latestBaseSnapshot(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	appID := strings.TrimSpace(r.URL.Query().Get("app_id"))
	branch := strings.TrimSpace(r.URL.Query().Get("branch"))
	project := strings.TrimSpace(r.URL.Query().Get("project"))
	if appID == "" {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}
	var snapshotID string
	var imageCount int64
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT s.id, s.image_count FROM preprod_snapshots s JOIN projects p ON p.id = s.project_id
		WHERE s.organization_id = ? AND s.app_id = ? AND (? = '' OR s.head_ref = ?)
		AND (? = '' OR p.id = ? OR p.slug = ? OR p.sentry_id = ?)
		ORDER BY s.created_at DESC, s.rowid DESC LIMIT 1
	`, organizationID, appID, branch, branch, project, project, project, project).Scan(&snapshotID, &imageCount)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not find snapshot")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"head_artifact_id": snapshotID, "image_count": imageCount})
}

func (s *Server) snapshotArchive(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var projectID string
	var raw []byte
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT project_id, manifest FROM preprod_snapshots WHERE id = ? AND organization_id = ?`, r.PathValue("snapshot_id"), organizationID).Scan(&projectID, &raw); err != nil {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if _, download := r.URL.Query()["download"]; !download {
		writeJSON(w, http.StatusOK, map[string]bool{"ready": true})
		return
	}
	var manifest snapshotManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		writeError(w, http.StatusInternalServerError, "stored snapshot manifest is invalid")
		return
	}
	type imageObject struct{ name, storageKey string }
	objects := make([]imageObject, 0, len(manifest.Images))
	for name, metadata := range manifest.Images {
		var image struct {
			ContentHash string `json:"content_hash"`
		}
		if json.Unmarshal(metadata, &image) != nil {
			writeError(w, http.StatusInternalServerError, "stored snapshot manifest is invalid")
			return
		}
		objectKey := organizationID + "/" + projectID + "/" + strings.ToLower(image.ContentHash)
		var storageKey string
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT b.storage_key FROM snapshot_objects o JOIN blobs b ON b.id = o.blob_id WHERE o.project_id = ? AND o.object_key = ?`, projectID, objectKey).Scan(&storageKey); err != nil {
			writeError(w, http.StatusConflict, "snapshot image content is unavailable")
			return
		}
		objects = append(objects, imageObject{name: name, storageKey: storageKey})
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="snapshot-`+r.PathValue("snapshot_id")+`.zip"`)
	archive := zip.NewWriter(w)
	for _, object := range objects {
		entry, err := archive.CreateHeader(&zip.FileHeader{Name: object.name, Method: zip.Deflate})
		if err != nil {
			break
		}
		file, err := s.store.Blobs.Open(object.storageKey)
		if err != nil {
			break
		}
		_, copyErr := io.Copy(entry, file)
		_ = file.Close()
		if copyErr != nil {
			break
		}
	}
	_ = archive.Close()
}

func (s *Server) snapshotObject(w http.ResponseWriter, r *http.Request) {
	organizationID, projectID, ok := s.authorizeSnapshotObjectRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid objectstore token or scope")
		return
	}
	objectKey, ok := validSnapshotObjectKey(r.PathValue("object_key"), organizationID, projectID)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid object key")
		return
	}
	if r.Method == http.MethodHead {
		var contentType string
		var size int64
		err := s.store.DB.QueryRowContext(r.Context(), `SELECT b.content_type, b.size FROM snapshot_objects o JOIN blobs b ON b.id = o.blob_id WHERE o.project_id = ? AND o.object_key = ?`, projectID, objectKey).Scan(&contentType, &size)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	storedKey, err := s.storeSnapshotObject(r.Context(), organizationID, projectID, objectKey, r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = storedKey
	writeJSON(w, http.StatusOK, map[string]string{"key": objectKey})
}

type objectstoreBatchResult struct {
	index       int
	status      int
	key         string
	contentType string
	body        string
}

func (s *Server) snapshotObjectBatch(w http.ResponseWriter, r *http.Request) {
	organizationID, projectID, ok := s.authorizeSnapshotObjectRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid objectstore token or scope")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, snapshotBatchMax)
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "multipart batch required")
		return
	}
	results := make([]objectstoreBatchResult, 0)
	for index := 0; ; index++ {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid objectstore batch")
			return
		}
		kind := strings.ToLower(strings.TrimSpace(part.Header.Get("X-Sn-Batch-Operation-Kind")))
		encodedKey := part.Header.Get("X-Sn-Batch-Operation-Key")
		objectKey, decodeErr := url.PathUnescape(encodedKey)
		if decodeErr != nil {
			objectKey = ""
		}
		objectKey, keyOK := validSnapshotObjectKey(objectKey, organizationID, projectID)
		result := objectstoreBatchResult{index: index, status: http.StatusBadRequest, key: objectKey, body: "invalid batch operation"}
		if keyOK && kind == "head" {
			var size int64
			err = s.store.DB.QueryRowContext(r.Context(), `SELECT b.content_type, b.size FROM snapshot_objects o JOIN blobs b ON b.id = o.blob_id WHERE o.project_id = ? AND o.object_key = ?`, projectID, objectKey).Scan(&result.contentType, &size)
			if err == nil {
				result.status = http.StatusOK
			} else if errors.Is(err, sql.ErrNoRows) {
				result.status = http.StatusNotFound
			} else {
				result.status, result.body = http.StatusInternalServerError, "object lookup failed"
			}
			_, _ = io.Copy(io.Discard, part)
		} else if keyOK && kind == "insert" {
			_, err = s.storeSnapshotObject(r.Context(), organizationID, projectID, objectKey, part.Header.Get("Content-Type"), part.Header.Get("Content-Encoding"), part)
			if err == nil {
				result.status, result.body = http.StatusOK, ""
			} else {
				result.status, result.body = http.StatusBadRequest, err.Error()
			}
		} else {
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
		results = append(results, result)
	}
	var response bytes.Buffer
	writer := multipart.NewWriter(&response)
	for _, result := range results {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", `form-data; name="part"`)
		header.Set("Content-Type", firstNonEmpty(result.contentType, "application/octet-stream"))
		header.Set("X-Sn-Batch-Operation-Index", strconv.Itoa(result.index))
		header.Set("X-Sn-Batch-Operation-Status", strconv.Itoa(result.status)+" "+http.StatusText(result.status))
		part, err := writer.CreatePart(header)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create batch response")
			return
		}
		_, _ = io.WriteString(part, result.body)
	}
	_ = writer.Close()
	w.Header().Set("Content-Type", writer.FormDataContentType())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.Bytes())
}

func (s *Server) authorizeSnapshotObjectRequest(r *http.Request) (string, string, bool) {
	parts := strings.Split(r.PathValue("scope"), ";")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "org=") || !strings.HasPrefix(parts[1], "project=") {
		return "", "", false
	}
	organizationID := strings.TrimPrefix(parts[0], "org=")
	projectID := strings.TrimPrefix(parts[1], "project=")
	authorization := strings.TrimSpace(r.Header.Get("X-Os-Auth"))
	token, found := strings.CutPrefix(authorization, "Bearer ")
	if !found || token == "" {
		return "", "", false
	}
	hash := sha256.Sum256([]byte(token))
	var expiresRaw string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT expires_at FROM snapshot_upload_tokens WHERE token_hash = ? AND organization_id = ? AND project_id = ?`, hash[:], organizationID, projectID).Scan(&expiresRaw); err != nil {
		return "", "", false
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresRaw)
	return organizationID, projectID, err == nil && time.Now().UTC().Before(expires)
}

func validSnapshotObjectKey(raw, organizationID, projectID string) (string, bool) {
	key := strings.Trim(strings.TrimSpace(raw), "/")
	prefix := organizationID + "/" + projectID + "/"
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	hash := strings.TrimPrefix(key, prefix)
	if strings.Contains(hash, "/") || !validSHA256(hash) {
		return "", false
	}
	return prefix + strings.ToLower(hash), true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (s *Server) storeSnapshotObject(ctx context.Context, organizationID, projectID, objectKey, contentType, contentEncoding string, body io.Reader) (string, error) {
	var source io.Reader = body
	var decoder *zstd.Decoder
	var err error
	if strings.EqualFold(strings.TrimSpace(contentEncoding), "zstd") {
		decoder, err = zstd.NewReader(body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(128<<20))
		if err != nil {
			return "", errors.New("invalid zstd object")
		}
		defer decoder.Close()
	} else if strings.TrimSpace(contentEncoding) != "" && !strings.EqualFold(strings.TrimSpace(contentEncoding), "identity") {
		return "", errors.New("unsupported object encoding")
	}
	if decoder != nil {
		source = decoder
	}
	stored, err := s.store.Blobs.Put(source, blobstore.MaxBlobBytes)
	if err != nil {
		return "", err
	}
	expectedHash := path.Base(objectKey)
	if stored.Checksum != expectedHash {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", errors.New("object hash does not match key")
	}
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	blobID := uuid.NewString()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", err
	}
	defer tx.Rollback()
	var oldBlobID, oldStorageKey sql.NullString
	_ = tx.QueryRowContext(ctx, `SELECT o.blob_id, b.storage_key FROM snapshot_objects o JOIN blobs b ON b.id = o.blob_id WHERE o.project_id = ? AND o.object_key = ?`, projectID, objectKey).Scan(&oldBlobID, &oldStorageKey)
	if _, err = tx.ExecContext(ctx, `INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type) VALUES (?, ?, ?, 'snapshot_image', ?, ?, ?, ?)`, blobID, organizationID, projectID, stored.Key, stored.Checksum, stored.Size, contentType); err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO snapshot_objects(project_id, organization_id, object_key, content_hash, blob_id) VALUES (?, ?, ?, ?, ?) ON CONFLICT(project_id, object_key) DO UPDATE SET blob_id = excluded.blob_id, created_at = CURRENT_TIMESTAMP`, projectID, organizationID, objectKey, expectedHash, blobID)
	}
	if err == nil && oldBlobID.Valid {
		_, err = tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, oldBlobID.String)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		s.removeBlobIfUnreferenced(context.Background(), stored.Key)
		return "", err
	}
	if oldStorageKey.Valid {
		s.removeBlobIfUnreferenced(context.Background(), oldStorageKey.String)
	}
	return stored.Key, nil
}

func readEncodedBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, limit+1)
	var source io.Reader = r.Body
	var decoder *zstd.Decoder
	var err error
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "zstd":
		decoder, err = zstd.NewReader(r.Body, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(32<<20))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		source = decoder
	default:
		return nil, errors.New("unsupported content encoding")
	}
	payload, err := io.ReadAll(io.LimitReader(source, limit+1))
	if err != nil || int64(len(payload)) > limit {
		return nil, fmt.Errorf("request exceeds %d bytes", limit)
	}
	return payload, nil
}

func safeArchiveName(name string) bool {
	name = strings.TrimSpace(strings.ReplaceAll(name, "\\", "/"))
	clean := path.Clean(name)
	return name != "" && clean == name && clean != "." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/")
}
