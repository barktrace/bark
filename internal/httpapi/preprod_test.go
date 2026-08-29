package httpapi

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestPreprodBuildAssemblyAndDownload(t *testing.T) {
	server, principal := managementFixture(t)
	originalBuild := testAPK(t)
	var normalized bytes.Buffer
	archive := zip.NewWriter(&normalized)
	entry, err := archive.Create("barktrace.apk")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write(originalBuild)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum(normalized.Bytes())
	checksum := hex.EncodeToString(digest[:])
	if err := server.storeUploadChunk(t.Context(), "org", checksum, normalized.Bytes()); err != nil {
		t.Fatal(err)
	}
	request := principalRequest(t, principal, http.MethodPost, "/api/0/projects/org/app/files/preprodartifacts/assemble/", `{"checksum":"`+checksum+`","chunks":["`+checksum+`"],"build_configuration":"release","install_groups":["internal"]}`)
	request.SetPathValue("org_slug", "org")
	request.SetPathValue("project_slug", "app")
	response := httptest.NewRecorder()
	server.assemblePreprodBuild(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("assemble status=%d body=%s", response.Code, response.Body.String())
	}
	var buildID string
	if err := server.store.DB.QueryRow(`SELECT id FROM preprod_builds WHERE project_id = 'project' AND format = 'apk'`).Scan(&buildID); err != nil {
		t.Fatal(err)
	}
	download := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/preprodartifacts/"+buildID+"/download/?response_format=apk", "")
	download.SetPathValue("org_slug", "org")
	download.SetPathValue("build_id", buildID)
	response = httptest.NewRecorder()
	server.downloadPreprodBuild(response, download)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), originalBuild) {
		t.Fatalf("download status=%d bytes=%d want=%d body=%s", response.Code, response.Body.Len(), len(originalBuild), response.Body.String())
	}
}

func TestSnapshotObjectstoreAndArchive(t *testing.T) {
	server, principal := managementFixture(t)
	server.cfg.PublicURL = "https://errors.example"
	optionsRequest := principalRequest(t, principal, http.MethodGet, "/api/0/projects/org/app/preprodartifacts/snapshots/upload-options/", "")
	optionsRequest.SetPathValue("org_slug", "org")
	optionsRequest.SetPathValue("project_slug", "app")
	response := httptest.NewRecorder()
	server.snapshotUploadOptions(response, optionsRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("options status=%d body=%s", response.Code, response.Body.String())
	}
	var options struct {
		Objectstore struct {
			AuthToken string `json:"authToken"`
		} `json:"objectstore"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil || options.Objectstore.AuthToken == "" {
		t.Fatalf("invalid upload options: %v body=%s", err, response.Body.String())
	}

	imageBytes := []byte("snapshot-image-content")
	hash := sha256.Sum256(imageBytes)
	contentHash := hex.EncodeToString(hash[:])
	objectKey := "org/project/" + contentHash
	batchResponse := runObjectstoreBatch(t, server, options.Objectstore.AuthToken, []testBatchOperation{{kind: "head", key: objectKey}})
	if status := batchPartStatus(t, batchResponse); status != http.StatusNotFound {
		t.Fatalf("missing object HEAD status=%d, want 404", status)
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(imageBytes, nil)
	encoder.Close()
	batchResponse = runObjectstoreBatch(t, server, options.Objectstore.AuthToken, []testBatchOperation{{kind: "insert", key: objectKey, body: compressed, encoding: "zstd"}})
	if status := batchPartStatus(t, batchResponse); status != http.StatusOK {
		t.Fatalf("object insert status=%d body=%s", status, batchResponse.Body.String())
	}
	batchResponse = runObjectstoreBatch(t, server, options.Objectstore.AuthToken, []testBatchOperation{{kind: "head", key: objectKey}})
	if status := batchPartStatus(t, batchResponse); status != http.StatusOK {
		t.Fatalf("existing object HEAD status=%d, want 200", status)
	}

	manifest := `{"app_id":"barktrace-web","images":{"screens/home.png":{"width":1,"height":1,"content_hash":"` + contentHash + `"}},"head_ref":"main"}`
	create := principalRequest(t, principal, http.MethodPost, "/api/0/projects/org/app/preprodartifacts/snapshots/", manifest)
	create.SetPathValue("org_slug", "org")
	create.SetPathValue("project_slug", "app")
	response = httptest.NewRecorder()
	server.createPreprodSnapshot(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		ArtifactID string `json:"artifactId"`
		ImageCount int    `json:"imageCount"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ArtifactID == "" || created.ImageCount != 1 {
		t.Fatalf("invalid snapshot response: %v body=%s", err, response.Body.String())
	}

	archiveRequest := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/preprodartifacts/snapshots/"+created.ArtifactID+"/archive/?download", "")
	archiveRequest.SetPathValue("org_slug", "org")
	archiveRequest.SetPathValue("snapshot_id", created.ArtifactID)
	response = httptest.NewRecorder()
	server.snapshotArchive(response, archiveRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("archive status=%d body=%s", response.Code, response.Body.String())
	}
	downloaded, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil || len(downloaded.File) != 1 || downloaded.File[0].Name != "screens/home.png" {
		t.Fatalf("invalid snapshot archive: %v", err)
	}
	file, err := downloaded.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(file)
	_ = file.Close()
	if err != nil || !bytes.Equal(contents, imageBytes) {
		t.Fatalf("snapshot content mismatch: %v", err)
	}
}

type testBatchOperation struct {
	kind, key, encoding string
	body                []byte
}

func runObjectstoreBatch(t *testing.T, server *Server, token string, operations []testBatchOperation) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, operation := range operations {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", `form-data; name="part"`)
		header.Set("Content-Type", "application/octet-stream")
		header.Set("X-Sn-Batch-Operation-Kind", operation.kind)
		header.Set("X-Sn-Batch-Operation-Key", strings.ReplaceAll(strings.ReplaceAll(operation.key, "/", "%2F"), "-", "%2D"))
		if operation.encoding != "" {
			header.Set("Content-Encoding", operation.encoding)
		}
		part, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write(operation.body)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/0/objectstore/v1/objects:batch/preprod/org=org;project=project/", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-Os-Auth", "Bearer "+token)
	request.SetPathValue("scope", "org=org;project=project")
	response := httptest.NewRecorder()
	server.snapshotObjectBatch(response, request)
	return response
}

func batchPartStatus(t *testing.T, response *httptest.ResponseRecorder) int {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("batch status=%d body=%s", response.Code, response.Body.String())
	}
	_, parameters, err := mime.ParseMediaType(response.Header().Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(bytes.NewReader(response.Body.Bytes()), parameters["boundary"])
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	status, _ := strconv.Atoi(strings.Fields(part.Header.Get("X-Sn-Batch-Operation-Status"))[0])
	return status
}

func testAPK(t *testing.T) []byte {
	t.Helper()
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	manifest, err := archive.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = manifest.Write([]byte("manifest"))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
