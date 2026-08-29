package httpapi

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSentryChunkUploadAssemblesArtifactBundle(t *testing.T) {
	server, principal := managementFixture(t)
	bundle := testArtifactBundle(t)
	digest := sha1.Sum(bundle)
	checksum := hex.EncodeToString(digest[:])
	requestBody := `{"checksum":"` + checksum + `","chunks":["` + checksum + `"],"projects":["app"],"version":"web@1.0.0"}`

	request := principalRequest(t, principal, http.MethodPost, "/api/0/organizations/org/artifactbundle/assemble/", requestBody)
	request.SetPathValue("org_slug", "org")
	response := httptest.NewRecorder()
	server.assembleArtifactBundle(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"state":"not_found"`)) || !bytes.Contains(response.Body.Bytes(), []byte(checksum)) {
		t.Fatalf("missing chunk response status=%d body=%s", response.Code, response.Body.String())
	}

	var upload bytes.Buffer
	writer := multipart.NewWriter(&upload)
	part, err := writer.CreateFormFile("file", checksum)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(bundle)
	_ = writer.Close()
	request = principalRequest(t, principal, http.MethodPost, "/api/0/organizations/org/chunk-upload/", upload.String())
	request.Body = ioNopCloser{bytes.NewReader(upload.Bytes())}
	request.ContentLength = int64(upload.Len())
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.sentryChunkUpload(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("chunk upload status=%d body=%s", response.Code, response.Body.String())
	}

	request = principalRequest(t, principal, http.MethodPost, "/api/0/organizations/org/artifactbundle/assemble/", requestBody)
	request.SetPathValue("org_slug", "org")
	response = httptest.NewRecorder()
	server.assembleArtifactBundle(response, request)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(`"state":"ok"`)) {
		t.Fatalf("assembly status=%d body=%s", response.Code, response.Body.String())
	}
	var artifacts, releases int
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM project_artifacts WHERE project_id = 'project' AND name = '~/app.min.js.map' AND artifact_type = 'sourcemap'`).Scan(&artifacts)
	_ = server.store.DB.QueryRow(`SELECT COUNT(*) FROM releases WHERE organization_id = 'org' AND version = 'web@1.0.0'`).Scan(&releases)
	if artifacts != 1 || releases != 1 {
		t.Fatalf("artifacts=%d releases=%d, want 1/1", artifacts, releases)
	}
}

func TestSentryReleaseResponseUsesCLIShape(t *testing.T) {
	server, principal := managementFixture(t)
	request := principalRequest(t, principal, http.MethodPost, "/api/0/organizations/org/releases/", `{"version":"api@2.0.0","projects":["app"],"dateReleased":"2026-08-29T12:00:00Z"}`)
	request.SetPathValue("org_slug", "org")
	response := httptest.NewRecorder()
	server.createSentryRelease(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create release status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Version      string `json:"version"`
		DateCreated  string `json:"dateCreated"`
		DateReleased string `json:"dateReleased"`
		Projects     []struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != "api@2.0.0" || payload.DateCreated == "" || payload.DateReleased != "2026-08-29T12:00:00Z" || len(payload.Projects) != 1 || payload.Projects[0].Slug != "app" {
		t.Fatalf("unexpected release response: %+v", payload)
	}
}

func testArtifactBundle(t *testing.T) []byte {
	t.Helper()
	var body bytes.Buffer
	_, _ = body.Write([]byte("SYSB"))
	if err := binary.Write(&body, binary.LittleEndian, uint32(2)); err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(&body)
	manifest, _ := archive.Create("manifest.json")
	_, _ = manifest.Write([]byte(`{"debug_id":"12345678-1234-1234-1234-123456789abc","files":{"files/_/_/app.min.js.map":{"type":"source_map","url":"~/app.min.js.map"}}}`))
	file, _ := archive.Create("files/_/_/app.min.js.map")
	_, _ = file.Write([]byte(`{"version":3,"file":"app.min.js","sources":["src/app.js"],"sourcesContent":["throw new Error('boom')"],"names":[],"mappings":"AAAA"}`))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

type ioNopCloser struct{ *bytes.Reader }

func (ioNopCloser) Close() error { return nil }
