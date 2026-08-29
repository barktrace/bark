package httpapi

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/ingest"
)

func TestSourceMapUploadAndEventSymbolication(t *testing.T) {
	server, principal := managementFixture(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("name", "~/app.min.js.map")
	_ = writer.WriteField("artifact_type", "sourcemap")
	file, err := writer.CreateFormFile("file", "app.min.js.map")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte(`{"version":3,"file":"app.min.js","sourceRoot":"webpack:///","sources":["src/app.js"],"sourcesContent":["throw new Error('boom');"],"names":["checkout"],"mappings":"AAAAA"}`))
	_ = writer.Close()
	request := httptest.NewRequest(http.MethodPost, "/artifacts?project_id=project&release=app@1.0.0", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request = request.WithContext(auth.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	server.uploadProjectArtifact(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status = %d body=%s", response.Code, response.Body.String())
	}
	service := ingest.New(server.store, 20<<20)
	payload := []byte(`{"event_id":"34343434343434343434343434343434","release":"app@1.0.0","exception":{"values":[{"type":"Error","value":"boom","stacktrace":{"frames":[{"filename":"https://cdn.example/app.min.js","abs_path":"https://cdn.example/app.min.js","lineno":1,"colno":0,"function":"a"}]}}]}}`)
	if _, err := service.StoreEvent(context.Background(), ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}, payload, ""); err != nil {
		t.Fatal(err)
	}
	var processed string
	if err := server.store.DB.QueryRow(`SELECT processed_payload FROM events WHERE event_id = '34343434343434343434343434343434'`).Scan(&processed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(processed, "webpack:///src/app.js") || !strings.Contains(processed, `"symbolicated":true`) {
		t.Fatalf("processed payload = %s", processed)
	}
}

func TestArtifactTypeRecognizesNativeDebugFiles(t *testing.T) {
	for _, name := range []string{"service.debug", "service.dwarf", "service.elf", "service.so", "Service.dylib", "Service.dSYM", "service.exe", "service.dll", "service.pdb", "service.sym"} {
		if got := artifactType("", name); got != "debug_file" {
			t.Errorf("artifactType(%q) = %q, want debug_file", name, got)
		}
	}
}

func TestSentryProguardUploadIndexesMappingAndUUID(t *testing.T) {
	server, principal := managementFixture(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("proguard_uuid", "12345678-1234-1234-1234-123456789abc")
	_ = writer.WriteField("version", "android@1.0.0")
	file, err := writer.CreateFormFile("file", "mapping.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("com.example.Checkout -> a.b:\n    1:1:void submit():42:42 -> c\n"))
	_ = writer.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/0/projects/org/app/files/proguard/", &body)
	request.SetPathValue("org_slug", "org")
	request.SetPathValue("project_slug", "app")
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request = request.WithContext(auth.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	server.sentryDebugArtifactUpload(response, request, "proguard")
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status = %d body=%s", response.Code, response.Body.String())
	}
	var kind, debugID, release string
	err = server.store.DB.QueryRow(`
		SELECT a.artifact_type, a.debug_id, r.version
		FROM project_artifacts a JOIN releases r ON r.id = a.release_id
		WHERE a.project_id = 'project' AND a.name = 'mapping.txt'
	`).Scan(&kind, &debugID, &release)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "proguard" || debugID != "12345678-1234-1234-1234-123456789abc" || release != "android@1.0.0" {
		t.Fatalf("stored kind=%q debug_id=%q release=%q", kind, debugID, release)
	}
}

func TestProguardUUIDFromChunkName(t *testing.T) {
	const expected = "12345678-1234-1234-1234-123456789abc"
	if got := proguardUUIDFromName("/proguard/" + expected + ".txt"); got != expected {
		t.Fatalf("proguardUUIDFromName() = %q, want %q", got, expected)
	}
	if got := proguardUUIDFromName("mapping.txt"); got != "" {
		t.Fatalf("invalid ProGuard name produced UUID %q", got)
	}
}
