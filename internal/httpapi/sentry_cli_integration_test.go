package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/ingest"
)

// TestSentryCLIWorkflow runs against the real sentry-cli binary when
// SENTRY_CLI_BIN is set. It is intentionally opt-in for normal Go test runs.
func TestSentryCLIWorkflow(t *testing.T) {
	binary := os.Getenv("SENTRY_CLI_BIN")
	if binary == "" {
		t.Skip("SENTRY_CLI_BIN is not set")
	}
	server, principal := managementFixture(t)
	mux := http.NewServeMux()
	protected := func(handler http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
		})
	}
	mux.Handle("GET /api/0/", protected(server.sentryAuthInfo))
	mux.Handle("GET /api/0/organizations/", protected(server.sentryOrganizations))
	mux.Handle("GET /api/0/organizations/{org_slug}/projects/", protected(server.sentryOrganizationProjects))
	mux.Handle("GET /api/0/organizations/{org_slug}/monitors/", protected(server.sentryOrganizationMonitors))
	mux.Handle("GET /api/0/organizations/{org_slug}/repos/", protected(server.sentryOrganizationRepositories))
	mux.Handle("POST /api/0/organizations/{org_slug}/code-mappings/bulk/", protected(server.sentryBulkCodeMappings))
	mux.Handle("GET /api/0/organizations/{org_slug}/events/", protected(server.sentryOrganizationEvents))
	mux.Handle("POST /api/0/organizations/{org_slug}/releases/", protected(server.createSentryRelease))
	mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/", protected(server.sentryReleaseDetail))
	mux.Handle("PUT /api/0/organizations/{org_slug}/releases/{version}/", protected(server.sentryReleaseDetail))
	mux.Handle("DELETE /api/0/organizations/{org_slug}/releases/{version}/", protected(server.deleteSentryRelease))
	mux.Handle("GET /api/0/organizations/{org_slug}/releases/{version}/deploys/", protected(server.sentryReleaseDeployList))
	mux.Handle("POST /api/0/organizations/{org_slug}/releases/{version}/deploys/", protected(server.sentryReleaseDeploys))
	mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/releases/", protected(server.sentryProjectReleases))
	mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/events/", protected(server.sentryProjectEvents))
	mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/issues/", protected(server.sentryProjectIssues))
	mux.Handle("PUT /api/0/projects/{org_slug}/{project_slug}/issues/", protected(server.sentryProjectIssues))
	mux.Handle("GET /api/0/organizations/{org_slug}/chunk-upload/", protected(server.sentryChunkUpload))
	mux.Handle("POST /api/0/organizations/{org_slug}/chunk-upload/", protected(server.sentryChunkUpload))
	mux.Handle("POST /api/0/organizations/{org_slug}/artifactbundle/assemble/", protected(server.assembleArtifactBundle))
	mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/files/difs/assemble/", protected(server.assembleDebugFiles))
	mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/files/preprodartifacts/assemble/", protected(server.assemblePreprodBuild))
	mux.Handle("GET /api/0/projects/{org_slug}/{project_slug}/preprodartifacts/snapshots/upload-options/", protected(server.snapshotUploadOptions))
	mux.Handle("POST /api/0/projects/{org_slug}/{project_slug}/preprodartifacts/snapshots/", protected(server.createPreprodSnapshot))
	mux.Handle("GET /api/0/organizations/{org_slug}/preprodartifacts/{preprod_path...}", protected(server.preprodOrganizationRoute))
	mux.Handle("POST /api/0/organizations/{org_slug}/preprodartifacts/{preprod_path...}", protected(server.preprodOrganizationRoute))
	mux.HandleFunc("HEAD /api/0/objectstore/v1/objects/preprod/{scope}/{object_key...}", server.snapshotObject)
	mux.HandleFunc("PUT /api/0/objectstore/v1/objects/preprod/{scope}/{object_key...}", server.snapshotObject)
	mux.HandleFunc("POST /api/0/objectstore/v1/objects:batch/preprod/{scope}/{$}", server.snapshotObjectBatch)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	server.cfg.PublicURL = httpServer.URL
	if _, err := server.store.DB.Exec(`INSERT INTO repositories(id, organization_id, name, provider) VALUES ('repo', 'org', 'example/repository', 'integrations:github')`); err != nil {
		t.Fatal(err)
	}

	environment := append(os.Environ(),
		"SENTRY_URL="+httpServer.URL+"/",
		"SENTRY_AUTH_TOKEN=bark_test_token",
		"SENTRY_ORG=org",
		"SENTRY_PROJECT=app",
	)
	runCLI := func(arguments ...string) string {
		t.Helper()
		command := exec.Command(binary, arguments...)
		command.Env = environment
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("sentry-cli %s: %v\n%s", strings.Join(arguments, " "), err, output)
		}
		return string(output)
	}
	if output := runCLI("info"); !strings.Contains(output, "User: user@example.com") {
		t.Fatalf("unexpected info output: %s", output)
	}
	runCLI("organizations", "list")
	runCLI("projects", "list")
	runCLI("repos", "list")
	runCLI("monitors", "list")
	runCLI("releases", "new", "cli@1.0.0")
	runCLI("releases", "set-commits", "cli@1.0.0", "--commit", "example/repository@abcdef123456")
	runCLI("releases", "finalize", "cli@1.0.0")
	runCLI("releases", "deploys", "cli@1.0.0", "new", "--env", "production")
	runCLI("deploys", "list", "--release", "cli@1.0.0")
	runCLI("releases", "info", "cli@1.0.0")
	runCLI("releases", "archive", "cli@1.0.0")
	runCLI("releases", "restore", "cli@1.0.0")
	runCLI("releases", "list")
	runCLI("releases", "new", "cli-delete@1.0.0")
	runCLI("releases", "delete", "cli-delete@1.0.0")

	sources := t.TempDir()
	if err := os.WriteFile(filepath.Join(sources, "app.min.js"), []byte(`function a(){throw Error("boom")}a();`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sources, "app.min.js.map"), []byte(`{"version":3,"file":"app.min.js","sources":["app.js"],"sourcesContent":["function checkout(){ throw new Error('boom'); }"],"names":["checkout"],"mappings":"AAAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI("sourcemaps", "upload", "--release", "cli@1.0.0", sources)
	runCLI("debug-files", "upload", "/bin/true")

	var artifacts int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM project_artifacts WHERE project_id = 'project'`).Scan(&artifacts); err != nil {
		t.Fatal(err)
	}
	if artifacts < 3 {
		t.Fatalf("sentry-cli indexed %d artifacts, want at least 3", artifacts)
	}
	ingestion := ingest.New(server.store, 20<<20)
	if _, err := ingestion.StoreEvent(context.Background(), ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}, []byte(`{"event_id":"30303030303030303030303030303030","release":"cli@1.0.0","exception":{"values":[{"type":"Error","value":"boom","stacktrace":{"frames":[{"filename":"~/app.min.js","abs_path":"~/app.min.js","lineno":1,"colno":0,"function":"a"}]}}]}}`), ""); err != nil {
		t.Fatal(err)
	}
	var processed string
	if err := server.store.DB.QueryRow(`SELECT processed_payload FROM events WHERE event_id = '30303030303030303030303030303030'`).Scan(&processed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(processed, `"symbolicated":true`) {
		t.Fatalf("sentry-cli source map did not symbolicate event: %s", processed)
	}
	if _, err := ingestion.StoreLogs(context.Background(), ingest.Project{ID: "project", OrganizationID: "org", PublicKey: "key"}, []byte(`{"items":[{"timestamp":"2026-08-29T13:00:00Z","level":"error","body":"checkout failed","trace_id":"abc123"}]}`)); err != nil {
		t.Fatal(err)
	}
	runCLI("events", "list")
	runCLI("issues", "list")
	runCLI("issues", "resolve", "--all")
	runCLI("logs", "list", "--max-rows", "10")
	mappings := filepath.Join(t.TempDir(), "mappings.json")
	if err := os.WriteFile(mappings, []byte(`[{"stackRoot":"com/example","sourceRoot":"src/main/java/com/example"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI("code-mappings", "upload", "--repo", "example/repository", "--default-branch", "main", mappings)

	apk := filepath.Join(t.TempDir(), "barktrace.apk")
	var apkBytes bytes.Buffer
	apkArchive := zip.NewWriter(&apkBytes)
	manifest, err := apkArchive.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = manifest.Write([]byte("barktrace-test-manifest"))
	if err := apkArchive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apk, apkBytes.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI("build", "upload", "--no-git-metadata", "--build-configuration", "release", apk)
	var buildID string
	if err := server.store.DB.QueryRow(`SELECT id FROM preprod_builds WHERE project_id = 'project'`).Scan(&buildID); err != nil {
		t.Fatal(err)
	}
	directDownload := principalRequest(t, principal, http.MethodGet, "/api/0/organizations/org/preprodartifacts/"+buildID+"/download/?response_format=apk", "")
	directDownload.SetPathValue("org_slug", "org")
	directDownload.SetPathValue("preprod_path", buildID+"/download/")
	directResponse := httptest.NewRecorder()
	server.preprodOrganizationRoute(directResponse, directDownload)
	if directResponse.Code != http.StatusOK {
		t.Fatalf("direct build download status=%d body=%s", directResponse.Code, directResponse.Body.String())
	}
	downloadedBuild := filepath.Join(t.TempDir(), "downloaded.apk")
	runCLI("build", "download", "--build-id", buildID, "--output", downloadedBuild)
	downloadedBytes, err := os.ReadFile(downloadedBuild)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloadedBytes, apkBytes.Bytes()) {
		t.Fatal("downloaded preprod build does not match the uploaded APK")
	}

	snapshotDir := t.TempDir()
	snapshotPath := filepath.Join(snapshotDir, "home.png")
	snapshotImage := image.NewRGBA(image.Rect(0, 0, 2, 2))
	snapshotImage.Set(0, 0, color.RGBA{R: 197, G: 241, B: 30, A: 255})
	var snapshotBytes bytes.Buffer
	if err := png.Encode(&snapshotBytes, snapshotImage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshotPath, snapshotBytes.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLI("snapshots", "upload", "--app-id", "barktrace-web", "--no-git-metadata", snapshotDir)
	var snapshots int
	if err := server.store.DB.QueryRow(`SELECT COUNT(*) FROM preprod_snapshots WHERE project_id = 'project' AND app_id = 'barktrace-web'`).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 {
		t.Fatalf("sentry-cli created %d snapshots, want 1", snapshots)
	}
	snapshotOutput := t.TempDir()
	runCLI("snapshots", "download", "--app-id", "barktrace-web", "--output", snapshotOutput)
	downloadedSnapshot, err := os.ReadFile(filepath.Join(snapshotOutput, "home.png"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloadedSnapshot, snapshotBytes.Bytes()) {
		t.Fatal("downloaded snapshot does not match the uploaded image")
	}
}
