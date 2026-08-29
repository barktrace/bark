package symbolicate

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/blobstore"
	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

func TestProcessEventSelectsMatchingDistribution(t *testing.T) {
	st := symbolicationStore(t)
	putSourceMapArtifact(t, st, "release", "~/app.min.js.map", "web-a", "", `{"version":3,"sources":["wrong.js"],"sourcesContent":["wrong();"],"names":["wrong"],"mappings":"AAAAA"}`)
	putSourceMapArtifact(t, st, "release", "~/app.min.js.map", "web-b", "", `{"version":3,"sources":["right.js"],"sourcesContent":["right();"],"names":["right"],"mappings":"AAAAA"}`)
	payload := []byte(`{"dist":"web-b","exception":{"values":[{"stacktrace":{"frames":[{"filename":"https://cdn.example/app.min.js","lineno":1,"colno":0}]}}]}}`)

	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("event was not symbolicated")
	}
	frame := processedFrame(t, processed)
	if frame["filename"] != "right.js" || frame["function"] != "right" || frame["context_line"] != "right();" {
		t.Fatalf("wrong distribution selected: %#v", frame)
	}
}

func TestProcessEventMatchesArtifactBundleDebugID(t *testing.T) {
	st := symbolicationStore(t)
	putSourceMapArtifact(t, st, "release", "~/unrelated-bundle-name.js.map", "", "12345678-1234-1234-1234-123456789abc", `{"version":3,"sources":["src/checkout.js"],"sourcesContent":["checkout();"],"names":["checkout"],"mappings":"AAAAA"}`)
	payload := []byte(`{
		"debug_meta":{"images":[{"type":"sourcemap","code_file":"https://cdn.example/assets/app.js","debug_id":"12345678123412341234123456789ABC"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"abs_path":"https://cdn.example/assets/app.js","lineno":1,"colno":0}]}}]}
	}`)

	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("debug-ID event was not symbolicated")
	}
	frame := processedFrame(t, processed)
	if frame["filename"] != "src/checkout.js" || frame["function"] != "checkout" {
		t.Fatalf("debug-ID source map was not selected: %#v", frame)
	}
}

func TestLookupBreakpadSymbolUsesFunctionRangeAndSourceLine(t *testing.T) {
	fixture := `MODULE Linux x86_64 ABCDEF app
FILE 0 /workspace/src/main.cc
PUBLIC 1010 0 public_fallback
FUNC m 1000 20 0 checkout worker
1000 8 41 0
1008 18 42 0
FUNC 2000 10 0 unrelated
2000 10 99 0
`

	matched := lookupBreakpadSymbol(bytes.NewBufferString(fixture), 0x1018)
	if matched.function != "checkout worker" || matched.address != 0x1000 || matched.filename != "/workspace/src/main.cc" || matched.line != 42 {
		t.Fatalf("function match = %#v", matched)
	}

	outsideFunction := lookupBreakpadSymbol(bytes.NewBufferString(fixture), 0x1020)
	if outsideFunction.function != "public_fallback" || outsideFunction.address != 0x1010 || outsideFunction.filename != "" || outsideFunction.line != 0 {
		t.Fatalf("range-end match = %#v", outsideFunction)
	}
}

func TestProcessEventAddsBreakpadSourceLocation(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifact(t, st, "ABCDEF", `MODULE Linux x86_64 ABCDEF app
FILE 3 /workspace/src/worker.cc
FUNC 1000 20 0 process_request
1000 20 73 3
`)
	payload := []byte(`{
		"debug_meta":{"images":[{"type":"elf","image_addr":"0x400000","image_size":"0x10000","debug_id":"ABCDEF"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x401008","filename":"app"}]}}]}
	}`)

	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("native event was not symbolicated")
	}
	frame := processedFrame(t, processed)
	if frame["function"] != "process_request" || frame["filename"] != "/workspace/src/worker.cc" || frame["lineno"] != float64(73) || frame["symbol_addr"] != "0x401000" {
		t.Fatalf("native frame = %#v", frame)
	}
}

func TestLookupELFFrameAddsDWARFSourceLocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF fixture requires Linux")
	}
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "fixture.go")
	binaryPath := filepath.Join(directory, "fixture")
	source := `package main

//go:noinline
func dwarf_target() int {
	return 42
}

func main() { _ = dwarf_target() }
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-gcflags=all=-N -l", "-o", binaryPath, sourcePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build ELF fixture: %v\n%s", err, output)
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := elf.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := parsed.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	var address uint64
	for _, symbol := range symbols {
		if strings.HasSuffix(symbol.Name, ".dwarf_target") {
			address = symbol.Value
			break
		}
	}
	_ = parsed.Close()
	if address == 0 {
		t.Fatal("fixture function symbol not found")
	}

	matched := lookupELFFrame(file, address, 0)
	if !strings.HasSuffix(matched.function, ".dwarf_target") || filepath.Base(matched.filename) != "fixture.go" || matched.line < 4 {
		t.Fatalf("ELF/DWARF match = %#v", matched)
	}

	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, "DWARF123", binary)
	payload := []byte(fmt.Sprintf(`{
		"debug_meta":{"images":[{"type":"elf","image_addr":"0x0","image_size":"0x0","debug_id":"DWARF123"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x%x","filename":"fixture"}]}}]}
	}`, address))
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := processedFrame(t, processed)
	if !changed || filepath.Base(frame["filename"].(string)) != "fixture.go" || frame["lineno"].(float64) < 4 || frame["symbolicated"] != true {
		t.Fatalf("processed ELF/DWARF frame = %#v, changed=%v", frame, changed)
	}
}

func TestDWARFSectionBudget(t *testing.T) {
	file := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".text", Size: maxDWARFBytes + 1}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: maxDWARFBytes - 1}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_line", Size: 1}},
	}}
	if !hasBoundedDWARF(file) {
		t.Fatal("DWARF data at the memory limit was rejected")
	}
	file.Sections = append(file.Sections, &elf.Section{SectionHeader: elf.SectionHeader{Name: ".debug_str", Size: 1}})
	if hasBoundedDWARF(file) {
		t.Fatal("DWARF data above the memory limit was accepted")
	}
}

func symbolicationStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.DB.Exec(`
		INSERT INTO organizations(id, slug, name) VALUES ('org', 'org', 'Organization');
		INSERT INTO projects(id, sentry_id, organization_id, slug, name, public_key) VALUES ('project', '1', 'org', 'app', 'App', 'public-key');
		INSERT INTO releases(id, organization_id, version, first_seen_at, last_seen_at) VALUES ('release', 'org', 'app@1.0.0', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
		INSERT INTO project_releases(project_id, release_id, first_seen_at, last_seen_at) VALUES ('project', 'release', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func putSourceMapArtifact(t *testing.T, st *store.Store, releaseID, name, dist, debugID, sourceMap string) {
	t.Helper()
	stored, err := st.Blobs.Put(bytes.NewBufferString(sourceMap), blobstore.MaxBlobBytes)
	if err != nil {
		t.Fatal(err)
	}
	blobID, artifactID := uuid.NewString(), uuid.NewString()
	_, err = st.DB.Exec(`
		INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type)
		VALUES (?, 'org', 'project', 'artifact', ?, ?, ?, 'application/json');
		INSERT INTO project_artifacts(id, project_id, release_id, blob_id, name, artifact_type, debug_id, dist)
		VALUES (?, 'project', ?, ?, ?, 'sourcemap', ?, ?);
	`, blobID, stored.Key, stored.Checksum, stored.Size, artifactID, releaseID, blobID, name, debugID, dist)
	if err != nil {
		t.Fatal(err)
	}
}

func putDebugArtifact(t *testing.T, st *store.Store, debugID, symbols string) {
	putDebugArtifactBytes(t, st, debugID, []byte(symbols))
}

func putDebugArtifactBytes(t *testing.T, st *store.Store, debugID string, contents []byte) {
	t.Helper()
	stored, err := st.Blobs.Put(bytes.NewReader(contents), blobstore.MaxBlobBytes)
	if err != nil {
		t.Fatal(err)
	}
	blobID, artifactID := uuid.NewString(), uuid.NewString()
	_, err = st.DB.Exec(`
		INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type)
		VALUES (?, 'org', 'project', 'artifact', ?, ?, ?, 'text/plain');
		INSERT INTO project_artifacts(id, project_id, release_id, blob_id, name, artifact_type, debug_id)
		VALUES (?, 'project', 'release', ?, 'app.sym', 'debug_file', ?);
	`, blobID, stored.Key, stored.Checksum, stored.Size, artifactID, blobID, debugID)
	if err != nil {
		t.Fatal(err)
	}
}

func processedFrame(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	exception := payload["exception"].(map[string]any)
	value := exception["values"].([]any)[0].(map[string]any)
	stacktrace := value["stacktrace"].(map[string]any)
	return stacktrace["frames"].([]any)[0].(map[string]any)
}
