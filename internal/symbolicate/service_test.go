package symbolicate

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
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

func TestLookupBreakpadSymbolExpandsNestedInlineRecords(t *testing.T) {
	matched := lookupBreakpadSymbol(bytes.NewBufferString(breakpadInlineFixture), 0x1010)
	if matched.function != "physical_function" || matched.filename != "/src/inner.cc" || matched.line != 30 || len(matched.inlines) != 2 {
		t.Fatalf("inline Breakpad match = %#v", matched)
	}
	if matched.inlines[0].function != "outer_inline" || matched.inlines[0].filename != "/src/physical.cc" || matched.inlines[0].line != 12 {
		t.Fatalf("outer inline = %#v", matched.inlines[0])
	}
	if matched.inlines[1].function != "inner_inline" || matched.inlines[1].filename != "/src/outer.cc" || matched.inlines[1].line != 21 {
		t.Fatalf("inner inline = %#v", matched.inlines[1])
	}
}

func TestBreakpadInlineDepthIsBounded(t *testing.T) {
	var fixture strings.Builder
	fixture.WriteString("MODULE Linux x86_64 DEEP app\nFILE 0 deep.cc\nINLINE_ORIGIN 0 inlined\nFUNC 1000 20 0 physical\n")
	for depth := 0; depth < maxNativeInlineDepth+100; depth++ {
		fmt.Fprintf(&fixture, "INLINE %d 1 0 0 1000 20\n", depth)
	}
	fixture.WriteString("1000 20 1 0\n")
	matched := lookupBreakpadSymbol(strings.NewReader(fixture.String()), 0x1008)
	if len(matched.inlines) != maxNativeInlineDepth {
		t.Fatalf("inline depth = %d, want %d", len(matched.inlines), maxNativeInlineDepth)
	}
}

func TestEventStacksSupportsSentryContainerShapes(t *testing.T) {
	stack := func() map[string]any { return map[string]any{"frames": []any{map[string]any{"function": "f"}}} }
	payload := map[string]any{
		"exception":  map[string]any{"values": []any{map[string]any{"stacktrace": stack()}}},
		"threads":    map[string]any{"values": []any{map[string]any{"stacktrace": stack()}}},
		"stacktrace": stack(),
	}
	if stacks := eventStacks(payload); len(stacks) != 3 {
		t.Fatalf("stack count = %d, want 3", len(stacks))
	}
	payload["exception"] = []any{map[string]any{"stacktrace": stack()}}
	if stacks := eventStacks(payload); len(stacks) != 3 {
		t.Fatalf("exception-array stack count = %d, want 3", len(stacks))
	}
}

func TestProcessEventExpandsNestedBreakpadFrames(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifact(t, st, "INLINE123", breakpadInlineFixture)
	payload := []byte(`{
		"debug_meta":{"images":[{"type":"elf","image_addr":"0x400000","image_size":"0x10000","debug_id":"INLINE123"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x401010","function":"unknown","filename":"app"}]}}]}
	}`)
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frames := processedFrames(t, processed)
	if !changed || len(frames) != 3 {
		t.Fatalf("expanded frames = %#v, changed=%v", frames, changed)
	}
	want := []struct {
		function, filename string
		line               float64
		inline             bool
	}{
		{"physical_function", "/src/physical.cc", 12, false},
		{"outer_inline", "/src/outer.cc", 21, true},
		{"inner_inline", "/src/inner.cc", 30, true},
	}
	for index, expected := range want {
		frame := frames[index]
		if frame["function"] != expected.function || frame["filename"] != expected.filename || frame["lineno"] != expected.line || (frame["inline"] == true) != expected.inline || frame["symbolicated"] != true || frame["original_function"] != "unknown" {
			t.Fatalf("frame %d = %#v", index, frame)
		}
		if expected.inline && frame["symbol_addr"] != "0x401008" {
			t.Fatalf("inline frame %d symbol address = %v", index, frame["symbol_addr"])
		}
	}
}

const breakpadInlineFixture = `MODULE Linux x86_64 INLINE123 app
FILE 1 /src/physical.cc
FILE 2 /src/outer.cc
FILE 3 /src/inner.cc
INLINE_ORIGIN 10 outer_inline
INLINE_ORIGIN 11 inner_inline
FUNC 1000 40 0 physical_function
INLINE 0 12 1 10 1008 18
INLINE 1 21 2 11 1008 10
1008 10 30 3
`

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
	parsed, err = elf.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	imageBase := elfPreferredBase(parsed)
	_ = parsed.Close()
	payload := []byte(fmt.Sprintf(`{
		"debug_meta":{"images":[{"type":"elf","image_addr":"0x%x","image_size":"0x0","debug_id":"DWARF123"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x%x","filename":"fixture"}]}}]}
	}`, imageBase, address))
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := processedFrame(t, processed)
	if !changed || filepath.Base(frame["filename"].(string)) != "fixture.go" || frame["lineno"].(float64) < 4 || frame["symbol_addr"] != fmt.Sprintf("0x%x", address) || frame["symbolicated"] != true {
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

func TestLookupMachOFrameAddsDWARFSourceLocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-compiled Mach-O fixture requires the Linux test environment")
	}
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "fixture.go")
	binaryPath := filepath.Join(directory, "fixture-macos")
	source := `package main

//go:noinline
func macho_target() int {
	return 84
}

func main() { _ = macho_target() }
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-gcflags=all=-N -l", "-o", binaryPath, sourcePath)
	command.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Mach-O fixture: %v\n%s", err, output)
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := macho.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Symtab == nil {
		t.Fatal("Mach-O fixture has no symbol table")
	}
	var address uint64
	for _, symbol := range parsed.Symtab.Syms {
		if strings.HasSuffix(symbol.Name, ".macho_target") {
			address = symbol.Value
			break
		}
	}
	text := parsed.Segment("__TEXT")
	if address == 0 || text == nil {
		t.Fatal("Mach-O fixture function or __TEXT segment not found")
	}
	imageBase := text.Addr
	_ = parsed.Close()

	matched := lookupMachOFrame(file, address, imageBase, "x86_64")
	if !strings.HasSuffix(matched.function, ".macho_target") || matched.address+imageBase != address || filepath.Base(matched.filename) != "fixture.go" || matched.line < 4 {
		t.Fatalf("Mach-O/DWARF match = %#v", matched)
	}

	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, "MACHO123", binary)
	payload := []byte(fmt.Sprintf(`{
		"debug_meta":{"images":[{"type":"macho","image_addr":"0x%x","image_size":"0x0","debug_id":"MACHO123","arch":"x86_64"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x%x","filename":"fixture-macos"}]}}]}
	}`, imageBase, address))
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := processedFrame(t, processed)
	if !changed || filepath.Base(frame["filename"].(string)) != "fixture.go" || frame["lineno"].(float64) < 4 || frame["symbol_addr"] != fmt.Sprintf("0x%x", address) {
		t.Fatalf("processed Mach-O/DWARF frame = %#v, changed=%v", frame, changed)
	}
}

func TestLookupUniversalMachOSelectsEventArchitecture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-compiled Mach-O fixtures require the Linux test environment")
	}
	directory := t.TempDir()
	amd, amdAddress, amdBase, amdCPU, amdSubCPU := buildMachOFixture(t, directory, "amd64", "amd_target")
	arm, armAddress, armBase, armCPU, armSubCPU := buildMachOFixture(t, directory, "arm64", "arm_target")

	const alignment = uint32(12)
	align := func(value int) int { return (value + (1 << alignment) - 1) &^ ((1 << alignment) - 1) }
	amdOffset := align(8 + 20*2)
	armOffset := align(amdOffset + len(amd))
	fat := make([]byte, armOffset+len(arm))
	binary.BigEndian.PutUint32(fat[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:8], 2)
	writeArch := func(offset int, cpu, subCPU uint32, payloadOffset, size int) {
		binary.BigEndian.PutUint32(fat[offset:offset+4], cpu)
		binary.BigEndian.PutUint32(fat[offset+4:offset+8], subCPU)
		binary.BigEndian.PutUint32(fat[offset+8:offset+12], uint32(payloadOffset))
		binary.BigEndian.PutUint32(fat[offset+12:offset+16], uint32(size))
		binary.BigEndian.PutUint32(fat[offset+16:offset+20], alignment)
	}
	writeArch(8, amdCPU, amdSubCPU, amdOffset, len(amd))
	writeArch(28, armCPU, armSubCPU, armOffset, len(arm))
	copy(fat[amdOffset:], amd)
	copy(fat[armOffset:], arm)

	amdMatch := lookupMachOFrame(bytes.NewReader(fat), amdAddress, amdBase, "x86_64")
	if !strings.HasSuffix(amdMatch.function, ".amd_target") || filepath.Base(amdMatch.filename) != "amd_target.go" {
		t.Fatalf("universal x86_64 match = %#v", amdMatch)
	}
	armMatch := lookupMachOFrame(bytes.NewReader(fat), armAddress, armBase, "arm64")
	if !strings.HasSuffix(armMatch.function, ".arm_target") || filepath.Base(armMatch.filename) != "arm_target.go" {
		t.Fatalf("universal arm64 match = %#v", armMatch)
	}
}

func buildMachOFixture(t *testing.T, directory, arch, target string) ([]byte, uint64, uint64, uint32, uint32) {
	t.Helper()
	sourcePath := filepath.Join(directory, target+".go")
	binaryPath := filepath.Join(directory, target)
	source := fmt.Sprintf("package main\n\n//go:noinline\nfunc %s() int { return 42 }\n\nfunc main() { _ = %s() }\n", target, target)
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-gcflags=all=-N -l", "-o", binaryPath, sourcePath)
	command.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s Mach-O fixture: %v\n%s", arch, err, output)
	}
	payload, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := macho.NewFile(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	if parsed.Symtab == nil || parsed.Segment("__TEXT") == nil {
		t.Fatal("Mach-O fixture is missing symbols or __TEXT")
	}
	var address uint64
	for _, symbol := range parsed.Symtab.Syms {
		if strings.HasSuffix(symbol.Name, "."+target) {
			address = symbol.Value
			break
		}
	}
	if address == 0 {
		t.Fatalf("Mach-O fixture symbol %s not found", target)
	}
	return payload, address, parsed.Segment("__TEXT").Addr, uint32(parsed.Cpu), uint32(parsed.SubCpu)
}

func TestLookupPEFrameAddsDWARFSourceLocation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-compiled PE fixture requires the Linux test environment")
	}
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "fixture.go")
	binaryPath := filepath.Join(directory, "fixture.exe")
	source := `package main

//go:noinline
func pe_target() int {
	return 126
}

func main() { _ = pe_target() }
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-gcflags=all=-N -l", "-o", binaryPath, sourcePath)
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build PE fixture: %v\n%s", err, output)
	}
	file, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := pe.NewFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var symbolRVA uint64
	for _, symbol := range parsed.Symbols {
		sectionIndex := int(symbol.SectionNumber) - 1
		if strings.HasSuffix(symbol.Name, ".pe_target") && sectionIndex >= 0 && sectionIndex < len(parsed.Sections) {
			symbolRVA = uint64(parsed.Sections[sectionIndex].VirtualAddress) + uint64(symbol.Value)
			break
		}
	}
	imageBase := peImageBase(parsed)
	_ = parsed.Close()
	if symbolRVA == 0 || imageBase == 0 {
		t.Fatal("PE fixture function or image base not found")
	}
	instructionAddress := imageBase + symbolRVA

	matched := lookupPEFrame(file, instructionAddress, imageBase)
	if !strings.HasSuffix(matched.function, ".pe_target") || matched.address+imageBase != instructionAddress || filepath.Base(matched.filename) != "fixture.go" || matched.line < 4 {
		t.Fatalf("PE/DWARF match = %#v", matched)
	}

	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, "PE123", binary)
	payload := []byte(fmt.Sprintf(`{
		"debug_meta":{"images":[{"type":"pe","image_addr":"0x%x","image_size":"0x0","debug_id":"PE123","arch":"x86_64"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x%x","filename":"fixture.exe"}]}}]}
	}`, imageBase, instructionAddress))
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := processedFrame(t, processed)
	if !changed || filepath.Base(frame["filename"].(string)) != "fixture.go" || frame["lineno"].(float64) < 4 || frame["symbol_addr"] != fmt.Sprintf("0x%x", instructionAddress) {
		t.Fatalf("processed PE/DWARF frame = %#v, changed=%v", frame, changed)
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
	return processedFrames(t, raw)[0]
}

func processedFrames(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	exception := payload["exception"].(map[string]any)
	value := exception["values"].([]any)[0].(map[string]any)
	stacktrace := value["stacktrace"].(map[string]any)
	rawFrames := stacktrace["frames"].([]any)
	frames := make([]map[string]any, 0, len(rawFrames))
	for _, rawFrame := range rawFrames {
		frames = append(frames, rawFrame.(map[string]any))
	}
	return frames
}
