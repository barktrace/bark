package symbolicate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/barktrace/bark/internal/blobstore"
	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

const proguardFixture = `# compiler: R8
com.example.checkout.PaymentService -> a.b:
    1:3:void submitOrder(java.lang.String):41:43 -> c
    void retry() -> d
com.example.checkout.Other -> x.y:
    1:1:void ignored():10:10 -> a
`

func TestProguardMapLookup(t *testing.T) {
	mapping, err := ParseProguardMap(bytes.NewBufferString(proguardFixture))
	if err != nil {
		t.Fatal(err)
	}
	position, ok := mapping.Lookup("a.b", "c", 2)
	if !ok || position.class != "com.example.checkout.PaymentService" || position.method != "submitOrder" || position.line != 42 {
		t.Fatalf("mapped position = %#v, ok=%v", position, ok)
	}
	position, ok = mapping.Lookup("a.b", "d", 0)
	if !ok || position.method != "retry" {
		t.Fatalf("method without lines = %#v, ok=%v", position, ok)
	}
}

func TestProguardMapRejectsOversizedInput(t *testing.T) {
	if _, err := parseProguardMap(bytes.NewBufferString("example.Type -> a:\n    void run() -> b\n"), 16); err == nil {
		t.Fatal("oversized ProGuard mapping was accepted")
	}
}

func TestProguardMapExpandsR8InlineChain(t *testing.T) {
	mapping, err := ParseProguardMap(strings.NewReader(`# {"id":"com.android.tools.r8.mapping","version":"2.0"}
com.android.tools.r8.naming.retrace.Main -> a.a:
# {"id":"sourceFile","fileName":"Main.kt"}
    6:7:void foo.bar.Baz.inlinee():80:81 -> a
    6:7:void method2(int):88 -> a
    6:7:void method1(java.lang.String):96 -> a
    6:7:void main(java.lang.String[]):102 -> a
`))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("a.a", "a", 7)
	if !ok || len(frames) != 4 {
		t.Fatalf("inline frames = %#v, ok=%v", frames, ok)
	}
	want := []struct {
		class, method, filename string
		line                    int
	}{
		{"foo.bar.Baz", "inlinee", "Baz.kt", 81},
		{"com.android.tools.r8.naming.retrace.Main", "method2", "Main.kt", 88},
		{"com.android.tools.r8.naming.retrace.Main", "method1", "Main.kt", 96},
		{"com.android.tools.r8.naming.retrace.Main", "main", "Main.kt", 102},
	}
	for index, expected := range want {
		actual := frames[index]
		if actual.class != expected.class || actual.method != expected.method || actual.filename != expected.filename || actual.line != expected.line || !actual.hasLine {
			t.Fatalf("inline frame[%d] = %#v, want %#v", index, actual, expected)
		}
	}
}

func TestProguardMapKeepsBareAmbiguityToOneFrame(t *testing.T) {
	mapping, err := ParseProguardMap(strings.NewReader(`com.android.tools.r8.R8 -> a.a:
    void foo(int) -> a
    void bar(int,int) -> a
`))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("a.a", "a", 0)
	if !ok || len(frames) != 1 || frames[0].method != "foo" {
		t.Fatalf("ambiguous frames = %#v, ok=%v", frames, ok)
	}
}

func TestProguardMapPrefersBaseMappingWithoutInputLine(t *testing.T) {
	mapping, err := ParseProguardMap(strings.NewReader(`example.Main -> a:
    1:1:void inlined():10:10 -> b
    1:1:void caller():20 -> b
    void fallback() -> b
`))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("a", "b", 0)
	if !ok || len(frames) != 1 || frames[0].method != "fallback" {
		t.Fatalf("missing-line frames = %#v, ok=%v", frames, ok)
	}
}

func TestProguardMapUsesFirstInlineGroupWithoutInputLine(t *testing.T) {
	mapping, err := ParseProguardMap(strings.NewReader(`example.Main -> a:
    2:4:void inner():10:12 -> b
    2:4:void outer():20 -> b
    5:5:void other():30:30 -> b
`))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("a", "b", 0)
	if !ok || len(frames) != 2 || frames[0].method != "inner" || frames[1].method != "outer" {
		t.Fatalf("missing-line inline frames = %#v, ok=%v", frames, ok)
	}
}

func TestProguardMapExpandsMultipleMatchingInlineGroups(t *testing.T) {
	mapping, err := ParseProguardMap(strings.NewReader(`com.android.tools.r8.Internal -> com.android.tools.r8.Internal:
    10:10:void some.inlinee1(int):10:10 -> zza
    10:10:void foo(int):10 -> zza
    11:12:void ignored(int):11:12 -> zza
    10:10:void some.inlinee2(int,int):20:20 -> zza
    10:10:void foo(int,int):42 -> zza
`))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("com.android.tools.r8.Internal", "zza", 10)
	if !ok || len(frames) != 4 {
		t.Fatalf("multiple inline groups = %#v, ok=%v", frames, ok)
	}
	want := []string{"inlinee1", "foo", "inlinee2", "foo"}
	for index, method := range want {
		if frames[index].method != method {
			t.Fatalf("frame[%d] method = %q, want %q", index, frames[index].method, method)
		}
	}
}

func TestProguardMapBoundsInlineExpansion(t *testing.T) {
	var fixture strings.Builder
	fixture.WriteString("example.Main -> a:\n")
	for index := 0; index < maxProguardInlineDepth+100; index++ {
		fmt.Fprintf(&fixture, "    1:1:void method%d():%d -> a\n", index, index+1)
	}
	mapping, err := ParseProguardMap(strings.NewReader(fixture.String()))
	if err != nil {
		t.Fatal(err)
	}
	frames, ok := mapping.LookupFrames("a", "a", 1)
	if !ok || len(frames) != maxProguardInlineDepth {
		t.Fatalf("bounded inline frame count = %d, ok=%v", len(frames), ok)
	}
	if frames[0].method != "method0" || frames[len(frames)-1].method != fmt.Sprintf("method%d", maxProguardInlineDepth+99) {
		t.Fatalf("bounded inline endpoints = %q ... %q", frames[0].method, frames[len(frames)-1].method)
	}
}

func FuzzParseProguardMap(f *testing.F) {
	f.Add(proguardFixture, "a.b", "c", 2)
	f.Add("broken -> :\n    2:1:void nope():x -> a\n", "broken", "a", 1)
	f.Fuzz(func(t *testing.T, fixture, class, method string, line int) {
		mapping, err := parseProguardMap(strings.NewReader(fixture), 1<<20)
		if err != nil {
			return
		}
		frames, _ := mapping.LookupFrames(class, method, line)
		if len(frames) > maxProguardInlineDepth {
			t.Fatalf("unbounded inline frame count = %d", len(frames))
		}
	})
}

func TestRealProguardFixture(t *testing.T) {
	fixture := os.Getenv("BARKTRACE_PROGUARD_FIXTURE")
	if fixture == "" {
		t.Skip("BARKTRACE_PROGUARD_FIXTURE is not configured")
	}
	file, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	mapping, err := ParseProguardMap(file)
	if err != nil {
		t.Fatal(err)
	}
	entries := 0
	for _, class := range mapping.classes {
		for _, methods := range class.methods {
			entries += len(methods)
		}
	}
	for obfuscatedClass, class := range mapping.classes {
		for obfuscatedMethod, methods := range class.methods {
			for index := 0; index+1 < len(methods); index++ {
				if !sameProguardRange(methods[index], methods[index+1]) || methods[index].obfuscatedEnd <= 0 {
					continue
				}
				frames, ok := mapping.LookupFrames(obfuscatedClass, obfuscatedMethod, methods[index].obfuscatedStart)
				if !ok || len(frames) < 2 || len(frames) > maxProguardInlineDepth {
					t.Fatalf("real inline lookup returned %d frames, ok=%v", len(frames), ok)
				}
				t.Logf("parsed %d classes and %d method entries; representative inline chain has %d frames", len(mapping.classes), entries, len(frames))
				return
			}
		}
	}
	t.Fatalf("parsed %d classes and %d method entries but found no R8 inline group", len(mapping.classes), entries)
}

func TestProcessEventAppliesMatchingProguardArtifact(t *testing.T) {
	st := symbolicationStore(t)
	putProguardArtifact(t, st, "OTHER", `wrong.Name -> a.b:`)
	putProguardArtifact(t, st, "PROGUARD123", proguardFixture)
	payload := []byte(`{
		"platform":"java",
		"debug_meta":{"images":[{"type":"proguard","uuid":"PROGUARD123"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"module":"a.b","function":"c","filename":"b.java","lineno":2}]}}]}
	}`)
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("ProGuard event was not symbolicated")
	}
	frame := processedFrame(t, processed)
	if frame["module"] != "com.example.checkout.PaymentService" || frame["function"] != "submitOrder" || frame["filename"] != "PaymentService.java" || frame["lineno"] != float64(42) || frame["original_module"] != "a.b" {
		t.Fatalf("ProGuard frame = %#v", frame)
	}
}

func TestProcessEventExpandsProguardFramesInSentryOrder(t *testing.T) {
	st := symbolicationStore(t)
	putProguardArtifact(t, st, "INLINE123", `com.example.Main -> a:
# {"id":"sourceFile","fileName":"Main.kt"}
    3:4:void com.example.Helper.crash():20:21 -> b
    3:4:void middle():30 -> b
    3:4:void outer():40 -> b
`)
	payload := []byte(`{
		"platform":"java",
		"proguard_uuid":"INLINE123",
		"exception":{"values":[{"stacktrace":{"frames":[{"module":"a","package":"a","function":"b","filename":"SourceFile","abs_path":"SourceFile","lineno":4,"colno":9}]}}]}
	}`)
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frames := processedFrames(t, processed)
	if !changed || len(frames) != 3 {
		t.Fatalf("expanded ProGuard frames = %#v, changed=%v", frames, changed)
	}
	want := []struct {
		class, method, filename string
		line                    float64
		inline                  bool
	}{
		{"com.example.Main", "outer", "Main.kt", 40, false},
		{"com.example.Main", "middle", "Main.kt", 30, true},
		{"com.example.Helper", "crash", "Helper.kt", 21, true},
	}
	for index, expected := range want {
		frame := frames[index]
		if frame["module"] != expected.class || frame["package"] != expected.class || frame["function"] != expected.method || frame["filename"] != expected.filename || frame["abs_path"] != expected.filename || frame["lineno"] != expected.line || (frame["inline"] == true) != expected.inline || frame["symbolicated"] != true {
			t.Fatalf("expanded ProGuard frame[%d] = %#v", index, frame)
		}
		if frame["original_module"] != "a" || frame["original_package"] != "a" || frame["original_function"] != "b" || frame["original_filename"] != "SourceFile" || frame["original_abs_path"] != "SourceFile" || frame["original_lineno"] != float64(4) || frame["original_colno"] != float64(9) {
			t.Fatalf("expanded ProGuard original frame[%d] = %#v", index, frame)
		}
		if _, exists := frame["colno"]; exists {
			t.Fatalf("expanded ProGuard frame[%d] retained an unmapped column: %#v", index, frame)
		}
	}
}

func putProguardArtifact(t *testing.T, st *store.Store, debugID, mapping string) {
	t.Helper()
	stored, err := st.Blobs.Put(bytes.NewBufferString(mapping), blobstore.MaxBlobBytes)
	if err != nil {
		t.Fatal(err)
	}
	blobID, artifactID := uuid.NewString(), uuid.NewString()
	_, err = st.DB.Exec(`
		INSERT INTO blobs(id, organization_id, project_id, kind, storage_key, checksum, size, content_type)
		VALUES (?, 'org', 'project', 'artifact', ?, ?, ?, 'text/plain');
		INSERT INTO project_artifacts(id, project_id, release_id, blob_id, name, artifact_type, debug_id)
		VALUES (?, 'project', 'release', ?, ?, 'proguard', ?);
	`, blobID, stored.Key, stored.Checksum, stored.Size, artifactID, blobID, debugID+".txt", debugID)
	if err != nil {
		t.Fatal(err)
	}
}
