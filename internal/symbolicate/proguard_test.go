package symbolicate

import (
	"bytes"
	"context"
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
