package blobstore

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestS3StoreRoundTrip(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=access/") {
			http.Error(w, "missing signature", http.StatusForbidden)
			return
		}
		if r.Header.Get("X-Amz-Content-Sha256") == "" || r.Header.Get("X-Amz-Date") == "" {
			http.Error(w, "missing signing headers", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			objects[r.URL.Path], _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := objects[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		case http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	store, err := NewS3(S3Config{Endpoint: server.URL, Region: "eu-west-1", Bucket: "telemetry", AccessKey: "access", SecretKey: "secret", Prefix: "prod", TempDir: t.TempDir(), Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Put(strings.NewReader("hello"), 10)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(result.Key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
	if err := store.Remove(result.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(result.Key); err == nil {
		t.Fatal("deleted object remained accessible")
	}
}

func TestS3StoreRejectsUnsafeConfigurationAndKeys(t *testing.T) {
	t.Parallel()
	if _, err := NewS3(S3Config{Endpoint: "http://s3.example", Bucket: "bucket", AccessKey: "key", SecretKey: "secret"}); err == nil {
		t.Fatal("insecure remote endpoint was accepted")
	}
	store, err := NewS3(S3Config{Endpoint: "https://s3.example", Bucket: "bucket", AccessKey: "key", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("../secret"); err == nil {
		t.Fatal("path traversal key was accepted")
	}
}
