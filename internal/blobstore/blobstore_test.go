package blobstore

import (
	"io"
	"strings"
	"testing"
)

func TestPutDeduplicatesAndRejectsTraversal(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Put(strings.NewReader("hello"), 10)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put(strings.NewReader("hello"), 10)
	if err != nil || first.Key != second.Key {
		t.Fatalf("dedup result = %#v %#v, %v", first, second, err)
	}
	file, err := store.Open(first.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	body, _ := io.ReadAll(file)
	if string(body) != "hello" {
		t.Fatalf("body = %q", body)
	}
	if _, err := store.Open("../secret"); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestPutEnforcesLimit(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(strings.NewReader("too long"), 3); err == nil {
		t.Fatal("oversize blob was accepted")
	}
}
