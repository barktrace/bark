package telemetry

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestDecodePayloadCompressionFormats(t *testing.T) {
	payload := []byte(`{"value":"decoded"}`)
	tests := map[string]func(*bytes.Buffer) error{
		"gzip": func(output *bytes.Buffer) error {
			writer := gzip.NewWriter(output)
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			return writer.Close()
		},
		"zlib": func(output *bytes.Buffer) error {
			writer := zlib.NewWriter(output)
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			return writer.Close()
		},
		"zstandard": func(output *bytes.Buffer) error {
			writer, err := zstd.NewWriter(output)
			if err != nil {
				return err
			}
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			return writer.Close()
		},
		"brotli": func(output *bytes.Buffer) error {
			writer := brotli.NewWriter(output)
			if _, err := writer.Write(payload); err != nil {
				return err
			}
			return writer.Close()
		},
	}
	for name, encode := range tests {
		t.Run(name, func(t *testing.T) {
			var compressed bytes.Buffer
			if err := encode(&compressed); err != nil {
				t.Fatal(err)
			}
			decoded, err := decodePayload(compressed.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("decoded payload = %q", decoded)
			}
		})
	}
}

func TestDecodePayloadRejectsCompressedExpansionPastLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	oversized := `{"value":"` + strings.Repeat("x", MaxDecompressedBytes) + `"}`
	if _, err := writer.Write([]byte(oversized)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decodePayload(compressed.Bytes()); err == nil || !strings.Contains(err.Error(), "decompressed payload exceeds") {
		t.Fatalf("expected decompressed-size error, got %v", err)
	}
}

func TestDecodePayloadRejectsCompressedInputPastLimit(t *testing.T) {
	if _, err := decodePayload(make([]byte, MaxCompressedBytes+1)); err == nil || !strings.Contains(err.Error(), "payload exceeds") {
		t.Fatalf("expected compressed-size error, got %v", err)
	}
}
