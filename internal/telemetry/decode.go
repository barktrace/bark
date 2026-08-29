package telemetry

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const (
	MaxCompressedBytes   = 16 << 20
	MaxDecompressedBytes = 24 << 20
)

func decodePayload(raw []byte) ([]byte, error) {
	if len(raw) > MaxCompressedBytes {
		return nil, errors.New("payload exceeds analysis size limit")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("payload is empty")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return trimmed, nil
	}
	read := func(reader io.Reader, close func()) ([]byte, error) {
		if close != nil {
			defer close()
		}
		decoded, err := io.ReadAll(io.LimitReader(reader, MaxDecompressedBytes+1))
		if err != nil {
			return nil, err
		}
		if len(decoded) > MaxDecompressedBytes {
			return nil, errors.New("decompressed payload exceeds analysis size limit")
		}
		decoded = bytes.TrimSpace(decoded)
		if len(decoded) == 0 || (decoded[0] != '{' && decoded[0] != '[') {
			return nil, errors.New("decoded payload is not JSON")
		}
		return decoded, nil
	}
	if len(trimmed) >= 2 && trimmed[0] == 0x1f && trimmed[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(trimmed))
		if err != nil {
			return nil, err
		}
		return read(reader, func() { _ = reader.Close() })
	}
	if len(trimmed) >= 4 && bytes.Equal(trimmed[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		reader, err := zstd.NewReader(bytes.NewReader(trimmed), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(32<<20))
		if err != nil {
			return nil, err
		}
		return read(reader, reader.Close)
	}
	if reader, err := zlib.NewReader(bytes.NewReader(trimmed)); err == nil {
		if decoded, decodeErr := read(reader, func() { _ = reader.Close() }); decodeErr == nil {
			return decoded, nil
		}
	}
	if decoded, err := read(brotli.NewReader(bytes.NewReader(trimmed)), nil); err == nil {
		return decoded, nil
	}
	return nil, errors.New("unsupported or invalid compressed payload")
}
