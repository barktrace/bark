package blobstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const MaxBlobBytes int64 = 100 << 20

type Backend interface {
	Put(io.Reader, int64) (Result, error)
	Open(string) (Reader, error)
	Remove(string) error
}

type Reader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

type Store struct{ root string }

type Result struct {
	Key      string
	Checksum string
	Size     int64
}

func New(dataDir string) (*Store, error) {
	root := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create blob directory: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) Put(reader io.Reader, limit int64) (Result, error) {
	if limit <= 0 || limit > MaxBlobBytes {
		limit = MaxBlobBytes
	}
	temporary, err := os.CreateTemp(s.root, ".upload-*")
	if err != nil {
		return Result{}, err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(reader, limit+1))
	if err != nil {
		return Result{}, err
	}
	if written > limit {
		return Result{}, errors.New("blob exceeds size limit")
	}
	if err := temporary.Sync(); err != nil {
		return Result{}, err
	}
	if err := temporary.Close(); err != nil {
		return Result{}, err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	key := filepath.Join(checksum[:2], checksum[2:4], checksum)
	destination := filepath.Join(s.root, key)
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return Result{}, err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			if _, statErr := os.Stat(destination); statErr != nil {
				return Result{}, err
			}
		}
		_ = os.Remove(temporaryName)
	}
	committed = true
	return Result{Key: filepath.ToSlash(key), Checksum: checksum, Size: written}, nil
}

func (s *Store) Open(key string) (Reader, error) {
	path, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (s *Store) Remove(key string) error {
	path, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) resolve(key string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(strings.TrimSpace(key)))
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", errors.New("invalid blob key")
	}
	return filepath.Join(s.root, clean), nil
}
