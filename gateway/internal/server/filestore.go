package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/objstore"
)

// FileStore keeps the content of the file tray: a local directory, or the
// recordings bucket under its own prefix.
type FileStore interface {
	// Put stores a finished file (a temporary file the store may move).
	Put(ctx context.Context, key, tmpPath string, size int64) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	// TempDir is where uploads are assembled before Put.
	TempDir() string
}

// DirFileStore keeps files in a directory.
type DirFileStore struct{ Dir string }

func (d DirFileStore) path(key string) (string, error) {
	if key == "" || strings.ContainsAny(key, `/\`) || strings.HasPrefix(key, ".") {
		return "", fmt.Errorf("invalid file key %q", key)
	}
	return filepath.Join(d.Dir, key), nil
}

func (d DirFileStore) Put(_ context.Context, key, tmp string, _ int64) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	return os.Rename(tmp, p) // TempDir is inside Dir: same filesystem
}

func (d DirFileStore) Open(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (d DirFileStore) Delete(_ context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (d DirFileStore) TempDir() string {
	t := filepath.Join(d.Dir, ".tmp")
	os.MkdirAll(t, 0o700)
	return t
}

// S3FileStore keeps files in a bucket.
type S3FileStore struct{ S3 *objstore.S3 }

func (s S3FileStore) Put(ctx context.Context, key, tmp string, size int64) error {
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(tmp)
	return s.S3.Put(ctx, key, f, size)
}

func (s S3FileStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.S3.Open(ctx, s.S3.Key(key))
}

func (s S3FileStore) Delete(ctx context.Context, key string) error {
	return s.S3.RemoveKey(ctx, s.S3.Key(key))
}

func (s S3FileStore) TempDir() string { return os.TempDir() }
