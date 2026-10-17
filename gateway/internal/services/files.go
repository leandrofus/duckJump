package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

const (
	DefaultFileMaxSize = 1 << 30
	DefaultFileTTL     = 7 * 24 * time.Hour
)

var (
	ErrFilesNotConfigured = errors.New("file transfer is not configured on this gateway (-files)")
	ErrInvalidFileName    = errors.New("invalid file name")
	ErrFileTooLarge       = errors.New("file is too large")
	ErrFileNotFound          = errors.New("file not found")
	ErrFileForbidden         = errors.New("you may no longer download files from the host this one came from")
	ErrFileTransferSSHOnly   = errors.New("file transfer is available on SSH connections")
	ErrFileTransferForbidden = errors.New("you may not transfer files with this connection")
)

type FileDeletedError struct {
	Reason string
}

func (e *FileDeletedError) Error() string {
	return "the file was deleted (" + e.Reason + ")"
}

type FileStore interface {
	Put(ctx context.Context, key, tmpPath string, size int64) error
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	TempDir() string
}

type FileService struct {
	store     *store.Store
	files     FileStore
	filesFn   func() FileStore
	maxSize   int64
	maxSizeFn func() int64
	ttl       time.Duration
	ttlFn     func() time.Duration
}

func NewFileService(st *store.Store, files FileStore, maxSize int64, ttl time.Duration) *FileService {
	return &FileService{
		store:   st,
		files:   files,
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func NewFileServiceWithFuncs(st *store.Store, filesFn func() FileStore, maxSizeFn func() int64, ttlFn func() time.Duration) *FileService {
	return &FileService{
		store:     st,
		filesFn:   filesFn,
		maxSizeFn: maxSizeFn,
		ttlFn:     ttlFn,
	}
}

func (s *FileService) getStore() FileStore {
	if s.filesFn != nil {
		return s.filesFn()
	}
	return s.files
}

func (s *FileService) Configured() bool {
	return s.getStore() != nil
}

func (s *FileService) MaxSize() int64 {
	var m int64
	if s.maxSizeFn != nil {
		m = s.maxSizeFn()
	} else {
		m = s.maxSize
	}
	if m > 0 {
		return m
	}
	return DefaultFileMaxSize
}

func (s *FileService) TTL() time.Duration {
	var t time.Duration
	if s.ttlFn != nil {
		t = s.ttlFn()
	} else {
		t = s.ttl
	}
	if t > 0 {
		return t
	}
	return DefaultFileTTL
}

func (s *FileService) CleanName(n string) (string, error) {
	n = path.Base(strings.ReplaceAll(n, `\`, "/"))
	n = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, n)
	if n == "" || n == "." || n == "/" || n == ".." || len(n) > 255 {
		return "", ErrInvalidFileName
	}
	return n, nil
}

func (s *FileService) Spool(r io.Reader, max int64) (tmp string, size int64, sum string, err error) {
	fs := s.getStore()
	if fs == nil {
		return "", 0, "", ErrFilesNotConfigured
	}
	f, err := os.CreateTemp(fs.TempDir(), "up-*")
	if err != nil {
		return "", 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	size, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(r, max+1))
	if err == nil && size > max {
		err = ErrFileTooLarge
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		os.Remove(f.Name())
		return "", 0, "", err
	}
	return f.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

func (s *FileService) Keep(ctx context.Context, actor store.Actor, userID, username, name, tmp string, size int64, sum, origin string, connID, connName, remotePath, action string) (db.AuditFile, error) {
	fs := s.getStore()
	if fs == nil {
		os.Remove(tmp)
		return db.AuditFile{}, ErrFilesNotConfigured
	}
	id := store.NewID()
	if err := fs.Put(ctx, id, tmp, size); err != nil {
		os.Remove(tmp)
		return db.AuditFile{}, fmt.Errorf("storing the file: %w", err)
	}
	now := store.Now()
	f := db.AuditFile{
		ID:         id,
		OwnerID:    userID,
		OwnerName:  username,
		Name:       name,
		Size:       size,
		Sha256:     sum,
		StorageKey: id,
		Origin:     origin,
		RemotePath: remotePath,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.TTL()),
	}
	details := map[string]any{"file_id": id, "name": name, "size": size, "sha256": sum}
	if connID != "" {
		f.ConnectionID = store.NullString(connID)
		details["connection_id"], details["connection"], details["path"] = connID, connName, remotePath
	}
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateFile(ctx, db.CreateFileParams{
			ID:           f.ID,
			OwnerID:      f.OwnerID,
			OwnerName:    f.OwnerName,
			Name:         name,
			Size:         size,
			Sha256:       sum,
			StorageKey:   id,
			Origin:       origin,
			ConnectionID: f.ConnectionID,
			RemotePath:   remotePath,
			Now:          now,
			ExpiresAt:    f.ExpiresAt,
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     action,
			ObjectType: "file",
			ObjectID:   id,
			Details:    details,
		})
	})
	if err != nil {
		fs.Delete(context.WithoutCancel(ctx), id)
	}
	return f, err
}

func (s *FileService) RemoveFile(ctx context.Context, f db.AuditFile, actor store.Actor, reason string) error {
	fs := s.getStore()
	if fs != nil {
		if err := fs.Delete(ctx, f.StorageKey); err != nil {
			return fmt.Errorf("deleting %s: %w", f.ID, err)
		}
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		if _, err := q.MarkFileDeleted(ctx, db.MarkFileDeletedParams{
			ID:     f.ID,
			Reason: reason,
			Now:    store.NullTime(store.Now()),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "file.delete",
			ObjectType: "file",
			ObjectID:   f.ID,
			Details:    map[string]any{"name": f.Name, "reason": reason},
		})
	})
}

func (s *FileService) ListUserFiles(ctx context.Context, userID string) ([]db.AuditFile, error) {
	return s.store.Q.ListUserFiles(ctx, userID)
}

func (s *FileService) GetTrayFile(ctx context.Context, userID, fileID string) (db.AuditFile, error) {
	f, err := s.store.Q.GetFile(ctx, fileID)
	if err != nil {
		return f, store.Classify(err)
	}
	if f.OwnerID != userID {
		return f, ErrFileNotFound
	}
	if f.DeletedAt.Valid {
		return f, &FileDeletedError{Reason: f.DeleteReason.String}
	}
	return f, nil
}

func (s *FileService) UploadToTray(ctx context.Context, actor store.Actor, userID, username, rawName string, r io.Reader, contentLength int64) (db.AuditFile, error) {
	if !s.Configured() {
		return db.AuditFile{}, ErrFilesNotConfigured
	}
	name, err := s.CleanName(rawName)
	if err != nil {
		return db.AuditFile{}, err
	}
	max := s.MaxSize()
	if contentLength > max {
		return db.AuditFile{}, ErrFileTooLarge
	}
	tmp, size, sum, err := s.Spool(r, max)
	if err != nil {
		return db.AuditFile{}, err
	}
	return s.Keep(ctx, actor, userID, username, name, tmp, size, sum, "upload", "", "", "", "file.upload")
}

func (s *FileService) DownloadFromTray(ctx context.Context, actor store.Actor, userID string, isDev bool, fileID string) (db.AuditFile, io.ReadCloser, error) {
	if !s.Configured() {
		return db.AuditFile{}, nil, ErrFilesNotConfigured
	}
	f, err := s.GetTrayFile(ctx, userID, fileID)
	if err != nil {
		return db.AuditFile{}, nil, err
	}
	if f.Origin == "host" && !isDev {
		allowed, err := s.store.CanDownload(ctx, userID, f.ConnectionID.String)
		if err != nil {
			return db.AuditFile{}, nil, err
		}
		if !allowed {
			return db.AuditFile{}, nil, ErrFileForbidden
		}
	}
	body, err := s.getStore().Open(ctx, f.StorageKey)
	if err != nil {
		return db.AuditFile{}, nil, err
	}
	if err := s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "file.download",
		ObjectType: "file",
		ObjectID:   f.ID,
		Details:    map[string]any{"name": f.Name, "size": f.Size, "sha256": f.Sha256},
	}); err != nil {
		body.Close()
		return db.AuditFile{}, nil, err
	}
	return f, body, nil
}

func (s *FileService) DeleteFromTray(ctx context.Context, actor store.Actor, userID, fileID string) error {
	if !s.Configured() {
		return ErrFilesNotConfigured
	}
	f, err := s.GetTrayFile(ctx, userID, fileID)
	if err != nil {
		return err
	}
	return s.RemoveFile(ctx, f, actor, "deleted by its owner")
}

func (s *FileService) PurgeFiles(ctx context.Context) (int, error) {
	if !s.Configured() {
		return 0, nil
	}
	n := 0
	for {
		rows, err := s.store.Q.ExpiredFiles(ctx, db.ExpiredFilesParams{Now: store.TS(store.Now()), Lim: 200})
		if err != nil || len(rows) == 0 {
			return n, err
		}
		for _, f := range rows {
			if err := s.RemoveFile(ctx, f, store.Actor{Name: "retention"}, "expired"); err != nil {
				return n, err
			}
			n++
		}
	}
}

func (s *FileService) ListFilesAudit(ctx context.Context, ownerID string, limit int64) ([]db.AuditFile, error) {
	return s.store.Q.ListFiles(ctx, db.ListFilesParams{
		OwnerID: ownerID,
		Lim:     limit,
	})
}

func (s *FileService) DownloadFileAudit(ctx context.Context, actor store.Actor, fileID string) (db.AuditFile, io.ReadCloser, error) {
	if !s.Configured() {
		return db.AuditFile{}, nil, ErrFilesNotConfigured
	}
	f, err := s.store.Q.GetFile(ctx, fileID)
	if err != nil {
		return db.AuditFile{}, nil, store.Classify(err)
	}
	if f.DeletedAt.Valid {
		return db.AuditFile{}, nil, &FileDeletedError{Reason: f.DeleteReason.String}
	}
	body, err := s.getStore().Open(ctx, f.StorageKey)
	if err != nil {
		return db.AuditFile{}, nil, err
	}
	if err := s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "file.view",
		ObjectType: "file",
		ObjectID:   f.ID,
		Details:    map[string]any{"name": f.Name, "owner": f.OwnerName},
	}); err != nil {
		body.Close()
		return db.AuditFile{}, nil, err
	}
	return f, body, nil
}

func (s *FileService) OpenStore(ctx context.Context, storageKey string) (io.ReadCloser, error) {
	fs := s.getStore()
	if fs == nil {
		return nil, ErrFilesNotConfigured
	}
	return fs.Open(ctx, storageKey)
}

func (s *FileService) CheckFileAccess(ctx context.Context, userID string, isDev bool, connID string, up, down bool) (db.ConfigConnection, error) {
	c, err := s.store.Q.GetConnection(ctx, connID)
	if err != nil {
		return c, store.Classify(err)
	}
	if c.Protocol != "ssh" {
		return c, ErrFileTransferSSHOnly
	}
	if isDev {
		return c, nil
	}
	canUp, err := s.store.CanUpload(ctx, userID, connID)
	if err != nil {
		return c, err
	}
	canDown, err := s.store.CanDownload(ctx, userID, connID)
	if err != nil {
		return c, err
	}
	if (up && !canUp) || (down && !canDown) || (!up && !down && !canUp && !canDown) {
		return c, ErrFileTransferForbidden
	}
	return c, nil
}

func (s *FileService) AuditPush(ctx context.Context, actor store.Actor, file db.AuditFile, conn db.ConfigConnection, dest string, overwrite bool) error {
	return s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "file.push",
		ObjectType: "file",
		ObjectID:   file.ID,
		Details: map[string]any{
			"name":          file.Name,
			"size":          file.Size,
			"sha256":        file.Sha256,
			"connection_id": conn.ID,
			"connection":    conn.Name,
			"path":          dest,
			"overwrite":     overwrite,
		},
	})
}
