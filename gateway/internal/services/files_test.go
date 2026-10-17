package services

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

type testFileStore struct {
	mu      sync.Mutex
	tempDir string
	files   map[string][]byte
}

func (m *testFileStore) TempDir() string {
	return m.tempDir
}

func (m *testFileStore) Put(ctx context.Context, key, tmpPath string, size int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	m.files[key] = data
	_ = os.Remove(tmpPath)
	return nil
}

func (m *testFileStore) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *testFileStore) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, key)
	return nil
}

func TestFileService(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	tmpDir := t.TempDir()
	fs := &testFileStore{
		tempDir: tmpDir,
		files:   make(map[string][]byte),
	}

	userSvc := NewUserService(st)
	u, err := userSvc.Create(ctx, CreateUserParams{
		Username:   "alice",
		Password:   "password1234",
		Role:       "user",
		CallerRole: "superadmin",
		Actor:      store.Actor{Name: "cli"},
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	aliceActor := store.Actor{
		ID:   u.ID,
		Name: u.Username,
	}

	// 1. Unconfigured FileService returns ErrFilesNotConfigured
	unconfSvc := NewFileService(st, nil, 0, 0)
	if unconfSvc.Configured() {
		t.Fatalf("expected unconfigured service")
	}
	_, err = unconfSvc.UploadToTray(ctx, aliceActor, u.ID, u.Username, "test.txt", bytes.NewReader([]byte("data")), 4)
	if !errors.Is(err, ErrFilesNotConfigured) {
		t.Fatalf("expected ErrFilesNotConfigured, got %v", err)
	}

	// 2. Configured FileService
	fileSvc := NewFileService(st, fs, 1024, 24*time.Hour)
	if !fileSvc.Configured() {
		t.Fatalf("expected configured service")
	}

	// Invalid file name
	_, err = fileSvc.UploadToTray(ctx, aliceActor, u.ID, u.Username, ".", bytes.NewReader([]byte("data")), 4)
	if !errors.Is(err, ErrInvalidFileName) {
		t.Fatalf("expected ErrInvalidFileName, got %v", err)
	}

	// 3. Upload file to tray
	content := []byte("hello world from tray")
	uploaded, err := fileSvc.UploadToTray(ctx, aliceActor, u.ID, u.Username, "hello.txt", bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("UploadToTray failed: %v", err)
	}
	if uploaded.Name != "hello.txt" || uploaded.Size != int64(len(content)) {
		t.Fatalf("unexpected uploaded file: %+v", uploaded)
	}

	// 4. List user files
	files, err := fileSvc.ListUserFiles(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].ID != uploaded.ID {
		t.Fatalf("unexpected user files list: %+v", files)
	}

	// 5. Download from tray
	fileRecord, reader, err := fileSvc.DownloadFromTray(ctx, aliceActor, u.ID, false, uploaded.ID)
	if err != nil {
		t.Fatalf("DownloadFromTray failed: %v", err)
	}
	readBytes, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(readBytes, content) {
		t.Fatalf("download content mismatch: got %q want %q", readBytes, content)
	}
	if fileRecord.ID != uploaded.ID {
		t.Fatalf("record mismatch: %+v", fileRecord)
	}

	// 6. Delete from tray
	err = fileSvc.DeleteFromTray(ctx, aliceActor, u.ID, uploaded.ID)
	if err != nil {
		t.Fatalf("DeleteFromTray failed: %v", err)
	}

	// 7. Get after delete should return FileDeletedError
	_, err = fileSvc.GetTrayFile(ctx, u.ID, uploaded.ID)
	var delErr *FileDeletedError
	if !errors.As(err, &delErr) {
		t.Fatalf("expected FileDeletedError, got %v", err)
	}

	// 8. Purge files with expired TTL
	// Upload an expired file directly
	expiredUploaded, err := fileSvc.UploadToTray(ctx, aliceActor, u.ID, u.Username, "expired.txt", bytes.NewReader([]byte("old")), 3)
	if err != nil {
		t.Fatalf("UploadToTray failed: %v", err)
	}

	// Move expiration to the past
	_, err = st.DB.ExecContext(ctx, "UPDATE audit_files SET expires_at = $1 WHERE id = $2", store.Now().Add(-10*time.Hour), expiredUploaded.ID)
	if err != nil {
		t.Fatalf("update expires_at failed: %v", err)
	}

	purged, err := fileSvc.PurgeFiles(ctx)
	if err != nil {
		t.Fatalf("PurgeFiles failed: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged file, got %d", purged)
	}

	// 9. CheckFileAccess and AuditPush
	connSvc := NewConnectionService(st)
	conn, err := connSvc.Create(ctx, CreateConnectionParams{
		Name:     "ssh-server",
		Protocol: "ssh",
		Host:     "127.0.0.1",
		Port:     22,
		Actor:    store.Actor{Name: "cli"},
	})
	if err != nil {
		t.Fatalf("Create connection failed: %v", err)
	}

	// Dev user has access
	c, err := fileSvc.CheckFileAccess(ctx, u.ID, true, conn.Connection.ID, true, true)
	if err != nil {
		t.Fatalf("CheckFileAccess for dev failed: %v", err)
	}
	if c.ID != conn.Connection.ID {
		t.Fatalf("conn ID mismatch: got %q, want %q", c.ID, conn.Connection.ID)
	}

	// Non-dev user without upload/download permission is forbidden
	_, err = fileSvc.CheckFileAccess(ctx, u.ID, false, conn.Connection.ID, true, false)
	if !errors.Is(err, ErrFileTransferForbidden) {
		t.Fatalf("expected ErrFileTransferForbidden, got %v", err)
	}

	// AuditPush
	err = fileSvc.AuditPush(ctx, aliceActor, expiredUploaded, conn.Connection, "/tmp/hello.txt", true)
	if err != nil {
		t.Fatalf("AuditPush failed: %v", err)
	}
}

