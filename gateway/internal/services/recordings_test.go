package services

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestRecordingService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Unconfigured service
	unconfiguredSvc := NewRecordingService(st, "", nil)
	if unconfiguredSvc.Configured() {
		t.Fatalf("expected service without dir or objects to be unconfigured")
	}

	days, err := unconfiguredSvc.RetentionDays(ctx)
	if err != nil {
		t.Fatalf("RetentionDays failed: %v", err)
	}
	if days != 0 {
		t.Fatalf("expected 0 default retention days, got %d", days)
	}

	// 2. Setting retention on unconfigured service should fail
	_, _, _, err = unconfiguredSvc.SetRetention(ctx, adminActor, "admin-id", 30)
	if !errors.Is(err, ErrRecordingsNotConfigured) {
		t.Fatalf("expected ErrRecordingsNotConfigured, got %v", err)
	}

	// 3. Validation error: retention days > 3650
	_, _, _, err = unconfiguredSvc.SetRetention(ctx, adminActor, "admin-id", 5000)
	if !errors.Is(err, ErrRetentionDaysInvalid) {
		t.Fatalf("expected ErrRetentionDaysInvalid, got %v", err)
	}

	// 4. Configured service with temp directory
	tmpDir := t.TempDir()
	recSvc := NewRecordingService(st, tmpDir, nil)
	if !recSvc.Configured() {
		t.Fatalf("expected service with dir to be configured")
	}

	// Set retention to 60 days
	prev, purged, bytesPurged, err := recSvc.SetRetention(ctx, adminActor, "admin-id", 60)
	if err != nil {
		t.Fatalf("SetRetention failed: %v", err)
	}
	if prev != 0 || purged != 0 || bytesPurged != 0 {
		t.Fatalf("unexpected result: prev=%d, purged=%d, bytes=%d", prev, purged, bytesPurged)
	}

	days, err = recSvc.RetentionDays(ctx)
	if err != nil {
		t.Fatalf("RetentionDays failed: %v", err)
	}
	if days != 60 {
		t.Fatalf("expected 60 retention days, got %d", days)
	}

	// 5. Usage stats
	u, err := recSvc.Usage(ctx, 60)
	if err != nil {
		t.Fatalf("Usage failed: %v", err)
	}
	if u.Recordings != 0 {
		t.Fatalf("expected 0 recordings, got %d", u.Recordings)
	}

	// 6. Test RecordingFile
	fName := "session123"
	fPath := tmpDir + "/" + fName + ".cast.gz"
	if err := os.WriteFile(fPath, []byte("fake asciicast gzip data"), 0644); err != nil {
		t.Fatalf("failed to write test recording file: %v", err)
	}

	foundPath, gz, size, err := recSvc.RecordingFile(fName)
	if err != nil {
		t.Fatalf("RecordingFile failed: %v", err)
	}
	if foundPath != fPath || !gz || size == 0 {
		t.Fatalf("unexpected file result: path=%s, gz=%v, size=%d", foundPath, gz, size)
	}

	// Test RecordingSize
	rSize, err := recSvc.RecordingSize(ctx, fName)
	if err != nil {
		t.Fatalf("RecordingSize failed: %v", err)
	}
	if rSize != size {
		t.Fatalf("RecordingSize mismatch: %d vs %d", rSize, size)
	}

	// 7. CheckViewRecording and AuditView
	sessSvc := NewSessionService(st)
	sessID := store.NewID()
	err = sessSvc.StartSession(ctx, StartSessionParams{
		SessionID:          sessID,
		UserID:             "user1",
		Username:           "alice",
		ConnectionID:       "conn1",
		ConnectionSnapshot: `{}`,
		Recording:          fName,
		Actor:              adminActor,
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	// Dev or auditor can view
	sessRec, err := recSvc.CheckViewRecording(ctx, adminActor, "user1", true, false, sessID)
	if err != nil {
		t.Fatalf("CheckViewRecording failed: %v", err)
	}
	if sessRec.ID != sessID {
		t.Fatalf("session ID mismatch: %s vs %s", sessRec.ID, sessID)
	}

	// Non-auditor without permission -> ErrForbidden
	_, err = recSvc.CheckViewRecording(ctx, adminActor, "user1", false, false, sessID)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}

	// AuditView
	if err := recSvc.AuditView(ctx, adminActor, sessID); err != nil {
		t.Fatalf("AuditView failed: %v", err)
	}
}

