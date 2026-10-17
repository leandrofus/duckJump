package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestFolderService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	fldSvc := NewFolderService(st)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Create root folder
	f1, err := fldSvc.Create(ctx, CreateFolderParams{
		Name:  "Infra",
		Actor: adminActor,
	})
	if err != nil {
		t.Fatalf("Create folder failed: %v", err)
	}
	if f1.Name != "Infra" {
		t.Fatalf("unexpected folder name: %s", f1.Name)
	}

	// 2. Create child folder
	f2, err := fldSvc.Create(ctx, CreateFolderParams{
		Name:     "Prod",
		ParentID: &f1.ID,
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Create child folder failed: %v", err)
	}

	// 3. Move parent inside child (should fail: ErrFolderInsideItself)
	_, err = fldSvc.Update(ctx, UpdateFolderParams{
		ID:          f1.ID,
		ParentID:    &f2.ID,
		ParentIDSet: true,
		Actor:       adminActor,
	})
	if !errors.Is(err, ErrFolderInsideItself) {
		t.Fatalf("expected ErrFolderInsideItself, got %v", err)
	}

	// 4. Delete non-empty parent folder (should fail: FolderNotEmptyError)
	err = fldSvc.Delete(ctx, adminActor, f1.ID)
	var notEmptyErr *FolderNotEmptyError
	if !errors.As(err, &notEmptyErr) {
		t.Fatalf("expected FolderNotEmptyError, got %v", err)
	}

	// 5. Delete child folder
	if err := fldSvc.Delete(ctx, adminActor, f2.ID); err != nil {
		t.Fatalf("Delete child folder failed: %v", err)
	}

	// 6. Delete now-empty parent folder
	if err := fldSvc.Delete(ctx, adminActor, f1.ID); err != nil {
		t.Fatalf("Delete parent folder failed: %v", err)
	}

	// 7. Get returns not found
	_, err = fldSvc.Get(ctx, f1.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
