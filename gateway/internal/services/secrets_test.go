package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

func TestSecretService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	v, err := vault.New(vault.GenerateKey())
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	secSvc := NewSecretService(st, v)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Validation errors
	_, err = secSvc.Create(ctx, CreateSecretParams{
		Name:     "bad-kind",
		Kind:     "invalid_kind",
		Username: "admin",
		Value:    "secret",
		Actor:    adminActor,
	})
	if !errors.Is(err, ErrSecretKindInvalid) {
		t.Fatalf("expected ErrSecretKindInvalid, got %v", err)
	}

	_, err = secSvc.Create(ctx, CreateSecretParams{
		Name:     "missing-val",
		Kind:     "password",
		Username: "admin",
		Value:    "",
		Actor:    adminActor,
	})
	if !errors.Is(err, ErrSecretMissingUsernameOrValue) {
		t.Fatalf("expected ErrSecretMissingUsernameOrValue, got %v", err)
	}

	// 2. Create password secret
	sec1, err := secSvc.Create(ctx, CreateSecretParams{
		Name:     "root-pwd",
		Kind:     "password",
		Username: "root",
		Value:    "supersecret123",
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Create secret failed: %v", err)
	}
	if sec1.Name != "root-pwd" || sec1.Kind != "password" || sec1.Username != "root" {
		t.Fatalf("unexpected secret properties: %+v", sec1)
	}

	// 3. Get and GetByName
	byID, err := secSvc.Get(ctx, sec1.ID)
	if err != nil {
		t.Fatalf("Get secret failed: %v", err)
	}
	if byID.ID != sec1.ID {
		t.Fatalf("Get returned different id: %s vs %s", byID.ID, sec1.ID)
	}

	byName, err := secSvc.GetByName(ctx, "root-pwd")
	if err != nil {
		t.Fatalf("GetByName secret failed: %v", err)
	}
	if byName.ID != sec1.ID {
		t.Fatalf("GetByName returned different id: %s", byName.ID)
	}

	// 4. Update metadata
	newName := "root-pwd-renamed"
	newUsername := "root2"
	updated, err := secSvc.Update(ctx, UpdateSecretParams{
		ID:       sec1.ID,
		Name:     &newName,
		Username: &newUsername,
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Update metadata failed: %v", err)
	}
	if updated.Name != newName || updated.Username != newUsername {
		t.Fatalf("unexpected updated metadata: %+v", updated)
	}

	// 5. Update value without kind should fail
	newVal := "newpass"
	_, err = secSvc.Update(ctx, UpdateSecretParams{
		ID:    sec1.ID,
		Value: &newVal,
		Actor: adminActor,
	})
	if !errors.Is(err, ErrSecretKindRequiredWithValue) {
		t.Fatalf("expected ErrSecretKindRequiredWithValue, got %v", err)
	}

	// 6. Update kind without value should fail
	newKind := "private_key"
	_, err = secSvc.Update(ctx, UpdateSecretParams{
		ID:    sec1.ID,
		Kind:  &newKind,
		Actor: adminActor,
	})
	if !errors.Is(err, ErrSecretKindRequiresValue) {
		t.Fatalf("expected ErrSecretKindRequiresValue, got %v", err)
	}

	// 7. Update value with kind
	updated, err = secSvc.Update(ctx, UpdateSecretParams{
		ID:    sec1.ID,
		Kind:  &newKind,
		Value: &newVal,
		Actor: adminActor,
	})
	if err != nil {
		t.Fatalf("Update value with kind failed: %v", err)
	}
	if updated.Kind != "private_key" {
		t.Fatalf("unexpected updated kind: %s", updated.Kind)
	}

	// Verify unsealing
	decrypted, err := v.Open(updated.Sealed, []byte(updated.ID))
	if err != nil {
		t.Fatalf("failed to decrypt updated secret: %v", err)
	}
	if string(decrypted) != newVal {
		t.Fatalf("expected %s, got %s", newVal, string(decrypted))
	}

	// 8. List
	list, err := secSvc.List(ctx)
	if err != nil {
		t.Fatalf("List secrets failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 secret in list, got %d", len(list))
	}

	// 9. Delete by name
	if err := secSvc.DeleteByName(ctx, adminActor, newName); err != nil {
		t.Fatalf("DeleteByName failed: %v", err)
	}

	// 10. Verify not found
	_, err = secSvc.Get(ctx, sec1.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
