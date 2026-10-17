package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestConnectionService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	svc := NewConnectionService(st)
	ctx := context.Background()
	actor := store.Actor{Name: "test-admin"}

	// 1. Invalid protocol
	_, err := svc.Create(ctx, CreateConnectionParams{
		Name:     "web1",
		Protocol: "invalid_proto",
		Host:     "10.0.0.1",
		Actor:    actor,
	})
	if !errors.Is(err, ErrProtocolInvalid) {
		t.Fatalf("expected ErrProtocolInvalid, got %v", err)
	}

	// 2. Successful create with default port (ssh -> 22)
	created, err := svc.Create(ctx, CreateConnectionParams{
		Name:     "web1",
		Protocol: "ssh",
		Host:     "10.0.0.1",
		Tags:     []string{"linux", "prod"},
		Actor:    actor,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if created.Connection.Port != 22 {
		t.Fatalf("expected default port 22, got %d", created.Connection.Port)
	}
	if len(created.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", created.Tags)
	}

	// 3. Get connection with tags
	got, err := svc.Get(ctx, created.Connection.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got.Connection.Name != "web1" || len(got.Tags) != 2 {
		t.Fatalf("unexpected fetched connection: %+v", got)
	}

	// 4. Update tags and host
	newHost := "10.0.0.2"
	newTags := []string{"linux", "staging"}
	updated, err := svc.Update(ctx, UpdateConnectionParams{
		ID:    created.Connection.ID,
		Host:  &newHost,
		Tags:  &newTags,
		Actor: actor,
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Connection.Host != "10.0.0.2" {
		t.Fatalf("expected host 10.0.0.2, got %s", updated.Connection.Host)
	}
	if len(updated.Tags) != 2 || updated.Tags[1] != "staging" {
		t.Fatalf("unexpected tags: %v", updated.Tags)
	}

	// 5. Host key approve & clear
	fp := "SHA256:abcd1234abcd1234abcd1234abcd1234"
	if err := svc.ApproveHostKey(ctx, actor, created.Connection.ID, fp); err != nil {
		t.Fatalf("ApproveHostKey failed: %v", err)
	}
	if err := svc.ClearHostKey(ctx, actor, created.Connection.ID); err != nil {
		t.Fatalf("ClearHostKey failed: %v", err)
	}

	// 6. Delete
	if err := svc.Delete(ctx, actor, created.Connection.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 7. Get after delete returns not found
	_, err = svc.Get(ctx, created.Connection.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected store.ErrNotFound, got %v", err)
	}
}
