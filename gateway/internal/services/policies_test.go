package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestPolicyService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	userSvc := NewUserService(st)
	connSvc := NewConnectionService(st)
	polSvc := NewPolicyService(st)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Create a user and a connection
	u, err := userSvc.Create(ctx, CreateUserParams{
		Username:   "poluser",
		Password:   "ComplexPassword123!",
		Role:       "user",
		CallerRole: "superadmin",
		Actor:      adminActor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	c, err := connSvc.Create(ctx, CreateConnectionParams{
		Name:     "polconn",
		Protocol: "ssh",
		Host:     "10.0.0.1",
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Create conn failed: %v", err)
	}

	// 2. Reject policy with no permissions
	falseVal := false
	_, err = polSvc.Create(ctx, CreatePolicyParams{
		SubjectType: "user",
		SubjectID:   u.ID,
		ObjectType:  "connection",
		ObjectRef:   c.Connection.ID,
		CanConnect:  &falseVal,
		Actor:       adminActor,
	})
	if !errors.Is(err, ErrPolicyNoPermissions) {
		t.Fatalf("expected ErrPolicyNoPermissions, got %v", err)
	}

	// 3. Create valid policy
	pol, err := polSvc.Create(ctx, CreatePolicyParams{
		SubjectType: "user",
		SubjectID:   u.ID,
		ObjectType:  "connection",
		ObjectRef:   c.Connection.ID,
		TTLSeconds:  3600,
		Description: "test grant",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create policy failed: %v", err)
	}
	if !pol.CanConnect {
		t.Fatal("expected CanConnect to default to true")
	}

	// 4. Duplicate policy is rejected
	_, err = polSvc.Create(ctx, CreatePolicyParams{
		SubjectType: "user",
		SubjectID:   u.ID,
		ObjectType:  "connection",
		ObjectRef:   c.Connection.ID,
		Actor:       adminActor,
	})
	if !errors.Is(err, ErrPolicyAlreadyExists) {
		t.Fatalf("expected ErrPolicyAlreadyExists, got %v", err)
	}

	// 5. Update policy
	trueVal := true
	updated, err := polSvc.Update(ctx, UpdatePolicyParams{
		ID:        pol.ID,
		CanUpload: &trueVal,
		Actor:     adminActor,
	})
	if err != nil {
		t.Fatalf("Update policy failed: %v", err)
	}
	if !updated.CanUpload {
		t.Fatal("expected CanUpload to be true")
	}

	// 6. Delete policy
	if err := polSvc.Delete(ctx, adminActor, pol.ID); err != nil {
		t.Fatalf("Delete policy failed: %v", err)
	}

	// 7. Verify deletion
	_, err = polSvc.Get(ctx, pol.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
