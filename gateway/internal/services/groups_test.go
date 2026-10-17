package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestGroupService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	grpSvc := NewGroupService(st)
	usrSvc := NewUserService(st)
	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// 1. Create a user
	u, err := usrSvc.Create(ctx, CreateUserParams{
		Username:   "grpuser",
		Password:   "ComplexPassword123!",
		Role:       "user",
		CallerRole: "superadmin",
		Actor:      adminActor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	// 2. Create a group
	g, err := grpSvc.Create(ctx, CreateGroupParams{
		Name:        "devops",
		Description: "DevOps Team",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create group failed: %v", err)
	}
	if g.Name != "devops" {
		t.Fatalf("unexpected group name: %s", g.Name)
	}

	// 3. Add member
	if err := grpSvc.AddMember(ctx, adminActor, g.ID, u.ID); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	// 4. List members
	members, err := grpSvc.ListMembers(ctx, g.ID)
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) != 1 || members[0].Username != "grpuser" {
		t.Fatalf("unexpected members: %+v", members)
	}

	// 5. Remove member
	if err := grpSvc.RemoveMember(ctx, adminActor, g.ID, u.ID); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	// 6. Removing non-member returns ErrMembershipNotFound
	err = grpSvc.RemoveMember(ctx, adminActor, g.ID, u.ID)
	if !errors.Is(err, ErrMembershipNotFound) {
		t.Fatalf("expected ErrMembershipNotFound, got %v", err)
	}

	// 7. Update group
	newDesc := "Updated DevOps Team"
	updated, err := grpSvc.Update(ctx, UpdateGroupParams{
		ID:          g.ID,
		Description: &newDesc,
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Update group failed: %v", err)
	}
	if updated.Description != newDesc {
		t.Fatalf("unexpected description: %s", updated.Description)
	}

	// 8. Delete group
	if err := grpSvc.Delete(ctx, adminActor, g.ID); err != nil {
		t.Fatalf("Delete group failed: %v", err)
	}

	// 9. Get returns not found
	_, err = grpSvc.Get(ctx, g.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
