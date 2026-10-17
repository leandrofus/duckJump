package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestOIDCService_ProvisionAndSync(t *testing.T) {
	st := newTestStore(t)
	svc := NewOIDCService(st)
	userSvc := NewUserService(st)
	groupSvc := NewGroupService(st)
	ctx := context.Background()

	// 1. Initial provision of a new OIDC user
	id1 := auth.Identity{
		Subject:     "oidc-sub-123",
		Username:    "alice_idp",
		DisplayName: "Alice Smith",
		Email:       "alice@example.com",
		Role:        "admin",
		Groups:      []string{"devs", "ops"},
	}
	u1, err := svc.Provision(ctx, id1)
	if err != nil {
		t.Fatalf("Initial provision failed: %v", err)
	}
	if u1.Username != "alice_idp" || u1.Role != "admin" || u1.Source != "oidc" {
		t.Fatalf("unexpected user: %+v", u1)
	}

	// Verify groups synced
	groups, err := userSvc.ListUserGroups(ctx, u1.ID)
	if err != nil {
		t.Fatalf("ListUserGroups failed: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// 2. Subsequent login updates profile and changes groups
	id1Updated := auth.Identity{
		Subject:     "oidc-sub-123",
		Username:    "alice_idp",
		DisplayName: "Alice S. Johnson",
		Email:       "alice.johnson@example.com",
		Role:        "user",
		Groups:      []string{"devs", "sec"}, // "ops" removed, "sec" added
	}
	u1Up, err := svc.Provision(ctx, id1Updated)
	if err != nil {
		t.Fatalf("Subsequent provision failed: %v", err)
	}
	if u1Up.DisplayName != "Alice S. Johnson" || u1Up.Role != "user" {
		t.Fatalf("expected updated profile, got %+v", u1Up)
	}

	groupsUp, err := userSvc.ListUserGroups(ctx, u1.ID)
	if err != nil {
		t.Fatalf("ListUserGroups after sync failed: %v", err)
	}
	if len(groupsUp) != 2 {
		t.Fatalf("expected 2 groups after sync, got %d", len(groupsUp))
	}
	groupNames := map[string]bool{}
	for _, g := range groupsUp {
		groupNames[g.Name] = true
	}
	if !groupNames["devs"] || !groupNames["sec"] || groupNames["ops"] {
		t.Fatalf("expected devs and sec, got %v", groupNames)
	}

	// 3. Local group shadowing: create local group "shadowed" and oidc user with that group
	_, err = groupSvc.Create(ctx, CreateGroupParams{
		Name:        "shadowed",
		Description: "local group",
		Actor:       store.Actor{Name: "admin"},
	})
	if err != nil {
		t.Fatalf("create local group failed: %v", err)
	}
	id2 := auth.Identity{
		Subject:  "oidc-sub-456",
		Username: "bob_idp",
		Role:     "user",
		Groups:   []string{"shadowed"},
	}
	u2, err := svc.Provision(ctx, id2)
	if err != nil {
		t.Fatalf("provision with shadowed group failed: %v", err)
	}
	u2Groups, err := userSvc.ListUserGroups(ctx, u2.ID)
	if err != nil {
		t.Fatalf("ListUserGroups for u2 failed: %v", err)
	}
	if len(u2Groups) != 0 {
		t.Fatalf("expected shadowed local group not to be assigned to oidc user, got %d", len(u2Groups))
	}

	// 4. Disabled user cannot log in
	dis := true
	_, err = userSvc.Update(ctx, UpdateUserParams{
		ID:         u1.ID,
		Disabled:   &dis,
		CallerRole: "superadmin",
		Actor:      store.Actor{Name: "admin"},
	})
	if err != nil {
		t.Fatalf("disable user failed: %v", err)
	}
	_, err = svc.Provision(ctx, id1Updated)
	if !errors.Is(err, auth.ErrDisabled) {
		t.Fatalf("expected ErrDisabled for disabled user, got %v", err)
	}

	// 5. Username clash with existing local user
	_, err = userSvc.Create(ctx, CreateUserParams{
		Username: "local_charlie",
		Password: "Password123!",
		Role:     "user",
		Actor:    store.Actor{Name: "admin"},
	})
	if err != nil {
		t.Fatalf("create local user failed: %v", err)
	}
	_, err = svc.Provision(ctx, auth.Identity{
		Subject:  "oidc-sub-789",
		Username: "local_charlie",
	})
	var le *auth.ErrLogin
	if !errors.As(err, &le) {
		t.Fatalf("expected ErrLogin for username collision, got %v", err)
	}
}
