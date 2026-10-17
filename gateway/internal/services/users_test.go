package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	store.SetAuditKey([]byte("test audit key, 32 bytes long..."))
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	return st
}

func TestUserService_LifecycleAndGuards(t *testing.T) {
	st := newTestStore(t)
	svc := NewUserService(st)
	ctx := context.Background()

	adminActor := store.Actor{Name: "root"}

	// 1. Create a superadmin
	u1, err := svc.Create(ctx, CreateUserParams{
		Username:   "admin1",
		Password:   "ComplexPassword123!",
		Role:       "superadmin",
		CallerRole: "superadmin",
		Actor:      adminActor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}
	if u1.Username != "admin1" || u1.Role != "superadmin" {
		t.Fatalf("unexpected created user: %+v", u1)
	}

	// 2. Non-superadmin cannot create a superadmin
	_, err = svc.Create(ctx, CreateUserParams{
		Username:   "admin2",
		Password:   "ComplexPassword123!",
		Role:       "superadmin",
		CallerRole: "admin",
		Actor:      adminActor,
	})
	if err != ErrSuperadminGuarded {
		t.Fatalf("expected ErrSuperadminGuarded, got: %v", err)
	}

	// 3. Create regular user
	u2, err := svc.Create(ctx, CreateUserParams{
		Username:   "regular",
		Password:   "ComplexPassword123!",
		Role:       "user",
		CallerRole: "admin",
		Actor:      adminActor,
	})
	if err != nil {
		t.Fatalf("Create regular user failed: %v", err)
	}

	// 4. Cannot delete yourself
	err = svc.Delete(ctx, adminActor, u2.ID, "admin", u2.ID)
	if err != ErrCannotSelfDelete {
		t.Fatalf("expected ErrCannotSelfDelete, got: %v", err)
	}

	// 5. Cannot delete last superadmin
	err = svc.Delete(ctx, adminActor, "caller-id", "superadmin", u1.ID)
	if !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("expected ErrLastSuperadmin, got: %v", err)
	}

	// 6. SetPassword on superadmin by regular admin fails
	err = svc.SetPassword(ctx, adminActor, "admin", u1.ID, "NewSuperPassword123!")
	if !errors.Is(err, ErrSuperadminGuarded) {
		t.Fatalf("expected ErrSuperadminGuarded, got: %v", err)
	}

	// 7. SetPassword by superadmin succeeds
	err = svc.SetPassword(ctx, adminActor, "superadmin", u2.ID, "NewRegularPass123!")
	if err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	// 8. ResetTOTP by superadmin succeeds
	err = svc.ResetTOTP(ctx, adminActor, "superadmin", u2.ID)
	if err != nil {
		t.Fatalf("ResetTOTP failed: %v", err)
	}

	// 9. Delete regular user succeeds
	err = svc.Delete(ctx, adminActor, "caller-id", "admin", u2.ID)
	if err != nil {
		t.Fatalf("Delete regular user failed: %v", err)
	}
}

