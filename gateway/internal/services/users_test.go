package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
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

func TestUserService_SelfService(t *testing.T) {
	st := newTestStore(t)
	svc := NewUserService(st)
	ctx := context.Background()
	actor := store.Actor{Name: "self-user"}

	u, err := svc.Create(ctx, CreateUserParams{
		Username: "selfuser",
		Password: "Password123!",
		Role:     "user",
		Actor:    actor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	authMock := func(ctx context.Context, username, password string) (db.ConfigUser, error) {
		if password == "WrongPassword!" {
			return db.ConfigUser{}, errors.New("bad credentials")
		}
		return u, nil
	}

	// 1. Change password - dev mode disallowed
	err = svc.ChangePassword(ctx, actor, u, true, "Password123!", "NewPassword123!", authMock)
	if !errors.Is(err, ErrDevModeNotAllowed) {
		t.Fatalf("expected ErrDevModeNotAllowed, got %v", err)
	}

	// 2. Change password - wrong current password
	err = svc.ChangePassword(ctx, actor, u, false, "WrongPassword!", "NewPassword123!", authMock)
	if !errors.Is(err, ErrCurrentPasswordWrong) {
		t.Fatalf("expected ErrCurrentPasswordWrong, got %v", err)
	}

	// 3. Change password - success
	err = svc.ChangePassword(ctx, actor, u, false, "Password123!", "NewPassword123!", authMock)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// 4. Enroll TOTP - dev mode disallowed
	sealMock := func(userID, secret string) []byte {
		return []byte("sealed:" + secret)
	}
	_, _, err = svc.EnrollTOTP(ctx, u, true, sealMock)
	if !errors.Is(err, ErrDevModeNotAllowed) {
		t.Fatalf("expected ErrDevModeNotAllowed, got %v", err)
	}

	// 5. Enroll TOTP - success
	secret, url, err := svc.EnrollTOTP(ctx, u, false, sealMock)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}
	if secret == "" || url == "" {
		t.Fatalf("expected non-empty secret and url")
	}

	// Fetch updated user with sealed totp
	u, err = svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get user failed: %v", err)
	}

	// 6. Confirm TOTP - wrong code
	checkMock := func(usr db.ConfigUser, code string) bool {
		return code == "123456"
	}
	err = svc.ConfirmTOTP(ctx, actor, u, "000000", checkMock)
	if !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}

	// 7. Confirm TOTP - valid code
	err = svc.ConfirmTOTP(ctx, actor, u, "123456", checkMock)
	if err != nil {
		t.Fatalf("ConfirmTOTP failed: %v", err)
	}

	u, err = svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get user failed: %v", err)
	}
	if !u.TOTPEnabled {
		t.Fatalf("expected TOTPEnabled = true")
	}

	// 8. Disable TOTP - wrong password
	err = svc.DisableTOTP(ctx, actor, u, "WrongPassword!", authMock)
	if !errors.Is(err, ErrPasswordWrong) {
		t.Fatalf("expected ErrPasswordWrong, got %v", err)
	}

	// 9. Disable TOTP - valid password
	err = svc.DisableTOTP(ctx, actor, u, "NewPassword123!", authMock)
	if err != nil {
		t.Fatalf("DisableTOTP failed: %v", err)
	}

	u, err = svc.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("Get user failed: %v", err)
	}
	if u.TOTPEnabled {
		t.Fatalf("expected TOTPEnabled = false after disable")
	}

	// 10. ListUserGroups
	groups, err := svc.ListUserGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserGroups failed: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected 0 groups for new user, got %d", len(groups))
	}

	// 11. ListUserAccess
	access, err := svc.ListUserAccess(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserAccess failed: %v", err)
	}
	if len(access) != 0 {
		t.Fatalf("expected 0 access entries for user without grants, got %d", len(access))
	}

	_, err = svc.ListUserAccess(ctx, "non-existent-user-id")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for non-existent user, got %v", err)
	}
}

