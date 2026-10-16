package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/totp"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

func newService(t *testing.T) (*Service, db.ConfigUser) {
	t.Helper()
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	v, _ := vault.New(vault.GenerateKey())
	h, _ := HashPassword("correct horse battery")
	ctx := context.Background()
	id := store.NewID()
	if err := st.Q.CreateUser(ctx, db.CreateUserParams{ID: id, Username: "ana", PasswordHash: store.NullString(h),
		Source: "local", Role: "user", Now: store.Now()}); err != nil {
		t.Fatal(err)
	}
	u, _ := st.Q.GetUser(ctx, id)
	return &Service{Store: st, Vault: v}, u
}

func TestAuthenticate(t *testing.T) {
	s, u := newService(t)
	ctx := context.Background()
	if _, err := s.Authenticate(ctx, "ana", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "ana", "wrong"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody", "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown user: %v", err)
	}
	s.Store.Q.UpdateUser(ctx, db.UpdateUserParams{ID: u.ID, Role: u.Role, Disabled: true, Now: store.Now()})
	if _, err := s.Authenticate(ctx, "ana", "correct horse battery"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled user: %v", err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short") == nil || CheckPasswordPolicy("ñññññññññ") == nil {
		t.Fatal("short password accepted")
	}
	if CheckPasswordPolicy("ñññññññññññ") != nil {
		t.Fatal("10+ characters refused")
	}
}

func TestSessions(t *testing.T) {
	s, u := newService(t)
	ctx := context.Background()
	tok, err := s.NewSession(ctx, u.ID, true, "10.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Session(ctx, tok)
	if err != nil || !sess.MFAPending || sess.User.ID != u.ID {
		t.Fatalf("%+v %v", sess, err)
	}
	if err := s.CompleteMFA(ctx, sess.IDHash); err != nil {
		t.Fatal(err)
	}
	if sess, _ = s.Session(ctx, tok); sess.MFAPending {
		t.Fatal("still pending after MFA")
	}
	if _, err := s.Session(ctx, "forged"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("forged token: %v", err)
	}

	// Disabling the user ends the session.
	s.Store.Q.UpdateUser(ctx, db.UpdateUserParams{ID: u.ID, Role: u.Role, Disabled: true, Now: store.Now()})
	if _, err := s.Session(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session of a disabled user: %v", err)
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	s, u := newService(t)
	ctx := context.Background()
	tok, _ := s.NewSession(ctx, u.ID, false, "", "")
	s.Store.Q.TouchWebSession(ctx, db.TouchWebSessionParams{IDHash: hashToken(tok), Now: store.Now().Add(-SessionIdle - time.Minute)})
	if _, err := s.Session(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Fatalf("idle session accepted: %v", err)
	}
}

func TestTOTP(t *testing.T) {
	s, u := newService(t)
	sec := totp.NewSecret()
	u.TOTPSealed = s.SealTOTP(u.ID, sec)
	code, _ := totp.Code(sec, time.Now())
	if !s.CheckTOTP(u, code) {
		t.Fatal("valid code refused")
	}
	if s.CheckTOTP(u, "000000") && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	other := u
	other.ID = store.NewID() // sealed for another user: does not open
	if s.CheckTOTP(other, code) {
		t.Fatal("secret opened under another user id")
	}
}

func init() { store.SetAuditKey([]byte("auth tests audit key............")) }
