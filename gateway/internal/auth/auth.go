// Package auth authenticates gateway users: local passwords (bcrypt) with
// optional TOTP, and web sessions stored in the database.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
	"github.com/leandrofus/palta/gateway/internal/totp"
	"github.com/leandrofus/palta/gateway/internal/vault"
)

var (
	ErrInvalid   = errors.New("invalid credentials")
	ErrDisabled  = errors.New("user disabled")
	ErrNoSession = errors.New("no valid session")
)

const (
	SessionAbsolute = 12 * time.Hour
	SessionIdle     = 30 * time.Minute
	MinPassword     = 10
)

type Service struct {
	Store *store.Store
	Vault *vault.Vault
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func CheckPasswordPolicy(pw string) error {
	if len([]rune(pw)) < MinPassword {
		return errors.New("password must have at least 10 characters")
	}
	return nil
}

// dummyHash keeps unknown-user logins as slow as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("palta-dummy"), bcrypt.DefaultCost)

// Authenticate checks a local username/password.
func (s *Service) Authenticate(ctx context.Context, username, password string) (db.ConfigUser, error) {
	u, err := s.Store.Q.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(store.Classify(err), store.ErrNotFound) {
			bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return u, ErrInvalid
		}
		return u, err
	}
	if u.Source != "local" || !u.PasswordHash.Valid ||
		bcrypt.CompareHashAndPassword([]byte(u.PasswordHash.String), []byte(password)) != nil {
		return u, ErrInvalid
	}
	if u.Disabled {
		return u, ErrDisabled
	}
	return u, nil
}

// TOTPSecret unseals a user's TOTP secret (enrolled or pending).
func (s *Service) TOTPSecret(u db.ConfigUser) (string, error) {
	if len(u.TOTPSealed) == 0 {
		return "", errors.New("no totp secret")
	}
	b, err := s.Vault.Open(u.TOTPSealed, []byte(u.ID))
	return string(b), err
}

func (s *Service) CheckTOTP(u db.ConfigUser, code string) bool {
	sec, err := s.TOTPSecret(u)
	return err == nil && totp.Validate(sec, code, time.Now())
}

func (s *Service) SealTOTP(userID, secret string) []byte {
	return s.Vault.Seal([]byte(secret), []byte(userID))
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// NewSession creates a web session and returns the cookie value. Only its
// hash is stored.
func (s *Service) NewSession(ctx context.Context, userID string, mfaPending bool, ip, ua string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	now := store.Now()
	err := s.Store.Q.CreateWebSession(ctx, db.CreateWebSessionParams{
		IDHash: hashToken(tok), UserID: userID, MfaPending: mfaPending, IP: ip, UserAgent: ua,
		Now: now, ExpiresAt: now.Add(SessionAbsolute),
	})
	return tok, err
}

type Session struct {
	IDHash     string
	User       db.ConfigUser
	MFAPending bool
}

// Session resolves a cookie value, enforcing absolute and idle expiry and
// sliding the idle window.
func (s *Service) Session(ctx context.Context, tok string) (Session, error) {
	if tok == "" {
		return Session{}, ErrNoSession
	}
	h := hashToken(tok)
	ws, err := s.Store.Q.GetWebSession(ctx, h)
	if err != nil {
		return Session{}, ErrNoSession
	}
	now := store.Now()
	if now.After(ws.ExpiresAt) || now.Sub(ws.LastSeenAt) > SessionIdle {
		s.Store.Q.DeleteWebSession(ctx, h)
		return Session{}, ErrNoSession
	}
	u, err := s.Store.Q.GetUser(ctx, ws.UserID)
	if err != nil || u.Disabled {
		s.Store.Q.DeleteWebSession(ctx, h)
		return Session{}, ErrNoSession
	}
	// Write at most once a minute.
	if now.Sub(ws.LastSeenAt) > time.Minute {
		s.Store.Q.TouchWebSession(ctx, db.TouchWebSessionParams{IDHash: h, Now: now})
	}
	return Session{IDHash: h, User: u, MFAPending: ws.MfaPending}, nil
}

func (s *Service) CompleteMFA(ctx context.Context, idHash string) error {
	return s.Store.Q.CompleteWebSessionMFA(ctx, db.CompleteWebSessionMFAParams{IDHash: idHash, Now: store.Now()})
}

func (s *Service) EndSession(ctx context.Context, idHash string) error {
	return s.Store.Q.DeleteWebSession(ctx, idHash)
}

// PurgeExpired deletes dead sessions; run it periodically.
func (s *Service) PurgeExpired(ctx context.Context) (int64, error) {
	now := store.Now()
	return s.Store.Q.DeleteExpiredWebSessions(ctx, db.DeleteExpiredWebSessionsParams{Now: store.TS(now), IdleBefore: store.TS(now.Add(-SessionIdle))})
}
