package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/totp"
)

var (
	ErrTargetNameRequired      = errors.New("target_name is required")
	ErrTokenRequired           = errors.New("token is required")
	ErrInvalidVerificationCode = errors.New("invalid verification code")
	ErrSupportSessionNotFound  = errors.New("support session not found")
)

type InvalidSupportStatusError struct {
	Status string
}

func (e *InvalidSupportStatusError) Error() string {
	return fmt.Sprintf("session cannot be verified in status %s", e.Status)
}

type SupportHubNotifier interface {
	CloseAndUnregisterByToken(token string)
	CloseAndUnregisterByID(id string)
	NotifyVerified(id string)
}

type CreateSupportSessionParams struct {
	TargetName string
	Reason     string
	Ticket     string
	TTLMinutes int
}

type RequestSupportSessionParams struct {
	TargetName  string
	Reason      string
	Ticket      string
	AccountType string
	Domain      string
	Hostname    string
	ClientOS    string
}

type SupportService struct {
	store    *store.Store
	notifier SupportHubNotifier
}

func NewSupportService(st *store.Store, notifier SupportHubNotifier) *SupportService {
	return &SupportService{
		store:    st,
		notifier: notifier,
	}
}

func generateVerificationCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%900000+100000)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func (s *SupportService) CreateSession(ctx context.Context, actor store.Actor, createdBy string, params CreateSupportSessionParams) (db.ConfigSupportSession, error) {
	if strings.TrimSpace(params.TargetName) == "" {
		return db.ConfigSupportSession{}, ErrTargetNameRequired
	}
	ttl := 30 * time.Minute
	if params.TTLMinutes > 0 {
		ttl = time.Duration(params.TTLMinutes) * time.Minute
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return db.ConfigSupportSession{}, err
	}
	token := hex.EncodeToString(tokenBytes)
	verificationCode := generateVerificationCode()
	id := store.NewID()
	now := store.Now()
	expiresAt := now.Add(ttl)

	err := s.store.Q.CreateSupportSession(ctx, db.CreateSupportSessionParams{
		ID:         id,
		Token:      token,
		CreatedBy:  createdBy,
		TargetName: strings.TrimSpace(params.TargetName),
		Reason:     strings.TrimSpace(params.Reason),
		Ticket:     strings.TrimSpace(params.Ticket),
		TotpSecret: verificationCode,
		ExpiresAt:  expiresAt,
		Now:        now,
	})
	if err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}

	sess, err := s.store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}

	_ = s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "support_session.created",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"target_name": params.TargetName,
			"ticket":      params.Ticket,
			"expires_at":  expiresAt.Format(time.RFC3339),
		},
	})
	return sess, nil
}

func (s *SupportService) RequestSession(ctx context.Context, actor store.Actor, createdBy, fallbackUsername string, params RequestSupportSessionParams) (db.ConfigSupportSession, string, error) {
	target := strings.TrimSpace(params.TargetName)
	if target == "" {
		target = fallbackUsername
	}
	if params.Domain != "" && !strings.Contains(target, `\`) && !strings.Contains(target, `@`) {
		target = fmt.Sprintf(`%s\%s`, params.Domain, target)
	}
	ttl := 30 * time.Minute
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return db.ConfigSupportSession{}, "", err
	}
	token := hex.EncodeToString(tokenBytes)
	verificationCode := generateVerificationCode()
	id := store.NewID()
	now := store.Now()
	expiresAt := now.Add(ttl)

	err := s.store.Q.CreateSupportSession(ctx, db.CreateSupportSessionParams{
		ID:         id,
		Token:      token,
		CreatedBy:  createdBy,
		TargetName: target,
		Reason:     strings.TrimSpace(params.Reason),
		Ticket:     strings.TrimSpace(params.Ticket),
		TotpSecret: verificationCode,
		ExpiresAt:  expiresAt,
		Now:        now,
	})
	if err != nil {
		return db.ConfigSupportSession{}, "", store.Classify(err)
	}

	sess, err := s.store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return db.ConfigSupportSession{}, "", store.Classify(err)
	}

	_ = s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "support_session.requested",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"target_name":  target,
			"ticket":       params.Ticket,
			"account_type": params.AccountType,
			"hostname":     params.Hostname,
			"client_os":    params.ClientOS,
		},
	})
	return sess, verificationCode, nil
}

func (s *SupportService) GetStatusByToken(ctx context.Context, token string) (db.ConfigSupportSession, error) {
	if token == "" {
		return db.ConfigSupportSession{}, ErrTokenRequired
	}
	sess, err := s.store.Q.GetSupportSessionByToken(ctx, token)
	if err != nil {
		return db.ConfigSupportSession{}, ErrSupportSessionNotFound
	}
	return sess, nil
}

func (s *SupportService) EndByToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrTokenRequired
	}
	sess, err := s.store.Q.GetSupportSessionByToken(ctx, token)
	if err != nil {
		return ErrSupportSessionNotFound
	}
	now := store.Now()
	_ = s.store.Q.EndSupportSession(ctx, db.EndSupportSessionParams{
		ID:          sess.ID,
		Now:         store.NullTime(now),
		EndedReason: "client_ended",
	})
	if s.notifier != nil {
		s.notifier.CloseAndUnregisterByToken(token)
	}
	return nil
}

func (s *SupportService) ListSessions(ctx context.Context, createdBy, status string) ([]db.ConfigSupportSession, error) {
	return s.store.Q.ListSupportSessions(ctx, db.ListSupportSessionsParams{
		CreatedBy: createdBy,
		Status:    status,
	})
}

func (s *SupportService) GetSession(ctx context.Context, id string) (db.ConfigSupportSession, error) {
	sess, err := s.store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}
	return sess, nil
}

func (s *SupportService) VerifyTOTP(ctx context.Context, actor store.Actor, id, code string) (db.ConfigSupportSession, error) {
	sess, err := s.store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}
	if sess.Status != "connected" && sess.Status != "pending" {
		return db.ConfigSupportSession{}, &InvalidSupportStatusError{Status: sess.Status}
	}
	cleanCode := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	cleanSecret := strings.ReplaceAll(strings.TrimSpace(sess.TotpSecret), " ", "")

	valid := cleanCode != "" && cleanCode == cleanSecret
	if !valid {
		valid = totp.Validate(sess.TotpSecret, cleanCode, time.Now())
	}
	if !valid {
		_ = s.store.AuditTx(ctx, store.Event{
			Actor:      actor,
			Action:     "support_session.verify_failed",
			ObjectType: "support_session",
			ObjectID:   id,
		})
		return db.ConfigSupportSession{}, ErrInvalidVerificationCode
	}

	now := store.Now()
	if err := s.store.Q.ActivateSupportSession(ctx, db.ActivateSupportSessionParams{
		ID:  id,
		Now: store.NullTime(now),
	}); err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}

	if s.notifier != nil {
		s.notifier.NotifyVerified(id)
	}

	_ = s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "support_session.totp_verified",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"activated_at": now.Format(time.RFC3339),
		},
	})

	return s.store.Q.GetSupportSession(ctx, id)
}

func (s *SupportService) EndSession(ctx context.Context, actor store.Actor, id string) (db.ConfigSupportSession, error) {
	now := store.Now()
	if s.notifier != nil {
		s.notifier.CloseAndUnregisterByID(id)
	}
	if err := s.store.Q.EndSupportSession(ctx, db.EndSupportSessionParams{
		ID:          id,
		Now:         store.NullTime(now),
		EndedReason: "operator_ended",
	}); err != nil {
		return db.ConfigSupportSession{}, store.Classify(err)
	}
	_ = s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "support_session.ended",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"ended_at": now.Format(time.RFC3339),
		},
	})
	return s.store.Q.GetSupportSession(ctx, id)
}

func (s *SupportService) ReleaseSession(ctx context.Context, sess db.ConfigSupportSession) error {
	now := store.Now()
	if now.After(sess.ExpiresAt) {
		return s.store.Q.EndSupportSession(ctx, db.EndSupportSessionParams{
			ID:          sess.ID,
			Now:         store.NullTime(now),
			EndedReason: "expired",
		})
	}
	return s.store.Q.ReleaseSupportSession(ctx, db.ReleaseSupportSessionParams{
		ID:         sess.ID,
		TotpSecret: generateVerificationCode(),
	})
}

func (s *SupportService) MarkConnected(ctx context.Context, sessionID, clientIP, os, hostname string) error {
	return s.store.Q.MarkSupportSessionConnected(ctx, db.MarkSupportSessionConnectedParams{
		ID:             sessionID,
		Now:            store.NullTime(store.Now()),
		ClientIP:       clientIP,
		ClientOs:       os,
		ClientHostname: hostname,
	})
}
