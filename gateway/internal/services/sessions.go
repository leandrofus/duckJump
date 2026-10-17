package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrSessionAlreadyEnded = errors.New("the session already ended")
)

type ListSessionsParams struct {
	UserID       string
	ConnectionID string
	ActiveOnly   bool
	Before       *time.Time
	Limit        int64
}

type SessionService struct {
	store *store.Store
}

func NewSessionService(st *store.Store) *SessionService {
	return &SessionService{store: st}
}

func (s *SessionService) List(ctx context.Context, params ListSessionsParams) ([]db.AuditSession, error) {
	lim := params.Limit
	if lim <= 0 {
		lim = 100
	}
	dbParams := db.ListSessionRecordsParams{
		UserID:       params.UserID,
		ConnectionID: params.ConnectionID,
		ActiveOnly:   params.ActiveOnly,
		Lim:          lim,
	}
	if params.Before != nil {
		dbParams.HasBefore = true
		dbParams.Before = store.TS(*params.Before)
	}
	return s.store.Q.ListSessionRecords(ctx, dbParams)
}

func (s *SessionService) Get(ctx context.Context, id string) (db.AuditSession, error) {
	row, err := s.store.Q.GetSessionRecord(ctx, id)
	if err != nil {
		return db.AuditSession{}, store.Classify(err)
	}
	return row, nil
}

func (s *SessionService) GetPurge(ctx context.Context, sessionID string) (db.AuditRecordingPurge, error) {
	return s.store.Q.GetRecordingPurge(ctx, sessionID)
}

func (s *SessionService) LiveRecordings(ctx context.Context) ([]db.LiveRecordingsRow, error) {
	return s.store.Q.LiveRecordings(ctx)
}

func (s *SessionService) RequestKill(ctx context.Context, actor store.Actor, sessionID string, reason string) (db.AuditSession, error) {
	var x db.AuditSession
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		var err error
		x, err = q.GetSessionRecord(ctx, sessionID)
		if err != nil {
			return store.Classify(err)
		}
		if x.EndedAt.Valid {
			return ErrSessionAlreadyEnded
		}
		if err := q.RequestSessionKill(ctx, db.RequestSessionKillParams{
			SessionID:   sessionID,
			Now:         store.Now(),
			RequestedBy: actor.Name,
			Reason:      reason,
		}); err != nil {
			return fmt.Errorf("recording the kill request: %w", err)
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "session.terminate",
			ObjectType: "session",
			ObjectID:   sessionID,
			Details:    map[string]any{"reason": reason},
		})
	})
	return x, err
}

type EndSessionParams struct {
	SessionID    string
	Reason       string
	BytesSent    int64
	BytesRecv    int64
	Actor        store.Actor
	ExtraDetails map[string]any
}

func (s *SessionService) EndSession(ctx context.Context, params EndSessionParams) error {
	ctx = context.WithoutCancel(ctx)
	now := store.Now()
	_ = s.store.Q.ForgetSession(ctx, params.SessionID)
	_ = s.store.Q.EndSessionRecord(ctx, db.EndSessionRecordParams{
		ID:        params.SessionID,
		EndReason: params.Reason,
		Now:       store.NullTime(now),
	})
	details := map[string]any{"reason": params.Reason}
	if params.BytesSent > 0 || params.BytesRecv > 0 {
		details["bytes_sent"] = params.BytesSent
		details["bytes_received"] = params.BytesRecv
	}
	for k, v := range params.ExtraDetails {
		if v != "" {
			details[k] = v
		}
	}
	return s.store.AuditTx(ctx, store.Event{
		Actor:      params.Actor,
		Action:     "session.end",
		ObjectType: "session",
		ObjectID:   params.SessionID,
		Details:    details,
	})
}

func (s *SessionService) Beat(ctx context.Context, sessionID, node string) error {
	return s.store.Q.BeatSession(ctx, db.BeatSessionParams{
		SessionID: sessionID,
		Node:      node,
		Now:       store.Now(),
	})
}

func (s *SessionService) AuditShare(ctx context.Context, actor store.Actor, sessionID string) error {
	return s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "session.share",
		ObjectType: "session",
		ObjectID:   sessionID,
	})
}

func (s *SessionService) AuditUnshare(ctx context.Context, actor store.Actor, sessionID string) error {
	return s.store.AuditTx(ctx, store.Event{
		Actor:      actor,
		Action:     "session.unshare",
		ObjectType: "session",
		ObjectID:   sessionID,
	})
}
