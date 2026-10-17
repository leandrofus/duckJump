package services

import (
	"context"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

type ListAuditEventsParams struct {
	BeforeID int64
	ActorID  string
	Action   string
	ObjectID string
	Limit    int64
}

type AuditService struct {
	store *store.Store
}

func NewAuditService(st *store.Store) *AuditService {
	return &AuditService{store: st}
}

func (s *AuditService) ListEvents(ctx context.Context, params ListAuditEventsParams) ([]db.AuditEvent, error) {
	lim := params.Limit
	if lim <= 0 {
		lim = 100
	}
	return s.store.Q.ListAuditEvents(ctx, db.ListAuditEventsParams{
		BeforeID: params.BeforeID,
		ActorID:  params.ActorID,
		Action:   params.Action,
		ObjectID: params.ObjectID,
		Lim:      lim,
	})
}

func (s *AuditService) Verify(ctx context.Context) (store.VerifyResult, error) {
	return s.store.VerifyAudit(ctx)
}

func (s *AuditService) Seal(ctx context.Context, actor store.Actor) (int64, error) {
	return s.store.SealAudit(ctx, actor)
}
