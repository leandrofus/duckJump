package services

import (
	"context"
	"errors"

	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrSiteKindInvalid   = errors.New("kind must be direct or agent")
	ErrSiteTokenNotAgent = errors.New("only agent sites have a token")
)

type SiteDisconnector interface {
	DisconnectSite(siteID string)
}

type CreateSiteParams struct {
	Name        string
	Kind        string
	Description string
	Actor       store.Actor
}

type CreateSiteResult struct {
	Site  db.ConfigSite
	Token string
}

type UpdateSiteParams struct {
	ID          string
	Name        *string
	Description *string
	Actor       store.Actor
}

type RotateTokenResult struct {
	Site  db.ConfigSite
	Token string
}

type SiteService struct {
	store        *store.Store
	disconnector SiteDisconnector
}

func NewSiteService(st *store.Store, disconnector SiteDisconnector) *SiteService {
	return &SiteService{store: st, disconnector: disconnector}
}

func (s *SiteService) List(ctx context.Context) ([]db.ListSitesRow, error) {
	return s.store.Q.ListSites(ctx)
}

func (s *SiteService) Get(ctx context.Context, id string) (db.ConfigSite, error) {
	st, err := s.store.Q.GetSite(ctx, id)
	if err != nil {
		return db.ConfigSite{}, store.Classify(err)
	}
	return st, nil
}

func (s *SiteService) GetByName(ctx context.Context, name string) (db.ConfigSite, error) {
	st, err := s.store.Q.GetSiteByName(ctx, name)
	if err != nil {
		return db.ConfigSite{}, store.Classify(err)
	}
	return st, nil
}

func (s *SiteService) Create(ctx context.Context, params CreateSiteParams) (CreateSiteResult, error) {
	if err := validateName(params.Name); err != nil {
		return CreateSiteResult{}, err
	}
	if params.Kind != "direct" && params.Kind != "agent" {
		return CreateSiteResult{}, ErrSiteKindInvalid
	}

	id := store.NewID()
	var tok string
	hash := ""
	if params.Kind == "agent" {
		tok = edge.NewToken()
		hash = edge.HashToken(tok)
	}

	var created db.ConfigSite
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateSite(ctx, db.CreateSiteParams{
			ID:             id,
			Name:           params.Name,
			Kind:           params.Kind,
			Description:    params.Description,
			AgentTokenHash: store.NullString(hash),
			Now:            store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "site.create",
			ObjectType: "site",
			ObjectID:   id,
			Details: map[string]any{
				"name": params.Name,
				"kind": params.Kind,
			},
		}); err != nil {
			return err
		}

		var err error
		created, err = q.GetSite(ctx, id)
		return err
	})
	if err != nil {
		return CreateSiteResult{}, err
	}
	return CreateSiteResult{Site: created, Token: tok}, nil
}

func (s *SiteService) Update(ctx context.Context, params UpdateSiteParams) (db.ConfigSite, error) {
	var out db.ConfigSite
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		if params.Name != nil {
			if err := validateName(*params.Name); err != nil {
				return err
			}
			st.Name = *params.Name
		}
		if params.Description != nil {
			st.Description = *params.Description
		}

		if err := q.UpdateSite(ctx, db.UpdateSiteParams{
			ID:          params.ID,
			Name:        st.Name,
			Description: st.Description,
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "site.update",
			ObjectType: "site",
			ObjectID:   params.ID,
			Details:    map[string]any{"name": st.Name},
		}); err != nil {
			return err
		}

		out = st
		return nil
	})
	if err != nil {
		return db.ConfigSite{}, err
	}
	return out, nil
}

func (s *SiteService) Delete(ctx context.Context, actor store.Actor, id string) error {
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if _, err := q.DeleteSite(ctx, id); err != nil {
			return store.Classify(err)
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "site.delete",
			ObjectType: "site",
			ObjectID:   id,
			Details:    map[string]any{"name": st.Name},
		})
	})
	if err != nil {
		return err
	}
	if s.disconnector != nil {
		s.disconnector.DisconnectSite(id)
	}
	return nil
}

func (s *SiteService) DeleteByName(ctx context.Context, actor store.Actor, name string) error {
	st, err := s.GetByName(ctx, name)
	if err != nil {
		return err
	}
	return s.Delete(ctx, actor, st.ID)
}

func (s *SiteService) RotateToken(ctx context.Context, actor store.Actor, id string) (RotateTokenResult, error) {
	tok := edge.NewToken()
	var out db.ConfigSite
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if st.Kind != "agent" {
			return ErrSiteTokenNotAgent
		}
		if err := q.SetSiteToken(ctx, db.SetSiteTokenParams{
			ID:             id,
			AgentTokenHash: store.NullString(edge.HashToken(tok)),
		}); err != nil {
			return err
		}
		out = st
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "site.token_rotate",
			ObjectType: "site",
			ObjectID:   id,
			Details:    map[string]any{"name": st.Name},
		})
	})
	if err != nil {
		return RotateTokenResult{}, err
	}
	if s.disconnector != nil {
		s.disconnector.DisconnectSite(id)
	}
	return RotateTokenResult{Site: out, Token: tok}, nil
}

func (s *SiteService) RotateTokenByName(ctx context.Context, actor store.Actor, name string) (RotateTokenResult, error) {
	st, err := s.GetByName(ctx, name)
	if err != nil {
		return RotateTokenResult{}, err
	}
	return s.RotateToken(ctx, actor, st.ID)
}
