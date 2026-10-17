package services

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var oidcActor = store.Actor{Name: "oidc"}

type OIDCService struct {
	store *store.Store
}

func NewOIDCService(st *store.Store) *OIDCService {
	return &OIDCService{store: st}
}

// Provision finds or creates the user of an identity and brings its
// profile, role and provider groups up to date, in one audited transaction.
func (s *OIDCService) Provision(ctx context.Context, id auth.Identity) (db.ConfigUser, error) {
	var u db.ConfigUser
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		var err error
		u, err = q.GetUserByOIDCSubject(ctx, store.NullString(id.Subject))
		switch {
		case errors.Is(store.Classify(err), store.ErrNotFound):
			if _, err := q.GetUserByUsername(ctx, id.Username); err == nil {
				return &auth.ErrLogin{Reason: "the username " + id.Username + " belongs to another account; ask an admin"}
			}
			role := id.Role
			if role == "" {
				role = "user"
			}
			uid := store.NewID()
			if err := q.CreateOIDCUser(ctx, db.CreateOIDCUserParams{
				ID:          uid,
				Username:    id.Username,
				DisplayName: id.DisplayName,
				Email:       id.Email,
				Role:        role,
				OidcSubject: store.NullString(id.Subject),
				Now:         store.Now(),
			}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{
				Actor:      oidcActor,
				Action:     "user.create",
				ObjectType: "user",
				ObjectID:   uid,
				Details: map[string]any{
					"username": id.Username,
					"role":     role,
					"source":   "oidc",
					"subject":  id.Subject,
				},
			}); err != nil {
				return err
			}
			if u, err = q.GetUser(ctx, uid); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if u.Disabled {
				return auth.ErrDisabled
			}
			next := u
			next.DisplayName, next.Email = id.DisplayName, id.Email
			if id.Role != "" {
				next.Role = id.Role
			}
			if next.DisplayName != u.DisplayName || next.Email != u.Email || next.Role != u.Role {
				if err := q.SyncOIDCUser(ctx, db.SyncOIDCUserParams{
					ID:          u.ID,
					DisplayName: next.DisplayName,
					Email:       next.Email,
					Role:        next.Role,
					Now:         store.Now(),
				}); err != nil {
					return err
				}
				changes := map[string]any{}
				if next.Role != u.Role {
					changes["role"] = map[string]string{"from": u.Role, "to": next.Role}
				}
				if next.DisplayName != u.DisplayName {
					changes["display_name"] = next.DisplayName
				}
				if next.Email != u.Email {
					changes["email"] = next.Email
				}
				if err := store.Audit(ctx, q, store.Event{
					Actor:      oidcActor,
					Action:     "user.update",
					ObjectType: "user",
					ObjectID:   u.ID,
					Details: map[string]any{
						"username": u.Username,
						"changes":  changes,
					},
				}); err != nil {
					return err
				}
				u = next
			}
		}
		return s.SyncOIDCGroups(ctx, q, u, id.Groups)
	})
	return u, err
}

// SyncOIDCGroups makes the user's provider groups (source oidc) match the
// claim. Local groups are never touched, even when a provider group has the
// same name.
func (s *OIDCService) SyncOIDCGroups(ctx context.Context, q *db.Queries, u db.ConfigUser, want []string) error {
	have, err := q.ListUserGroups(ctx, u.ID)
	if err != nil {
		return err
	}
	member := map[string]bool{}
	for _, g := range have {
		if g.Source != "oidc" {
			continue
		}
		member[g.Name] = true
		if !slices.Contains(want, g.Name) {
			if _, err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{
				Actor:      oidcActor,
				Action:     "group.member_remove",
				ObjectType: "group",
				ObjectID:   g.ID,
				Details: map[string]any{
					"group":    g.Name,
					"user_id":  u.ID,
					"username": u.Username,
				},
			}); err != nil {
				return err
			}
		}
	}
	for _, name := range want {
		if member[name] {
			continue
		}
		g, err := q.GetGroupByName(ctx, name)
		switch {
		case errors.Is(store.Classify(err), store.ErrNotFound):
			g = db.ConfigGroup{ID: store.NewID(), Name: name, Source: "oidc"}
			if err := q.CreateGroup(ctx, db.CreateGroupParams{
				ID:          g.ID,
				Name:        name,
				Description: "From the identity provider",
				Source:      "oidc",
				Now:         store.Now(),
			}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{
				Actor:      oidcActor,
				Action:     "group.create",
				ObjectType: "group",
				ObjectID:   g.ID,
				Details: map[string]any{
					"name":   name,
					"source": "oidc",
				},
			}); err != nil {
				return err
			}
		case err != nil:
			return err
		case g.Source != "oidc":
			slog.Warn("identity provider group shadowed by a local group; membership not synced", "group", name, "user", u.Username)
			continue
		}
		if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
			return err
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      oidcActor,
			Action:     "group.member_add",
			ObjectType: "group",
			ObjectID:   g.ID,
			Details: map[string]any{
				"group":    name,
				"user_id":  u.ID,
				"username": u.Username,
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
