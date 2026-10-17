package services

import (
	"context"
	"errors"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrGroupSyncedReadOnly = errors.New("groups synced from an identity provider are read-only")
	ErrMembershipNotFound  = errors.New("membership not found")
	ErrGroupNotFound       = errors.New("group not found")
)

type CreateGroupParams struct {
	Name        string
	Description string
	Actor       store.Actor
}

type UpdateGroupParams struct {
	ID          string
	Name        *string
	Description *string
	Actor       store.Actor
}

type GroupService struct {
	store *store.Store
}

func NewGroupService(st *store.Store) *GroupService {
	return &GroupService{store: st}
}

func (s *GroupService) List(ctx context.Context) ([]db.ListGroupsRow, error) {
	return s.store.Q.ListGroups(ctx)
}

func (s *GroupService) Get(ctx context.Context, id string) (db.ConfigGroup, error) {
	g, err := s.store.Q.GetGroup(ctx, id)
	if err != nil {
		return db.ConfigGroup{}, store.Classify(err)
	}
	return g, nil
}

func (s *GroupService) GetByName(ctx context.Context, name string) (db.ConfigGroup, error) {
	g, err := s.store.Q.GetGroupByName(ctx, name)
	if err != nil {
		return db.ConfigGroup{}, store.Classify(err)
	}
	return g, nil
}

func (s *GroupService) Create(ctx context.Context, params CreateGroupParams) (db.ConfigGroup, error) {
	if err := validateName(params.Name); err != nil {
		return db.ConfigGroup{}, err
	}

	id := store.NewID()
	var created db.ConfigGroup

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateGroup(ctx, db.CreateGroupParams{
			ID:          id,
			Name:        params.Name,
			Description: params.Description,
			Source:      "local",
			Now:         store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "group.create",
			ObjectType: "group",
			ObjectID:   id,
			Details:    map[string]any{"name": params.Name},
		}); err != nil {
			return err
		}

		g, err := q.GetGroup(ctx, id)
		if err != nil {
			return err
		}
		created = g
		return nil
	})

	return created, err
}

func (s *GroupService) Update(ctx context.Context, params UpdateGroupParams) (db.ConfigGroup, error) {
	var updated db.ConfigGroup

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}
		if g.Source != "local" {
			return ErrGroupSyncedReadOnly
		}

		if params.Name != nil {
			if err := validateName(*params.Name); err != nil {
				return err
			}
			g.Name = *params.Name
		}
		if params.Description != nil {
			g.Description = *params.Description
		}

		if err := q.UpdateGroup(ctx, db.UpdateGroupParams{
			ID:          params.ID,
			Name:        g.Name,
			Description: g.Description,
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "group.update",
			ObjectType: "group",
			ObjectID:   params.ID,
			Details:    map[string]any{"name": g.Name, "description": g.Description},
		}); err != nil {
			return err
		}

		updated = g
		return nil
	})

	return updated, err
}

func (s *GroupService) Delete(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if err := q.DeletePoliciesForSubject(ctx, db.DeletePoliciesForSubjectParams{
			SubjectType: "group",
			SubjectID:   id,
		}); err != nil {
			return err
		}
		if _, err := q.DeleteGroup(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "group.delete",
			ObjectType: "group",
			ObjectID:   id,
			Details:    map[string]any{"name": g.Name},
		})
	})
}

func (s *GroupService) ListMembers(ctx context.Context, groupID string) ([]db.ConfigUser, error) {
	if _, err := s.store.Q.GetGroup(ctx, groupID); err != nil {
		return nil, store.Classify(err)
	}
	return s.store.Q.ListGroupMembers(ctx, groupID)
}

func (s *GroupService) AddMember(ctx context.Context, actor store.Actor, groupID, userID string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, groupID)
		if err != nil {
			return store.Classify(err)
		}
		if g.Source != "local" {
			return ErrGroupSyncedReadOnly
		}
		u, err := q.GetUser(ctx, userID)
		if err != nil {
			return store.Classify(err)
		}
		if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: groupID, UserID: userID}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "group.member_add",
			ObjectType: "group",
			ObjectID:   groupID,
			Details:    map[string]any{"group": g.Name, "user_id": userID, "username": u.Username},
		})
	})
}

func (s *GroupService) RemoveMember(ctx context.Context, actor store.Actor, groupID, userID string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, groupID)
		if err != nil {
			return store.Classify(err)
		}
		if g.Source != "local" {
			return ErrGroupSyncedReadOnly
		}
		u, err := q.GetUser(ctx, userID)
		if err != nil {
			return store.Classify(err)
		}
		n, err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: groupID, UserID: userID})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrMembershipNotFound
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "group.member_remove",
			ObjectType: "group",
			ObjectID:   groupID,
			Details:    map[string]any{"group": g.Name, "user_id": userID, "username": u.Username},
		})
	})
}
