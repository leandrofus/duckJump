package services

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrFolderInsideItself   = errors.New("a folder cannot be moved inside itself")
	ErrParentFolderNotFound = errors.New("parent folder not found")
	ErrFolderNotFound       = errors.New("folder not found")
)

type FolderNotEmptyError struct {
	Folders     int64
	Connections int64
}

func (e *FolderNotEmptyError) Error() string {
	return fmt.Sprintf("folder is not empty (%d folders, %d connections)", e.Folders, e.Connections)
}

type CreateFolderParams struct {
	Name     string
	ParentID *string
	Actor    store.Actor
}

type UpdateFolderParams struct {
	ID          string
	Name        *string
	ParentID    *string
	ParentIDSet bool
	Actor       store.Actor
}

type FolderService struct {
	store *store.Store
}

func NewFolderService(st *store.Store) *FolderService {
	return &FolderService{store: st}
}

func (s *FolderService) List(ctx context.Context) ([]db.ConfigFolder, error) {
	return s.store.Q.ListFolders(ctx)
}

func (s *FolderService) Get(ctx context.Context, id string) (db.ConfigFolder, error) {
	f, err := s.store.Q.GetFolder(ctx, id)
	if err != nil {
		return db.ConfigFolder{}, store.Classify(err)
	}
	return f, nil
}

func (s *FolderService) GetByName(ctx context.Context, name string) (db.ConfigFolder, error) {
	folders, err := s.store.Q.ListFolders(ctx)
	if err != nil {
		return db.ConfigFolder{}, err
	}
	for _, f := range folders {
		if f.Name == name {
			return f, nil
		}
	}
	return db.ConfigFolder{}, store.ErrNotFound
}

func (s *FolderService) Create(ctx context.Context, params CreateFolderParams) (db.ConfigFolder, error) {
	if err := validateName(params.Name); err != nil {
		return db.ConfigFolder{}, err
	}

	id := store.NewID()
	parent := derefString(params.ParentID)
	var created db.ConfigFolder

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if parent != "" {
			if _, err := q.GetFolder(ctx, parent); err != nil {
				return fmt.Errorf("%w: %s", ErrParentFolderNotFound, parent)
			}
		}

		if err := q.CreateFolder(ctx, db.CreateFolderParams{
			ID:       id,
			ParentID: store.NullString(parent),
			Name:     params.Name,
			Now:      store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "folder.create",
			ObjectType: "folder",
			ObjectID:   id,
			Details:    map[string]any{"name": params.Name, "parent_id": parent},
		}); err != nil {
			return err
		}

		f, err := q.GetFolder(ctx, id)
		if err != nil {
			return err
		}
		created = f
		return nil
	})

	return created, err
}

func (s *FolderService) Update(ctx context.Context, params UpdateFolderParams) (db.ConfigFolder, error) {
	var updated db.ConfigFolder

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		f, err := q.GetFolder(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		if params.Name != nil {
			if err := validateName(*params.Name); err != nil {
				return err
			}
			f.Name = *params.Name
		}

		if params.ParentIDSet {
			newParent := derefString(params.ParentID)
			if newParent == "" {
				f.ParentID = store.NullString("")
			} else {
				if _, err := q.GetFolder(ctx, newParent); err != nil {
					return fmt.Errorf("%w: %s", ErrParentFolderNotFound, newParent)
				}
				sub, err := q.FolderSubtree(ctx, params.ID)
				if err != nil {
					return err
				}
				if slices.Contains(sub, newParent) {
					return ErrFolderInsideItself
				}
				f.ParentID = store.NullString(newParent)
			}
		}

		if err := q.UpdateFolder(ctx, db.UpdateFolderParams{
			ID:       params.ID,
			ParentID: f.ParentID,
			Name:     f.Name,
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "folder.update",
			ObjectType: "folder",
			ObjectID:   params.ID,
			Details:    map[string]any{"name": f.Name, "parent_id": f.ParentID.String},
		}); err != nil {
			return err
		}

		updated = f
		return nil
	})

	return updated, err
}

func (s *FolderService) Delete(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		f, err := q.GetFolder(ctx, id)
		if err != nil {
			return store.Classify(err)
		}

		n, err := q.CountFolderChildren(ctx, id)
		if err != nil {
			return err
		}
		if n.Folders > 0 || n.Connections > 0 {
			return &FolderNotEmptyError{Folders: n.Folders, Connections: n.Connections}
		}

		if err := q.DeletePoliciesForObject(ctx, db.DeletePoliciesForObjectParams{
			ObjectType: "folder",
			ObjectRef:  id,
		}); err != nil {
			return err
		}

		if _, err := q.DeleteFolder(ctx, id); err != nil {
			return store.Classify(err)
		}

		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "folder.delete",
			ObjectType: "folder",
			ObjectID:   id,
			Details:    map[string]any{"name": f.Name},
		})
	})
}
