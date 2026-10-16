package server

import (
	"net/http"
	"slices"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema FolderRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   parent_id: { type: [string, 'null'], format: uuid, description: null for a root folder }

type folderRequest struct {
	Name     string  `json:"name"`
	ParentID *string `json:"parent_id"`
}

// openapi:schema UpdateFolderRequest
// type: object
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   parent_id: { type: [string, 'null'], format: uuid, description: Move the folder; null moves it to the root. }

type updateFolderRequest struct {
	Name     opt[string] `json:"name"`
	ParentID opt[string] `json:"parent_id"`
}

// openapi:operation
// summary: List folders
// description: Flat list; build the tree from parent_id.
// tags: [folders]
// responses:
//   '200': { description: Folders, schema: '[]Folder' }

func (s *Server) listFolders(w http.ResponseWriter, r *http.Request, p principal) error {
	fs, err := s.Store.Q.ListFolders(r.Context())
	if err != nil {
		return err
	}
	out := make([]folderDTO, 0, len(fs))
	for _, f := range fs {
		out = append(out, toFolder(f))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Create a folder
// tags: [folders]
// requestBody: { schema: FolderRequest }
// responses:
//   '201': { description: Created, schema: Folder }
//   '409': Error

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	var req folderRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := validName("name", req.Name); err != nil {
		return err
	}
	ctx, id := r.Context(), store.NewID()
	parent := ""
	if req.ParentID != nil {
		parent = *req.ParentID
	}
	err := s.tx(ctx, func(q *db.Queries) error {
		if parent != "" {
			if _, err := q.GetFolder(ctx, parent); err != nil {
				return fromStore(err, "parent folder")
			}
		}
		if err := q.CreateFolder(ctx, db.CreateFolderParams{ID: id, ParentID: store.NullString(parent), Name: req.Name, Now: store.Now()}); err != nil {
			return fromStore(err, "folder")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "folder.create", ObjectType: "folder", ObjectID: id,
			Details: map[string]any{"name": req.Name, "parent_id": parent}})
	})
	if err != nil {
		return err
	}
	f, err := s.Store.Q.GetFolder(ctx, id)
	if err != nil {
		return err
	}
	return created(w, toFolder(f))
}

// openapi:operation
// summary: Rename or move a folder
// tags: [folders]
// requestBody: { schema: UpdateFolderRequest }
// responses:
//   '200': { description: Updated, schema: Folder }
//   '409': Error

func (s *Server) updateFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateFolderRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigFolder
	err := s.tx(ctx, func(q *db.Queries) error {
		f, err := q.GetFolder(ctx, id)
		if err != nil {
			return fromStore(err, "folder")
		}
		if req.Name.Set {
			if err := validName("name", req.Name.V); err != nil {
				return err
			}
			f.Name = req.Name.V
		}
		if req.ParentID.Set {
			if req.ParentID.Null || req.ParentID.V == "" {
				f.ParentID = store.NullString("")
			} else {
				if _, err := q.GetFolder(ctx, req.ParentID.V); err != nil {
					return fromStore(err, "parent folder")
				}
				// A folder cannot move under itself or its descendants.
				sub, err := q.FolderSubtree(ctx, id)
				if err != nil {
					return err
				}
				if slices.Contains(sub, req.ParentID.V) {
					return conflict("a folder cannot be moved inside itself")
				}
				f.ParentID = store.NullString(req.ParentID.V)
			}
		}
		if err := q.UpdateFolder(ctx, db.UpdateFolderParams{ID: id, ParentID: f.ParentID, Name: f.Name}); err != nil {
			return fromStore(err, "folder")
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "folder.update", ObjectType: "folder", ObjectID: id,
			Details: map[string]any{"name": f.Name, "parent_id": f.ParentID.String}}); err != nil {
			return err
		}
		out = f
		return nil
	})
	if err != nil {
		return err
	}
	return ok(w, toFolder(out))
}

// openapi:operation
// summary: Delete an empty folder
// description: Fails with 409 while it contains folders or connections. Also deletes the policies on it.
// tags: [folders]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		f, err := q.GetFolder(ctx, id)
		if err != nil {
			return fromStore(err, "folder")
		}
		n, err := q.CountFolderChildren(ctx, id)
		if err != nil {
			return err
		}
		if n.Folders > 0 || n.Connections > 0 {
			return conflict("folder is not empty (%d folders, %d connections)", n.Folders, n.Connections)
		}
		if err := q.DeletePoliciesForObject(ctx, db.DeletePoliciesForObjectParams{ObjectType: "folder", ObjectRef: id}); err != nil {
			return err
		}
		if _, err := q.DeleteFolder(ctx, id); err != nil {
			return fromStore(err, "folder")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "folder.delete", ObjectType: "folder", ObjectID: id,
			Details: map[string]any{"name": f.Name}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}
