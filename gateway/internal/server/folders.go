package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
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
	return handleOK(w, func() ([]folderDTO, error) {
		fs, err := s.Folders.List(r.Context())
		if err != nil {
			return nil, fromService(err, "folder")
		}
		out := make([]folderDTO, 0, len(fs))
		for _, f := range fs {
			out = append(out, toFolder(f))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Create a folder
// tags: [folders]
// requestBody: { schema: FolderRequest }
// responses:
//   '201': { description: Created, schema: Folder }
//   '409': Error

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req folderRequest) (folderDTO, error) {
		f, err := s.Folders.Create(r.Context(), services.CreateFolderParams{
			Name:     req.Name,
			ParentID: req.ParentID,
			Actor:    p.actor(),
		})
		if err != nil {
			return folderDTO{}, fromService(err, "folder")
		}
		return toFolder(f), nil
	})
}

// openapi:operation
// summary: Rename or move a folder
// tags: [folders]
// requestBody: { schema: UpdateFolderRequest }
// responses:
//   '200': { description: Updated, schema: Folder }
//   '409': Error

func (s *Server) updateFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateFolderRequest) (folderDTO, error) {
		var parentID *string
		if req.ParentID.Set && !req.ParentID.Null {
			parentID = &req.ParentID.V
		}

		f, err := s.Folders.Update(r.Context(), services.UpdateFolderParams{
			ID:          r.PathValue("id"),
			Name:        req.Name.Ptr(),
			ParentID:    parentID,
			ParentIDSet: req.ParentID.Set,
			Actor:       p.actor(),
		})
		if err != nil {
			return folderDTO{}, fromService(err, "folder")
		}
		return toFolder(f), nil
	})
}

// openapi:operation
// summary: Delete an empty folder
// description: Fails with 409 while it contains folders or connections. Also deletes the policies on it.
// tags: [folders]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Folders.Delete(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "folder")
	})
}
