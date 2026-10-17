package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema GroupRequest
// type: object
// required: [name]
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   description: { type: string }

type groupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// openapi:schema UpdateGroupRequest
// type: object
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   description: { type: string }

type updateGroupRequest struct {
	Name        opt[string] `json:"name"`
	Description opt[string] `json:"description"`
}

// openapi:operation
// summary: List groups
// tags: [groups]
// responses:
//   '200': { description: Groups with member counts, schema: '[]Group' }

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]groupDTO, error) {
		gs, err := s.Groups.List(r.Context())
		if err != nil {
			return nil, fromService(err, "group")
		}
		out := make([]groupDTO, 0, len(gs))
		for _, g := range gs {
			d := toGroup(db.ConfigGroup{ID: g.ID, Name: g.Name, Description: g.Description, Source: g.Source, CreatedAt: g.CreatedAt})
			n := g.MemberCount
			d.MemberCount = &n
			out = append(out, d)
		}
		return out, nil
	})
}

// openapi:operation
// summary: Create a group
// tags: [groups]
// requestBody: { schema: GroupRequest }
// responses:
//   '201': { description: Created, schema: Group }
//   '409': Error

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req groupRequest) (groupDTO, error) {
		g, err := s.Groups.Create(r.Context(), services.CreateGroupParams{
			Name:        req.Name,
			Description: req.Description,
			Actor:       p.actor(),
		})
		if err != nil {
			return groupDTO{}, fromService(err, "group")
		}
		return toGroup(g), nil
	})
}

// openapi:operation
// summary: Get a group
// tags: [groups]
// responses:
//   '200': { description: The group, schema: Group }

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (groupDTO, error) {
		g, err := s.Groups.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return groupDTO{}, fromService(err, "group")
		}
		return toGroup(g), nil
	})
}

// openapi:operation
// summary: Update a group
// tags: [groups]
// requestBody: { schema: UpdateGroupRequest }
// responses:
//   '200': { description: Updated, schema: Group }
//   '409': Error

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateGroupRequest) (groupDTO, error) {
		g, err := s.Groups.Update(r.Context(), services.UpdateGroupParams{
			ID:          r.PathValue("id"),
			Name:        req.Name.Ptr(),
			Description: req.Description.Ptr(),
			Actor:       p.actor(),
		})
		if err != nil {
			return groupDTO{}, fromService(err, "group")
		}
		return toGroup(g), nil
	})
}

// openapi:operation
// summary: Delete a group
// description: Also deletes the policies granted to the group.
// tags: [groups]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Groups.Delete(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "group")
	})
}

// openapi:operation
// summary: List group members
// tags: [groups]
// responses:
//   '200': { description: Members, schema: '[]User' }

func (s *Server) groupMembers(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]userDTO, error) {
		us, err := s.Groups.ListMembers(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, fromService(err, "group")
		}
		out := make([]userDTO, 0, len(us))
		for _, u := range us {
			out = append(out, toUser(u))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Add a user to a group
// description: Idempotent.
// tags: [groups]
// responses:
//   '204': { description: Member added }

func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Groups.AddMember(r.Context(), p.actor(), r.PathValue("id"), r.PathValue("user"))
		return fromService(err, "group")
	})
}

// openapi:operation
// summary: Remove a user from a group
// tags: [groups]
// responses:
//   '204': { description: Member removed }

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Groups.RemoveMember(r.Context(), p.actor(), r.PathValue("id"), r.PathValue("user"))
		return fromService(err, "group")
	})
}
