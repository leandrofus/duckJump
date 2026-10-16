package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/store"
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
	gs, err := s.Store.Q.ListGroups(r.Context())
	if err != nil {
		return err
	}
	out := make([]groupDTO, 0, len(gs))
	for _, g := range gs {
		d := toGroup(db.ConfigGroup{ID: g.ID, Name: g.Name, Description: g.Description, Source: g.Source, CreatedAt: g.CreatedAt})
		n := g.MemberCount
		d.MemberCount = &n
		out = append(out, d)
	}
	return ok(w, out)
}

// openapi:operation
// summary: Create a group
// tags: [groups]
// requestBody: { schema: GroupRequest }
// responses:
//   '201': { description: Created, schema: Group }
//   '409': Error

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	var req groupRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := validName("name", req.Name); err != nil {
		return err
	}
	ctx, id := r.Context(), store.NewID()
	err := s.tx(ctx, func(q *db.Queries) error {
		if err := q.CreateGroup(ctx, db.CreateGroupParams{ID: id, Name: req.Name, Description: req.Description, Source: "local", Now: store.Now()}); err != nil {
			return fromStore(err, "group")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "group.create", ObjectType: "group", ObjectID: id,
			Details: map[string]any{"name": req.Name}})
	})
	if err != nil {
		return err
	}
	g, err := s.Store.Q.GetGroup(ctx, id)
	if err != nil {
		return err
	}
	return created(w, toGroup(g))
}

// openapi:operation
// summary: Get a group
// tags: [groups]
// responses:
//   '200': { description: The group, schema: Group }

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	g, err := s.Store.Q.GetGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		return fromStore(err, "group")
	}
	return ok(w, toGroup(g))
}

// openapi:operation
// summary: Update a group
// tags: [groups]
// requestBody: { schema: UpdateGroupRequest }
// responses:
//   '200': { description: Updated, schema: Group }
//   '409': Error

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateGroupRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigGroup
	err := s.tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, id)
		if err != nil {
			return fromStore(err, "group")
		}
		if g.Source != "local" {
			return conflict("groups synced from an identity provider are read-only")
		}
		if req.Name.Set {
			if err := validName("name", req.Name.V); err != nil {
				return err
			}
			g.Name = req.Name.V
		}
		if req.Description.Set {
			g.Description = req.Description.V
		}
		if err := q.UpdateGroup(ctx, db.UpdateGroupParams{ID: id, Name: g.Name, Description: g.Description}); err != nil {
			return fromStore(err, "group")
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "group.update", ObjectType: "group", ObjectID: id,
			Details: map[string]any{"name": g.Name, "description": g.Description}}); err != nil {
			return err
		}
		out = g
		return nil
	})
	if err != nil {
		return err
	}
	return ok(w, toGroup(out))
}

// openapi:operation
// summary: Delete a group
// description: Also deletes the policies granted to the group.
// tags: [groups]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, id)
		if err != nil {
			return fromStore(err, "group")
		}
		if err := q.DeletePoliciesForSubject(ctx, db.DeletePoliciesForSubjectParams{SubjectType: "group", SubjectID: id}); err != nil {
			return err
		}
		if _, err := q.DeleteGroup(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "group.delete", ObjectType: "group", ObjectID: id,
			Details: map[string]any{"name": g.Name}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

// openapi:operation
// summary: List group members
// tags: [groups]
// responses:
//   '200': { description: Members, schema: '[]User' }

func (s *Server) groupMembers(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if _, err := s.Store.Q.GetGroup(ctx, id); err != nil {
		return fromStore(err, "group")
	}
	us, err := s.Store.Q.ListGroupMembers(ctx, id)
	if err != nil {
		return err
	}
	out := make([]userDTO, 0, len(us))
	for _, u := range us {
		out = append(out, toUser(u))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Add a user to a group
// description: Idempotent.
// tags: [groups]
// responses:
//   '204': { description: Member added }

func (s *Server) addGroupMember(w http.ResponseWriter, r *http.Request, p principal) error {
	return s.changeMembership(w, r, p, true)
}

// openapi:operation
// summary: Remove a user from a group
// tags: [groups]
// responses:
//   '204': { description: Member removed }

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request, p principal) error {
	return s.changeMembership(w, r, p, false)
}

func (s *Server) changeMembership(w http.ResponseWriter, r *http.Request, p principal, add bool) error {
	ctx, gid, uid := r.Context(), r.PathValue("id"), r.PathValue("user")
	err := s.tx(ctx, func(q *db.Queries) error {
		g, err := q.GetGroup(ctx, gid)
		if err != nil {
			return fromStore(err, "group")
		}
		if g.Source != "local" {
			return conflict("groups synced from an identity provider are read-only")
		}
		u, err := q.GetUser(ctx, uid)
		if err != nil {
			return fromStore(err, "user")
		}
		action := "group.member_add"
		if add {
			err = q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: gid, UserID: uid})
		} else {
			action = "group.member_remove"
			var n int64
			if n, err = q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: gid, UserID: uid}); err == nil && n == 0 {
				return notFound("membership")
			}
		}
		if err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: action, ObjectType: "group", ObjectID: gid,
			Details: map[string]any{"group": g.Name, "user_id": uid, "username": u.Username}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}
