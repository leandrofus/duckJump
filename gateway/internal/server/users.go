package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema CreateUserRequest
// type: object
// required: [username, password]
// additionalProperties: false
// properties:
//   username: { type: string, pattern: '^[a-z0-9][a-z0-9._-]{0,63}$' }
//   password: { type: string, format: password, minLength: 10 }
//   display_name: { type: string }
//   email: { type: string, format: email }
//   role: { $ref: '#/components/schemas/Role' }

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

// openapi:schema UpdateUserRequest
// type: object
// additionalProperties: false
// properties:
//   display_name: { type: string }
//   email: { type: string, format: email }
//   role: { $ref: '#/components/schemas/Role' }
//   disabled: { type: boolean }

type updateUserRequest struct {
	DisplayName opt[string] `json:"display_name"`
	Email       opt[string] `json:"email"`
	Role        opt[string] `json:"role"`
	Disabled    opt[bool]   `json:"disabled"`
}

// openapi:schema PasswordRequest
// type: object
// required: [password]
// additionalProperties: false
// properties:
//   password: { type: string, format: password, minLength: 10 }

type passwordRequest struct {
	Password string `json:"password"`
}

// guardSuperadmin: only superadmins may create, change or remove superadmins.
func guardSuperadmin(p principal, targetRole string) error {
	if targetRole == "superadmin" && p.User.Role != "superadmin" {
		return &apiError{http.StatusForbidden, "forbidden", "only a superadmin can manage superadmins"}
	}
	return nil
}

// lastSuperadmin reports whether u is the only enabled superadmin.
func lastSuperadmin(ctx context.Context, q *db.Queries, u db.ConfigUser) (bool, error) {
	if u.Role != "superadmin" || u.Disabled {
		return false, nil
	}
	all, err := q.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	n := 0
	for _, x := range all {
		if x.Role == "superadmin" && !x.Disabled {
			n++
		}
	}
	return n == 1, nil
}

// openapi:operation
// summary: List users
// tags: [users]
// responses:
//   '200': { description: All users, schema: '[]User' }

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, p principal) error {
	us, err := s.Store.Q.ListUsers(r.Context())
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
// summary: Create a local user
// tags: [users]
// requestBody: { schema: CreateUserRequest }
// responses:
//   '201': { description: Created, schema: User }
//   '409': Error

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p principal) error {
	var req createUserRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !reUsername.MatchString(req.Username) {
		return badRequest("username must be lowercase letters, digits, . _ - (max 64)")
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if !roles[req.Role] {
		return badRequest("unknown role %q", req.Role)
	}
	if err := guardSuperadmin(p, req.Role); err != nil {
		return err
	}
	if err := auth.CheckPasswordPolicy(req.Password); err != nil {
		return badRequest("%v", err)
	}
	h, err := auth.HashPassword(req.Password)
	if err != nil {
		return err
	}
	ctx, id := r.Context(), store.NewID()
	err = s.tx(ctx, func(q *db.Queries) error {
		if err := q.CreateUser(ctx, db.CreateUserParams{
			ID: id, Username: req.Username, DisplayName: req.DisplayName, Email: req.Email,
			PasswordHash: store.NullString(h), Source: "local", Role: req.Role, Now: store.Now(),
		}); err != nil {
			return fromStore(err, "user")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "user.create", ObjectType: "user", ObjectID: id,
			Details: map[string]any{"username": req.Username, "role": req.Role}})
	})
	if err != nil {
		return err
	}
	u, err := s.Store.Q.GetUser(ctx, id)
	if err != nil {
		return err
	}
	return created(w, toUser(u))
}

// openapi:operation
// summary: Get a user
// tags: [users]
// responses:
//   '200': { description: The user, schema: User }

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, p principal) error {
	u, err := s.Store.Q.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		return fromStore(err, "user")
	}
	return ok(w, toUser(u))
}

// openapi:operation
// summary: Update a user
// description: Disabling a user also ends their web sessions.
// tags: [users]
// requestBody: { schema: UpdateUserRequest }
// responses:
//   '200': { description: Updated, schema: User }
//   '409': Error

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateUserRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigUser
	err := s.tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, id)
		if err != nil {
			return fromStore(err, "user")
		}
		if err := guardSuperadmin(p, u.Role); err != nil {
			return err
		}
		changes := map[string]any{}
		next := u
		if req.DisplayName.Set {
			next.DisplayName = req.DisplayName.V
			changes["display_name"] = next.DisplayName
		}
		if req.Email.Set {
			next.Email = req.Email.V
			changes["email"] = next.Email
		}
		if req.Role.Set && req.Role.V != u.Role && u.Source == "oidc" && s.OIDC != nil && s.OIDC.RolesClaim != "" {
			return conflict("the role of %s comes from the identity provider (%s)", u.Username, s.OIDC.RolesClaim)
		}
		if req.Role.Set {
			if !roles[req.Role.V] {
				return badRequest("unknown role %q", req.Role.V)
			}
			if err := guardSuperadmin(p, req.Role.V); err != nil {
				return err
			}
			next.Role = req.Role.V
			changes["role"] = map[string]string{"from": u.Role, "to": next.Role}
		}
		if req.Disabled.Set {
			next.Disabled = req.Disabled.V
			changes["disabled"] = next.Disabled
		}
		if (next.Role != "superadmin" || next.Disabled) && u.Role == "superadmin" {
			if last, err := lastSuperadmin(ctx, q, u); err != nil {
				return err
			} else if last {
				return conflict("cannot demote or disable the last superadmin")
			}
		}
		if err := q.UpdateUser(ctx, db.UpdateUserParams{ID: id, DisplayName: next.DisplayName, Email: next.Email,
			Role: next.Role, Disabled: next.Disabled, Now: store.Now()}); err != nil {
			return err
		}
		if next.Disabled && !u.Disabled {
			if err := q.DeleteUserWebSessions(ctx, id); err != nil {
				return err
			}
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "user.update", ObjectType: "user", ObjectID: id, Details: changes}); err != nil {
			return err
		}
		out, err = q.GetUser(ctx, id)
		return err
	})
	if err != nil {
		return err
	}
	return ok(w, toUser(out))
}

// openapi:operation
// summary: Delete a user
// description: Also deletes the policies granted to the user. Audit history is kept.
// tags: [users]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if id == p.User.ID {
		return conflict("you cannot delete yourself")
	}
	err := s.tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, id)
		if err != nil {
			return fromStore(err, "user")
		}
		if err := guardSuperadmin(p, u.Role); err != nil {
			return err
		}
		if last, err := lastSuperadmin(ctx, q, u); err != nil {
			return err
		} else if last {
			return conflict("cannot delete the last superadmin")
		}
		if err := q.DeletePoliciesForSubject(ctx, db.DeletePoliciesForSubjectParams{SubjectType: "user", SubjectID: id}); err != nil {
			return err
		}
		if _, err := q.DeleteUser(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "user.delete", ObjectType: "user", ObjectID: id,
			Details: map[string]any{"username": u.Username}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

// openapi:operation
// summary: Reset a user's password
// description: Ends all of the user's web sessions.
// tags: [users]
// requestBody: { schema: PasswordRequest }
// responses:
//   '204': { description: Password changed }

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, p principal) error {
	var req passwordRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := auth.CheckPasswordPolicy(req.Password); err != nil {
		return badRequest("%v", err)
	}
	h, err := auth.HashPassword(req.Password)
	if err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	err = s.tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, id)
		if err != nil {
			return fromStore(err, "user")
		}
		if err := guardSuperadmin(p, u.Role); err != nil {
			return err
		}
		if u.Source != "local" {
			return conflict("only local users have a password")
		}
		if err := q.SetUserPassword(ctx, db.SetUserPasswordParams{ID: id, PasswordHash: store.NullString(h), Now: store.Now()}); err != nil {
			return err
		}
		if err := q.DeleteUserWebSessions(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "user.password_reset", ObjectType: "user", ObjectID: id})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

// openapi:operation
// summary: Reset a user's TOTP
// description: Removes the second factor so the user can enroll again.
// tags: [users]
// responses:
//   '204': { description: TOTP removed }

func (s *Server) resetTOTP(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, id)
		if err != nil {
			return fromStore(err, "user")
		}
		if err := guardSuperadmin(p, u.Role); err != nil {
			return err
		}
		if err := q.SetUserTOTP(ctx, db.SetUserTOTPParams{ID: id, Now: store.Now()}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "user.totp_reset", ObjectType: "user", ObjectID: id})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

// openapi:operation
// summary: Groups a user belongs to
// tags: [users]
// responses:
//   '200': { description: Groups, schema: '[]Group' }

func (s *Server) userGroups(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if _, err := s.Store.Q.GetUser(ctx, id); err != nil {
		return fromStore(err, "user")
	}
	gs, err := s.Store.Q.ListUserGroups(ctx, id)
	if err != nil {
		return err
	}
	out := make([]groupDTO, 0, len(gs))
	for _, g := range gs {
		out = append(out, toGroup(g))
	}
	return ok(w, out)
}

// openapi:schema AccessEntry
// type: object
// required: [connection, grants]
// properties:
//   connection: { $ref: '#/components/schemas/Connection' }
//   grants:
//     type: array
//     description: The unexpired policies that give this access.
//     items: { $ref: '#/components/schemas/Policy' }

type accessEntry struct {
	Connection connectionDTO `json:"connection"`
	Grants     []policyDTO   `json:"grants"`
}

// openapi:operation
// summary: Connections a user can access, and why
// tags: [users]
// responses:
//   '200': { description: Effective access, schema: '[]AccessEntry' }

func (s *Server) userAccess(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if _, err := s.Store.Q.GetUser(ctx, id); err != nil {
		return fromStore(err, "user")
	}
	conns, err := s.Store.GrantedConnections(ctx, id)
	if err != nil {
		return err
	}
	tags, err := s.tagIndex(ctx)
	if err != nil {
		return err
	}
	out := make([]accessEntry, 0, len(conns))
	for _, c := range conns {
		ps, err := s.Store.Grants(ctx, id, c.ID)
		if err != nil {
			return err
		}
		e := accessEntry{Connection: toConnection(c, tags[c.ID]), Grants: []policyDTO{}}
		for _, p := range ps {
			e.Grants = append(e.Grants, toPolicy(p))
		}
		out = append(out, e)
	}
	return ok(w, out)
}
