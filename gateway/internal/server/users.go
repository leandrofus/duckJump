package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
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

// openapi:operation
// summary: List users
// tags: [users]
// responses:
//   '200': { description: All users, schema: '[]User' }

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]userDTO, error) {
		us, err := s.Users.List(r.Context())
		if err != nil {
			return nil, fromService(err, "user")
		}
		out := make([]userDTO, 0, len(us))
		for _, u := range us {
			out = append(out, toUser(u))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Create a local user
// tags: [users]
// requestBody: { schema: CreateUserRequest }
// responses:
//   '201': { description: Created, schema: User }
//   '409': Error

func (s *Server) createUser(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req createUserRequest) (userDTO, error) {
		u, err := s.Users.Create(r.Context(), services.CreateUserParams{
			Username:    req.Username,
			DisplayName: req.DisplayName,
			Email:       req.Email,
			Password:    req.Password,
			Role:        req.Role,
			CallerRole:  p.User.Role,
			Actor:       p.actor(),
		})
		if err != nil {
			return userDTO{}, fromService(err, "user")
		}
		return toUser(u), nil
	})
}

// openapi:operation
// summary: Get a user
// tags: [users]
// responses:
//   '200': { description: The user, schema: User }

func (s *Server) getUser(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (userDTO, error) {
		u, err := s.Users.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return userDTO{}, fromService(err, "user")
		}
		return toUser(u), nil
	})
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
	return handleAction(w, r, func(req updateUserRequest) (userDTO, error) {
		rolesClaim := ""
		if s.OIDC != nil {
			rolesClaim = s.OIDC.RolesClaim
		}
		u, err := s.Users.Update(r.Context(), services.UpdateUserParams{
			ID:          r.PathValue("id"),
			DisplayName: req.DisplayName.Ptr(),
			Email:       req.Email.Ptr(),
			Role:        req.Role.Ptr(),
			Disabled:    req.Disabled.Ptr(),
			CallerRole:  p.User.Role,
			Actor:       p.actor(),
			OIDCRoles:   s.OIDC != nil && s.OIDC.RolesClaim != "",
			RolesClaim:  rolesClaim,
		})
		if err != nil {
			return userDTO{}, fromService(err, "user")
		}
		return toUser(u), nil
	})
}

// openapi:operation
// summary: Delete a user
// description: Also deletes the policies granted to the user. Audit history is kept.
// tags: [users]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Users.Delete(r.Context(), p.actor(), p.User.ID, p.User.Role, r.PathValue("id"))
		return fromService(err, "user")
	})
}

// openapi:operation
// summary: Reset a user's password
// description: Ends all of the user's web sessions.
// tags: [users]
// requestBody: { schema: PasswordRequest }
// responses:
//   '204': { description: Password changed }

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		var req passwordRequest
		if err := decode(r, &req); err != nil {
			return err
		}
		err := s.Users.SetPassword(r.Context(), p.actor(), p.User.Role, r.PathValue("id"), req.Password)
		return fromService(err, "user")
	})
}

// openapi:operation
// summary: Reset a user's TOTP
// description: Removes the second factor so the user can enroll again.
// tags: [users]
// responses:
//   '204': { description: TOTP removed }

func (s *Server) resetTOTP(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Users.ResetTOTP(r.Context(), p.actor(), p.User.Role, r.PathValue("id"))
		return fromService(err, "user")
	})
}

// openapi:operation
// summary: Groups a user belongs to
// tags: [users]
// responses:
//   '200': { description: Groups, schema: '[]Group' }

func (s *Server) userGroups(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]groupDTO, error) {
		ctx, id := r.Context(), r.PathValue("id")
		if _, err := s.Users.Get(ctx, id); err != nil {
			return nil, fromService(err, "user")
		}
		gs, err := s.Store.Q.ListUserGroups(ctx, id)
		if err != nil {
			return nil, err
		}
		out := make([]groupDTO, 0, len(gs))
		for _, g := range gs {
			out = append(out, toGroup(g))
		}
		return out, nil
	})
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
	return handleOK(w, func() ([]accessEntry, error) {
		ctx, id := r.Context(), r.PathValue("id")
		if _, err := s.Users.Get(ctx, id); err != nil {
			return nil, fromService(err, "user")
		}
		conns, err := s.Store.GrantedConnections(ctx, id)
		if err != nil {
			return nil, err
		}
		tags, err := s.tagIndex(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]accessEntry, 0, len(conns))
		for _, c := range conns {
			ps, err := s.Store.Grants(ctx, id, c.ID)
			if err != nil {
				return nil, err
			}
			e := accessEntry{Connection: toConnection(c, tags[c.ID]), Grants: []policyDTO{}}
			for _, p := range ps {
				e.Grants = append(e.Grants, toPolicy(p))
			}
			out = append(out, e)
		}
		return out, nil
	})
}
