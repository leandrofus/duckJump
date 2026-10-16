package server

import (
	"net/http"

	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
)

// openapi:schema SecretRequest
// type: object
// required: [name, kind, username, value]
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   kind: { type: string, enum: [password, private_key] }
//   username: { type: string, description: Account on the target host. }
//   value: { type: string, format: password, writeOnly: true, description: 'Password, or private key in OpenSSH/PEM format.' }

type secretRequest struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Value    string `json:"value"`
}

// openapi:schema UpdateSecretRequest
// type: object
// additionalProperties: false
// description: Sending value replaces the stored credential (kind is required with it).
// properties:
//   name: { type: string, maxLength: 128 }
//   username: { type: string }
//   kind: { type: string, enum: [password, private_key] }
//   value: { type: string, format: password, writeOnly: true }

type updateSecretRequest struct {
	Name     opt[string] `json:"name"`
	Username opt[string] `json:"username"`
	Kind     opt[string] `json:"kind"`
	Value    opt[string] `json:"value"`
}

func validSecretKind(k string) error {
	if k != "password" && k != "private_key" {
		return badRequest("kind must be password or private_key")
	}
	return nil
}

// openapi:operation
// summary: List vaulted credentials
// description: Values are never returned by any endpoint.
// tags: [secrets]
// responses:
//   '200': { description: Secrets metadata, schema: '[]Secret' }

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, p principal) error {
	rows, err := s.Store.Q.ListSecrets(r.Context())
	if err != nil {
		return err
	}
	out := make([]secretDTO, 0, len(rows))
	for _, x := range rows {
		n := x.ConnectionCount
		out = append(out, secretDTO{ID: x.ID, Name: x.Name, Kind: x.Kind, Username: x.Username, ConnectionCount: &n,
			CreatedAt: x.CreatedAt.UTC(), UpdatedAt: x.UpdatedAt.UTC()})
	}
	return ok(w, out)
}

// openapi:operation
// summary: Vault a credential
// tags: [secrets]
// requestBody: { schema: SecretRequest }
// responses:
//   '201': { description: Created, schema: Secret }
//   '409': Error

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	var req secretRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := validName("name", req.Name); err != nil {
		return err
	}
	if err := validSecretKind(req.Kind); err != nil {
		return err
	}
	if req.Username == "" || req.Value == "" {
		return badRequest("username and value are required")
	}
	ctx, id := r.Context(), store.NewID()
	err := s.tx(ctx, func(q *db.Queries) error {
		if err := q.CreateSecret(ctx, db.CreateSecretParams{ID: id, Name: req.Name, Kind: req.Kind, Username: req.Username,
			Sealed: s.Vault.Seal([]byte(req.Value), []byte(id)), Now: store.Now()}); err != nil {
			return fromStore(err, "secret")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "secret.create", ObjectType: "secret", ObjectID: id,
			Details: map[string]any{"name": req.Name, "kind": req.Kind, "username": req.Username}})
	})
	if err != nil {
		return err
	}
	sec, err := s.Store.Q.GetSecret(ctx, id)
	if err != nil {
		return err
	}
	return created(w, toSecret(sec))
}

// openapi:operation
// summary: Get a credential's metadata
// tags: [secrets]
// responses:
//   '200': { description: Metadata, schema: Secret }

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	sec, err := s.Store.Q.GetSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		return fromStore(err, "secret")
	}
	return ok(w, toSecret(sec))
}

// openapi:operation
// summary: Update or replace a credential
// tags: [secrets]
// requestBody: { schema: UpdateSecretRequest }
// responses:
//   '200': { description: Updated, schema: Secret }
//   '409': Error

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateSecretRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigSecret
	err := s.tx(ctx, func(q *db.Queries) error {
		sec, err := q.GetSecret(ctx, id)
		if err != nil {
			return fromStore(err, "secret")
		}
		details := map[string]any{}
		if req.Name.Set || req.Username.Set {
			if req.Name.Set {
				if err := validName("name", req.Name.V); err != nil {
					return err
				}
				sec.Name = req.Name.V
				details["name"] = sec.Name
			}
			if req.Username.Set {
				sec.Username = req.Username.V
				details["username"] = sec.Username
			}
			if err := q.UpdateSecretMeta(ctx, db.UpdateSecretMetaParams{ID: id, Name: sec.Name, Username: sec.Username, Now: store.Now()}); err != nil {
				return fromStore(err, "secret")
			}
		}
		if req.Value.Set {
			if !req.Kind.Set {
				return badRequest("kind is required when replacing the value")
			}
			if err := validSecretKind(req.Kind.V); err != nil {
				return err
			}
			if req.Value.V == "" {
				return badRequest("value must not be empty")
			}
			if err := q.UpdateSecretValue(ctx, db.UpdateSecretValueParams{ID: id, Kind: req.Kind.V,
				Sealed: s.Vault.Seal([]byte(req.Value.V), []byte(id)), Now: store.Now()}); err != nil {
				return err
			}
			details["value_replaced"] = true
			details["kind"] = req.Kind.V
		} else if req.Kind.Set {
			return badRequest("kind can only change together with value")
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "secret.update", ObjectType: "secret", ObjectID: id, Details: details}); err != nil {
			return err
		}
		out, err = q.GetSecret(ctx, id)
		return err
	})
	if err != nil {
		return err
	}
	return ok(w, toSecret(out))
}

// openapi:operation
// summary: Delete a credential
// description: Connections using it are left without a credential.
// tags: [secrets]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		sec, err := q.GetSecret(ctx, id)
		if err != nil {
			return fromStore(err, "secret")
		}
		if _, err := q.DeleteSecret(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "secret.delete", ObjectType: "secret", ObjectID: id,
			Details: map[string]any{"name": sec.Name}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}
