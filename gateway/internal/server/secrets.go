package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
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

func toSecretSummary(x db.ListSecretsRow) secretDTO {
	n := x.ConnectionCount
	return secretDTO{
		ID: x.ID, Name: x.Name, Kind: x.Kind, Username: x.Username, ConnectionCount: &n,
		CreatedAt: x.CreatedAt.UTC(), UpdatedAt: x.UpdatedAt.UTC(),
	}
}

// openapi:operation
// summary: List vaulted credentials
// description: Values are never returned by any endpoint.
// tags: [secrets]
// responses:
//   '200': { description: Secrets metadata, schema: '[]Secret' }

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]secretDTO, error) {
		rows, err := s.Secrets.List(r.Context())
		if err != nil {
			return nil, fromService(err, "secret")
		}
		out := make([]secretDTO, len(rows))
		for i, x := range rows {
			out[i] = toSecretSummary(x)
		}
		return out, nil
	})
}

// openapi:operation
// summary: Vault a credential
// tags: [secrets]
// requestBody: { schema: SecretRequest }
// responses:
//   '201': { description: Created, schema: Secret }
//   '409': Error

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req secretRequest) (secretDTO, error) {
		sec, err := s.Secrets.Create(r.Context(), services.CreateSecretParams{
			Name:     req.Name,
			Kind:     req.Kind,
			Username: req.Username,
			Value:    req.Value,
			Actor:    p.actor(),
		})
		if err != nil {
			return secretDTO{}, fromService(err, "secret")
		}
		return toSecret(sec), nil
	})
}

// openapi:operation
// summary: Get a credential's metadata
// tags: [secrets]
// responses:
//   '200': { description: Metadata, schema: Secret }

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (secretDTO, error) {
		sec, err := s.Secrets.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return secretDTO{}, fromService(err, "secret")
		}
		return toSecret(sec), nil
	})
}

// openapi:operation
// summary: Update or replace a credential
// tags: [secrets]
// requestBody: { schema: UpdateSecretRequest }
// responses:
//   '200': { description: Updated, schema: Secret }
//   '409': Error

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateSecretRequest) (secretDTO, error) {
		sec, err := s.Secrets.Update(r.Context(), services.UpdateSecretParams{
			ID:       r.PathValue("id"),
			Name:     req.Name.Ptr(),
			Username: req.Username.Ptr(),
			Kind:     req.Kind.Ptr(),
			Value:    req.Value.Ptr(),
			Actor:    p.actor(),
		})
		if err != nil {
			return secretDTO{}, fromService(err, "secret")
		}
		return toSecret(sec), nil
	})
}

// openapi:operation
// summary: Delete a credential
// description: Connections using it are left without a credential.
// tags: [secrets]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Secrets.Delete(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "secret")
	})
}
