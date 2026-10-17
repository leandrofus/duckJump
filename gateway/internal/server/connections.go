package server

import (
	"encoding/json"
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
)

// openapi:schema ConnectionRequest
// type: object
// required: [name, protocol, host]
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   protocol: { type: string, enum: [ssh, rdp, vnc, tcp, http, https] }
//   host: { type: string }
//   port: { type: integer, minimum: 1, maximum: 65535, description: 'Defaults: ssh 22, rdp 3389, vnc 5900, http 80, https 443.' }
//   folder_id: { type: [string, 'null'], format: uuid }
//   site_id: { type: [string, 'null'], format: uuid, description: null means reachable directly from duckjumpd. }
//   environment: { type: string, examples: [prod, staging, dev] }
//   description: { type: string }
//   tags: { type: array, items: { type: string, pattern: '^[a-z0-9][a-z0-9._-]{0,31}$' } }
//   backend: { type: string, enum: [paltad, guacd], default: paltad }
//   credential_mode: { type: string, enum: [vault, prompt], default: vault }
//   secret_id: { type: [string, 'null'], format: uuid }
//   params: { type: object, description: 'Protocol-specific settings. RDP: domain (string) and security (any, nla or tls). HTTP/HTTPS: virtual_host (string).' }
//   record: { type: boolean, default: true }
//   record_input: { type: boolean, default: false, description: Also record keystrokes (captures typed passwords). }

type connectionRequest struct {
	Name           string          `json:"name"`
	Protocol       string          `json:"protocol"`
	Host           string          `json:"host"`
	Port           int64           `json:"port"`
	FolderID       *string         `json:"folder_id"`
	SiteID         *string         `json:"site_id"`
	Environment    string          `json:"environment"`
	Description    string          `json:"description"`
	Tags           []string        `json:"tags"`
	Backend        string          `json:"backend"`
	CredentialMode string          `json:"credential_mode"`
	SecretID       *string         `json:"secret_id"`
	Params         json.RawMessage `json:"params"`
	Record         *bool           `json:"record"`
	RecordInput    bool            `json:"record_input"`
}

// openapi:schema UpdateConnectionRequest
// type: object
// additionalProperties: false
// description: Only the fields present change. tags replaces the whole set.
// properties:
//   name: { type: string, maxLength: 128 }
//   protocol: { type: string, enum: [ssh, rdp, vnc, tcp, http, https] }
//   host: { type: string, description: Changing it clears the pinned host key. }
//   port: { type: integer, minimum: 1, maximum: 65535 }
//   folder_id: { type: [string, 'null'], format: uuid }
//   site_id: { type: [string, 'null'], format: uuid }
//   environment: { type: string }
//   description: { type: string }
//   tags: { type: array, items: { type: string } }
//   backend: { type: string, enum: [paltad, guacd] }
//   credential_mode: { type: string, enum: [vault, prompt] }
//   secret_id: { type: [string, 'null'], format: uuid }
//   params: { type: object }
//   record: { type: boolean }
//   record_input: { type: boolean }

type updateConnectionRequest struct {
	Name           opt[string]          `json:"name"`
	Protocol       opt[string]          `json:"protocol"`
	Host           opt[string]          `json:"host"`
	Port           opt[int64]           `json:"port"`
	FolderID       opt[string]          `json:"folder_id"`
	SiteID         opt[string]          `json:"site_id"`
	Environment    opt[string]          `json:"environment"`
	Description    opt[string]          `json:"description"`
	Tags           opt[[]string]        `json:"tags"`
	Backend        opt[string]          `json:"backend"`
	CredentialMode opt[string]          `json:"credential_mode"`
	SecretID       opt[string]          `json:"secret_id"`
	Params         opt[json.RawMessage] `json:"params"`
	Record         opt[bool]            `json:"record"`
	RecordInput    opt[bool]            `json:"record_input"`
}

// openapi:operation
// summary: List connections
// tags: [connections]
// responses:
//   '200': { description: The whole catalog, schema: '[]Connection' }

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]connectionDTO, error) {
		cs, tags, err := s.Connections.ListWithTags(r.Context())
		if err != nil {
			return nil, fromService(err, "connection")
		}
		out := make([]connectionDTO, 0, len(cs))
		for _, c := range cs {
			out = append(out, toConnection(c, tags[c.ID]))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Create a connection
// tags: [connections]
// requestBody: { schema: ConnectionRequest }
// responses:
//   '201': { description: Created, schema: Connection }
//   '409': Error

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req connectionRequest) (connectionDTO, error) {
		res, err := s.Connections.Create(r.Context(), services.CreateConnectionParams{
			Name:           req.Name,
			Protocol:       req.Protocol,
			Host:           req.Host,
			Port:           req.Port,
			FolderID:       req.FolderID,
			SiteID:         req.SiteID,
			Environment:    req.Environment,
			Description:    req.Description,
			Tags:           req.Tags,
			Backend:        req.Backend,
			CredentialMode: req.CredentialMode,
			SecretID:       req.SecretID,
			Params:         string(req.Params),
			Record:         req.Record,
			RecordInput:    req.RecordInput,
			Actor:          p.actor(),
		})
		if err != nil {
			return connectionDTO{}, fromService(err, "connection")
		}
		return toConnection(res.Connection, res.Tags), nil
	})
}

// openapi:operation
// summary: Get a connection
// tags: [connections]
// responses:
//   '200': { description: The connection, schema: Connection }

func (s *Server) getConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (connectionDTO, error) {
		res, err := s.Connections.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return connectionDTO{}, fromService(err, "connection")
		}
		return toConnection(res.Connection, res.Tags), nil
	})
}

// openapi:operation
// summary: Update a connection
// tags: [connections]
// requestBody: { schema: UpdateConnectionRequest }
// responses:
//   '200': { description: Updated, schema: Connection }
//   '409': Error

func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateConnectionRequest) (connectionDTO, error) {
		var paramsStr *string
		if req.Params.Set {
			str := string(req.Params.V)
			paramsStr = &str
		}
		var folderID *string
		if req.FolderID.Set && !req.FolderID.Null {
			folderID = &req.FolderID.V
		}
		var siteID *string
		if req.SiteID.Set && !req.SiteID.Null {
			siteID = &req.SiteID.V
		}
		var secretID *string
		if req.SecretID.Set && !req.SecretID.Null {
			secretID = &req.SecretID.V
		}

		res, err := s.Connections.Update(r.Context(), services.UpdateConnectionParams{
			ID:             r.PathValue("id"),
			Name:           req.Name.Ptr(),
			Protocol:       req.Protocol.Ptr(),
			Host:           req.Host.Ptr(),
			Port:           req.Port.Ptr(),
			FolderID:       folderID,
			FolderIDSet:    req.FolderID.Set,
			SiteID:         siteID,
			SiteIDSet:      req.SiteID.Set,
			Environment:    req.Environment.Ptr(),
			Description:    req.Description.Ptr(),
			Tags:           req.Tags.Ptr(),
			Backend:        req.Backend.Ptr(),
			CredentialMode: req.CredentialMode.Ptr(),
			SecretID:       secretID,
			SecretIDSet:    req.SecretID.Set,
			Params:         paramsStr,
			ParamsNull:     req.Params.Null,
			Record:         req.Record.Ptr(),
			RecordInput:    req.RecordInput.Ptr(),
			Actor:          p.actor(),
		})
		if err != nil {
			return connectionDTO{}, fromService(err, "connection")
		}
		return toConnection(res.Connection, res.Tags), nil
	})
}

// openapi:operation
// summary: Delete a connection
// description: Also deletes the policies on it. Session history is kept.
// tags: [connections]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Connections.Delete(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "connection")
	})
}

// openapi:operation
// summary: Forget the pinned host key
// description: >-
//   The next session reports the key the host presents, to be approved (or,
//   with trust on first use, pins it).
// tags: [connections]
// responses:
//   '204': { description: Host key cleared }

func (s *Server) clearHostKey(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Connections.ClearHostKey(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "connection")
	})
}

// openapi:schema ApproveHostKeyRequest
// type: object
// required: [fingerprint]
// additionalProperties: false
// properties:
//   fingerprint: { type: string, pattern: '^SHA256:', description: 'The key to pin, as checked on the server itself (ssh-keygen -lf, or the certificate key for RDP and VNC). Usually the host_key_pending value.' }

type approveHostKeyRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// openapi:operation
// summary: Approve (pin) a host key
// description: >-
//   Pins the fingerprint as the key sessions must find on the server. Use it
//   after comparing host_key_pending with the key shown on the server itself,
//   or to pin a known key up front. Replaces a pinned key.
// tags: [connections]
// requestBody: { schema: ApproveHostKeyRequest }
// responses:
//   '204': { description: Host key pinned }

func (s *Server) approveHostKey(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		var req approveHostKeyRequest
		if err := decode(r, &req); err != nil {
			return err
		}
		err := s.Connections.ApproveHostKey(r.Context(), p.actor(), r.PathValue("id"), req.Fingerprint)
		return fromService(err, "connection")
	})
}
