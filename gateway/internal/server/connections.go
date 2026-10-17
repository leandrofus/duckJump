package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
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

// tagIndex maps connection id -> tags, for list responses.
func (s *Server) tagIndex(ctx context.Context) (map[string][]string, error) {
	rows, err := s.Store.Q.ListAllConnectionTags(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, t := range rows {
		m[t.ConnectionID] = append(m[t.ConnectionID], t.Tag)
	}
	return m, nil
}

func (s *Server) connectionDTO(ctx context.Context, q *db.Queries, c db.ConfigConnection) (connectionDTO, error) {
	tags, err := q.ListConnectionTags(ctx, c.ID)
	return toConnection(c, tags), err
}

// checkConnection validates a connection row and the objects it references.
func checkConnection(ctx context.Context, q *db.Queries, c *db.ConfigConnection) error {
	if err := validName("name", c.Name); err != nil {
		return err
	}
	def, ok := protocols[c.Protocol]
	if !ok {
		return badRequest("protocol must be ssh, rdp, vnc, tcp, http or https")
	}
	if c.Port == 0 && def > 0 {
		c.Port = def
	}
	if c.Port < 1 || c.Port > 65535 {
		return badRequest("port out of range")
	}
	if c.Host == "" {
		return badRequest("host is required")
	}
	if c.Backend != store.BackendNative && c.Backend != "guacd" {
		return badRequest("backend must be duckjumpd or guacd")
	}
	if c.CredentialMode != "vault" && c.CredentialMode != "prompt" {
		return badRequest("credential_mode must be vault or prompt")
	}
	if !json.Valid([]byte(c.Params)) || len(c.Params) == 0 || c.Params[0] != '{' {
		return badRequest("params must be a JSON object")
	}
	if c.FolderID.Valid {
		if _, err := q.GetFolder(ctx, c.FolderID.String); err != nil {
			return fromStore(err, "folder")
		}
	}
	if c.SiteID.Valid {
		if _, err := q.GetSite(ctx, c.SiteID.String); err != nil {
			return fromStore(err, "site")
		}
	}
	if c.SecretID.Valid {
		if _, err := q.GetSecret(ctx, c.SecretID.String); err != nil {
			return fromStore(err, "secret")
		}
	}
	return nil
}

func setTags(ctx context.Context, q *db.Queries, id string, tags []string) error {
	if err := q.ClearConnectionTags(ctx, id); err != nil {
		return err
	}
	for _, t := range tags {
		if err := q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: id, Tag: t}); err != nil {
			return err
		}
	}
	return nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// optID is the id a nullable PATCH field sets ("" for null).
func optID(o opt[string]) string {
	if o.Null {
		return ""
	}
	return o.V
}

// openapi:operation
// summary: List connections
// tags: [connections]
// responses:
//   '200': { description: The whole catalog, schema: '[]Connection' }

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	cs, err := s.Store.Q.ListConnections(ctx)
	if err != nil {
		return err
	}
	tags, err := s.tagIndex(ctx)
	if err != nil {
		return err
	}
	out := make([]connectionDTO, 0, len(cs))
	for _, c := range cs {
		out = append(out, toConnection(c, tags[c.ID]))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Create a connection
// tags: [connections]
// requestBody: { schema: ConnectionRequest }
// responses:
//   '201': { description: Created, schema: Connection }
//   '409': Error

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	var req connectionRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	tags, err := validTags(req.Tags)
	if err != nil {
		return err
	}
	c := db.ConfigConnection{
		ID: store.NewID(), Name: req.Name, Protocol: req.Protocol, Host: req.Host, Port: req.Port,
		FolderID: store.NullString(deref(req.FolderID)), SiteID: store.NullString(deref(req.SiteID)),
		Environment: req.Environment, Description: req.Description, Backend: req.Backend,
		CredentialMode: req.CredentialMode, SecretID: store.NullString(deref(req.SecretID)),
		Params: string(req.Params), Record: req.Record == nil || *req.Record, RecordInput: req.RecordInput,
	}
	if c.Backend == "" {
		c.Backend = store.BackendNative
	}
	if c.CredentialMode == "" {
		c.CredentialMode = "vault"
	}
	if c.Params == "" || c.Params == "null" {
		c.Params = "{}"
	}
	ctx := r.Context()
	var out connectionDTO
	err = s.tx(ctx, func(q *db.Queries) error {
		if err := checkConnection(ctx, q, &c); err != nil {
			return err
		}
		if err := q.CreateConnection(ctx, db.CreateConnectionParams{
			ID: c.ID, Name: c.Name, Protocol: c.Protocol, Host: c.Host, Port: c.Port, FolderID: c.FolderID,
			SiteID: c.SiteID, Environment: c.Environment, Description: c.Description, Backend: c.Backend,
			CredentialMode: c.CredentialMode, SecretID: c.SecretID, Params: c.Params, Record: c.Record,
			RecordInput: c.RecordInput, Now: store.Now(),
		}); err != nil {
			return fromStore(err, "connection")
		}
		if err := setTags(ctx, q, c.ID, tags); err != nil {
			return err
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.create", ObjectType: "connection", ObjectID: c.ID,
			Details: map[string]any{"name": c.Name, "protocol": c.Protocol, "host": c.Host, "port": c.Port}}); err != nil {
			return err
		}
		row, err := q.GetConnection(ctx, c.ID)
		if err != nil {
			return err
		}
		out, err = s.connectionDTO(ctx, q, row)
		return err
	})
	if err != nil {
		return err
	}
	return created(w, out)
}

// openapi:operation
// summary: Get a connection
// tags: [connections]
// responses:
//   '200': { description: The connection, schema: Connection }

func (s *Server) getConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	c, err := s.Store.Q.GetConnection(ctx, r.PathValue("id"))
	if err != nil {
		return fromStore(err, "connection")
	}
	out, err := s.connectionDTO(ctx, s.Store.Q, c)
	if err != nil {
		return err
	}
	return ok(w, out)
}

// openapi:operation
// summary: Update a connection
// tags: [connections]
// requestBody: { schema: UpdateConnectionRequest }
// responses:
//   '200': { description: Updated, schema: Connection }
//   '409': Error

func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateConnectionRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out connectionDTO
	err := s.tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return fromStore(err, "connection")
		}
		changed := []string{}
		set := func(name string, present bool, apply func()) {
			if present {
				apply()
				changed = append(changed, name)
			}
		}
		set("name", req.Name.Set, func() { c.Name = req.Name.V })
		set("protocol", req.Protocol.Set, func() { c.Protocol = req.Protocol.V })
		set("host", req.Host.Set, func() {
			if req.Host.V != c.Host {
				c.HostKey = store.NullString("") // a different host has a different key
			}
			c.Host = req.Host.V
		})
		set("port", req.Port.Set, func() { c.Port = req.Port.V })
		set("folder_id", req.FolderID.Set, func() { c.FolderID = store.NullString(optID(req.FolderID)) })
		set("site_id", req.SiteID.Set, func() { c.SiteID = store.NullString(optID(req.SiteID)) })
		set("environment", req.Environment.Set, func() { c.Environment = req.Environment.V })
		set("description", req.Description.Set, func() { c.Description = req.Description.V })
		set("backend", req.Backend.Set, func() { c.Backend = req.Backend.V })
		set("credential_mode", req.CredentialMode.Set, func() { c.CredentialMode = req.CredentialMode.V })
		set("secret_id", req.SecretID.Set, func() { c.SecretID = store.NullString(optID(req.SecretID)) })
		set("params", req.Params.Set, func() {
			c.Params = string(req.Params.V)
			if req.Params.Null {
				c.Params = "{}"
			}
		})
		set("record", req.Record.Set, func() { c.Record = req.Record.V })
		set("record_input", req.RecordInput.Set, func() { c.RecordInput = req.RecordInput.V })
		if err := checkConnection(ctx, q, &c); err != nil {
			return err
		}
		if err := q.UpdateConnection(ctx, db.UpdateConnectionParams{
			ID: id, Name: c.Name, Protocol: c.Protocol, Host: c.Host, Port: c.Port, FolderID: c.FolderID,
			SiteID: c.SiteID, Environment: c.Environment, Description: c.Description, Backend: c.Backend,
			CredentialMode: c.CredentialMode, SecretID: c.SecretID, Params: c.Params, Record: c.Record,
			RecordInput: c.RecordInput, HostKey: c.HostKey, Now: store.Now(),
		}); err != nil {
			return fromStore(err, "connection")
		}
		if req.Tags.Set {
			tags, err := validTags(req.Tags.V)
			if err != nil {
				return err
			}
			if err := setTags(ctx, q, id, tags); err != nil {
				return err
			}
			changed = append(changed, "tags")
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.update", ObjectType: "connection", ObjectID: id,
			Details: map[string]any{"name": c.Name, "changed": changed}}); err != nil {
			return err
		}
		row, err := q.GetConnection(ctx, id)
		if err != nil {
			return err
		}
		out, err = s.connectionDTO(ctx, q, row)
		return err
	})
	if err != nil {
		return err
	}
	return ok(w, out)
}

// openapi:operation
// summary: Delete a connection
// description: Also deletes the policies on it. Session history is kept.
// tags: [connections]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return fromStore(err, "connection")
		}
		if err := q.DeletePoliciesForObject(ctx, db.DeletePoliciesForObjectParams{ObjectType: "connection", ObjectRef: id}); err != nil {
			return err
		}
		if _, err := q.DeleteConnection(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.delete", ObjectType: "connection", ObjectID: id,
			Details: map[string]any{"name": c.Name}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
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
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return fromStore(err, "connection")
		}
		old := c.HostKey.String
		c.HostKey = store.NullString("")
		if err := q.UpdateConnection(ctx, db.UpdateConnectionParams{
			ID: id, Name: c.Name, Protocol: c.Protocol, Host: c.Host, Port: c.Port, FolderID: c.FolderID,
			SiteID: c.SiteID, Environment: c.Environment, Description: c.Description, Backend: c.Backend,
			CredentialMode: c.CredentialMode, SecretID: c.SecretID, Params: c.Params, Record: c.Record,
			RecordInput: c.RecordInput, HostKey: c.HostKey, Now: store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.host_key_cleared", ObjectType: "connection", ObjectID: id,
			Details: map[string]any{"name": c.Name, "previous": old}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
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
	var req approveHostKeyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	fp := strings.TrimSpace(req.Fingerprint)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 20 || len(fp) > 200 {
		return badRequest("fingerprint must look like SHA256:...")
	}
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return fromStore(err, "connection")
		}
		if _, err := q.ApproveHostKey(ctx, db.ApproveHostKeyParams{ID: id, HostKey: store.NullString(fp), Now: store.Now()}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.host_key_approved", ObjectType: "connection", ObjectID: id,
			Details: map[string]any{"name": c.Name, "fingerprint": fp, "previous": c.HostKey.String, "was_pending": c.HostKeyPending.String == fp}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}
