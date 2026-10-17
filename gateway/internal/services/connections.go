package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	reTag = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

	ErrNameInvalid           = errors.New("name must be 1-128 characters")
	ErrProtocolInvalid       = errors.New("protocol must be ssh, rdp, vnc, tcp, http or https")
	ErrPortOutOfRange        = errors.New("port out of range")
	ErrHostRequired          = errors.New("host is required")
	ErrBackendInvalid        = errors.New("backend must be duckjumpd or guacd")
	ErrCredentialModeInvalid = errors.New("credential_mode must be vault or prompt")
	ErrParamsNotJSONObject   = errors.New("params must be a JSON object")
	ErrInvalidTag            = errors.New("invalid tag (lowercase letters, digits, . _ -; max 32)")
	ErrInvalidFingerprint    = errors.New("fingerprint must look like SHA256:...")

	defaultPorts = map[string]int64{
		"ssh":   22,
		"rdp":   3389,
		"vnc":   5900,
		"tcp":   0,
		"http":  80,
		"https": 443,
	}
)

type ConnectionWithTags struct {
	Connection db.ConfigConnection
	Tags       []string
}

type CreateConnectionParams struct {
	Name           string
	Protocol       string
	Host           string
	Port           int64
	FolderID       *string
	SiteID         *string
	Environment    string
	Description    string
	Tags           []string
	Backend        string
	CredentialMode string
	SecretID       *string
	Params         string
	Record         *bool
	RecordInput    bool
	HostKey        string
	Actor          store.Actor
}

type UpdateConnectionParams struct {
	ID             string
	Name           *string
	Protocol       *string
	Host           *string
	Port           *int64
	FolderID       *string
	FolderIDSet    bool
	SiteID         *string
	SiteIDSet      bool
	Environment    *string
	Description    *string
	Tags           *[]string
	Backend        *string
	CredentialMode *string
	SecretID       *string
	SecretIDSet    bool
	Params         *string
	ParamsNull     bool
	Record         *bool
	RecordInput    *bool
	Actor          store.Actor
}

type ConnectionService struct {
	store *store.Store
}

func NewConnectionService(st *store.Store) *ConnectionService {
	return &ConnectionService{store: st}
}

func (s *ConnectionService) List(ctx context.Context) ([]db.ConfigConnection, error) {
	return s.store.Q.ListConnections(ctx)
}

func (s *ConnectionService) ListWithTags(ctx context.Context) ([]db.ConfigConnection, map[string][]string, error) {
	cs, err := s.store.Q.ListConnections(ctx)
	if err != nil {
		return nil, nil, err
	}
	tags, err := s.TagIndex(ctx)
	if err != nil {
		return nil, nil, err
	}
	return cs, tags, nil
}

func (s *ConnectionService) Get(ctx context.Context, id string) (ConnectionWithTags, error) {
	c, err := s.store.Q.GetConnection(ctx, id)
	if err != nil {
		return ConnectionWithTags{}, store.Classify(err)
	}
	tags, err := s.store.Q.ListConnectionTags(ctx, id)
	if err != nil {
		return ConnectionWithTags{}, err
	}
	return ConnectionWithTags{Connection: c, Tags: tags}, nil
}

func (s *ConnectionService) GetByName(ctx context.Context, name string) (db.ConfigConnection, error) {
	c, err := s.store.Q.GetConnectionByName(ctx, name)
	if err != nil {
		return db.ConfigConnection{}, store.Classify(err)
	}
	return c, nil
}

func (s *ConnectionService) TagIndex(ctx context.Context) (map[string][]string, error) {
	rows, err := s.store.Q.ListAllConnectionTags(ctx)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]string)
	for _, t := range rows {
		m[t.ConnectionID] = append(m[t.ConnectionID], t.Tag)
	}
	return m, nil
}

func (s *ConnectionService) ListTags(ctx context.Context, connectionID string) ([]string, error) {
	return s.store.Q.ListConnectionTags(ctx, connectionID)
}

func (s *ConnectionService) AddTags(ctx context.Context, actor store.Actor, connectionID string, tags []string) error {
	clean, err := cleanTags(tags)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, connectionID)
		if err != nil {
			return store.Classify(err)
		}
		for _, t := range clean {
			_ = q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: connectionID, Tag: t})
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "connection.tag_add",
			ObjectType: "connection",
			ObjectID:   connectionID,
			Details:    map[string]any{"name": c.Name, "tags": clean},
		})
	})
}

func (s *ConnectionService) ClearTags(ctx context.Context, actor store.Actor, connectionID string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, connectionID)
		if err != nil {
			return store.Classify(err)
		}
		if err := q.ClearConnectionTags(ctx, connectionID); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "connection.tag_clear",
			ObjectType: "connection",
			ObjectID:   connectionID,
			Details:    map[string]any{"name": c.Name},
		})
	})
}

func (s *ConnectionService) Create(ctx context.Context, params CreateConnectionParams) (ConnectionWithTags, error) {
	if err := validateName(params.Name); err != nil {
		return ConnectionWithTags{}, err
	}
	defPort, ok := defaultPorts[params.Protocol]
	if !ok {
		return ConnectionWithTags{}, ErrProtocolInvalid
	}
	port := params.Port
	if port == 0 && defPort > 0 {
		port = defPort
	}
	if port < 1 || port > 65535 {
		return ConnectionWithTags{}, ErrPortOutOfRange
	}
	if strings.TrimSpace(params.Host) == "" {
		return ConnectionWithTags{}, ErrHostRequired
	}
	backend := params.Backend
	if backend == "" {
		backend = store.BackendNative
	}
	if backend != store.BackendNative && backend != "guacd" {
		return ConnectionWithTags{}, ErrBackendInvalid
	}
	credMode := params.CredentialMode
	if credMode == "" {
		credMode = "vault"
	}
	if credMode != "vault" && credMode != "prompt" {
		return ConnectionWithTags{}, ErrCredentialModeInvalid
	}
	pStr := params.Params
	if pStr == "" || pStr == "null" {
		pStr = "{}"
	}
	if !json.Valid([]byte(pStr)) || len(pStr) == 0 || pStr[0] != '{' {
		return ConnectionWithTags{}, ErrParamsNotJSONObject
	}
	if params.HostKey != "" && !strings.HasPrefix(params.HostKey, "SHA256:") {
		return ConnectionWithTags{}, ErrInvalidFingerprint
	}
	tags, err := cleanTags(params.Tags)
	if err != nil {
		return ConnectionWithTags{}, err
	}

	record := true
	if params.Record != nil {
		record = *params.Record
	}

	id := store.NewID()
	var created db.ConfigConnection

	err = s.store.Tx(ctx, func(q *db.Queries) error {
		folderID := derefString(params.FolderID)
		if folderID != "" {
			if _, err := q.GetFolder(ctx, folderID); err != nil {
				return store.Classify(err)
			}
		}
		siteID := derefString(params.SiteID)
		if siteID != "" {
			if _, err := q.GetSite(ctx, siteID); err != nil {
				return store.Classify(err)
			}
		}
		secretID := derefString(params.SecretID)
		if secretID != "" {
			if _, err := q.GetSecret(ctx, secretID); err != nil {
				return store.Classify(err)
			}
		}

		if err := q.CreateConnection(ctx, db.CreateConnectionParams{
			ID:             id,
			Name:           params.Name,
			Protocol:       params.Protocol,
			Host:           params.Host,
			Port:           port,
			FolderID:       store.NullString(folderID),
			SiteID:         store.NullString(siteID),
			Environment:    params.Environment,
			Description:    params.Description,
			Backend:        backend,
			CredentialMode: credMode,
			SecretID:       store.NullString(secretID),
			Params:         pStr,
			Record:         record,
			RecordInput:    params.RecordInput,
			Now:            store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if params.HostKey != "" {
			if _, err := q.ApproveHostKey(ctx, db.ApproveHostKeyParams{
				ID:      id,
				HostKey: store.NullString(params.HostKey),
				Now:     store.Now(),
			}); err != nil {
				return err
			}
		}

		for _, t := range tags {
			if err := q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: id, Tag: t}); err != nil {
				return err
			}
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "connection.create",
			ObjectType: "connection",
			ObjectID:   id,
			Details: map[string]any{
				"name":     params.Name,
				"protocol": params.Protocol,
				"host":     params.Host,
				"port":     port,
			},
		}); err != nil {
			return err
		}

		row, err := q.GetConnection(ctx, id)
		if err != nil {
			return err
		}
		created = row
		return nil
	})

	if err != nil {
		return ConnectionWithTags{}, err
	}
	return ConnectionWithTags{Connection: created, Tags: tags}, nil
}

func (s *ConnectionService) Update(ctx context.Context, params UpdateConnectionParams) (ConnectionWithTags, error) {
	var updated db.ConfigConnection
	var finalTags []string

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		changed := []string{}
		set := func(name string, present bool, apply func()) {
			if present {
				apply()
				changed = append(changed, name)
			}
		}

		set("name", params.Name != nil, func() { c.Name = *params.Name })
		set("protocol", params.Protocol != nil, func() { c.Protocol = *params.Protocol })
		set("host", params.Host != nil, func() {
			if *params.Host != c.Host {
				c.HostKey = store.NullString("")
			}
			c.Host = *params.Host
		})
		set("port", params.Port != nil, func() { c.Port = *params.Port })
		set("folder_id", params.FolderIDSet, func() { c.FolderID = store.NullString(derefString(params.FolderID)) })
		set("site_id", params.SiteIDSet, func() { c.SiteID = store.NullString(derefString(params.SiteID)) })
		set("environment", params.Environment != nil, func() { c.Environment = *params.Environment })
		set("description", params.Description != nil, func() { c.Description = *params.Description })
		set("backend", params.Backend != nil, func() { c.Backend = *params.Backend })
		set("credential_mode", params.CredentialMode != nil, func() { c.CredentialMode = *params.CredentialMode })
		set("secret_id", params.SecretIDSet, func() { c.SecretID = store.NullString(derefString(params.SecretID)) })
		set("params", params.Params != nil || params.ParamsNull, func() {
			if params.ParamsNull || params.Params == nil {
				c.Params = "{}"
			} else {
				c.Params = *params.Params
			}
		})
		set("record", params.Record != nil, func() { c.Record = *params.Record })
		set("record_input", params.RecordInput != nil, func() { c.RecordInput = *params.RecordInput })

		if err := validateName(c.Name); err != nil {
			return err
		}
		defPort, ok := defaultPorts[c.Protocol]
		if !ok {
			return ErrProtocolInvalid
		}
		if c.Port == 0 && defPort > 0 {
			c.Port = defPort
		}
		if c.Port < 1 || c.Port > 65535 {
			return ErrPortOutOfRange
		}
		if strings.TrimSpace(c.Host) == "" {
			return ErrHostRequired
		}
		if c.Backend != store.BackendNative && c.Backend != "guacd" {
			return ErrBackendInvalid
		}
		if c.CredentialMode != "vault" && c.CredentialMode != "prompt" {
			return ErrCredentialModeInvalid
		}
		if !json.Valid([]byte(c.Params)) || len(c.Params) == 0 || c.Params[0] != '{' {
			return ErrParamsNotJSONObject
		}

		if c.FolderID.Valid {
			if _, err := q.GetFolder(ctx, c.FolderID.String); err != nil {
				return store.Classify(err)
			}
		}
		if c.SiteID.Valid {
			if _, err := q.GetSite(ctx, c.SiteID.String); err != nil {
				return store.Classify(err)
			}
		}
		if c.SecretID.Valid {
			if _, err := q.GetSecret(ctx, c.SecretID.String); err != nil {
				return store.Classify(err)
			}
		}

		if err := q.UpdateConnection(ctx, db.UpdateConnectionParams{
			ID:             params.ID,
			Name:           c.Name,
			Protocol:       c.Protocol,
			Host:           c.Host,
			Port:           c.Port,
			FolderID:       c.FolderID,
			SiteID:         c.SiteID,
			Environment:    c.Environment,
			Description:    c.Description,
			Backend:        backendOrNative(c.Backend),
			CredentialMode: c.CredentialMode,
			SecretID:       c.SecretID,
			Params:         c.Params,
			Record:         c.Record,
			RecordInput:    c.RecordInput,
			HostKey:        c.HostKey,
			Now:            store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if params.Tags != nil {
			tags, err := cleanTags(*params.Tags)
			if err != nil {
				return err
			}
			if err := q.ClearConnectionTags(ctx, params.ID); err != nil {
				return err
			}
			for _, t := range tags {
				if err := q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: params.ID, Tag: t}); err != nil {
					return err
				}
			}
			changed = append(changed, "tags")
			finalTags = tags
		} else {
			existingTags, err := q.ListConnectionTags(ctx, params.ID)
			if err != nil {
				return err
			}
			finalTags = existingTags
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "connection.update",
			ObjectType: "connection",
			ObjectID:   params.ID,
			Details:    map[string]any{"name": c.Name, "changed": changed},
		}); err != nil {
			return err
		}

		row, err := q.GetConnection(ctx, params.ID)
		if err != nil {
			return err
		}
		updated = row
		return nil
	})

	if err != nil {
		return ConnectionWithTags{}, err
	}
	return ConnectionWithTags{Connection: updated, Tags: finalTags}, nil
}

func (s *ConnectionService) Delete(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if err := q.DeletePoliciesForObject(ctx, db.DeletePoliciesForObjectParams{
			ObjectType: "connection",
			ObjectRef:  id,
		}); err != nil {
			return err
		}
		if _, err := q.DeleteConnection(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "connection.delete",
			ObjectType: "connection",
			ObjectID:   id,
			Details:    map[string]any{"name": c.Name},
		})
	})
}

func (s *ConnectionService) ClearHostKey(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		old := c.HostKey.String
		c.HostKey = store.NullString("")
		if err := q.UpdateConnection(ctx, db.UpdateConnectionParams{
			ID:             id,
			Name:           c.Name,
			Protocol:       c.Protocol,
			Host:           c.Host,
			Port:           c.Port,
			FolderID:       c.FolderID,
			SiteID:         c.SiteID,
			Environment:    c.Environment,
			Description:    c.Description,
			Backend:        c.Backend,
			CredentialMode: c.CredentialMode,
			SecretID:       c.SecretID,
			Params:         c.Params,
			Record:         c.Record,
			RecordInput:    c.RecordInput,
			HostKey:        c.HostKey,
			Now:            store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "connection.host_key_cleared",
			ObjectType: "connection",
			ObjectID:   id,
			Details:    map[string]any{"name": c.Name, "previous": old},
		})
	})
}

func (s *ConnectionService) ApproveHostKey(ctx context.Context, actor store.Actor, id, fingerprint string) error {
	fp := strings.TrimSpace(fingerprint)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 20 || len(fp) > 200 {
		return ErrInvalidFingerprint
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		c, err := q.GetConnection(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if _, err := q.ApproveHostKey(ctx, db.ApproveHostKeyParams{
			ID:      id,
			HostKey: store.NullString(fp),
			Now:     store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "connection.host_key_approved",
			ObjectType: "connection",
			ObjectID:   id,
			Details: map[string]any{
				"name":        c.Name,
				"fingerprint": fp,
				"previous":    c.HostKey.String,
				"was_pending": c.HostKeyPending.String == fp,
			},
		})
	})
}

func validateName(v string) error {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 128 {
		return ErrNameInvalid
	}
	return nil
}

func cleanTags(tags []string) ([]string, error) {
	seen := make(map[string]bool)
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if !reTag.MatchString(t) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidTag, t)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func backendOrNative(b string) string {
	if b == "" {
		return store.BackendNative
	}
	return b
}

func (s *ConnectionService) PinHostKey(ctx context.Context, id, hostKey string) error {
	return s.store.Q.PinHostKey(ctx, db.PinHostKeyParams{
		ID:      id,
		HostKey: store.NullString(hostKey),
	})
}

