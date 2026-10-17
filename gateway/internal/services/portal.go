package services

import (
	"context"
	"encoding/json"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

type PortalConnectionItem struct {
	Connection  db.ConfigConnection
	FolderPath  string
	Tags        []string
	Credentials string // "vault", "prompt", "none"
	CanUpload   bool
	CanDownload bool
	CanForward  bool
	VirtualHost string
}

type PortalService struct {
	store *store.Store
}

func NewPortalService(st *store.Store) *PortalService {
	return &PortalService{store: st}
}

func (s *PortalService) ListConnections(ctx context.Context, userID string, isDev bool) ([]PortalConnectionItem, error) {
	var conns []db.ConfigConnection
	var err error
	if isDev {
		conns, err = s.store.Q.ListConnections(ctx)
	} else {
		conns, err = s.store.GrantedConnections(ctx, userID)
	}
	if err != nil {
		return nil, store.Classify(err)
	}

	tags, err := s.tagIndex(ctx)
	if err != nil {
		return nil, store.Classify(err)
	}

	folders, err := s.store.Q.ListFolders(ctx)
	if err != nil {
		return nil, store.Classify(err)
	}

	byID := map[string]db.ConfigFolder{}
	for _, f := range folders {
		byID[f.ID] = f
	}
	buildPath := func(id string) string {
		var parts []string
		for depth := 0; id != "" && depth < 64; depth++ {
			f, ok := byID[id]
			if !ok {
				break
			}
			parts = append([]string{f.Name}, parts...)
			id = f.ParentID.String
		}
		out := ""
		for i, n := range parts {
			if i > 0 {
				out += " / "
			}
			out += n
		}
		return out
	}

	out := make([]PortalConnectionItem, 0, len(conns))
	for _, c := range conns {
		t := tags[c.ID]
		if t == nil {
			t = []string{}
		}
		creds := "none"
		switch {
		case c.SecretID.Valid:
			creds = "vault"
		case c.CredentialMode == "prompt" || c.Protocol == "ssh":
			creds = "prompt"
		}
		up, down := isDev, isDev
		if !isDev && c.Protocol == "ssh" {
			grants, err := s.store.Grants(ctx, userID, c.ID)
			if err != nil {
				return nil, store.Classify(err)
			}
			for _, g := range grants {
				up, down = up || g.CanUpload, down || g.CanDownload
			}
		}
		canForward := isDev
		if !isDev {
			canForward, _ = s.store.CanForward(ctx, userID, c.ID)
		}
		var extra struct {
			VirtualHost string `json:"virtual_host"`
			HTTPHost    string `json:"http_host"`
		}
		_ = json.Unmarshal([]byte(c.Params), &extra)
		vhost := extra.VirtualHost
		if vhost == "" {
			vhost = extra.HTTPHost
		}
		out = append(out, PortalConnectionItem{
			Connection:  c,
			FolderPath:  buildPath(c.FolderID.String),
			Tags:        t,
			Credentials: creds,
			CanUpload:   up,
			CanDownload: down,
			CanForward:  canForward,
			VirtualHost: vhost,
		})
	}
	return out, nil
}

func (s *PortalService) tagIndex(ctx context.Context) (map[string][]string, error) {
	rows, err := s.store.Q.ListAllConnectionTags(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string][]string{}
	for _, r := range rows {
		m[r.ConnectionID] = append(m[r.ConnectionID], r.Tag)
	}
	return m, nil
}
