package server

import (
	"encoding/json"
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema PortalConnection
// type: object
// required: [id, name, protocol, environment, description, folder_path, tags, record, credentials, can_upload, can_download, can_forward]
// properties:
//   id: { type: string, format: uuid }
//   name: { type: string }
//   protocol: { type: string, enum: [ssh, rdp, vnc, tcp, http, https] }
//   environment: { type: string }
//   description: { type: string }
//   folder_path: { type: string, description: 'Folder names from the root, joined by " / "; empty at the root.' }
//   tags: { type: array, items: { type: string } }
//   record: { type: boolean, description: Sessions are recorded; the UI tells the user. }
//   credentials: { type: string, enum: [vault, prompt, none], description: 'vault: injected, nothing to ask. prompt: ask the user before connecting. none: try without; the server may answer credentials_required.' }
//   can_upload: { type: boolean, description: May send files from the tray to this host. }
//   can_download: { type: boolean, description: May take files from this host into the tray. }
//   can_forward: { type: boolean, description: May establish a TCP/HTTP port-forwarding tunnel to this host. }
//   virtual_host: { type: string, description: 'Virtual host header to inject for HTTP virtual servers.' }

type portalConnectionDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Environment string   `json:"environment"`
	Description string   `json:"description"`
	FolderPath  string   `json:"folder_path"`
	Tags        []string `json:"tags"`
	Record      bool     `json:"record"`
	Credentials string   `json:"credentials"`
	CanUpload   bool     `json:"can_upload"`
	CanDownload bool     `json:"can_download"`
	CanForward  bool     `json:"can_forward"`
	VirtualHost string   `json:"virtual_host,omitempty"`
}

// openapi:operation
// summary: Connections I can open
// description: >-
//   The connections the caller holds an unexpired connect grant for. Nobody
//   bypasses grants, admins included: an admin who needs access grants it
//   to themselves, and that is audited.
// tags: [portal]
// responses:
//   '200': { description: Connections, schema: '[]PortalConnection' }

func (s *Server) portalConnections(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	var conns []db.ConfigConnection
	var err error
	if p.Dev {
		conns, err = s.Store.Q.ListConnections(ctx)
	} else {
		conns, err = s.Store.GrantedConnections(ctx, p.User.ID)
	}
	if err != nil {
		return err
	}
	tags, err := s.tagIndex(ctx)
	if err != nil {
		return err
	}
	folders, err := s.Store.Q.ListFolders(ctx)
	if err != nil {
		return err
	}
	byID := map[string]db.ConfigFolder{}
	for _, f := range folders {
		byID[f.ID] = f
	}
	path := func(id string) string {
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
	out := make([]portalConnectionDTO, 0, len(conns))
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
		up, down := p.Dev, p.Dev
		if !p.Dev && c.Protocol == "ssh" {
			grants, err := s.Store.Grants(ctx, p.User.ID, c.ID)
			if err != nil {
				return err
			}
			for _, g := range grants {
				up, down = up || g.CanUpload, down || g.CanDownload
			}
		}
		canForward := p.Dev
		if !p.Dev {
			canForward, _ = s.Store.CanForward(ctx, p.User.ID, c.ID)
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
		out = append(out, portalConnectionDTO{c.ID, c.Name, c.Protocol, c.Environment, c.Description, path(c.FolderID.String), t, c.Record, creds, up, down, canForward, vhost})
	}
	return ok(w, out)
}
