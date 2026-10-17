package server

import (
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
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

func toPortalConnectionDTO(item services.PortalConnectionItem) portalConnectionDTO {
	c := item.Connection
	return portalConnectionDTO{
		ID:          c.ID,
		Name:        c.Name,
		Protocol:    c.Protocol,
		Environment: c.Environment,
		Description: c.Description,
		FolderPath:  item.FolderPath,
		Tags:        item.Tags,
		Record:      c.Record,
		Credentials: item.Credentials,
		CanUpload:   item.CanUpload,
		CanDownload: item.CanDownload,
		CanForward:  item.CanForward,
		VirtualHost: item.VirtualHost,
	}
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
	items, err := s.Portal.ListConnections(r.Context(), p.User.ID, p.Dev)
	if err != nil {
		return fromService(err, "portal")
	}
	out := make([]portalConnectionDTO, 0, len(items))
	for _, item := range items {
		out = append(out, toPortalConnectionDTO(item))
	}
	return ok(w, out)
}
