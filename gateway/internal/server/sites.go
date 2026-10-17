package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema SiteRequest
// type: object
// required: [name, kind]
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   kind: { type: string, enum: [direct, agent] }
//   description: { type: string }

type siteRequest struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// openapi:schema UpdateSiteRequest
// type: object
// additionalProperties: false
// properties:
//   name: { type: string, maxLength: 128 }
//   description: { type: string }

type updateSiteRequest struct {
	Name        opt[string] `json:"name"`
	Description opt[string] `json:"description"`
}

// openapi:schema Agent
// type: object
// required: [name, remote_addr, connected_at]
// properties:
//   name: { type: string }
//   remote_addr: { type: string, description: Public address the agent connects from. }
//   connected_at: { type: string, format: date-time }

type agentDTO struct {
	Name        string    `json:"name"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
}

func (s *Server) siteURLs(r *http.Request) (downloadURL, serverURL, frontendURL, installURL string) {
	baseURL := ""
	if r != nil {
		scheme := "http"
		if s.secureRequest(r) {
			scheme = "https"
		}
		reqURL := scheme + "://" + r.Host

		// If FrontendURL has multiple comma-separated URLs, match against the request
		for _, u := range strings.Split(s.FrontendURL, ",") {
			u = strings.TrimSpace(strings.TrimRight(u, "/"))
			if u == "" {
				continue
			}
			if strings.HasSuffix(u, "://"+r.Host) || strings.EqualFold(u, reqURL) {
				baseURL = u
				break
			}
		}
		if baseURL == "" {
			first := strings.TrimSpace(strings.TrimRight(strings.Split(s.FrontendURL, ",")[0], "/"))
			if first != "" {
				baseURL = first
			} else {
				baseURL = reqURL
			}
		}
	} else if s.FrontendURL != "" {
		baseURL = strings.TrimSpace(strings.TrimRight(strings.Split(s.FrontendURL, ",")[0], "/"))
	}

	frontendURL = baseURL
	if baseURL != "" {
		downloadURL = baseURL + "/agent/duckjump-agent"
		installURL = baseURL + "/agent/install.sh"
	}

	if s.AgentServerURL != "" {
		serverURL = s.AgentServerURL
		return
	}

	scheme := "ws"
	host := ""
	if r != nil {
		if s.secureRequest(r) {
			scheme = "wss"
		}
		h, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			h = r.Host
		}
		host = h
	}

	if host == "" {
		host = "127.0.0.1"
	}

	if s.FrontendURL == "" && s.AgentListen != "" {
		_, port, err := net.SplitHostPort(s.AgentListen)
		if err == nil && port != "" {
			serverURL = fmt.Sprintf("%s://%s:%s/agent/connect", scheme, host, port)
			return
		}
	}

	if baseURL != "" {
		ws := strings.Replace(baseURL, "http://", "ws://", 1)
		ws = strings.Replace(ws, "https://", "wss://", 1)
		serverURL = ws + "/agent/connect"
		return
	}

	serverURL = fmt.Sprintf("%s://%s/agent/connect", scheme, host)
	return
}

func (s *Server) siteDTO(r *http.Request, st db.ConfigSite, count *int64) siteDTO {
	d := siteDTO{ID: st.ID, Name: st.Name, Kind: st.Kind, Description: st.Description, ConnectionCount: count, CreatedAt: st.CreatedAt.UTC()}
	if st.Kind == "agent" {
		if s.Hub != nil {
			n := s.Hub.Connected(st.ID)
			d.AgentsOnline = &n
		}
		dl, srv, fe, inst := s.siteURLs(r)
		d.AgentDownloadURL = dl
		d.AgentServerURL = srv
		d.FrontendURL = fe
		d.AgentInstallURL = inst
	}
	return d
}

// openapi:operation
// summary: List sites
// tags: [sites]
// responses:
//   '200': { description: Sites with connection counts and agents online, schema: '[]Site' }

func (s *Server) listSites(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]siteDTO, error) {
		rows, err := s.Sites.List(r.Context())
		if err != nil {
			return nil, fromService(err, "site")
		}
		out := make([]siteDTO, 0, len(rows))
		for _, x := range rows {
			n := x.ConnectionCount
			out = append(out, s.siteDTO(r, db.ConfigSite{ID: x.ID, Name: x.Name, Kind: x.Kind, Description: x.Description, CreatedAt: x.CreatedAt}, &n))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Create a site
// description: For kind=agent the response carries agent_token, shown only this once.
// tags: [sites]
// requestBody: { schema: SiteRequest }
// responses:
//   '201': { description: Created, schema: Site }
//   '409': Error

func (s *Server) createSite(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req siteRequest) (siteDTO, error) {
		res, err := s.Sites.Create(r.Context(), services.CreateSiteParams{
			Name:        req.Name,
			Kind:        req.Kind,
			Description: req.Description,
			Actor:       p.actor(),
		})
		if err != nil {
			return siteDTO{}, fromService(err, "site")
		}
		d := s.siteDTO(r, res.Site, nil)
		d.AgentToken = res.Token
		return d, nil
	})
}

// openapi:operation
// summary: Get a site
// tags: [sites]
// responses:
//   '200': { description: The site, schema: Site }

func (s *Server) getSite(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (siteDTO, error) {
		st, err := s.Sites.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return siteDTO{}, fromService(err, "site")
		}
		return s.siteDTO(r, st, nil), nil
	})
}

// openapi:operation
// summary: Update a site
// tags: [sites]
// requestBody: { schema: UpdateSiteRequest }
// responses:
//   '200': { description: Updated, schema: Site }
//   '409': Error

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updateSiteRequest) (siteDTO, error) {
		st, err := s.Sites.Update(r.Context(), services.UpdateSiteParams{
			ID:          r.PathValue("id"),
			Name:        req.Name.Ptr(),
			Description: req.Description.Ptr(),
			Actor:       p.actor(),
		})
		if err != nil {
			return siteDTO{}, fromService(err, "site")
		}
		return s.siteDTO(r, st, nil), nil
	})
}

// openapi:operation
// summary: Delete a site
// description: Fails with 409 while connections use it. Connected agents are dropped.
// tags: [sites]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		return fromService(s.Sites.Delete(r.Context(), p.actor(), r.PathValue("id")), "site")
	})
}

// openapi:operation
// summary: Rotate a site's agent token
// description: Returns the new token once. Agents using the old token are disconnected and must be reconfigured.
// tags: [sites]
// responses:
//   '200': { description: New token in agent_token, schema: Site }
//   '409': Error

func (s *Server) rotateSiteToken(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (siteDTO, error) {
		res, err := s.Sites.RotateToken(r.Context(), p.actor(), r.PathValue("id"))
		if err != nil {
			return siteDTO{}, fromService(err, "site")
		}
		d := s.siteDTO(r, res.Site, nil)
		d.AgentToken = res.Token
		return d, nil
	})
}

// openapi:operation
// summary: Agents connected for a site
// tags: [sites]
// responses:
//   '200': { description: Live agent connections on this gateway, schema: '[]Agent' }

func (s *Server) siteAgents(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if _, err := s.Sites.Get(ctx, id); err != nil {
		return fromService(err, "site")
	}
	out := []agentDTO{}
	if s.Hub != nil {
		for _, a := range s.Hub.Agents(id) {
			out = append(out, agentDTO{Name: a.Name, RemoteAddr: a.Remote, ConnectedAt: a.ConnectedAt.UTC()})
		}
	}
	return ok(w, out)
}
