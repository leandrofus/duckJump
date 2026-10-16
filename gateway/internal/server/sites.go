package server

import (
	"net/http"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/store"
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

func (s *Server) siteDTO(st db.ConfigSite, count *int64) siteDTO {
	d := siteDTO{ID: st.ID, Name: st.Name, Kind: st.Kind, Description: st.Description, ConnectionCount: count, CreatedAt: st.CreatedAt.UTC()}
	if st.Kind == "agent" && s.Hub != nil {
		n := s.Hub.Connected(st.ID)
		d.AgentsOnline = &n
	}
	return d
}

// openapi:operation
// summary: List sites
// tags: [sites]
// responses:
//   '200': { description: Sites with connection counts and agents online, schema: '[]Site' }

func (s *Server) listSites(w http.ResponseWriter, r *http.Request, p principal) error {
	rows, err := s.Store.Q.ListSites(r.Context())
	if err != nil {
		return err
	}
	out := make([]siteDTO, 0, len(rows))
	for _, x := range rows {
		n := x.ConnectionCount
		out = append(out, s.siteDTO(db.ConfigSite{ID: x.ID, Name: x.Name, Kind: x.Kind, Description: x.Description, CreatedAt: x.CreatedAt}, &n))
	}
	return ok(w, out)
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
	var req siteRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := validName("name", req.Name); err != nil {
		return err
	}
	if req.Kind != "direct" && req.Kind != "agent" {
		return badRequest("kind must be direct or agent")
	}
	ctx, id := r.Context(), store.NewID()
	var tok string
	hash := ""
	if req.Kind == "agent" {
		tok = edge.NewToken()
		hash = edge.HashToken(tok)
	}
	err := s.tx(ctx, func(q *db.Queries) error {
		if err := q.CreateSite(ctx, db.CreateSiteParams{ID: id, Name: req.Name, Kind: req.Kind, Description: req.Description,
			AgentTokenHash: store.NullString(hash), Now: store.Now()}); err != nil {
			return fromStore(err, "site")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "site.create", ObjectType: "site", ObjectID: id,
			Details: map[string]any{"name": req.Name, "kind": req.Kind}})
	})
	if err != nil {
		return err
	}
	st, err := s.Store.Q.GetSite(ctx, id)
	if err != nil {
		return err
	}
	d := s.siteDTO(st, nil)
	d.AgentToken = tok
	return created(w, d)
}

// openapi:operation
// summary: Get a site
// tags: [sites]
// responses:
//   '200': { description: The site, schema: Site }

func (s *Server) getSite(w http.ResponseWriter, r *http.Request, p principal) error {
	st, err := s.Store.Q.GetSite(r.Context(), r.PathValue("id"))
	if err != nil {
		return fromStore(err, "site")
	}
	return ok(w, s.siteDTO(st, nil))
}

// openapi:operation
// summary: Update a site
// tags: [sites]
// requestBody: { schema: UpdateSiteRequest }
// responses:
//   '200': { description: Updated, schema: Site }
//   '409': Error

func (s *Server) updateSite(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updateSiteRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigSite
	err := s.tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, id)
		if err != nil {
			return fromStore(err, "site")
		}
		if req.Name.Set {
			if err := validName("name", req.Name.V); err != nil {
				return err
			}
			st.Name = req.Name.V
		}
		if req.Description.Set {
			st.Description = req.Description.V
		}
		if err := q.UpdateSite(ctx, db.UpdateSiteParams{ID: id, Name: st.Name, Description: st.Description}); err != nil {
			return fromStore(err, "site")
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "site.update", ObjectType: "site", ObjectID: id,
			Details: map[string]any{"name": st.Name}}); err != nil {
			return err
		}
		out = st
		return nil
	})
	if err != nil {
		return err
	}
	return ok(w, s.siteDTO(out, nil))
}

// openapi:operation
// summary: Delete a site
// description: Fails with 409 while connections use it. Connected agents are dropped.
// tags: [sites]
// responses:
//   '204': { description: Deleted }
//   '409': Error

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, id)
		if err != nil {
			return fromStore(err, "site")
		}
		if _, err := q.DeleteSite(ctx, id); err != nil {
			return fromStore(err, "site")
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "site.delete", ObjectType: "site", ObjectID: id,
			Details: map[string]any{"name": st.Name}})
	})
	if err != nil {
		return err
	}
	if s.Hub != nil {
		s.Hub.DisconnectSite(id)
	}
	return noContent(w)
}

// openapi:operation
// summary: Rotate a site's agent token
// description: Returns the new token once. Agents using the old token are disconnected and must be reconfigured.
// tags: [sites]
// responses:
//   '200': { description: New token in agent_token, schema: Site }
//   '409': Error

func (s *Server) rotateSiteToken(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	tok := edge.NewToken()
	var out db.ConfigSite
	err := s.tx(ctx, func(q *db.Queries) error {
		st, err := q.GetSite(ctx, id)
		if err != nil {
			return fromStore(err, "site")
		}
		if st.Kind != "agent" {
			return conflict("only agent sites have a token")
		}
		if err := q.SetSiteToken(ctx, db.SetSiteTokenParams{ID: id, AgentTokenHash: store.NullString(edge.HashToken(tok))}); err != nil {
			return err
		}
		out = st
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "site.token_rotate", ObjectType: "site", ObjectID: id,
			Details: map[string]any{"name": st.Name}})
	})
	if err != nil {
		return err
	}
	if s.Hub != nil {
		s.Hub.DisconnectSite(id)
	}
	d := s.siteDTO(out, nil)
	d.AgentToken = tok
	return ok(w, d)
}

// openapi:operation
// summary: Agents connected for a site
// tags: [sites]
// responses:
//   '200': { description: Live agent connections on this gateway, schema: '[]Agent' }

func (s *Server) siteAgents(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	if _, err := s.Store.Q.GetSite(ctx, id); err != nil {
		return fromStore(err, "site")
	}
	out := []agentDTO{}
	if s.Hub != nil {
		for _, a := range s.Hub.Agents(id) {
			out = append(out, agentDTO{Name: a.Name, RemoteAddr: a.Remote, ConnectedAt: a.ConnectedAt.UTC()})
		}
	}
	return ok(w, out)
}
