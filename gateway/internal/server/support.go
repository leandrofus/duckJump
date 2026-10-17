package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema CreateSupportSession
// type: object
// required: [target_name]
// additionalProperties: false
// properties:
//   target_name: { type: string, description: 'Name or identifier of the user or machine receiving support.' }
//   reason: { type: string, description: 'Reason for the support session.' }
//   ticket: { type: string, description: 'Optional ITSM ticket or issue ID.' }
//   ttl_minutes: { type: integer, default: 30, description: 'How long until the invitation expires in minutes.' }

type createSupportSessionReq struct {
	TargetName string `json:"target_name"`
	Reason     string `json:"reason"`
	Ticket     string `json:"ticket"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// openapi:schema RequestSupportSession
// type: object
// additionalProperties: false
// properties:
//   target_name: { type: string, description: 'User or machine requesting support (default: the caller).' }
//   reason: { type: string, description: 'Reason for the support session.' }
//   ticket: { type: string, description: 'Optional ticket identifier.' }
//   account_type: { type: string, description: 'Account type: local, ad, or sso.' }
//   domain: { type: string, description: 'Windows Active Directory domain if applicable.' }
//   hostname: { type: string, description: 'Client machine hostname.' }
//   client_os: { type: string, description: 'Client operating system.' }

type requestSupportSessionReq struct {
	TargetName  string `json:"target_name"`
	Reason      string `json:"reason"`
	Ticket      string `json:"ticket"`
	AccountType string `json:"account_type"`
	Domain      string `json:"domain"`
	Hostname    string `json:"hostname"`
	ClientOS    string `json:"client_os"`
}

// openapi:schema VerifySupportTOTP
// type: object
// required: [code]
// additionalProperties: false
// properties:
//   code: { type: string, description: '6-digit TOTP verification code from the client.' }

type verifySupportTOTPReq struct {
	Code string `json:"code"`
}

// openapi:schema SupportStatus
// type: object
// required: [id, token, status, target_name, reason, ticket, expires_at]
// properties:
//   id: { type: string, format: uuid }
//   token: { type: string }
//   status: { type: string, enum: [pending, connected, active, ended, expired] }
//   target_name: { type: string }
//   reason: { type: string }
//   ticket: { type: string }
//   client_hostname: { type: string }
//   client_os: { type: string }
//   connected_at: { type: [string, 'null'], format: date-time }
//   activated_at: { type: [string, 'null'], format: date-time }
//   ended_at: { type: [string, 'null'], format: date-time }
//   expires_at: { type: string, format: date-time }

type supportStatusDTO struct {
	ID             string     `json:"id"`
	Token          string     `json:"token"`
	Status         string     `json:"status"`
	TargetName     string     `json:"target_name"`
	Reason         string     `json:"reason"`
	Ticket         string     `json:"ticket"`
	ClientHostname string     `json:"client_hostname"`
	ClientOS       string     `json:"client_os"`
	ConnectedAt    *time.Time `json:"connected_at"`
	ActivatedAt    *time.Time `json:"activated_at"`
	EndedAt        *time.Time `json:"ended_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
}

// openapi:schema SupportEnded
// type: object
// required: [status]
// properties:
//   status: { type: string, enum: [ended] }

type supportEnded struct {
	Status string `json:"status"`
}

// openapi:schema SupportSession
// type: object
// required: [id, token, join_url, created_by, target_name, reason, ticket, status, expires_at, created_at]
// properties:
//   id: { type: string, format: uuid }
//   token: { type: string }
//   join_url: { type: string }
//   created_by: { type: string, format: uuid }
//   target_name: { type: string }
//   reason: { type: string }
//   ticket: { type: string }
//   status: { type: string, enum: [pending, connected, active, ended, expired] }
//   expires_at: { type: string, format: date-time }
//   connected_at: { type: [string, 'null'], format: date-time }
//   activated_at: { type: [string, 'null'], format: date-time }
//   ended_at: { type: [string, 'null'], format: date-time }
//   client_ip: { type: string }
//   client_os: { type: string }
//   client_hostname: { type: string }
//   created_at: { type: string, format: date-time }
//   totp_secret: { type: string, description: 'Verification code; only in the answer to /support/request.' }
//   verification_code: { type: string, description: 'Verification code the requester reads to the technician; only in the answer to /support/request.' }

type supportSessionDTO struct {
	ID               string     `json:"id"`
	Token            string     `json:"token"`
	JoinURL          string     `json:"join_url"`
	CreatedBy        string     `json:"created_by"`
	TargetName       string     `json:"target_name"`
	Reason           string     `json:"reason"`
	Ticket           string     `json:"ticket"`
	TotpSecret       string     `json:"totp_secret,omitempty"`
	VerificationCode string     `json:"verification_code,omitempty"`
	Status           string     `json:"status"`
	ExpiresAt        time.Time  `json:"expires_at"`
	ConnectedAt      *time.Time `json:"connected_at"`
	ActivatedAt      *time.Time `json:"activated_at"`
	EndedAt          *time.Time `json:"ended_at"`
	ClientIP         string     `json:"client_ip"`
	ClientOS         string     `json:"client_os"`
	ClientHostname   string     `json:"client_hostname"`
	CreatedAt        time.Time  `json:"created_at"`
}

// SupportHub coordinates active on-demand support sessions.
type SupportHub struct {
	mu       sync.Mutex
	sessions map[string]*activeSupport
	byToken  map[string]*activeSupport
}

type activeSupport struct {
	id          string
	token       string
	yamuxSess   *yamux.Session
	controlConn net.Conn
	displayConn net.Conn
	displayWS   *websocket.Conn
	verified    bool
	closed      chan struct{}
	once        sync.Once
}

func newActiveSupport(id, token string, sess *yamux.Session) *activeSupport {
	return &activeSupport{
		id:        id,
		token:     token,
		yamuxSess: sess,
		closed:    make(chan struct{}),
	}
}

func (a *activeSupport) close() {
	a.once.Do(func() {
		close(a.closed)
		if a.yamuxSess != nil {
			a.yamuxSess.Close()
		}
		if a.displayWS != nil {
			a.displayWS.Close(websocket.StatusNormalClosure, "session ended")
		}
		if a.controlConn != nil {
			a.controlConn.Close()
		}
		if a.displayConn != nil {
			a.displayConn.Close()
		}
	})
}

func NewSupportHub() *SupportHub {
	return &SupportHub{
		sessions: make(map[string]*activeSupport),
		byToken:  make(map[string]*activeSupport),
	}
}

func (h *SupportHub) Register(a *activeSupport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[a.id] = a
	h.byToken[a.token] = a
}

func (h *SupportHub) Unregister(a *activeSupport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, a.id)
	delete(h.byToken, a.token)
}

func (h *SupportHub) Get(id string) *activeSupport {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

func (h *SupportHub) GetByToken(token string) *activeSupport {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byToken[token]
}

func (h *SupportHub) CloseAndUnregisterByToken(token string) {
	if a := h.GetByToken(token); a != nil {
		a.close()
		h.Unregister(a)
	}
}

func (h *SupportHub) CloseAndUnregisterByID(id string) {
	if a := h.Get(id); a != nil {
		a.close()
		h.Unregister(a)
	}
}

func (h *SupportHub) NotifyVerified(id string) {
	if a := h.Get(id); a != nil {
		a.verified = true
		if a.controlConn != nil {
			_ = json.NewEncoder(a.controlConn).Encode(map[string]any{
				"type":          "code_verified",
				"totp_verified": true,
			})
		}
	}
}

func (s *Server) toSupportSessionDTO(r db.ConfigSupportSession) supportSessionDTO {
	joinURL := fmt.Sprintf("%s/support/join/%s", strings.TrimRight(s.FrontendURL, "/"), r.Token)
	return supportSessionDTO{
		ID:             r.ID,
		Token:          r.Token,
		JoinURL:        joinURL,
		CreatedBy:      r.CreatedBy,
		TargetName:     r.TargetName,
		Reason:         r.Reason,
		Ticket:         r.Ticket,
		Status:         r.Status,
		ExpiresAt:      r.ExpiresAt.UTC(),
		ConnectedAt:    timePtr(r.ConnectedAt),
		ActivatedAt:    timePtr(r.ActivatedAt),
		EndedAt:        timePtr(r.EndedAt),
		ClientIP:       r.ClientIP,
		ClientOS:       r.ClientOs,
		ClientHostname: r.ClientHostname,
		CreatedAt:      r.CreatedAt.UTC(),
	}
}

// openapi:operation
// summary: Create an on-demand remote support session
// description: Generates a support session with a one-time token and TOTP secret.
// tags: [support]
// requestBody: { schema: CreateSupportSession }
// responses:
//   '201': { description: Created, schema: SupportSession }

func (s *Server) createSupportSession(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req createSupportSessionReq) (supportSessionDTO, error) {
		sess, err := s.Support.CreateSession(r.Context(), p.actor(), p.User.ID, services.CreateSupportSessionParams{
			TargetName: req.TargetName,
			Reason:     req.Reason,
			Ticket:     req.Ticket,
			TTLMinutes: req.TTLMinutes,
		})
		if err != nil {
			return supportSessionDTO{}, fromService(err, "support_session")
		}
		return s.toSupportSessionDTO(sess), nil
	})
}

// openapi:operation
// summary: Request an on-demand remote support session (from client desktop app)
// description: >-
//   Initiates a support request from the user's desktop application. Needs a
//   logged-in session (password or single sign-on); the session is owned by
//   the caller. target_name defaults to the caller's username.
// tags: [support]
// requestBody: { schema: RequestSupportSession }
// responses:
//   '201': { description: Created, schema: SupportSession }
//   '401': Error

func (s *Server) requestSupportSession(w http.ResponseWriter, r *http.Request) {
	if err := checkCSRF(r); err != nil {
		writeErr(w, err)
		return
	}
	// The request is owned by whoever asks: an anonymous caller could
	// otherwise open sessions in the name of any user.
	p, pending, err := s.resolve(r)
	switch {
	case err != nil:
		writeErr(w, err)
		return
	case pending:
		writeErr(w, &apiError{http.StatusForbidden, "mfa_required", "complete the TOTP step first"})
		return
	}
	var req requestSupportSessionReq
	if err := decode(r, &req); err != nil {
		writeErr(w, badRequest("%s", err.Error()))
		return
	}
	sess, code, err := s.Support.RequestSession(r.Context(), p.actor(), p.User.ID, p.User.Username, services.RequestSupportSessionParams{
		TargetName:  req.TargetName,
		Reason:      req.Reason,
		Ticket:      req.Ticket,
		AccountType: req.AccountType,
		Domain:      req.Domain,
		Hostname:    req.Hostname,
		ClientOS:    req.ClientOS,
	})
	if err != nil {
		writeErr(w, fromService(err, "support_session"))
		return
	}

	dto := s.toSupportSessionDTO(sess)
	dto.TotpSecret = code
	dto.VerificationCode = code

	_ = created(w, dto)
}

// openapi:operation
// summary: Get support session status by token (for desktop app)
// description: Returns the current status of an ongoing support session.
// tags: [support]
// responses:
//   '200': { description: Current state, schema: SupportStatus }
//   '404': Error

func (s *Server) getSupportStatusByToken(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sess, err := s.Support.GetStatusByToken(r.Context(), token)
	if err != nil {
		writeErr(w, fromService(err, "support_session"))
		return
	}
	ok(w, supportStatusDTO{
		ID:             sess.ID,
		Token:          sess.Token,
		Status:         sess.Status,
		TargetName:     sess.TargetName,
		Reason:         sess.Reason,
		Ticket:         sess.Ticket,
		ClientHostname: sess.ClientHostname,
		ClientOS:       sess.ClientOs,
		ConnectedAt:    timePtr(sess.ConnectedAt),
		ActivatedAt:    timePtr(sess.ActivatedAt),
		EndedAt:        timePtr(sess.EndedAt),
		ExpiresAt:      sess.ExpiresAt.UTC(),
	})
}

// openapi:operation
// summary: End support session by token (for desktop app emergency stop)
// description: Immediately closes an active support session from the client.
// tags: [support]
// responses:
//   '200': { description: Ended, schema: SupportEnded }
//   '403': Error
//   '404': Error

func (s *Server) endSupportSessionByToken(w http.ResponseWriter, r *http.Request) {
	if err := checkCSRF(r); err != nil {
		writeErr(w, err)
		return
	}
	token := r.PathValue("token")
	if err := s.Support.EndByToken(r.Context(), token); err != nil {
		writeErr(w, fromService(err, "support_session"))
		return
	}
	ok(w, supportEnded{Status: "ended"})
}

// openapi:operation
// summary: List support sessions
// description: Lists support sessions created by the caller (or all if admin).
// tags: [support]
// responses:
//   '200': { description: OK, schema: '[]SupportSession' }

func (s *Server) listSupportSessions(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	createdBy := p.User.ID
	if p.User.Role == "superadmin" || p.User.Role == "admin" || p.User.Role == "auditor" {
		createdBy = "" // all
	}
	status := r.URL.Query().Get("status")

	rows, err := s.Support.ListSessions(ctx, createdBy, status)
	if err != nil {
		return fromService(err, "support_session")
	}

	out := make([]supportSessionDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.toSupportSessionDTO(row))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Get support session details
// tags: [support]
// responses:
//   '200': { description: OK, schema: SupportSession }

func (s *Server) getSupportSession(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (supportSessionDTO, error) {
		sess, err := s.Support.GetSession(r.Context(), r.PathValue("id"))
		if err != nil {
			return supportSessionDTO{}, fromService(err, "support_session")
		}
		return s.toSupportSessionDTO(sess), nil
	})
}

// openapi:operation
// summary: Verify remote user TOTP for support session
// description: Validates the 6-digit TOTP code shown on the remote client.
// tags: [support]
// requestBody: { schema: VerifySupportTOTP }
// responses:
//   '200': { description: OK, schema: SupportSession }

func (s *Server) verifySupportTOTP(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req verifySupportTOTPReq) (supportSessionDTO, error) {
		updated, err := s.Support.VerifyTOTP(r.Context(), p.actor(), r.PathValue("id"), req.Code)
		if err != nil {
			return supportSessionDTO{}, fromService(err, "support_session")
		}
		return s.toSupportSessionDTO(updated), nil
	})
}

// openapi:operation
// summary: End a support session
// tags: [support]
// responses:
//   '200': { description: Session ended, schema: SupportSession }

func (s *Server) endSupportSession(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (supportSessionDTO, error) {
		updated, err := s.Support.EndSession(r.Context(), p.actor(), r.PathValue("id"))
		if err != nil {
			return supportSessionDTO{}, fromService(err, "support_session")
		}
		return s.toSupportSessionDTO(updated), nil
	})
}

// openapi:operation
// summary: Connect support agent tunnel (WebSocket)
// description: Upgrades to a WebSocket carrying a multiplexed yamux session for display, control and sftp.
// tags: [support]
// responses:
//   '101': { description: Switching to the WebSocket protocol }

func (s *Server) ServeSupportAgentTunnel(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	sess, err := s.Support.GetStatusByToken(ctx, token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusNotFound)
		return
	}

	if sess.Status == "ended" || sess.Status == "expired" || time.Now().After(sess.ExpiresAt) {
		http.Error(w, "session is closed", http.StatusGone)
		return
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Error("support tunnel: websocket accept", "err", err)
		return
	}
	defer ws.Close(websocket.StatusInternalError, "closed")

	clientIP := s.clientIP(r)
	streamType := r.URL.Query().Get("stream")

	if streamType == "control" {
		active := s.SupportHub.Get(sess.ID)
		if active == nil {
			active = newActiveSupport(sess.ID, sess.Token, nil)
			s.SupportHub.Register(active)
		}
		conn := websocket.NetConn(ctx, ws, websocket.MessageText)
		active.controlConn = conn
		defer func() {
			active.close()
			s.SupportHub.Unregister(active)
			s.releaseSupportSession(sess)
		}()

		// Send initial config with verification code
		_ = json.NewEncoder(conn).Encode(map[string]any{
			"type":        "init",
			"code":        sess.TotpSecret,
			"totp_secret": sess.TotpSecret,
		})

		s.handleAgentStream(sess.ID, active, conn, clientIP)
		return
	}

	if streamType == "display" {
		active := s.SupportHub.Get(sess.ID)
		if active == nil {
			active = newActiveSupport(sess.ID, sess.Token, nil)
			s.SupportHub.Register(active)
		}
		active.displayWS = ws

		select {
		case <-ctx.Done():
		case <-active.closed:
		}
		return
	}

	ycfg := yamux.DefaultConfig()
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 10 * time.Second

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	yamuxSess, err := yamux.Server(netConn, ycfg)
	if err != nil {
		slog.Error("support tunnel: yamux server", "err", err)
		return
	}
	defer yamuxSess.Close()

	active := newActiveSupport(sess.ID, sess.Token, yamuxSess)
	s.SupportHub.Register(active)
	defer func() {
		active.close()
		s.SupportHub.Unregister(active)
		s.releaseSupportSession(sess)
	}()

	// Accept streams from agent
	// Stream 1 is Control (JSON lines)
	// Stream 2 is Display (DJTP frames)
	for {
		stream, err := yamuxSess.AcceptStream()
		if err != nil {
			break
		}
		go s.handleAgentStream(sess.ID, active, stream, clientIP)
	}
}

// releaseSupportSession: the agent disconnected (the user stopped it, closed
// the app, lost the network). The link keeps working until it expires, so
// the user can connect again; with a new verification code, so the operator
// cannot get back in on the old one. Ending a session is the operator's or
// the user's explicit call (…/end), or its expiry.
func (s *Server) releaseSupportSession(sess db.ConfigSupportSession) {
	_ = s.Support.ReleaseSession(context.Background(), sess)
}

func (s *Server) handleAgentStream(sessionID string, active *activeSupport, stream net.Conn, clientIP string) {
	var header struct {
		Stream   string `json:"stream"`
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
	}

	// Read first line as stream header
	dec := json.NewDecoder(stream)
	if err := dec.Decode(&header); err != nil {
		stream.Close()
		return
	}

	switch header.Stream {
	case "control":
		active.controlConn = stream
		_ = s.Support.MarkConnected(context.Background(), sessionID, clientIP, header.OS, header.Hostname)
		// Keep control stream alive and read events
		var msg map[string]any
		for dec.Decode(&msg) == nil {
			if msgType, ok := msg["type"].(string); ok && msgType == "disconnect" {
				active.close()
				break
			}
		}

	case "display":
		active.displayConn = stream
	default:
		stream.Close()
	}
}

// openapi:operation
// summary: Connect operator to support display stream (WebSocket)
// description: Upgrades to a WebSocket streaming raw DJTP display frames and accepting input events.
// tags: [support]
// responses:
//   '101': { description: Switching to the WebSocket protocol }

func (s *Server) operatorSupportWS(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	active := s.SupportHub.Get(id)
	if active == nil || (active.displayConn == nil && active.displayWS == nil) {
		return notFound("support session active stream")
	}
	if !active.verified {
		return forbidden("support session not yet verified with TOTP")
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	defer ws.Close(websocket.StatusInternalError, "closed")

	displayStream := active.displayConn
	displayWS := active.displayWS
	ctx := r.Context()
	errc := make(chan error, 2)

	// Pump display frames from agent -> browser WebSocket
	go func() {
		if displayWS != nil {
			for {
				typ, data, err := displayWS.Read(ctx)
				if err != nil {
					errc <- err
					return
				}
				if err := ws.Write(ctx, typ, data); err != nil {
					errc <- err
					return
				}
			}
		} else if displayStream != nil {
			buf := make([]byte, 64*1024)
			for {
				n, err := displayStream.Read(buf)
				if err != nil {
					errc <- err
					return
				}
				if err := ws.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
					errc <- err
					return
				}
			}
		}
	}()

	// Pump input events from browser WebSocket -> agent
	go func() {
		for {
			typ, reader, err := ws.Reader(ctx)
			if err != nil {
				errc <- err
				return
			}
			if typ == websocket.MessageBinary {
				data, err := io.ReadAll(reader)
				if err != nil {
					errc <- err
					return
				}
				if displayWS != nil {
					if err := displayWS.Write(ctx, websocket.MessageBinary, data); err != nil {
						errc <- err
						return
					}
				} else if displayStream != nil {
					if _, err := displayStream.Write(data); err != nil {
						errc <- err
						return
					}
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-active.closed:
	case <-errc:
	}

	return nil
}
