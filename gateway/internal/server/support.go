package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/totp"
)

// generateVerificationCode generates an on-the-fly random 6-digit verification code.
func generateVerificationCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%900000+100000)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

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
	var req createSupportSessionReq
	if err := decode(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.TargetName) == "" {
		return badRequest("target_name is required")
	}
	ttl := 30 * time.Minute
	if req.TTLMinutes > 0 {
		ttl = time.Duration(req.TTLMinutes) * time.Minute
	}

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	verificationCode := generateVerificationCode()
	id := store.NewID()
	now := store.Now()
	expiresAt := now.Add(ttl)

	ctx := r.Context()
	err := s.Store.Q.CreateSupportSession(ctx, db.CreateSupportSessionParams{
		ID:         id,
		Token:      token,
		CreatedBy:  p.User.ID,
		TargetName: strings.TrimSpace(req.TargetName),
		Reason:     strings.TrimSpace(req.Reason),
		Ticket:     strings.TrimSpace(req.Ticket),
		TotpSecret: verificationCode,
		ExpiresAt:  expiresAt,
		Now:        now,
	})
	if err != nil {
		return fromStore(err, "support_session")
	}

	sess, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return fromStore(err, "support_session")
	}

	s.Store.AuditTx(ctx, store.Event{
		Actor:      p.actor(),
		Action:     "support_session.created",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"target_name": req.TargetName,
			"ticket":      req.Ticket,
			"expires_at":  expiresAt.Format(time.RFC3339),
		},
	})

	return created(w, s.toSupportSessionDTO(sess))
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
	if strings.TrimSpace(req.TargetName) == "" {
		req.TargetName = p.User.Username
	}
	ttl := 30 * time.Minute

	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeErr(w, err)
		return
	}
	token := hex.EncodeToString(tokenBytes)
	verificationCode := generateVerificationCode()
	id := store.NewID()
	now := store.Now()
	expiresAt := now.Add(ttl)

	ctx := r.Context()
	createdBy := p.User.ID

	target := strings.TrimSpace(req.TargetName)
	if req.Domain != "" && !strings.Contains(target, `\`) && !strings.Contains(target, `@`) {
		target = fmt.Sprintf(`%s\%s`, req.Domain, target)
	}

	err = s.Store.Q.CreateSupportSession(ctx, db.CreateSupportSessionParams{
		ID:         id,
		Token:      token,
		CreatedBy:  createdBy,
		TargetName: target,
		Reason:     strings.TrimSpace(req.Reason),
		Ticket:     strings.TrimSpace(req.Ticket),
		TotpSecret: verificationCode,
		ExpiresAt:  expiresAt,
		Now:        now,
	})
	if err != nil {
		writeErr(w, fromStore(err, "support_session"))
		return
	}

	sess, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		writeErr(w, fromStore(err, "support_session"))
		return
	}

	dto := s.toSupportSessionDTO(sess)
	dto.TotpSecret = verificationCode
	dto.VerificationCode = verificationCode

	s.Store.AuditTx(ctx, store.Event{
		Actor:      p.actor(),
		Action:     "support_session.requested",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"target_name":  target,
			"ticket":       req.Ticket,
			"account_type": req.AccountType,
			"hostname":     req.Hostname,
			"client_os":    req.ClientOS,
		},
	})

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
	if token == "" {
		writeErr(w, badRequest("token is required"))
		return
	}
	ctx := r.Context()
	sess, err := s.Store.Q.GetSupportSessionByToken(ctx, token)
	if err != nil {
		writeErr(w, notFound("support session not found"))
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
	if token == "" {
		writeErr(w, badRequest("token is required"))
		return
	}
	ctx := r.Context()
	sess, err := s.Store.Q.GetSupportSessionByToken(ctx, token)
	if err != nil {
		writeErr(w, notFound("support session not found"))
		return
	}
	now := store.Now()
	_ = s.Store.Q.EndSupportSession(ctx, db.EndSupportSessionParams{
		ID:          sess.ID,
		Now:         store.NullTime(now),
		EndedReason: "client_ended",
	})
	if active := s.SupportHub.GetByToken(token); active != nil {
		active.close()
		s.SupportHub.Unregister(active)
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

	rows, err := s.Store.Q.ListSupportSessions(ctx, db.ListSupportSessionsParams{
		CreatedBy: createdBy,
		Status:    status,
	})
	if err != nil {
		return fromStore(err, "support_session")
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
	ctx := r.Context()
	id := r.PathValue("id")
	sess, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return fromStore(err, "support_session")
	}
	return ok(w, s.toSupportSessionDTO(sess))
}

// openapi:operation
// summary: Verify remote user TOTP for support session
// description: Validates the 6-digit TOTP code shown on the remote client.
// tags: [support]
// requestBody: { schema: VerifySupportTOTP }
// responses:
//   '200': { description: OK, schema: SupportSession }

func (s *Server) verifySupportTOTP(w http.ResponseWriter, r *http.Request, p principal) error {
	var req verifySupportTOTPReq
	if err := decode(r, &req); err != nil {
		return err
	}

	ctx := r.Context()
	id := r.PathValue("id")
	sess, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return fromStore(err, "support_session")
	}

	if sess.Status != "connected" && sess.Status != "pending" {
		return badRequest("session cannot be verified in status %s", sess.Status)
	}

	cleanCode := strings.ReplaceAll(strings.TrimSpace(req.Code), " ", "")
	cleanSecret := strings.ReplaceAll(strings.TrimSpace(sess.TotpSecret), " ", "")

	// Direct match for on-the-fly verification code
	valid := cleanCode != "" && cleanCode == cleanSecret
	if !valid {
		// Fallback for legacy RFC6238 TOTP secrets
		valid = totp.Validate(sess.TotpSecret, cleanCode, time.Now())
	}

	if !valid {
		s.Store.AuditTx(ctx, store.Event{
			Actor:      p.actor(),
			Action:     "support_session.verify_failed",
			ObjectType: "support_session",
			ObjectID:   id,
		})
		return badRequest("invalid verification code")
	}

	now := store.Now()
	if err := s.Store.Q.ActivateSupportSession(ctx, db.ActivateSupportSessionParams{
		ID:  id,
		Now: store.NullTime(now),
	}); err != nil {
		return fromStore(err, "support_session")
	}

	// Notify active support session if connected
	if a := s.SupportHub.Get(id); a != nil {
		a.verified = true
		if a.controlConn != nil {
			_ = json.NewEncoder(a.controlConn).Encode(map[string]any{
				"type":          "code_verified",
				"totp_verified": true,
			})
		}
	}

	s.Store.AuditTx(ctx, store.Event{
		Actor:      p.actor(),
		Action:     "support_session.totp_verified",
		ObjectType: "support_session",
		ObjectID:   id,
		Details: map[string]any{
			"activated_at": now.Format(time.RFC3339),
		},
	})

	updated, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return fromStore(err, "support_session")
	}
	return ok(w, s.toSupportSessionDTO(updated))
}

// openapi:operation
// summary: End a support session
// tags: [support]
// responses:
//   '200': { description: Session ended, schema: SupportSession }

func (s *Server) endSupportSession(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	id := r.PathValue("id")
	now := store.Now()

	if a := s.SupportHub.Get(id); a != nil {
		a.close()
		s.SupportHub.Unregister(a)
	}

	if err := s.Store.Q.EndSupportSession(ctx, db.EndSupportSessionParams{
		ID:          id,
		Now:         store.NullTime(now),
		EndedReason: "operator_ended",
	}); err != nil {
		return fromStore(err, "support_session")
	}

	s.Store.AuditTx(ctx, store.Event{
		Actor:      p.actor(),
		Action:     "support_session.ended",
		ObjectType: "support_session",
		ObjectID:   id,
	})

	updated, err := s.Store.Q.GetSupportSession(ctx, id)
	if err != nil {
		return fromStore(err, "support_session")
	}
	return ok(w, s.toSupportSessionDTO(updated))
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
	sess, err := s.Store.Q.GetSupportSessionByToken(ctx, token)
	if err != nil {
		http.Error(w, "invalid or expired token", http.StatusNotFound)
		return
	}

	if sess.Status == "ended" || sess.Status == "expired" {
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
			_ = s.Store.Q.EndSupportSession(context.Background(), db.EndSupportSessionParams{
				ID:          sess.ID,
				Now:         store.NullTime(time.Now()),
				EndedReason: "agent_disconnected",
			})
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
		// Mark ended if active dropped
		_ = s.Store.Q.EndSupportSession(context.Background(), db.EndSupportSessionParams{
			ID:          sess.ID,
			Now:         store.NullTime(time.Now()),
			EndedReason: "agent_disconnected",
		})
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
		_ = s.Store.Q.MarkSupportSessionConnected(context.Background(), db.MarkSupportSessionConnectedParams{
			ID:             sessionID,
			Now:            store.NullTime(time.Now()),
			ClientIP:       clientIP,
			ClientOs:       header.OS,
			ClientHostname: header.Hostname,
		})
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
