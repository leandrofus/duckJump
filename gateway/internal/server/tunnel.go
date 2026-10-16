package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/djtp"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Browser <-> gateway WebSocket:
//   - binary messages: terminal bytes (output down, keystrokes up)
//   - text messages: JSON control ({"type":"resize","cols":..,"rows":..} up;
//     ready / exit / error down)

// openapi:operation
// summary: Open a session (WebSocket)
// description: >-
//   Upgrades to a WebSocket. Binary messages carry terminal bytes both ways;
//   text messages carry JSON control: {"type":"resize","cols":N,"rows":N}
//   from the client; ready, exit and error from the server. Requires a
//   connect grant on the connection. The session is recorded per the
//   connection's settings and audited.
// tags: [portal]
// parameters:
//   - { name: cols, in: query, schema: { type: integer, default: 80 } }
//   - { name: rows, in: query, schema: { type: integer, default: 24 } }
//   - { name: width, in: query, schema: { type: integer, default: 1280 }, description: 'RDP: desktop width in pixels.' }
//   - { name: height, in: query, schema: { type: integer, default: 800 }, description: 'RDP: desktop height in pixels.' }
//   - { name: credentials, in: query, schema: { type: integer, enum: [1] }, description: 'The client sends the credentials as its first text message: {"type":"credentials","username","password","domain"}. Only for connections without a vaulted credential; they are used once and never stored.' }
// responses:
//   '101': { description: Switching to the WebSocket protocol }
//   '501': Error

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request, p principal) error {
	if joinID := r.URL.Query().Get("join"); joinID != "" {
		return s.joinSession(w, r, p, joinID)
	}

	ctx, connID := r.Context(), r.PathValue("id")
	conn, err := s.Store.Q.GetConnection(ctx, connID)
	if err != nil {
		return fromStore(err, "connection")
	}
	if !p.Dev {
		allowed, err := s.Store.CanConnect(ctx, p.User.ID, connID)
		if err != nil {
			return err
		}
		if !allowed {
			s.Store.AuditTx(ctx, store.Event{Actor: p.actor(), Action: "session.denied", ObjectType: "connection", ObjectID: connID,
				Details: map[string]any{"name": conn.Name}})
			return errForbidden
		}
	}
	if conn.Backend != store.BackendNative {
		return &apiError{http.StatusNotImplemented, "not_implemented", "the guacd backend is not implemented yet"}
	}
	cols, rows := atoiDefault(r.URL.Query().Get("cols"), 80), atoiDefault(r.URL.Query().Get("rows"), 24)
	if conn.Protocol == "rdp" {
		// For RDP the desktop size, in pixels, of the space the browser has.
		cols, rows = sizeParam(r.URL.Query().Get("width"), 1280), sizeParam(r.URL.Query().Get("height"), 800)
	}

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil // Accept already answered
	}
	defer ws.CloseNow()
	ws.SetReadLimit(djtp.MaxFrameLen)

	sessionID := randomID(16)
	log := slog.With("session", sessionID, "user", p.User.Username, "conn", conn.Name)
	prompted := r.URL.Query().Get("credentials") == "1"

	// Live until it ends: re-checked while it runs, and can be terminated.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	ls := &liveSession{
		id:           sessionID,
		userID:       p.User.ID,
		username:     p.User.Username,
		connID:       connID,
		conn:         conn,
		cancel:       cancel,
		participants: make(map[string]*liveParticipant),
		shareTokens:  make(map[string]shareTokenInfo),
	}
	if !graphical(conn.Protocol) {
		ls.sshBuffer = newTerminalBuffer(128 * 1024)
	}
	s.live.add(ls)
	defer s.live.remove(sessionID)

	reason, err := s.runSession(ctx, ws, ls, conn, p, sessionID, cols, rows, prompted, log)
	var term *terminated
	if errors.As(context.Cause(ctx), &term) {
		log.Info("session terminated", "reason", term.reason)
		ws.Close(websocket.StatusPolicyViolation, "terminated")
		return nil
	}
	if err != nil {
		log.Warn("session ended with error", "err", err)
		msg := map[string]string{"type": "error", "message": err.Error()}
		var se *sessionError
		if errors.As(err, &se) {
			msg["code"], msg["message"] = se.Code, se.Message
			if se.Fingerprint != "" {
				msg["fingerprint"] = se.Fingerprint
			}
		}
		sendJSON(ctx, ws, msg)
		ws.Close(websocket.StatusInternalError, "session error")
		return nil
	}
	log.Info("session ended", "reason", reason)
	ws.Close(websocket.StatusNormalClosure, reason)
	return nil
}

// graphical reports whether a protocol uses display frames (VNC, RDP)
// instead of a terminal byte stream.
func graphical(protocol string) bool { return protocol == "vnc" || protocol == "rdp" }

// sessionError carries a code the client acts on: credentials_required
// (ask the user and retry), auth_failed, host_key_mismatch…
type sessionError struct {
	Code, Message string
	Fingerprint   string // host_key_unverified: the key to verify and approve
}

func (e *sessionError) Error() string { return e.Code + ": " + e.Message }

// sessionCreds are the credentials a session uses and where they came from.
type sessionCreds struct {
	Username, Password, Domain string
	PrivateKey                 string // ssh, vaulted keys only
	Source                     string // vault | prompt | none
	SecretName                 string
}

// resolveCreds picks the session's credentials: the vaulted secret; or, for
// connections without one, what the user typed (first WebSocket message,
// never stored); or none, letting the server show its own login.
func (s *Server) resolveCreds(ctx context.Context, ws *websocket.Conn, c db.ConfigConnection, prompted bool) (sessionCreds, error) {
	if prompted {
		if c.SecretID.Valid {
			return sessionCreds{}, &sessionError{Code: "bad_request", Message: "this connection uses a vaulted credential"}
		}
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		typ, data, err := ws.Read(rctx)
		if err != nil || typ != websocket.MessageText {
			return sessionCreds{}, errors.New("expected the credentials message")
		}
		var m struct{ Type, Username, Password, Domain string }
		if json.Unmarshal(data, &m) != nil || m.Type != "credentials" || len(m.Username) > 256 || len(m.Password) > 1024 || len(m.Domain) > 256 {
			return sessionCreds{}, &sessionError{Code: "bad_request", Message: "invalid credentials message"}
		}
		return sessionCreds{Username: strings.TrimSpace(m.Username), Password: m.Password, Domain: strings.TrimSpace(m.Domain), Source: "prompt"}, nil
	}
	if c.SecretID.Valid {
		return s.vaultCreds(ctx, c)
	}
	// No credential at all: SSH can't go further, and "prompt" connections
	// always ask. RDP and VNC try without (login screen / no-password server).
	if c.CredentialMode == "prompt" || c.Protocol == "ssh" {
		return sessionCreds{}, &sessionError{Code: "credentials_required", Message: "this connection needs your credentials"}
	}
	return sessionCreds{Source: "none"}, nil
}

// vaultCreds unseals the connection's vaulted credential.
func (s *Server) vaultCreds(ctx context.Context, c db.ConfigConnection) (sessionCreds, error) {
	sec, err := s.Store.Q.GetSecret(ctx, c.SecretID.String)
	if err != nil {
		return sessionCreds{}, fmt.Errorf("loading secret: %w", err)
	}
	plain, err := s.Vault.Open(sec.Sealed, []byte(sec.ID))
	if err != nil {
		return sessionCreds{}, fmt.Errorf("unsealing secret %q: %w", sec.Name, err)
	}
	cr := sessionCreds{Username: sec.Username, Source: "vault", SecretName: sec.Name}
	if sec.Kind == "private_key" {
		if c.Protocol != "ssh" {
			return sessionCreds{}, fmt.Errorf("%s needs a password credential, not a private key", c.Protocol)
		}
		cr.PrivateKey = string(plain)
	} else {
		cr.Password = string(plain)
	}
	return cr, nil
}

func (s *Server) runSession(ctx context.Context, ws *websocket.Conn, ls *liveSession, c db.ConfigConnection, p principal,
	sessionID string, cols, rows int, prompted bool, log *slog.Logger) (string, error) {

	cr, err := s.resolveCreds(ctx, ws, c, prompted)
	if err != nil {
		return "", err
	}
	var params any
	switch c.Protocol {
	case "ssh":
		params = s.sshParams(c, cr, cols, rows)
	case "vnc":
		var extra struct {
			Security string `json:"security"`
		}
		json.Unmarshal([]byte(c.Params), &extra)
		vp := djtp.VNCParams{Host: c.Host, Port: int(c.Port), Username: cr.Username, Security: extra.Security, TrustUnknown: s.TrustOnFirstUse}
		if vp.Security == "" {
			vp.Security = "any"
		}
		if cr.Password != "" {
			pw := cr.Password
			vp.Password = &pw
		}
		if c.HostKey.Valid {
			vp.CertFingerprint = &c.HostKey.String
		}
		params = vp
	case "rdp":
		var extra struct {
			Domain   string `json:"domain"`
			Security string `json:"security"`
		}
		json.Unmarshal([]byte(c.Params), &extra)
		if extra.Security == "" {
			extra.Security = "any"
		}
		if cr.Domain != "" {
			extra.Domain = cr.Domain
		}
		rp := djtp.RDPParams{Host: c.Host, Port: int(c.Port), Username: cr.Username, Password: cr.Password,
			Domain: extra.Domain, Security: extra.Security, Width: cols, Height: rows}
		if c.HostKey.Valid {
			rp.CertFingerprint = &c.HostKey.String
		}
		rp.TrustUnknown = s.TrustOnFirstUse
		params = rp
	}
	var rec *djtp.Recording
	recName := ""
	if c.Record {
		recName = sessionID
		rec = &djtp.Recording{Name: recName, IncludeInput: c.RecordInput}
	}
	pd, siteName, err := s.openDaemon(ctx, c, p, sessionID, c.Protocol, params, rec, log)
	if err != nil {
		return "", err
	}
	defer pd.Close()
	// A terminated session unblocks whatever waits on the daemon.
	defer context.AfterFunc(ctx, func() { pd.Close() })()
	ls.pd = pd
	ls.siteName = siteName

	// The snapshot keeps the audit faithful if the connection is edited or
	// deleted later. Never includes credentials.
	snap, _ := json.Marshal(map[string]any{"id": c.ID, "name": c.Name, "protocol": c.Protocol, "host": c.Host, "port": c.Port,
		"site": siteName, "secret": cr.SecretName, "account": cr.Username, "credentials": cr.Source, "record": c.Record, "record_input": c.RecordInput})
	err = s.tx(ctx, func(q *db.Queries) error {
		if err := q.StartSessionRecord(ctx, db.StartSessionRecordParams{
			ID: sessionID, UserID: store.NullString(p.User.ID), Username: p.User.Username, ConnectionID: c.ID,
			ConnectionSnapshot: string(snap), Site: siteName, ClientIP: p.IP, Recording: store.NullString(recName), Now: store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "session.start", ObjectType: "session", ObjectID: sessionID,
			Details: map[string]any{"connection_id": c.ID, "connection": c.Name, "account": cr.Username, "credentials": cr.Source}})
	})
	if err != nil {
		return "", fmt.Errorf("audit: %w", err)
	}
	if err := s.Store.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: sessionID, Node: s.node(), Now: store.Now()}); err != nil {
		log.Error("session heartbeat", "err", err)
	}
	reason := "closed"
	defer func() {
		ctx := context.WithoutCancel(ctx)
		s.Store.Q.ForgetSession(ctx, sessionID)
		s.Store.Q.EndSessionRecord(ctx, db.EndSessionRecordParams{ID: sessionID, EndReason: reason, Now: store.NullTime(store.Now())})
		s.Store.AuditTx(ctx, store.Event{Actor: p.actor(), Action: "session.end", ObjectType: "session", ObjectID: sessionID,
			Details: map[string]any{"reason": reason}})
	}()
	log.Info("session started")

	ownerID := randomID(8)
	lp := &liveParticipant{
		id:       ownerID,
		userID:   p.User.ID,
		username: p.User.Username,
		isOwner:  true,
		ws:       ws,
		sendCh:   make(chan wsMessage, 512),
	}
	ls.addParticipant(lp)

	sendJSON(ctx, ws, map[string]any{
		"type":            "ready",
		"session_id":      sessionID,
		"connection_id":   c.ID,
		"protocol":        c.Protocol,
		"title":           c.Name,
		"is_owner":        true,
		"has_control":     true,
		"controller":      ownerID,
		"controller_name": p.User.Username,
		"my_id":           ownerID,
	})

	// duckjumpd -> browser. When the daemon side ends, closing the WebSockets
	// unblocks the read loops.
	down := make(chan string, 1)
	go func() {
		var why string
		defer func() {
			down <- why
			ls.mu.RLock()
			for _, part := range ls.participants {
				part.ws.Close(websocket.StatusNormalClosure, why)
			}
			ls.mu.RUnlock()
		}()
		for {
			f, err := djtp.ReadFrame(pd)
			if err != nil {
				why = "daemon closed"
				return
			}
			switch f.Kind {
			case djtp.KindOutput:
				if ls.sshBuffer != nil {
					ls.sshBuffer.Write(f.Payload)
				}
				ls.broadcastBinary(f.Payload)
			case djtp.KindDisplay:
				// Graphical sessions: binary messages carry the frame kind first.
				ls.broadcastBinary(append([]byte{djtp.KindDisplay}, f.Payload...))
			case djtp.KindControl:
				ls.broadcastText(f.Payload)
				if ctrl, _ := djtp.DecodeControl(f); ctrl.Type == "exit" || ctrl.Type == "error" {
					why = ctrl.Type
					return
				}
			}
		}
	}()

	err = s.runParticipant(ctx, ls, lp, p, log)
	var term *terminated
	if errors.As(context.Cause(ctx), &term) {
		reason = "terminated: " + term.reason
		djtp.WriteControl(pd, djtp.Control{Type: "close"})
		return reason, nil
	}
	select {
	case reason = <-down:
	default:
		ls.mu.RLock()
		activeCount := len(ls.participants)
		ls.mu.RUnlock()
		if activeCount > 0 {
			select {
			case reason = <-down:
			case <-ctx.Done():
				reason = "closed"
			}
		} else {
			reason = "client disconnected"
			djtp.WriteControl(pd, djtp.Control{Type: "close"})
		}
	}
	return reason, nil
}

func (s *Server) runParticipant(ctx context.Context, ls *liveSession, lp *liveParticipant, princ principal, log *slog.Logger) error {
	defer ls.removeParticipant(lp.id)

	go func() {
		for m := range lp.sendCh {
			wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := lp.ws.Write(wctx, m.msgType, m.data)
			cancel()
			if err != nil {
				lp.ws.CloseNow()
				return
			}
		}
	}()

	for {
		typ, data, err := lp.ws.Read(ctx)
		if err != nil {
			return err
		}
		switch typ {
		case websocket.MessageBinary:
			if !graphical(ls.conn.Protocol) {
				if ls.hasControl(lp.id) {
					err = djtp.WriteFrame(ls.pd, djtp.KindInput, data)
				}
			} else if len(data) > 1 && data[0] == djtp.KindInputEvent {
				if data[1] == 0x03 { // Ack
					err = djtp.WriteFrame(ls.pd, djtp.KindInputEvent, data[1:])
				} else if ls.hasControl(lp.id) {
					err = djtp.WriteFrame(ls.pd, djtp.KindInputEvent, data[1:])
				}
			}
		case websocket.MessageText:
			var m struct {
				Type string `json:"type"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
				Text string `json:"text"`
				To   string `json:"to"`
			}
			if json.Unmarshal(data, &m) != nil {
				break
			}
			switch m.Type {
			case "resize":
				if ls.hasControl(lp.id) && m.Cols > 0 && m.Rows > 0 {
					err = djtp.WriteControl(ls.pd, djtp.Control{Type: "resize", Cols: m.Cols, Rows: m.Rows})
				}
			case "clipboard":
				if ls.hasControl(lp.id) && graphical(ls.conn.Protocol) && len(m.Text) <= 1<<20 {
					err = djtp.WriteControl(ls.pd, djtp.Control{Type: "clipboard", Text: m.Text})
				}
			case "yield_control":
				_ = s.tx(ctx, func(q *db.Queries) error {
					return ls.yieldControl(ctx, lp.id, m.To, princ.actor(), q)
				})
			case "take_control":
				_ = s.tx(ctx, func(q *db.Queries) error {
					return ls.takeControl(ctx, lp.id, princ.actor(), q)
				})
			case "request_control":
				ls.requestControl(lp.id)
			}
		}
		if err != nil {
			return err
		}
	}
}

func (s *Server) joinSession(w http.ResponseWriter, r *http.Request, p principal, sessionID string) error {
	ctx := r.Context()
	ls := s.live.get(sessionID)
	if ls == nil {
		return &apiError{http.StatusNotFound, "session_not_found", "this session is not active or has ended"}
	}

	token := r.URL.Query().Get("token")
	canAccess := p.Dev || admins[p.User.Role] || ls.userID == p.User.ID || (token != "" && ls.validateShareToken(token))
	if !canAccess {
		allowed, err := s.Store.CanConnect(ctx, p.User.ID, ls.connID)
		if err != nil {
			return err
		}
		if !allowed {
			s.Store.AuditTx(ctx, store.Event{
				Actor:      p.actor(),
				Action:     "session.join_denied",
				ObjectType: "session",
				ObjectID:   sessionID,
				Details:    map[string]any{"connection": ls.conn.Name},
			})
			return errForbidden
		}
	}

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil
	}
	defer ws.CloseNow()
	ws.SetReadLimit(djtp.MaxFrameLen)

	isOwner := ls.userID == p.User.ID
	partID := randomID(8)
	lp := &liveParticipant{
		id:       partID,
		userID:   p.User.ID,
		username: p.User.Username,
		isOwner:  isOwner,
		ws:       ws,
		sendCh:   make(chan wsMessage, 512),
	}

	log := slog.With("session", sessionID, "user", p.User.Username, "role", "participant")
	log.Info("joined live session")

	s.Store.AuditTx(ctx, store.Event{
		Actor:      p.actor(),
		Action:     "session.join",
		ObjectType: "session",
		ObjectID:   sessionID,
		Details:    map[string]any{"connection": ls.conn.Name, "owner": ls.username},
	})
	defer func() {
		s.Store.AuditTx(context.WithoutCancel(ctx), store.Event{
			Actor:      p.actor(),
			Action:     "session.leave",
			ObjectType: "session",
			ObjectID:   sessionID,
			Details:    map[string]any{"connection": ls.conn.Name},
		})
	}()

	ls.addParticipant(lp)

	sendJSON(ctx, ws, map[string]any{
		"type":            "ready",
		"session_id":      ls.id,
		"connection_id":   ls.connID,
		"protocol":        ls.conn.Protocol,
		"title":           ls.conn.Name,
		"is_owner":        isOwner,
		"has_control":     ls.hasControl(lp.id),
		"controller":      ls.controllerID,
		"controller_name": ls.controllerName,
		"my_id":           lp.id,
	})

	if !graphical(ls.conn.Protocol) && ls.sshBuffer != nil {
		if buf := ls.sshBuffer.Bytes(); len(buf) > 0 {
			_ = ws.Write(ctx, websocket.MessageBinary, buf)
		}
	} else if graphical(ls.conn.Protocol) && ls.pd != nil {
		_ = djtp.WriteControl(ls.pd, djtp.Control{Type: "refresh"})
	}

	_ = s.runParticipant(ctx, ls, lp, p, log)
	ws.Close(websocket.StatusNormalClosure, "left")
	return nil
}

// openapi:operation
// summary: Create a share token for a live session
// tags: [portal]
// responses:
//   '201': { schema: SessionShare, description: Share token created }
//   '403': Error
//   '404': Error
func (s *Server) createSessionShare(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	ls := s.live.get(id)
	if ls == nil {
		return notFound("no active session with this id")
	}
	if !p.Dev && !admins[p.User.Role] && ls.userID != p.User.ID {
		return errForbidden
	}
	tok := ls.createShareToken(p.User.Username)
	_ = store.Audit(ctx, s.Store.Q, store.Event{
		Actor:      p.actor(),
		Action:     "session.share",
		ObjectType: "session",
		ObjectID:   id,
	})
	return writeJSON(w, http.StatusCreated, map[string]any{
		"share_token":   tok,
		"session_id":    id,
		"connection_id": ls.connID,
	})
}

// openapi:operation
// summary: Get live session sharing info or active token
// tags: [portal]
// responses:
//   '200': { schema: SessionShare, description: Share token retrieved }
//   '403': Error
//   '404': Error
func (s *Server) getSessionShare(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	ls := s.live.get(id)
	if ls == nil {
		return notFound("no active session with this id")
	}
	if !p.Dev && !admins[p.User.Role] && ls.userID != p.User.ID {
		return errForbidden
	}
	tok := ls.activeShareToken()
	if tok == "" {
		tok = ls.createShareToken(p.User.Username)
	}
	return writeJSON(w, http.StatusOK, map[string]any{
		"share_token":   tok,
		"session_id":    id,
		"connection_id": ls.connID,
	})
}

// openapi:operation
// summary: Revoke share tokens for a live session
// tags: [portal]
// responses:
//   '204': { description: Share token revoked }
//   '403': Error
//   '404': Error
func (s *Server) revokeSessionShare(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	ls := s.live.get(id)
	if ls == nil {
		return notFound("no active session with this id")
	}
	if !p.Dev && !admins[p.User.Role] && ls.userID != p.User.ID {
		return errForbidden
	}
	ls.revokeShareTokens()
	_ = store.Audit(ctx, s.Store.Q, store.Event{
		Actor:      p.actor(),
		Action:     "session.unshare",
		ObjectType: "session",
		ObjectID:   id,
	})
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// openapi:operation
// summary: Get metadata of a live session for joiners
// tags: [portal]
// responses:
//   '200': { schema: SessionInfo, description: Session info }
//   '403': Error
//   '404': Error
func (s *Server) getSessionInfo(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	ls := s.live.get(id)
	if ls == nil {
		return notFound("session is not active or has ended")
	}
	tok := r.URL.Query().Get("token")
	canAccess := p.Dev || admins[p.User.Role] || ls.userID == p.User.ID || (tok != "" && ls.validateShareToken(tok))
	if !canAccess {
		allowed, err := s.Store.CanConnect(ctx, p.User.ID, ls.connID)
		if err != nil || !allowed {
			return errForbidden
		}
	}
	return writeJSON(w, http.StatusOK, map[string]any{
		"session_id":      ls.id,
		"connection_id":   ls.connID,
		"connection_name": ls.conn.Name,
		"protocol":        ls.conn.Protocol,
		"owner_username":  ls.username,
		"active":          true,
	})
}

// openapi:operation
// summary: Join a live session (WebSocket)
// tags: [portal]
// responses:
//   '101': { description: Switching to WebSocket }
//   '403': Error
//   '404': Error
func (s *Server) joinSessionEndpoint(w http.ResponseWriter, r *http.Request, p principal) error {
	id := r.PathValue("id")
	return s.joinSession(w, r, p, id)
}

// unverifiedHostKey handles a server whose key nobody approved yet: duckjumpd
// stopped before sending any credential. The key waits on the connection
// for an admin to compare it with the real one and approve it.
func (s *Server) unverifiedHostKey(ctx context.Context, c db.ConfigConnection, p principal, fp string, log *slog.Logger) error {
	ctx = context.WithoutCancel(ctx)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 200 {
		return &sessionError{Code: "connect_failed", Message: "the daemon reported an invalid host key"}
	}
	log.Warn("host key not approved", "fingerprint", fp)
	if !c.HostKeyPending.Valid || c.HostKeyPending.String != fp {
		err := s.tx(ctx, func(q *db.Queries) error {
			if err := q.SetPendingHostKey(ctx, db.SetPendingHostKeyParams{ID: c.ID, HostKeyPending: store.NullString(fp)}); err != nil {
				return err
			}
			return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "connection.host_key_pending", ObjectType: "connection", ObjectID: c.ID,
				Details: map[string]any{"name": c.Name, "fingerprint": fp}})
		})
		if err != nil {
			log.Error("recording the pending host key", "err", err)
		}
	}
	return &sessionError{Code: "host_key_unverified", Fingerprint: fp,
		Message: "the server's key " + fp + " has not been approved yet: an admin must check it against the server and approve it"}
}

// openDaemon starts a session on duckjumpd (through the site's edge relay
// when it has one) and waits until the remote side is up. It handles
// unknown host keys (pending approval, or pinned on first use). The caller
// closes the returned connection.
func (s *Server) openDaemon(ctx context.Context, c db.ConfigConnection, p principal, sessionID, protocol string, params any,
	rec *djtp.Recording, log *slog.Logger) (net.Conn, string, error) {
	var relay *djtp.Relay
	siteName := ""
	if c.SiteID.Valid {
		site, err := s.Store.Q.GetSite(ctx, c.SiteID.String)
		if err != nil {
			return nil, "", fmt.Errorf("loading site: %w", err)
		}
		siteName = site.Name
		if site.Kind == "agent" {
			tk, err := s.Hub.Ticket(site.ID, c.Host, int(c.Port), sessionID)
			if err != nil {
				return nil, "", fmt.Errorf("site %s: %w", site.Name, err)
			}
			relay = &djtp.Relay{Addr: s.RelayAddr, Ticket: tk, TLSFingerprint: s.RelayFingerprint}
			log = log.With("site", site.Name)
		}
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	var pd net.Conn
	var err error
	if s.DaemonTLS != nil {
		pd, err = (&tls.Dialer{NetDialer: d, Config: s.DaemonTLS}).DialContext(ctx, "tcp", s.DaemonAddr)
	} else {
		pd, err = d.DialContext(ctx, "tcp", s.DaemonAddr)
	}
	if err != nil {
		return nil, "", fmt.Errorf("duckjumpd unreachable: %w", err)
	}
	fail := func(err error) (net.Conn, string, error) {
		pd.Close()
		return nil, "", err
	}
	if err := djtp.WriteControl(pd, djtp.Control{
		Type: "hello", Version: djtp.Version, Token: s.DaemonToken, SessionID: sessionID,
		Protocol: protocol, Params: params, Recording: rec, Relay: relay,
	}); err != nil {
		return fail(err)
	}
	// The daemon answers ready or error once the remote side is up. RDP gets
	// longer: after authenticating, Windows logs the user on before the
	// session starts, and a fresh logon can take a minute.
	wait := 30 * time.Second
	if protocol == "rdp" {
		wait = 100 * time.Second
	}
	pd.SetReadDeadline(time.Now().Add(wait))
	f, err := djtp.ReadFrame(pd)
	if err != nil {
		return fail(fmt.Errorf("waiting for duckjumpd: %w", err))
	}
	pd.SetReadDeadline(time.Time{})
	first, err := djtp.DecodeControl(f)
	if err != nil || f.Kind != djtp.KindControl {
		return fail(errors.New("protocol error from duckjumpd"))
	}
	if first.Type == "error" && first.Code == "host_key_unknown" {
		return fail(s.unverifiedHostKey(ctx, c, p, first.Message, log))
	}
	if first.Type == "error" {
		return fail(&sessionError{Code: first.Code, Message: first.Message})
	}
	if first.Type != "ready" {
		return fail(fmt.Errorf("unexpected %q from duckjumpd", first.Type))
	}
	if first.HostKeyFingerprint != nil && !c.HostKey.Valid && s.TrustOnFirstUse {
		log.Info("pinning host key (trust on first use)", "fingerprint", *first.HostKeyFingerprint)
		if err := s.Store.Q.PinHostKey(ctx, db.PinHostKeyParams{ID: c.ID, HostKey: store.NullString(*first.HostKeyFingerprint)}); err != nil {
			log.Error("pinning host key", "err", err)
		}
	}
	return pd, siteName, nil
}

// sshParams are the DJTP parameters of an SSH (or SFTP) session.
func (s *Server) sshParams(c db.ConfigConnection, cr sessionCreds, cols, rows int) djtp.SSHParams {
	authp := djtp.SSHAuth{Method: "password", Password: cr.Password}
	if cr.PrivateKey != "" {
		authp = djtp.SSHAuth{Method: "private_key", Key: cr.PrivateKey}
	}
	sp := djtp.SSHParams{
		Host: c.Host, Port: int(c.Port), Username: cr.Username, Auth: authp,
		Term: "xterm-256color", Cols: cols, Rows: rows, TrustUnknown: s.TrustOnFirstUse,
	}
	if c.HostKey.Valid {
		sp.HostKey = &c.HostKey.String
	}
	return sp
}

func sendJSON(ctx context.Context, ws *websocket.Conn, v any) {
	b, _ := json.Marshal(v)
	ws.Write(ctx, websocket.MessageText, b)
}

// sizeParam reads a desktop dimension in pixels (RDP sessions).
func sizeParam(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 200 || n > 8192 {
		return def
	}
	return n
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 1000 {
		return def
	}
	return n
}

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
