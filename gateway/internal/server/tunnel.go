package server

import (
	"context"
	"crypto/rand"
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

	"github.com/leandrofus/palta/gateway/internal/ptp"
	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
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
	if conn.Backend != "paltad" {
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
	ws.SetReadLimit(ptp.MaxFrameLen)

	sessionID := randomID(16)
	log := slog.With("session", sessionID, "user", p.User.Username, "conn", conn.Name)
	prompted := r.URL.Query().Get("credentials") == "1"
	reason, err := s.runSession(ctx, ws, conn, p, sessionID, cols, rows, prompted, log)
	if err != nil {
		log.Warn("session ended with error", "err", err)
		msg := map[string]string{"type": "error", "message": err.Error()}
		var se *sessionError
		if errors.As(err, &se) {
			msg["code"], msg["message"] = se.Code, se.Message
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
type sessionError struct{ Code, Message string }

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
			return sessionCreds{}, &sessionError{"bad_request", "this connection uses a vaulted credential"}
		}
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		typ, data, err := ws.Read(rctx)
		if err != nil || typ != websocket.MessageText {
			return sessionCreds{}, errors.New("expected the credentials message")
		}
		var m struct{ Type, Username, Password, Domain string }
		if json.Unmarshal(data, &m) != nil || m.Type != "credentials" || len(m.Username) > 256 || len(m.Password) > 1024 || len(m.Domain) > 256 {
			return sessionCreds{}, &sessionError{"bad_request", "invalid credentials message"}
		}
		return sessionCreds{Username: strings.TrimSpace(m.Username), Password: m.Password, Domain: strings.TrimSpace(m.Domain), Source: "prompt"}, nil
	}
	if c.SecretID.Valid {
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
	// No credential at all: SSH can't go further, and "prompt" connections
	// always ask. RDP and VNC try without (login screen / no-password server).
	if c.CredentialMode == "prompt" || c.Protocol == "ssh" {
		return sessionCreds{}, &sessionError{"credentials_required", "this connection needs your credentials"}
	}
	return sessionCreds{Source: "none"}, nil
}

func (s *Server) runSession(ctx context.Context, ws *websocket.Conn, c db.ConfigConnection, p principal,
	sessionID string, cols, rows int, prompted bool, log *slog.Logger) (string, error) {

	cr, err := s.resolveCreds(ctx, ws, c, prompted)
	if err != nil {
		return "", err
	}
	var params any
	switch c.Protocol {
	case "ssh":
		authp := ptp.SSHAuth{Method: "password", Password: cr.Password}
		if cr.PrivateKey != "" {
			authp = ptp.SSHAuth{Method: "private_key", Key: cr.PrivateKey}
		}
		sp := ptp.SSHParams{
			Host: c.Host, Port: int(c.Port), Username: cr.Username, Auth: authp,
			Term: "xterm-256color", Cols: cols, Rows: rows,
		}
		if c.HostKey.Valid {
			sp.HostKey = &c.HostKey.String
		}
		params = sp
	case "vnc":
		vp := ptp.VNCParams{Host: c.Host, Port: int(c.Port)}
		if cr.Password != "" {
			pw := cr.Password
			vp.Password = &pw
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
		rp := ptp.RDPParams{Host: c.Host, Port: int(c.Port), Username: cr.Username, Password: cr.Password,
			Domain: extra.Domain, Security: extra.Security, Width: cols, Height: rows}
		if c.HostKey.Valid {
			rp.CertFingerprint = &c.HostKey.String
		}
		params = rp
	}
	var relay *ptp.Relay
	siteName := ""
	if c.SiteID.Valid {
		site, err := s.Store.Q.GetSite(ctx, c.SiteID.String)
		if err != nil {
			return "", fmt.Errorf("loading site: %w", err)
		}
		siteName = site.Name
		if site.Kind == "agent" {
			tk, err := s.Hub.Ticket(site.ID, c.Host, int(c.Port), sessionID)
			if err != nil {
				return "", fmt.Errorf("site %s: %w", site.Name, err)
			}
			relay = &ptp.Relay{Addr: s.RelayAddr, Ticket: tk}
			log = log.With("site", site.Name)
		}
	}
	var rec *ptp.Recording
	recName := ""
	if c.Record {
		recName = sessionID
		rec = &ptp.Recording{Name: recName, IncludeInput: c.RecordInput}
	}

	d := net.Dialer{Timeout: 5 * time.Second}
	pd, err := d.DialContext(ctx, "tcp", s.PaltadAddr)
	if err != nil {
		return "", fmt.Errorf("paltad unreachable: %w", err)
	}
	defer pd.Close()

	if err := ptp.WriteControl(pd, ptp.Control{
		Type: "hello", Version: ptp.Version, Token: s.PaltadToken, SessionID: sessionID,
		Protocol: c.Protocol, Params: params, Recording: rec, Relay: relay,
	}); err != nil {
		return "", err
	}

	// The daemon answers ready or error once the remote side is up. RDP gets
	// longer: after authenticating, Windows logs the user on before the
	// session starts, and a fresh logon can take a minute.
	wait := 30 * time.Second
	if c.Protocol == "rdp" {
		wait = 100 * time.Second
	}
	pd.SetReadDeadline(time.Now().Add(wait))
	f, err := ptp.ReadFrame(pd)
	if err != nil {
		return "", fmt.Errorf("waiting for paltad: %w", err)
	}
	pd.SetReadDeadline(time.Time{})
	first, err := ptp.DecodeControl(f)
	if err != nil || f.Kind != ptp.KindControl {
		return "", errors.New("protocol error from paltad")
	}
	if first.Type == "error" {
		return "", &sessionError{first.Code, first.Message}
	}
	if first.Type != "ready" {
		return "", fmt.Errorf("unexpected %q from paltad", first.Type)
	}
	if first.HostKeyFingerprint != nil && !c.HostKey.Valid {
		log.Info("pinning host key (trust on first use)", "fingerprint", *first.HostKeyFingerprint)
		if err := s.Store.Q.PinHostKey(ctx, db.PinHostKeyParams{ID: c.ID, HostKey: store.NullString(*first.HostKeyFingerprint)}); err != nil {
			log.Error("pinning host key", "err", err)
		}
	}

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
	reason := "closed"
	defer func() {
		ctx := context.WithoutCancel(ctx)
		s.Store.Q.EndSessionRecord(ctx, db.EndSessionRecordParams{ID: sessionID, EndReason: reason, Now: store.NullTime(store.Now())})
		s.Store.AuditTx(ctx, store.Event{Actor: p.actor(), Action: "session.end", ObjectType: "session", ObjectID: sessionID,
			Details: map[string]any{"reason": reason}})
	}()
	log.Info("session started")
	sendJSON(ctx, ws, map[string]any{"type": "ready", "session_id": sessionID})

	// paltad -> browser. When the daemon side ends, closing the WebSocket
	// unblocks the read loop below with a proper close frame.
	down := make(chan string, 1)
	go func() {
		var why string
		defer func() {
			down <- why
			ws.Close(websocket.StatusNormalClosure, why)
		}()
		for {
			f, err := ptp.ReadFrame(pd)
			if err != nil {
				why = "daemon closed"
				return
			}
			switch f.Kind {
			case ptp.KindOutput:
				if ws.Write(ctx, websocket.MessageBinary, f.Payload) != nil {
					why = "client gone"
					return
				}
			case ptp.KindDisplay:
				// Graphical sessions: binary messages carry the frame kind first.
				if ws.Write(ctx, websocket.MessageBinary, append([]byte{ptp.KindDisplay}, f.Payload...)) != nil {
					why = "client gone"
					return
				}
			case ptp.KindControl:
				ws.Write(ctx, websocket.MessageText, f.Payload)
				if c, _ := ptp.DecodeControl(f); c.Type == "exit" || c.Type == "error" {
					why = c.Type
					return
				}
			}
		}
	}()

	// browser -> paltad
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			select {
			case reason = <-down:
			default:
				reason = "client disconnected"
				ptp.WriteControl(pd, ptp.Control{Type: "close"})
			}
			return reason, nil
		}
		switch typ {
		case websocket.MessageBinary:
			if !graphical(c.Protocol) {
				err = ptp.WriteFrame(pd, ptp.KindInput, data)
			} else if len(data) > 1 && data[0] == ptp.KindInputEvent {
				err = ptp.WriteFrame(pd, ptp.KindInputEvent, data[1:])
			} // anything else from the browser is dropped
		case websocket.MessageText:
			var m struct {
				Type       string
				Cols, Rows int
				Text       string
			}
			if json.Unmarshal(data, &m) != nil {
				break
			}
			switch {
			case m.Type == "resize" && m.Cols > 0 && m.Rows > 0:
				err = ptp.WriteControl(pd, ptp.Control{Type: "resize", Cols: m.Cols, Rows: m.Rows})
			case m.Type == "clipboard" && graphical(c.Protocol) && len(m.Text) <= 1<<20:
				err = ptp.WriteControl(pd, ptp.Control{Type: "clipboard", Text: m.Text})
			}
		}
		if err != nil {
			return "daemon write failed", nil
		}
	}
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
