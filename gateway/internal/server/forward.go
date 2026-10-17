package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.n != nil {
		c.n.Add(int64(n))
	}
	return n, err
}

type countingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 && c.n != nil {
		c.n.Add(int64(n))
	}
	return n, err
}

// openapi:operation
// summary: Open a TCP/HTTP port-forwarding tunnel (WebSocket)
// description: >-
//   Upgrades to a WebSocket carrying binary TCP streams to the destination.
//   Destination is the connection's host:port, optionally overridden with a port
//   whitelisted in connection params. For HTTP/HTTPS connections or when requested,
//   automatically injects the configured or query-specified virtual host (Host header).
// tags: [sessions]
// parameters:
//   - { name: id, in: path, required: true, schema: { type: string }, description: Connection ID or name }
//   - { name: port, in: query, schema: { type: integer }, description: 'Target port, if allowed by connection allow_ports.' }
//   - { name: vhost, in: query, schema: { type: string }, description: 'Virtual host header to inject for HTTP virtual servers.' }
// responses:
//   '101': { description: Switching to the WebSocket protocol }
//   '403': Error
//   '404': Error

func (s *Server) forwardTunnel(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	connID := r.PathValue("id")
	conn, err := s.Store.Q.GetConnection(ctx, connID)
	if err != nil {
		// Try resolving by name
		cByName, err2 := s.Store.Q.GetConnectionByName(ctx, connID)
		if err2 == nil {
			conn = cByName
		} else {
			return fromStore(err, "connection")
		}
	}

	if !p.Dev {
		allowed, err := s.Store.CanForward(ctx, p.User.ID, conn.ID)
		if err != nil {
			return err
		}
		if !allowed {
			s.Store.AuditTx(ctx, store.Event{
				Actor:      p.actor(),
				Action:     "session.denied",
				ObjectType: "connection",
				ObjectID:   conn.ID,
				Details:    map[string]any{"name": conn.Name, "protocol": conn.Protocol},
			})
			return errForbidden
		}
	}

	targetHost := conn.Host
	targetPort := int(conn.Port)
	if targetPort == 0 {
		if conn.Protocol == "https" {
			targetPort = 443
		} else if conn.Protocol == "http" {
			targetPort = 80
		}
	}

	var extra struct {
		AllowPorts  []int  `json:"allow_ports"`
		VirtualHost string `json:"virtual_host"`
		HTTPHost    string `json:"http_host"`
	}
	_ = json.Unmarshal([]byte(conn.Params), &extra)

	if qPort := r.URL.Query().Get("port"); qPort != "" {
		if pVal, err := strconv.Atoi(qPort); err == nil && pVal > 0 && pVal <= 65535 {
			if len(extra.AllowPorts) > 0 {
				allowed := false
				for _, ap := range extra.AllowPorts {
					if ap == pVal {
						allowed = true
						break
					}
				}
				if !allowed {
					return badRequest("port %d is not allowed for connection %s", pVal, conn.Name)
				}
			}
			targetPort = pVal
		}
	}

	vhost := r.URL.Query().Get("vhost")
	if vhost == "" {
		vhost = extra.VirtualHost
	}
	if vhost == "" {
		vhost = extra.HTTPHost
	}
	if vhost == "" && (conn.Protocol == "http" || conn.Protocol == "https") {
		vhost = targetHost
		if (conn.Protocol == "http" && targetPort != 80) || (conn.Protocol == "https" && targetPort != 443) {
			vhost = net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
		}
	}

	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil
	}
	defer ws.CloseNow()

	sessionID := randomID(16)
	log := slog.With("session", sessionID, "user", p.User.Username, "conn", conn.Name, "target", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	ls := &liveSession{
		id:       sessionID,
		userID:   p.User.ID,
		username: p.User.Username,
		connID:   conn.ID,
		conn:     conn,
		cancel:   cancel,
		empty:    make(chan struct{}, 1),
	}
	s.live.add(ls)
	defer s.live.remove(sessionID)

	var target net.Conn
	var siteName string
	if conn.SiteID.Valid {
		st, _ := s.Store.Q.GetSite(ctx, conn.SiteID.String)
		siteName = st.Name
		if s.Hub != nil {
			target, err = s.Hub.Dial(conn.SiteID.String, targetHost, targetPort, sessionID)
		} else {
			err = fmt.Errorf("edge hub is not active")
		}
	} else {
		target, err = net.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), 10*time.Second)
	}
	if err != nil {
		log.Warn("forward dial failed", "err", err)
		ws.Close(websocket.StatusInternalError, fmt.Sprintf("dial %s:%d failed: %v", targetHost, targetPort, err))
		return nil
	}
	defer target.Close()

	if conn.Protocol == "https" {
		vhostHost := vhost
		if h, _, err := net.SplitHostPort(vhost); err == nil {
			vhostHost = h
		}
		tlsConn := tls.Client(target, &tls.Config{InsecureSkipVerify: true, ServerName: vhostHost})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			log.Warn("https tls handshake failed", "err", err)
			ws.Close(websocket.StatusInternalError, fmt.Sprintf("tls handshake %s:%d failed: %v", targetHost, targetPort, err))
			return nil
		}
		target = tlsConn
	}

	startTime := time.Now()
	auditDetails := map[string]any{
		"id": conn.ID, "name": conn.Name, "protocol": conn.Protocol, "host": targetHost, "port": targetPort,
		"site": siteName,
	}
	if vhost != "" {
		auditDetails["virtual_host"] = vhost
	}
	snap, _ := json.Marshal(auditDetails)
	_ = s.tx(ctx, func(q *db.Queries) error {
		if err := q.StartSessionRecord(ctx, db.StartSessionRecordParams{
			ID:                 sessionID,
			UserID:             store.NullString(p.User.ID),
			Username:           p.User.Username,
			ConnectionID:       conn.ID,
			ConnectionSnapshot: string(snap),
			Site:               siteName,
			ClientIP:           p.IP,
			Now:                store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      p.actor(),
			Action:     "session.start",
			ObjectType: "session",
			ObjectID:   sessionID,
			Details: map[string]any{
				"connection_id": conn.ID,
				"connection":    conn.Name,
				"protocol":      conn.Protocol,
				"target":        net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
				"virtual_host":  vhost,
			},
		})
	})
	_ = s.Store.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: sessionID, Node: s.node(), Now: store.Now()})

	wsConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer wsConn.Close()

	var sent, recv atomic.Int64
	errc := make(chan error, 1)

	isHTTP := conn.Protocol == "http" || conn.Protocol == "https" || vhost != ""
	if isHTTP {
		protoScheme := "http"
		if conn.Protocol == "https" {
			protoScheme = "https"
		}
		go func() {
			errc <- proxyHTTPStream(ctx, wsConn, target, vhost, protoScheme, &sent, &recv, log)
		}()
	} else {
		go func() {
			errc <- copyBidirectional(ctx, wsConn, target, &sent, &recv)
		}()
	}

	reason := "closed"
	select {
	case <-ctx.Done():
		var term *terminated
		if errors.As(context.Cause(ctx), &term) {
			reason = term.reason
			log.Info("forward session terminated", "reason", reason)
		} else {
			reason = "context done"
		}
	case err := <-errc:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			reason = fmt.Sprintf("error: %v", err)
		}
	}

	dur := time.Since(startTime).Seconds()
	auditCtx := context.WithoutCancel(ctx)
	_ = s.Store.Q.ForgetSession(auditCtx, sessionID)
	_ = s.Store.Q.EndSessionRecord(auditCtx, db.EndSessionRecordParams{
		ID:        sessionID,
		EndReason: reason,
		Now:       store.NullTime(store.Now()),
	})
	endDetails := map[string]any{
		"connection":     conn.Name,
		"protocol":       conn.Protocol,
		"duration_s":     dur,
		"bytes_sent":     sent.Load(),
		"bytes_received": recv.Load(),
		"reason":         reason,
	}
	if vhost != "" {
		endDetails["virtual_host"] = vhost
	}
	s.Store.AuditTx(auditCtx, store.Event{
		Actor:      p.actor(),
		Action:     "session.end",
		ObjectType: "session",
		ObjectID:   sessionID,
		Details:    endDetails,
	})

	ws.Close(websocket.StatusNormalClosure, reason)
	return nil
}

func copyBidirectional(ctx context.Context, wsConn, target net.Conn, sent, recv *atomic.Int64) error {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, &countingReader{r: wsConn, n: sent})
		if tcpConn, ok := target.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(wsConn, &countingReader{r: target, n: recv})
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func proxyHTTPStream(ctx context.Context, wsConn, target net.Conn, vhost, scheme string, sent, recv *atomic.Int64, log *slog.Logger) error {
	br := bufio.NewReader(wsConn)
	tr := bufio.NewReader(target)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Peek to detect EOF or client disconnection
		if _, err := br.Peek(1); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			log.Debug("failed to parse HTTP request, falling back to bidirectional copy", "err", err)
			return copyBidirectional(ctx, wsConn, target, sent, recv)
		}

		origHost := req.Host
		if vhost != "" {
			req.Host = vhost
			req.Header.Set("Host", vhost)
		}
		if origHost != "" {
			req.Header.Set("X-Forwarded-Host", origHost)
		}
		if req.Header.Get("X-Forwarded-For") == "" {
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", scheme)
		}

		isWebSocket := strings.EqualFold(req.Header.Get("Upgrade"), "websocket")

		cwSent := &countingWriter{w: target, n: sent}
		if err := req.Write(cwSent); err != nil {
			return err
		}

		resp, err := http.ReadResponse(tr, req)
		if err != nil {
			return err
		}

		// Rewrite redirect Location header back to origHost so the client browser stays on the local address
		if loc := resp.Header.Get("Location"); loc != "" && origHost != "" && vhost != "" {
			vhostBare := vhost
			if h, _, err := net.SplitHostPort(vhost); err == nil {
				vhostBare = h
			}
			for _, pfx := range []string{
				"http://" + vhost,
				"https://" + vhost,
				"http://" + vhostBare,
				"https://" + vhostBare,
			} {
				if strings.HasPrefix(loc, pfx) {
					resp.Header.Set("Location", "http://"+origHost+strings.TrimPrefix(loc, pfx))
					break
				}
			}
		}

		cwRecv := &countingWriter{w: wsConn, n: recv}
		if err := resp.Write(cwRecv); err != nil {
			return err
		}

		if isWebSocket && resp.StatusCode == http.StatusSwitchingProtocols {
			return copyBidirectional(ctx, wsConn, target, sent, recv)
		}

		if resp.Close || req.Close {
			return nil
		}
	}
}

// openapi:operation
// summary: Direct HTTP Reverse Proxy to target connection
// description: >-
//   Reverse proxies HTTP requests directly to the target connection with automatic
//   virtual host injection and PAM audit logging.
// tags: [sessions]
// parameters:
//   - { name: id, in: path, required: true, schema: { type: string }, description: Connection ID or name }
// responses:
//   '200': { description: Proxied HTTP response }
//   '403': Error
//   '404': Error

func (s *Server) httpProxy(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	connID := r.PathValue("id")
	conn, err := s.Store.Q.GetConnection(ctx, connID)
	if err != nil {
		cByName, err2 := s.Store.Q.GetConnectionByName(ctx, connID)
		if err2 == nil {
			conn = cByName
		} else {
			return fromStore(err, "connection")
		}
	}

	if !p.Dev {
		allowed, err := s.Store.CanForward(ctx, p.User.ID, conn.ID)
		if err != nil {
			return err
		}
		if !allowed {
			s.Store.AuditTx(ctx, store.Event{
				Actor:      p.actor(),
				Action:     "session.denied",
				ObjectType: "connection",
				ObjectID:   conn.ID,
				Details:    map[string]any{"name": conn.Name, "protocol": conn.Protocol},
			})
			return errForbidden
		}
	}

	targetHost := conn.Host
	targetPort := int(conn.Port)
	if targetPort == 0 {
		if conn.Protocol == "https" {
			targetPort = 443
		} else {
			targetPort = 80
		}
	}

	var extra struct {
		VirtualHost string `json:"virtual_host"`
		HTTPHost    string `json:"http_host"`
	}
	_ = json.Unmarshal([]byte(conn.Params), &extra)

	vhost := r.URL.Query().Get("vhost")
	if vhost == "" {
		vhost = extra.VirtualHost
	}
	if vhost == "" {
		vhost = extra.HTTPHost
	}
	if vhost == "" {
		vhost = targetHost
		if (conn.Protocol == "http" && targetPort != 80) || (conn.Protocol == "https" && targetPort != 443) {
			vhost = net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
		}
	}

	scheme := "http"
	if conn.Protocol == "https" {
		scheme = "https"
	}

	targetURL, _ := url.Parse(fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(targetHost, strconv.Itoa(targetPort))))

	prefix := fmt.Sprintf("/api/v1/connections/%s/http", connID)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	if conn.SiteID.Valid && s.Hub != nil {
		proxy.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.Hub.Dial(conn.SiteID.String, targetHost, targetPort, randomID(16))
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: vhost},
		}
	} else if conn.Protocol == "https" {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: vhost},
		}
	}

	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		origPath := req.URL.Path
		if strings.HasPrefix(origPath, prefix) {
			req.URL.Path = strings.TrimPrefix(origPath, prefix)
			if !strings.HasPrefix(req.URL.Path, "/") {
				req.URL.Path = "/" + req.URL.Path
			}
		}
		req.Host = vhost
		req.Header.Set("Host", vhost)
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Proto", scheme)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if loc := resp.Header.Get("Location"); loc != "" {
			if strings.HasPrefix(loc, "/") {
				resp.Header.Set("Location", prefix+loc)
			} else {
				vhostBare := vhost
				if h, _, err := net.SplitHostPort(vhost); err == nil {
					vhostBare = h
				}
				for _, pfx := range []string{
					"http://" + vhost,
					"https://" + vhost,
					"http://" + vhostBare,
					"https://" + vhostBare,
				} {
					if strings.HasPrefix(loc, pfx) {
						resp.Header.Set("Location", prefix+strings.TrimPrefix(loc, pfx))
						break
					}
				}
			}
		}
		return nil
	}

	proxy.ServeHTTP(w, r)
	return nil
}
