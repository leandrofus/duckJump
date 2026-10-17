package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
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

// openapi:operation
// summary: Open a TCP port-forwarding tunnel (WebSocket)
// description: >-
//   Upgrades to a WebSocket carrying binary TCP streams to the destination.
//   Destination is the connection's host:port, optionally overridden with a port
//   whitelisted in connection params.
// tags: [sessions]
// parameters:
//   - { name: id, in: path, required: true, schema: { type: string }, description: Connection ID or name }
//   - { name: port, in: query, schema: { type: integer }, description: 'Target port, if allowed by connection allow_ports.' }
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
				Details:    map[string]any{"name": conn.Name, "protocol": "tcp"},
			})
			return errForbidden
		}
	}

	targetHost := conn.Host
	targetPort := int(conn.Port)
	if qPort := r.URL.Query().Get("port"); qPort != "" {
		if pVal, err := strconv.Atoi(qPort); err == nil && pVal > 0 && pVal <= 65535 {
			var extra struct {
				AllowPorts []int `json:"allow_ports"`
			}
			_ = json.Unmarshal([]byte(conn.Params), &extra)
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
		log.Warn("tcp forward dial failed", "err", err)
		ws.Close(websocket.StatusInternalError, fmt.Sprintf("dial %s:%d failed: %v", targetHost, targetPort, err))
		return nil
	}
	defer target.Close()

	startTime := time.Now()
	snap, _ := json.Marshal(map[string]any{
		"id": conn.ID, "name": conn.Name, "protocol": "tcp", "host": targetHost, "port": targetPort,
		"site": siteName,
	})
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
				"protocol":      "tcp",
				"target":        net.JoinHostPort(targetHost, strconv.Itoa(targetPort)),
			},
		})
	})
	_ = s.Store.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: sessionID, Node: s.node(), Now: store.Now()})

	wsConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer wsConn.Close()

	var sent, recv atomic.Int64
	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(target, &countingReader{r: wsConn, n: &sent})
		if tcpConn, ok := target.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errc <- err
	}()

	go func() {
		_, err := io.Copy(wsConn, &countingReader{r: target, n: &recv})
		errc <- err
	}()

	reason := "closed"
	select {
	case <-ctx.Done():
		var term *terminated
		if errors.As(context.Cause(ctx), &term) {
			reason = term.reason
			log.Info("tcp session terminated", "reason", reason)
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
	s.Store.AuditTx(auditCtx, store.Event{
		Actor:      p.actor(),
		Action:     "session.end",
		ObjectType: "session",
		ObjectID:   sessionID,
		Details: map[string]any{
			"connection":     conn.Name,
			"protocol":       "tcp",
			"duration_s":     dur,
			"bytes_sent":     sent.Load(),
			"bytes_received": recv.Load(),
			"reason":         reason,
		},
	})

	ws.Close(websocket.StatusNormalClosure, reason)
	return nil
}
