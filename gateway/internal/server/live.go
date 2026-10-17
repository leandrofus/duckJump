package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Access is checked when a session opens and then kept checked while it
// runs: a session ends when its grant expires or is revoked, when its user
// is disabled or deleted, or when an admin terminates it.

// SuperviseInterval is how often live sessions are re-checked. Changes made
// through the API re-check at once; this bounds the delay for grants that
// simply expire and for kill requests from other processes (the CLI).
const SuperviseInterval = 10 * time.Second

// staleAfter: a session whose heartbeat is older than this is considered
// lost (its gateway stopped) and closed by whichever gateway notices.
const staleAfter = 3 * SuperviseInterval

type wsMessage struct {
	msgType websocket.MessageType
	data    []byte
}

type liveParticipant struct {
	id         string // random client participant id
	userID     string
	username   string
	isOwner    bool
	ws         *websocket.Conn
	sendCh     chan wsMessage
	closedOnce sync.Once
}

func (p *liveParticipant) send(msgType websocket.MessageType, data []byte) {
	select {
	case p.sendCh <- wsMessage{msgType: msgType, data: data}:
	default:
	}
}

func (p *liveParticipant) close() {
	p.closedOnce.Do(func() {
		close(p.sendCh)
	})
}

type shareTokenInfo struct {
	token     string
	createdAt time.Time
	createdBy string
}

type terminalBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func newTerminalBuffer(max int) *terminalBuffer {
	if max <= 0 {
		max = 128 * 1024
	}
	return &terminalBuffer{buf: make([]byte, 0, 4096), max: max}
}

func (tb *terminalBuffer) Write(p []byte) {
	if tb == nil || len(p) == 0 {
		return
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if len(p) >= tb.max {
		tb.buf = append(tb.buf[:0], p[len(p)-tb.max:]...)
		return
	}
	if len(tb.buf)+len(p) > tb.max {
		overflow := (len(tb.buf) + len(p)) - tb.max
		copy(tb.buf, tb.buf[overflow:])
		tb.buf = tb.buf[:len(tb.buf)-overflow]
	}
	tb.buf = append(tb.buf, p...)
}

func (tb *terminalBuffer) Bytes() []byte {
	if tb == nil {
		return nil
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	out := make([]byte, len(tb.buf))
	copy(out, tb.buf)
	return out
}

type liveSession struct {
	id, userID, connID string
	username           string
	conn               db.ConfigConnection
	siteName           string
	notify             func(code, message string) // tells the client why, before the tunnel closes
	cancel             context.CancelCauseFunc

	mu             sync.RWMutex
	pd             net.Conn
	participants   map[string]*liveParticipant
	controllerID   string // participant ID currently having input control
	controllerName string
	shareTokens    map[string]shareTokenInfo
	sshBuffer      *terminalBuffer
	empty          chan struct{}
}

func (ls *liveSession) addParticipant(p *liveParticipant) {
	ls.mu.Lock()
	if ls.participants == nil {
		ls.participants = make(map[string]*liveParticipant)
	}
	ls.participants[p.id] = p
	if ls.controllerID == "" {
		ls.controllerID = p.id
		ls.controllerName = p.username
	}
	count := len(ls.participants)
	ls.mu.Unlock()
	if count > 1 {
		ls.broadcastPresence()
	}
}

func (ls *liveSession) removeParticipant(id string) int {
	ls.mu.Lock()
	p, ok := ls.participants[id]
	if !ok {
		count := len(ls.participants)
		ls.mu.Unlock()
		return count
	}
	delete(ls.participants, id)
	p.close()

	// If controller left, assign control to owner or next participant
	if ls.controllerID == id {
		ls.controllerID = ""
		ls.controllerName = ""
		for _, other := range ls.participants {
			if other.isOwner {
				ls.controllerID = other.id
				ls.controllerName = other.username
				break
			}
		}
		if ls.controllerID == "" {
			for _, other := range ls.participants {
				ls.controllerID = other.id
				ls.controllerName = other.username
				break
			}
		}
	}
	count := len(ls.participants)
	if count == 0 && ls.empty != nil {
		select {
		case ls.empty <- struct{}{}:
		default:
		}
	}
	ls.mu.Unlock()

	if count > 0 {
		ls.broadcastPresence()
	}
	return count
}

func (ls *liveSession) hasControl(participantID string) bool {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.controllerID == participantID
}

func (ls *liveSession) broadcastBinary(data []byte) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	for _, p := range ls.participants {
		p.send(websocket.MessageBinary, data)
	}
}

func (ls *liveSession) broadcastText(data []byte) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	for _, p := range ls.participants {
		p.send(websocket.MessageText, data)
	}
}

func (ls *liveSession) broadcastPresence() {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	type partInfo struct {
		ID         string `json:"id"`
		UserID     string `json:"user_id"`
		Username   string `json:"username"`
		IsOwner    bool   `json:"is_owner"`
		HasControl bool   `json:"has_control"`
	}
	parts := make([]partInfo, 0, len(ls.participants))
	for _, p := range ls.participants {
		parts = append(parts, partInfo{
			ID:         p.id,
			UserID:     p.userID,
			Username:   p.username,
			IsOwner:    p.isOwner,
			HasControl: p.id == ls.controllerID,
		})
	}

	for _, p := range ls.participants {
		msg, _ := json.Marshal(map[string]any{
			"type":            "presence",
			"participants":    parts,
			"controller":      ls.controllerID,
			"controller_name": ls.controllerName,
			"has_control":     p.id == ls.controllerID,
			"my_id":           p.id,
		})
		p.send(websocket.MessageText, msg)
	}
}

func (ls *liveSession) yieldControl(ctx context.Context, fromParticipantID, toParticipantID string, actor store.Actor, q *db.Queries) error {
	ls.mu.Lock()
	from, okFrom := ls.participants[fromParticipantID]
	to, okTo := ls.participants[toParticipantID]
	if !okFrom || !okTo {
		ls.mu.Unlock()
		return errors.New("participant not found")
	}
	// Current controller, session owner, or admin can yield control
	if fromParticipantID != ls.controllerID && !from.isOwner && actor.Name != "root" {
		ls.mu.Unlock()
		return errors.New("not authorized to yield control")
	}
	ls.controllerID = to.id
	ls.controllerName = to.username
	ls.mu.Unlock()

	ls.broadcastPresence()
	ctrlMsg, _ := json.Marshal(map[string]any{
		"type":            "control_granted",
		"controller":      to.id,
		"controller_name": to.username,
	})
	ls.broadcastText(ctrlMsg)

	if q != nil {
		_ = store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "session.control_yield",
			ObjectType: "session",
			ObjectID:   ls.id,
			Details:    map[string]any{"to": to.username, "to_id": to.userID},
		})
	}
	return nil
}

func (ls *liveSession) takeControl(ctx context.Context, participantID string, actor store.Actor, q *db.Queries) error {
	ls.mu.Lock()
	p, ok := ls.participants[participantID]
	if !ok {
		ls.mu.Unlock()
		return errors.New("participant not found")
	}
	if !p.isOwner && actor.Name != "root" {
		ls.mu.Unlock()
		return errors.New("only the owner can reclaim control")
	}
	ls.controllerID = p.id
	ls.controllerName = p.username
	ls.mu.Unlock()

	ls.broadcastPresence()
	ctrlMsg, _ := json.Marshal(map[string]any{
		"type":            "control_granted",
		"controller":      p.id,
		"controller_name": p.username,
	})
	ls.broadcastText(ctrlMsg)

	if q != nil {
		_ = store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "session.control_take",
			ObjectType: "session",
			ObjectID:   ls.id,
		})
	}
	return nil
}

func (ls *liveSession) requestControl(participantID string) {
	ls.mu.RLock()
	p, ok := ls.participants[participantID]
	ctrl, okCtrl := ls.participants[ls.controllerID]
	ls.mu.RUnlock()

	if !ok || !okCtrl {
		return
	}
	msg, _ := json.Marshal(map[string]any{
		"type":      "control_requested",
		"from":      p.id,
		"from_name": p.username,
	})
	ctrl.send(websocket.MessageText, msg)
}

func (ls *liveSession) createShareToken(createdBy string) string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.shareTokens == nil {
		ls.shareTokens = make(map[string]shareTokenInfo)
	}
	tok := randomID(16)
	ls.shareTokens[tok] = shareTokenInfo{
		token:     tok,
		createdAt: time.Now(),
		createdBy: createdBy,
	}
	return tok
}

func (ls *liveSession) activeShareToken() string {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	for tok := range ls.shareTokens {
		return tok
	}
	return ""
}

func (ls *liveSession) validateShareToken(tok string) bool {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	if ls.shareTokens == nil {
		return false
	}
	_, ok := ls.shareTokens[tok]
	return ok
}

func (ls *liveSession) revokeShareTokens() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.shareTokens = make(map[string]shareTokenInfo)
}

func (ls *liveSession) notifyAll(code, reason string) {
	if ls.notify != nil {
		ls.notify(code, reason)
		return
	}
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	msg, _ := json.Marshal(map[string]string{"type": "error", "code": code, "message": reason})
	for _, p := range ls.participants {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = p.ws.Write(ctx, websocket.MessageText, msg)
		cancel()
	}
}

// terminated is the cause a live session's context is cancelled with.
type terminated struct{ reason string }

func (t *terminated) Error() string { return t.reason }

type liveSessions struct {
	mu sync.Mutex
	m  map[string]*liveSession
}

func (l *liveSessions) add(s *liveSession) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*liveSession{}
	}
	l.m[s.id] = s
}

func (l *liveSessions) remove(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, id)
}

func (l *liveSessions) get(id string) *liveSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[id]
}

func (l *liveSessions) list() []*liveSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]*liveSession, 0, len(l.m))
	for _, s := range l.m {
		out = append(out, s)
	}
	return out
}

// terminate ends a live session, telling the client why.
func (s *Server) terminate(ls *liveSession, code, reason string) {
	slog.Info("terminating session", "session", ls.id, "reason", reason)
	ls.notifyAll(code, reason)
	ls.cancel(&terminated{reason})
}

// Supervise re-checks live sessions every SuperviseInterval until ctx ends.
func (s *Server) Supervise(ctx context.Context) {
	t := time.NewTicker(SuperviseInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkLive(ctx)
			s.beat(ctx)
			if err := s.SweepStale(ctx); err != nil && ctx.Err() == nil {
				slog.Error("closing lost sessions", "err", err)
			}
		}
	}
}

// beat refreshes the heartbeat of every live session held here.
func (s *Server) beat(ctx context.Context) {
	for _, ls := range s.live.list() {
		if err := s.Store.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: ls.id, Node: s.node(), Now: store.Now()}); err != nil {
			slog.Error("session heartbeat", "session", ls.id, "err", err)
		}
	}
}

// SweepStale closes open sessions no gateway holds any more (crashed or
// stopped without closing them), on this gateway's database.
func (s *Server) SweepStale(ctx context.Context) error {
	cutoff := store.TS(store.Now().Add(-staleAfter))
	return s.tx(ctx, func(q *db.Queries) error {
		ids, err := q.CloseStaleSessions(ctx, db.CloseStaleSessionsParams{Now: store.NullTime(store.Now()), Cutoff: cutoff})
		if err != nil {
			return err
		}
		for _, id := range ids {
			slog.Warn("closed a session its gateway lost", "session", id)
			if err := store.Audit(ctx, q, store.Event{Actor: store.Actor{Name: "gateway"}, Action: "session.end", ObjectType: "session",
				ObjectID: id, Details: map[string]any{"reason": "lost: the gateway holding it stopped"}}); err != nil {
				return err
			}
		}
		return q.DeleteStaleHeartbeats(ctx, cutoff)
	})
}

// node names this gateway process in heartbeats.
func (s *Server) node() string {
	s.nodeOnce.Do(func() {
		h, _ := os.Hostname()
		s.nodeName = fmt.Sprintf("%s/%d", h, os.Getpid())
	})
	return s.nodeName
}

// revalidate re-checks live sessions now, in the background (after a
// change to users, groups, policies or connections).
func (s *Server) revalidate() {
	go s.checkLive(context.Background())
}

func (s *Server) checkLive(ctx context.Context) {
	s.checkMu.Lock()
	defer s.checkMu.Unlock()
	live := s.live.list()
	if len(live) == 0 {
		return
	}
	kills, err := s.Store.Q.ListSessionKills(ctx)
	if err != nil {
		slog.Error("checking live sessions", "err", err)
		return
	}
	killed := map[string]db.AuditSessionKill{}
	for _, k := range kills {
		killed[k.SessionID] = k
	}
	for _, ls := range live {
		if k, ok := killed[ls.id]; ok {
			msg := "terminated by " + k.RequestedBy
			if k.Reason != "" {
				msg += ": " + k.Reason
			}
			s.terminate(ls, "session_terminated", msg)
			continue
		}
		if ls.userID == "" { // dev mode
			continue
		}
		if why, err := s.stillAllowed(ctx, ls); err != nil {
			slog.Error("checking live session", "session", ls.id, "err", err)
		} else if why != "" {
			s.terminate(ls, "access_revoked", why)
		}
	}
}

// stillAllowed returns why a live session may no longer run ("" if it may).
func (s *Server) stillAllowed(ctx context.Context, ls *liveSession) (string, error) {
	u, err := s.Store.Q.GetUser(ctx, ls.userID)
	if errors.Is(store.Classify(err), store.ErrNotFound) {
		return "the user was deleted", nil
	}
	if err != nil {
		return "", err
	}
	if u.Disabled {
		return "the user was disabled", nil
	}
	ok, err := s.Store.CanConnect(ctx, ls.userID, ls.connID)
	if err != nil {
		return "", err
	}
	if !ok {
		return "access to this connection expired or was revoked", nil
	}
	return "", nil
}

// revalidating re-checks live sessions after admin changes that can take
// access away.
func (s *Server) revalidating(next http.Handler) http.Handler {
	prefixes := []string{"/api/v1/users", "/api/v1/groups", "/api/v1/policies", "/api/v1/connections", "/api/v1/folders"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Method == http.MethodGet || r.Method == http.MethodHead || strings.HasSuffix(r.URL.Path, "/session") || strings.Contains(r.URL.Path, "/files/") {
			return
		}
		for _, p := range prefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				s.revalidate()
				return
			}
		}
	})
}

// openapi:schema TerminateSessionRequest
// type: object
// additionalProperties: false
// properties:
//   reason: { type: string, maxLength: 500, description: Shown to the user and kept in the audit log. }

type terminateRequest struct {
	Reason string `json:"reason"`
}

// openapi:operation
// summary: Terminate a live session
// description: >-
//   Ends an open session now: the user's tunnel closes with the reason. The
//   request is recorded (append-only) and audited; a gateway process holding
//   the session picks it up within seconds even when it is not the one that
//   received the request.
// tags: [audit]
// requestBody: { schema: TerminateSessionRequest, required: false }
// responses:
//   '202': { description: Termination requested }
//   '409': Error

func (s *Server) terminateSession(w http.ResponseWriter, r *http.Request, p principal) error {
	var req terminateRequest
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			return err
		}
	}
	if len(req.Reason) > 500 {
		return badRequest("reason is too long")
	}
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		x, err := q.GetSessionRecord(ctx, id)
		if err != nil {
			return fromStore(err, "session")
		}
		if x.EndedAt.Valid {
			return conflict("the session already ended")
		}
		return RequestKill(ctx, q, id, p.actor(), req.Reason)
	})
	if err != nil {
		return err
	}
	if ls := s.live.get(id); ls != nil {
		msg := "terminated by " + p.User.Username
		if req.Reason != "" {
			msg += ": " + req.Reason
		}
		s.terminate(ls, "session_terminated", msg)
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

// RequestKill records (and audits) a request to end a session. The gateway
// holding it acts on it at its next check.
func RequestKill(ctx context.Context, q *db.Queries, sessionID string, by store.Actor, reason string) error {
	if err := q.RequestSessionKill(ctx, db.RequestSessionKillParams{SessionID: sessionID, Now: store.Now(),
		RequestedBy: by.Name, Reason: reason}); err != nil {
		return fmt.Errorf("recording the kill request: %w", err)
	}
	return store.Audit(ctx, q, store.Event{Actor: by, Action: "session.terminate", ObjectType: "session", ObjectID: sessionID,
		Details: map[string]any{"reason": reason}})
}
