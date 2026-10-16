package edge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
)

const ticketTTL = 30 * time.Second

var ErrNoAgent = errors.New("no edge agent connected for this site")

// Hub tracks connected agents and relays duckjumpd connections through them.
//
// duckjumpd never talks to agents directly: the gateway hands it a one-time
// ticket in Hello, duckjumpd presents it on the relay listener, and the hub
// opens a stream to an agent of the ticket's site for exactly the host and
// port the ticket names.
type Hub struct {
	// lookup maps an agent token hash to its site. Kept as a function so the
	// agent binary does not link the store.
	lookup SiteLookup

	mu      sync.Mutex
	agents  map[string][]*agentConn // by site id
	next    map[string]int          // round-robin cursor
	tickets map[string]ticket
}

type agentConn struct {
	name      string
	remote    string
	connected time.Time
	sess      *yamux.Session
}

// AgentInfo describes a live agent connection.
type AgentInfo struct {
	Name        string
	Remote      string
	ConnectedAt time.Time
}

// Agents lists the agents of a site connected to this gateway.
func (h *Hub) Agents(site string) []AgentInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AgentInfo, 0, len(h.agents[site]))
	for _, a := range h.agents[site] {
		out = append(out, AgentInfo{a.name, a.remote, a.connected})
	}
	return out
}

// DisconnectSite drops every agent of a site (token rotated, site deleted).
func (h *Hub) DisconnectSite(site string) {
	h.mu.Lock()
	list := append([]*agentConn(nil), h.agents[site]...)
	h.mu.Unlock()
	for _, a := range list {
		a.sess.Close()
	}
}

type ticket struct {
	site    string
	host    string
	port    int
	session string
	expires time.Time
}

// SiteLookup returns the agent site whose token hashes to tokenHash.
type SiteLookup func(ctx context.Context, tokenHash string) (id, name string, err error)

func NewHub(lookup SiteLookup) *Hub {
	return &Hub{lookup: lookup, agents: map[string][]*agentConn{}, next: map[string]int{}, tickets: map[string]ticket{}}
}

func HashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func NewToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return "pat_" + hex.EncodeToString(b)
}

// ServeAgent handles GET /agent/connect.
func (h *Hub) ServeAgent(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	siteID, siteName, err := h.lookup(r.Context(), HashToken(tok))
	if err != nil {
		slog.Warn("agent rejected", "remote", r.RemoteAddr, "err", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Agents are not browsers; the token is the authentication.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, err := yamux.Client(websocket.NetConn(ctx, ws, websocket.MessageBinary), yamuxConfig())
	if err != nil {
		ws.Close(websocket.StatusInternalError, "yamux")
		return
	}
	ac := &agentConn{name: r.Header.Get("X-DuckJump-Agent"), remote: r.RemoteAddr, connected: time.Now(), sess: sess}
	log := slog.With("site", siteName, "agent", ac.name, "remote", ac.remote)
	h.add(siteID, ac)
	log.Info("agent connected")
	<-sess.CloseChan()
	h.remove(siteID, ac)
	log.Info("agent disconnected")
}

func (h *Hub) add(site string, ac *agentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.agents[site] = append(h.agents[site], ac)
}

func (h *Hub) remove(site string, ac *agentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	list := h.agents[site]
	for i, a := range list {
		if a == ac {
			h.agents[site] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

// Connected reports how many agents of a site are online.
func (h *Hub) Connected(site string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.agents[site])
}

// Ticket authorizes one relayed connection to host:port through site.
func (h *Hub) Ticket(site string, host string, port int, session string) (string, error) {
	if h.Connected(site) == 0 {
		return "", ErrNoAgent
	}
	b := make([]byte, 24)
	rand.Read(b)
	id := hex.EncodeToString(b)
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	for k, t := range h.tickets {
		if now.After(t.expires) {
			delete(h.tickets, k)
		}
	}
	h.tickets[id] = ticket{site: site, host: host, port: port, session: session, expires: now.Add(ticketTTL)}
	return id, nil
}

func (h *Hub) redeem(id string) (ticket, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.tickets[id]
	delete(h.tickets, id)
	return t, ok && time.Now().Before(t.expires)
}

// dial opens a stream to host:port through one of the site's agents,
// round-robin across those connected.
func (h *Hub) dial(t ticket) (net.Conn, error) {
	h.mu.Lock()
	list := h.agents[t.site]
	if len(list) == 0 {
		h.mu.Unlock()
		return nil, ErrNoAgent
	}
	ac := list[h.next[t.site]%len(list)]
	h.next[t.site]++
	h.mu.Unlock()

	st, err := ac.sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("opening stream to agent %s: %w", ac.name, err)
	}
	st.SetDeadline(time.Now().Add(20 * time.Second))
	if err := writeJSONLine(st, dialRequest{Host: t.host, Port: t.port, Session: t.session}); err != nil {
		st.Close()
		return nil, err
	}
	if err := readStatus(st); err != nil {
		st.Close()
		return nil, fmt.Errorf("agent %s: %w", ac.name, err)
	}
	st.SetDeadline(time.Time{})
	slog.Info("edge dial", "agent", ac.name, "target", net.JoinHostPort(t.host, fmt.Sprint(t.port)), "session", t.session)
	return st, nil
}

// ServeRelay accepts duckjumpd connections: "<ticket>\n", answered with
// "ok\n" or "err <reason>\n", then raw bytes to the target.
func (h *Hub) ServeRelay(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go h.relay(c)
	}
}

func (h *Hub) relay(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	id, err := readLine(c)
	if err != nil {
		return
	}
	t, ok := h.redeem(id)
	if !ok {
		writeLine(c, "err invalid or expired ticket")
		slog.Warn("relay: bad ticket", "remote", c.RemoteAddr())
		return
	}
	up, err := h.dial(t)
	if err != nil {
		writeLine(c, "err "+err.Error())
		slog.Warn("relay: dial failed", "session", t.session, "err", err)
		return
	}
	defer up.Close()
	if writeLine(c, "ok") != nil {
		return
	}
	c.SetDeadline(time.Time{})
	pipe(c, up)
}

// pipe copies both ways until either side is done.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.KeepAliveInterval = 15 * time.Second
	return cfg
}
