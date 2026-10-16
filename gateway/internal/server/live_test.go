package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/djtp"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// fakeDaemon answers each hello with reply (nil: ready) and then holds the
// session until the gateway closes it. Hellos are sent to the channel.
func fakeDaemon(t *testing.T, reply *djtp.Control) (string, chan djtp.Control) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	hellos := make(chan djtp.Control, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				f, err := djtp.ReadFrame(c)
				if err != nil {
					return
				}
				h, _ := djtp.DecodeControl(f)
				hellos <- h
				if reply != nil {
					djtp.WriteControl(c, *reply)
					return
				}
				djtp.WriteControl(c, djtp.Control{Type: "ready", SessionID: h.SessionID})
				for {
					if _, err := djtp.ReadFrame(c); err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String(), hellos
}

// openSession opens c's session WebSocket on a connection.
func (c *client) openSession(t *testing.T, connID string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u := strings.Replace(c.e.srv.URL, "http", "ws", 1) + "/api/v1/connections/" + connID + "/session"
	hdr := http.Header{}
	for _, ck := range c.http.Jar.Cookies(mustURL(c.e.srv.URL)) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws
}

func readMsg(t *testing.T, ws *websocket.Conn) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("reading the session: %v", err)
		}
		if typ == websocket.MessageText {
			m := map[string]string{}
			json.Unmarshal(data, &m)
			return m
		}
	}
}

// liveEnv: ana holds a grant on a vaulted ssh connection.
func liveEnv(t *testing.T) (e *env, root, ana *client, connID, anaID, policyID string) {
	e = newEnv(t)
	e.server.DaemonAddr, _ = fakeDaemon(t, nil)
	e.mkUser("ana", "user")
	root = e.as("root")
	var sec secretDTO
	root.do("POST", "/secrets", secretRequest{Name: "s", Kind: "password", Username: "u", Value: "p"}, 201, &sec)
	var c connectionDTO
	root.do("POST", "/connections", connectionRequest{Name: "web1", Protocol: "ssh", Host: "h", SecretID: &sec.ID}, 201, &c)
	var users []userDTO
	root.do("GET", "/users", nil, 200, &users)
	for _, u := range users {
		if u.Username == "ana" {
			anaID = u.ID
		}
	}
	var pol policyDTO
	root.do("POST", "/policies", policyRequest{SubjectType: "user", SubjectID: anaID, ObjectType: "connection", ObjectRef: c.ID}, 201, &pol)
	return e, root, e.as("ana"), c.ID, anaID, pol.ID
}

func waitSessionEnd(t *testing.T, e *env, id string) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		x, err := e.st.Q.GetSessionRecord(context.Background(), id)
		if err == nil && x.EndedAt.Valid {
			return x.EndReason.String
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("session record never closed")
	return ""
}

func TestRevokedGrantEndsLiveSession(t *testing.T) {
	e, root, ana, connID, _, policyID := liveEnv(t)
	ws := ana.openSession(t, connID)
	ready := readMsg(t, ws)
	if ready["type"] != "ready" {
		t.Fatalf("got %v", ready)
	}
	root.do("DELETE", "/policies/"+policyID, nil, 204, nil)
	if m := readMsg(t, ws); m["code"] != "access_revoked" {
		t.Fatalf("after revoking the grant: %v", m)
	}
	if r := waitSessionEnd(t, e, ready["session_id"]); !strings.Contains(r, "revoked") {
		t.Fatalf("end reason %q", r)
	}
}

func TestExpiredGrantEndsLiveSession(t *testing.T) {
	e, root, ana, connID, anaID, policyID := liveEnv(t)
	root.do("DELETE", "/policies/"+policyID, nil, 204, nil)
	root.do("POST", "/policies", policyRequest{SubjectType: "user", SubjectID: anaID, ObjectType: "connection", ObjectRef: connID, TTLSeconds: 1}, 201, nil)
	ws := ana.openSession(t, connID)
	if m := readMsg(t, ws); m["type"] != "ready" {
		t.Fatalf("got %v", m)
	}
	time.Sleep(1100 * time.Millisecond)
	e.server.checkLive(context.Background()) // what the supervisor does every SuperviseInterval
	if m := readMsg(t, ws); m["code"] != "access_revoked" {
		t.Fatalf("after the grant expired: %v", m)
	}
}

func TestDisabledUserLosesLiveSession(t *testing.T) {
	_, root, ana, connID, anaID, _ := liveEnv(t)
	ws := ana.openSession(t, connID)
	readMsg(t, ws)
	root.do("PATCH", "/users/"+anaID, map[string]any{"disabled": true}, 200, nil)
	if m := readMsg(t, ws); m["code"] != "access_revoked" || !strings.Contains(m["message"], "disabled") {
		t.Fatalf("after disabling the user: %v", m)
	}
}

func TestTerminateSession(t *testing.T) {
	e, root, ana, connID, _, _ := liveEnv(t)
	ws := ana.openSession(t, connID)
	id := readMsg(t, ws)["session_id"]

	e.as("ana").do("POST", "/audit/sessions/"+id+"/terminate", nil, 403, nil)
	root.do("POST", "/audit/sessions/"+id+"/terminate", terminateRequest{Reason: "incident 42"}, 202, nil)
	if m := readMsg(t, ws); m["code"] != "session_terminated" || !strings.Contains(m["message"], "incident 42") {
		t.Fatalf("got %v", m)
	}
	if r := waitSessionEnd(t, e, id); !strings.Contains(r, "incident 42") {
		t.Fatalf("end reason %q", r)
	}
	root.do("POST", "/audit/sessions/"+id+"/terminate", nil, 409, nil)
	var evs []auditEventDTO
	root.do("GET", "/audit/events?action=session.terminate", nil, 200, &evs)
	if len(evs) != 1 || evs[0].ObjectID != id {
		t.Fatalf("audit: %+v", evs)
	}

	// A request recorded by another process (the CLI) is picked up too.
	ws = ana.openSession(t, connID)
	id = readMsg(t, ws)["session_id"]
	if err := e.st.Tx(context.Background(), func(q *db.Queries) error {
		return RequestKill(context.Background(), q, id, store.Actor{Name: "cli"}, "")
	}); err != nil {
		t.Fatal(err)
	}
	e.server.checkLive(context.Background())
	if m := readMsg(t, ws); m["code"] != "session_terminated" || !strings.Contains(m["message"], "cli") {
		t.Fatalf("got %v", m)
	}
}

func TestUnknownHostKeyNeedsApproval(t *testing.T) {
	e, root, ana, connID, _, _ := liveEnv(t)
	const fp = "SHA256:Zm9vYmFyYmF6cXV4cXV1eGZvb2Jhcg"
	var hellos chan djtp.Control
	e.server.DaemonAddr, hellos = fakeDaemon(t, &djtp.Control{Type: "error", Code: "host_key_unknown", Message: fp})

	m := readMsg(t, ana.openSession(t, connID))
	if m["code"] != "host_key_unverified" || m["fingerprint"] != fp {
		t.Fatalf("got %v", m)
	}
	var h djtp.Control
	select {
	case h = <-hellos:
	case <-time.After(time.Second):
		t.Fatal("no hello")
	}
	b, _ := json.Marshal(h.Params)
	if strings.Contains(string(b), "trust_unknown") {
		t.Fatalf("trust on first use requested by default: %s", b)
	}
	var c connectionDTO
	root.do("GET", "/connections/"+connID, nil, 200, &c)
	if c.HostKey != nil || c.HostKeyPending == nil || *c.HostKeyPending != fp {
		t.Fatalf("pending: %+v", c)
	}

	ana.do("PUT", "/connections/"+connID+"/host-key", approveHostKeyRequest{Fingerprint: fp}, 403, nil)
	root.do("PUT", "/connections/"+connID+"/host-key", approveHostKeyRequest{Fingerprint: "nope"}, 400, nil)
	root.do("PUT", "/connections/"+connID+"/host-key", approveHostKeyRequest{Fingerprint: fp}, 204, nil)
	root.do("GET", "/connections/"+connID, nil, 200, &c)
	if c.HostKey == nil || *c.HostKey != fp || c.HostKeyPending != nil {
		t.Fatalf("approved: %+v", c)
	}
}

func TestClientIPBehindProxies(t *testing.T) {
	trusted, err := ParseProxies("10.0.0.0/8, 127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{TrustedProxies: trusted}
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:5000", "1.2.3.4", "203.0.113.9"},                        // not a proxy: header ignored
		{"127.0.0.1:5000", "198.51.100.7", "198.51.100.7"},                    // one proxy
		{"127.0.0.1:5000", "6.6.6.6, 198.51.100.7, 10.1.1.1", "198.51.100.7"}, // spoofed entry on the left
		{"127.0.0.1:5000", "", "127.0.0.1"},
		{"127.0.0.1:5000", "garbage", "127.0.0.1"},
		{"[::ffff:127.0.0.1]:5000", "198.51.100.7", "198.51.100.7"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s / %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	if !s.secureRequest(r) {
		t.Error("X-Forwarded-Proto from a trusted proxy ignored")
	}
	r.RemoteAddr = "203.0.113.9:1"
	if s.secureRequest(r) {
		t.Error("X-Forwarded-Proto believed from a client")
	}
	if !(&Server{SecureCookies: true}).secureRequest(r) {
		t.Error("SecureCookies not honoured")
	}
}

// Login rate limiting keys on the real client behind a proxy: one client's
// failures do not lock out everybody behind the same proxy.
func TestRateLimitPerClientBehindProxy(t *testing.T) {
	e := newEnv(t)
	e.server.TrustedProxies, _ = ParseProxies("127.0.0.1")
	login := func(client string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"root","password":"wrong-password"}`))
		req.Header.Set(csrfHeader, "1")
		req.Header.Set("X-Forwarded-For", client)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 5; i++ {
		login("198.51.100.1")
	}
	if got := login("198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("attacker not limited: %d", got)
	}
	if got := login("198.51.100.2"); got != http.StatusUnauthorized {
		t.Fatalf("another client behind the proxy locked out: %d", got)
	}
}

// Sessions whose gateway stopped are closed by any gateway; sessions some
// gateway still holds are not.
func TestSweepStaleSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := store.Now().Add(-time.Hour)
	for _, id := range []string{"lost", "held", "young"} {
		started := old
		if id == "young" {
			started = store.Now() // just started; its first heartbeat may not be written yet
		}
		if err := e.st.Q.StartSessionRecord(ctx, db.StartSessionRecordParams{ID: id, Username: "u", ConnectionID: "c",
			ConnectionSnapshot: "{}", Now: started}); err != nil {
			t.Fatal(err)
		}
	}
	e.st.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: "held", Node: "other-gateway", Now: store.Now()})
	e.st.Q.BeatSession(ctx, db.BeatSessionParams{SessionID: "lost", Node: "dead-gateway", Now: old})
	if err := e.server.SweepStale(ctx); err != nil {
		t.Fatal(err)
	}
	for id, wantOpen := range map[string]bool{"lost": false, "held": true, "young": true} {
		x, _ := e.st.Q.GetSessionRecord(ctx, id)
		if x.EndedAt.Valid == wantOpen {
			t.Errorf("%s: ended=%v", id, x.EndedAt.Valid)
		}
	}
	if res, _ := e.st.VerifyAudit(ctx); !res.OK {
		t.Fatalf("audit: %+v", res)
	}
}

func (c *client) joinSession(t *testing.T, sessionID string, query string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u := strings.Replace(c.e.srv.URL, "http", "ws", 1) + "/api/v1/sessions/" + sessionID + "/join"
	if query != "" {
		u += "?" + query
	}
	hdr := http.Header{}
	for _, ck := range c.http.Jar.Cookies(mustURL(c.e.srv.URL)) {
		hdr.Add("Cookie", ck.Name + "=" + ck.Value)
	}
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws
}

func TestSharedSessionAndControlCession(t *testing.T) {
	e, root, ana, connID, _, _ := liveEnv(t)
	wsAna := ana.openSession(t, connID)
	defer wsAna.CloseNow()
	readyAna := readMsg(t, wsAna)
	sessionID := readyAna["session_id"]
	anaPartID := readyAna["my_id"]

	if readyAna["type"] != "ready" || sessionID == "" || anaPartID == "" {
		t.Fatalf("unexpected ready message for ana: %v", readyAna)
	}

	// Ana creates a share token
	var share sessionShareDTO
	ana.do("POST", "/sessions/"+sessionID+"/share", nil, 201, &share)
	if share.ShareToken == "" {
		t.Fatal("empty share token")
	}

	// Info endpoint check
	var info sessionInfoDTO
	ana.do("GET", "/sessions/"+sessionID+"/info", nil, 200, &info)
	if info.SessionID != sessionID || !info.Active {
		t.Fatalf("unexpected session info: %+v", info)
	}

	// Bob joins using the share token
	e.mkUser("bob", "user")
	bob := e.as("bob")
	wsBob := bob.joinSession(t, sessionID, "token="+share.ShareToken)
	defer wsBob.CloseNow()
	readyBob := readMsg(t, wsBob)
	bobPartID := readyBob["my_id"]

	if readyBob["type"] != "ready" || bobPartID == "" {
		t.Fatalf("unexpected ready message for bob: %v", readyBob)
	}
	if readyBob["is_owner"] == "true" {
		t.Fatal("bob should not be owner")
	}

	// Ana and Bob receive presence update
	presAna := readMsg(t, wsAna)
	if presAna["type"] != "presence" || presAna["controller"] != anaPartID {
		t.Fatalf("expected presence with controller ana: %v", presAna)
	}

	presBob := readMsg(t, wsBob)
	if presBob["type"] != "presence" || presBob["controller"] != anaPartID {
		t.Fatalf("expected presence with controller ana: %v", presBob)
	}

	// Ana yields control to Bob
	yieldPayload, _ := json.Marshal(map[string]string{"type": "yield_control", "to": bobPartID})
	if err := wsAna.Write(context.Background(), websocket.MessageText, yieldPayload); err != nil {
		t.Fatal(err)
	}

	// Both should receive control_granted
	msgAna := readMsg(t, wsAna)
	for msgAna["type"] == "presence" {
		msgAna = readMsg(t, wsAna)
	}
	if msgAna["type"] != "control_granted" || msgAna["controller"] != bobPartID {
		t.Fatalf("expected control_granted to bob: %v", msgAna)
	}

	msgBob := readMsg(t, wsBob)
	for msgBob["type"] == "presence" {
		msgBob = readMsg(t, wsBob)
	}
	if msgBob["type"] != "control_granted" || msgBob["controller"] != bobPartID {
		t.Fatalf("expected control_granted to bob: %v", msgBob)
	}

	// Bob requests control (or asks)
	reqPayload, _ := json.Marshal(map[string]string{"type": "request_control"})
	if err := wsAna.Write(context.Background(), websocket.MessageText, reqPayload); err != nil {
		t.Fatal(err)
	}
	reqMsg := readMsg(t, wsBob)
	if reqMsg["type"] != "control_requested" {
		t.Fatalf("expected control_requested message: %v", reqMsg)
	}

	// Ana (owner) takes back control
	takePayload, _ := json.Marshal(map[string]string{"type": "take_control"})
	if err := wsAna.Write(context.Background(), websocket.MessageText, takePayload); err != nil {
		t.Fatal(err)
	}

	takeAna := readMsg(t, wsAna)
	for takeAna["type"] == "presence" {
		takeAna = readMsg(t, wsAna)
	}
	if takeAna["type"] != "control_granted" || takeAna["controller"] != anaPartID {
		t.Fatalf("expected control reclaimed by ana: %v", takeAna)
	}

	// Root can also join directly
	wsRoot := root.joinSession(t, sessionID, "")
	defer wsRoot.CloseNow()
	readyRoot := readMsg(t, wsRoot)
	if readyRoot["type"] != "ready" {
		t.Fatalf("root failed to join: %v", readyRoot)
	}
}
