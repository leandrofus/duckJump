package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func echoServer(t *testing.T) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	tcpAddr := l.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port
}

func (c *client) openForward(t *testing.T, connID string, query string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := strings.Replace(c.e.srv.URL, "http", "ws", 1) + "/api/v1/connections/" + connID + "/forward"
	if query != "" {
		u += "?" + query
	}
	hdr := http.Header{}
	for _, ck := range c.http.Jar.Cookies(mustURL(c.e.srv.URL)) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
}

func TestTCPPortForwarding(t *testing.T) {
	host, port := echoServer(t)

	e := newEnv(t)
	e.mkUser("ana", "user")
	e.mkUser("bob", "user")
	root := e.as("root")
	ana := e.as("ana")
	bob := e.as("bob")

	var anaMe meResponse
	ana.do("GET", "/auth/me", nil, 200, &anaMe)

	// Create TCP connection
	var conn connectionDTO
	root.do("POST", "/connections", connectionRequest{
		Name:     "db1",
		Protocol: "tcp",
		Host:     host,
		Port:     int64(port),
	}, 201, &conn)

	// Grant Ana forward access
	var pol policyDTO
	canForward := true
	root.do("POST", "/policies", policyRequest{
		SubjectType: "user",
		SubjectID:   anaMe.User.ID,
		ObjectType:  "connection",
		ObjectRef:   conn.ID,
		CanConnect:  &canForward,
		CanForward:  true,
	}, 201, &pol)

	// 1. Ana connects and sends bytes
	ws, resp, err := ana.openForward(t, conn.ID, "")
	if err != nil {
		t.Fatalf("ana failed to open forward: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 Switching Protocols, got %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	testPayload := []byte("ping duckjump tcp forwarder")
	if _, err := netConn.Write(testPayload); err != nil {
		t.Fatalf("writing payload: %v", err)
	}

	buf := make([]byte, len(testPayload))
	if _, err := io.ReadFull(netConn, buf); err != nil {
		t.Fatalf("reading echoed payload: %v", err)
	}
	if string(buf) != string(testPayload) {
		t.Fatalf("got %q, want %q", string(buf), string(testPayload))
	}

	_ = netConn.Close()
	_ = ws.Close(websocket.StatusNormalClosure, "done")

	// 2. Bob (without grant) attempts forward -> 403 Forbidden
	_, respBob, err := bob.openForward(t, conn.ID, "")
	if err == nil {
		t.Fatal("expected bob to be rejected, but connected")
	}
	if respBob == nil || respBob.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for bob, got: %v", respBob)
	}

	// 3. Check audit log (with retry loop as server async writes session.end)
	foundStart, foundEnd := false, false
	for attempt := 0; attempt < 50; attempt++ {
		var events []auditEventDTO
		root.do("GET", "/audit/events?limit=20", nil, 200, &events)
		for _, ev := range events {
			var d map[string]any
			_ = json.Unmarshal(ev.Details, &d)

			if ev.Action == "session.start" {
				if connVal, ok := d["connection"].(string); ok && connVal == "db1" {
					foundStart = true
				}
			}
			if ev.Action == "session.end" {
				if connVal, ok := d["connection"].(string); ok && connVal == "db1" {
					foundEnd = true
					if bRecv, ok := d["bytes_received"].(float64); !ok || bRecv == 0 {
						t.Errorf("expected bytes_received in audit, got: %v", d["bytes_received"])
					}
				}
			}
		}
		if foundStart && foundEnd {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !foundStart {
		t.Error("audit event session.start not found for db1")
	}
	if !foundEnd {
		t.Error("audit event session.end not found for db1")
	}
}

func TestTCPPortForwarding_AllowPorts(t *testing.T) {
	host, port := echoServer(t)

	e := newEnv(t)
	e.mkUser("ana", "user")
	root := e.as("root")
	ana := e.as("ana")

	var anaMe meResponse
	ana.do("GET", "/auth/me", nil, 200, &anaMe)

	// Create TCP connection with allow_ports
	var conn connectionDTO
	root.do("POST", "/connections", connectionRequest{
		Name:     "db-restricted",
		Protocol: "tcp",
		Host:     host,
		Port:     int64(port),
		Params:   json.RawMessage(`{"allow_ports":[5432]}`),
	}, 201, &conn)

	canForward := true
	root.do("POST", "/policies", policyRequest{
		SubjectType: "user",
		SubjectID:   anaMe.User.ID,
		ObjectType:  "connection",
		ObjectRef:   conn.ID,
		CanConnect:  &canForward,
		CanForward:  true,
	}, 201, nil)

	// Requesting port 9999 (not in allow_ports) -> 400 Bad Request
	_, resp, err := ana.openForward(t, conn.ID, "port=9999")
	if err == nil {
		t.Fatal("expected port 9999 to be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got: %v", resp)
	}
}

func TestTCPPortForwarding_ViaSessionEndpoint(t *testing.T) {
	host, port := echoServer(t)

	e := newEnv(t)
	e.mkUser("ana", "user")
	root := e.as("root")
	ana := e.as("ana")

	var anaMe meResponse
	ana.do("GET", "/auth/me", nil, 200, &anaMe)

	var conn connectionDTO
	root.do("POST", "/connections", connectionRequest{
		Name:     "db-session",
		Protocol: "tcp",
		Host:     host,
		Port:     int64(port),
	}, 201, &conn)

	canForward := true
	root.do("POST", "/policies", policyRequest{
		SubjectType: "user",
		SubjectID:   anaMe.User.ID,
		ObjectType:  "connection",
		ObjectRef:   conn.ID,
		CanConnect:  &canForward,
		CanForward:  true,
	}, 201, nil)

	// Open via /api/v1/connections/{id}/session
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := strings.Replace(e.srv.URL, "http", "ws", 1) + "/api/v1/connections/" + conn.ID + "/session"
	hdr := http.Header{}
	for _, ck := range ana.http.Jar.Cookies(mustURL(e.srv.URL)) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	ws, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatalf("dial via /session failed: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	defer ws.CloseNow()

	netConn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	msg := []byte("transparent forward through session endpoint")
	if _, err := netConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(netConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", string(buf), string(msg))
	}
}

