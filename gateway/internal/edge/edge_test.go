package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
)

func TestParseAllow(t *testing.T) {
	r, err := ParseAllow("10.20.0.0/16:22,3389")
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("10.20.5.9")
	if !allowed([]AllowRule{r}, a, 22) || allowed([]AllowRule{r}, a, 80) {
		t.Fatal("port filtering broken")
	}
	single, _ := ParseAllow("192.168.1.10")
	if !allowed([]AllowRule{single}, netip.MustParseAddr("192.168.1.10"), 5900) ||
		allowed([]AllowRule{single}, netip.MustParseAddr("192.168.1.11"), 5900) {
		t.Fatal("single address rule broken")
	}
	if _, err := ParseAllow("10.0.0.0/8:http"); err == nil {
		t.Fatal("accepted bad port")
	}
}

// Full path: relay client -> hub -> yamux over WebSocket -> agent -> TCP target.
func TestRelayThroughAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	tok := NewToken()
	site := store.NewID()
	if err := st.Q.CreateSite(ctx, db.CreateSiteParams{
		ID: site, Name: "edge1", Kind: "agent", AgentTokenHash: store.NullString(HashToken(tok)), Now: store.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Target: an echo server that greets first, like an SSH server does.
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { io.WriteString(c, "HELLO\n"); io.Copy(c, c); c.Close() }()
		}
	}()
	tport := target.Addr().(*net.TCPAddr).Port

	hub := NewHub(st.AgentSiteLookup)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/connect", hub.ServeAgent)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	relay, _ := net.Listen("tcp", "127.0.0.1:0")
	go hub.ServeRelay(relay)

	rule, _ := ParseAllow("127.0.0.1:" + strconv.Itoa(tport))
	go RunAgent(ctx, AgentConfig{
		Server: "ws" + strings.TrimPrefix(srv.URL, "http") + "/agent/connect",
		Token:  tok, Name: "test-agent", Allow: []AllowRule{rule},
	})
	for i := 0; hub.Connected(site) == 0; i++ {
		if i > 100 {
			t.Fatal("agent never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	dialRelay := func(host string, port int) (net.Conn, *bufio.Reader, string) {
		tk, err := hub.Ticket(site, host, port, "s1")
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp", relay.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, tk+"\n")
		br := bufio.NewReader(c)
		status, _ := br.ReadString('\n')
		return c, br, strings.TrimSpace(status)
	}

	c, br, status := dialRelay("127.0.0.1", tport)
	defer c.Close()
	if status != "ok" {
		t.Fatalf("status %q", status)
	}
	if greet, _ := br.ReadString('\n'); greet != "HELLO\n" {
		t.Fatalf("greeting %q", greet)
	}
	io.WriteString(c, "ping\n")
	if echo, _ := br.ReadString('\n'); echo != "ping\n" {
		t.Fatalf("echo %q", echo)
	}

	// Not in the agent's allow list: refused by the agent itself.
	c2, _, status := dialRelay("127.0.0.1", tport+1)
	c2.Close()
	if !strings.Contains(status, "not allowed") {
		t.Fatalf("want refusal, got %q", status)
	}

	// Tickets are single use.
	tk, _ := hub.Ticket(site, "127.0.0.1", tport, "s2")
	if _, ok := hub.redeem(tk); !ok {
		t.Fatal("fresh ticket rejected")
	}
	if _, ok := hub.redeem(tk); ok {
		t.Fatal("ticket redeemed twice")
	}
}
