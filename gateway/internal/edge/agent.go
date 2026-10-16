package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// AllowRule permits dials to addresses in Prefix on Ports (empty = any port).
type AllowRule struct {
	Prefix netip.Prefix
	Ports  []int
}

// ParseAllow parses "10.20.0.0/16:22,3389" or "10.20.0.5" (any port).
func ParseAllow(s string) (AllowRule, error) {
	var r AllowRule
	cidr, ports, hasPorts := strings.Cut(s, ":")
	if !strings.Contains(cidr, "/") {
		a, err := netip.ParseAddr(cidr)
		if err != nil {
			return r, fmt.Errorf("allow %q: %w", s, err)
		}
		cidr = netip.PrefixFrom(a, a.BitLen()).String()
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return r, fmt.Errorf("allow %q: %w", s, err)
	}
	r.Prefix = p.Masked()
	if hasPorts {
		for _, ps := range strings.Split(ports, ",") {
			n, err := strconv.Atoi(ps)
			if err != nil || n < 1 || n > 65535 {
				return r, fmt.Errorf("allow %q: bad port %q", s, ps)
			}
			r.Ports = append(r.Ports, n)
		}
	}
	return r, nil
}

func allowed(rules []AllowRule, addr netip.Addr, port int) bool {
	for _, r := range rules {
		if r.Prefix.Contains(addr.Unmap()) && (len(r.Ports) == 0 || slices.Contains(r.Ports, port)) {
			return true
		}
	}
	return false
}

type AgentConfig struct {
	Server string // ws(s)://host:port/agent/connect
	Token  string
	Name   string
	// Allow is the local, final word on what the gateway may reach through
	// this agent. Empty denies everything.
	Allow []AllowRule
	// RootCAs trusts these instead of the system roots (self-signed gateway).
	RootCAs *x509.CertPool
}

// RunAgent keeps the tunnel up, reconnecting with backoff, until ctx ends.
func RunAgent(ctx context.Context, cfg AgentConfig) error {
	backoff := time.Second
	for {
		start := time.Now()
		err := runOnce(ctx, cfg)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		wait := backoff + time.Duration(rand.Int64N(int64(backoff/2+1)))
		slog.Warn("tunnel down, reconnecting", "err", err, "in", wait.Round(time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func runOnce(ctx context.Context, cfg AgentConfig) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + cfg.Token}, "X-Palta-Agent": {cfg.Name}},
	}
	if cfg.RootCAs != nil {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12}}}
	}
	ws, _, err := websocket.Dial(dctx, cfg.Server, opts)
	if err != nil {
		return err
	}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	sess, err := yamux.Server(websocket.NetConn(sctx, ws, websocket.MessageBinary), yamuxConfig())
	if err != nil {
		return err
	}
	defer sess.Close()
	slog.Info("tunnel up", "server", cfg.Server)
	go func() { <-ctx.Done(); sess.Close() }()
	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go handleStream(st, cfg.Allow)
	}
}

func handleStream(st net.Conn, rules []AllowRule) {
	defer st.Close()
	st.SetDeadline(time.Now().Add(20 * time.Second))
	line, err := readLine(st)
	if err != nil {
		return
	}
	var req dialRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil || req.Port < 1 || req.Port > 65535 {
		writeLine(st, "err bad request")
		return
	}
	log := slog.With("target", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)), "session", req.Session)

	// Resolve here and check every address, then dial the checked one, so a
	// name cannot point the agent outside its allow list.
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", req.Host)
	if err != nil || len(ips) == 0 {
		writeLine(st, "err cannot resolve host")
		log.Warn("dial refused: resolve", "err", err)
		return
	}
	for _, ip := range ips {
		if !allowed(rules, ip, req.Port) {
			writeLine(st, "err target not allowed by agent policy")
			log.Warn("dial refused: not in allow list", "ip", ip)
			return
		}
	}
	target := net.JoinHostPort(ips[0].Unmap().String(), strconv.Itoa(req.Port))
	c, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		writeLine(st, "err "+err.Error())
		log.Warn("dial failed", "err", err)
		return
	}
	defer c.Close()
	if writeLine(st, "ok") != nil {
		return
	}
	st.SetDeadline(time.Time{})
	log.Info("dial ok")
	pipe(st, c)
}
