// Package access restricts who may connect by source address.
// Entries can be IPs, CIDRs or hostnames (re-resolved periodically).
// Loopback is always allowed.
package access

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type List struct {
	mu       sync.RWMutex
	entries  []string
	prefixes []netip.Prefix
	hosts    map[string][]netip.Addr
}

// New builds a list. Loopback is always allowed.
func New(entries []string) (*List, error) {
	l := &List{}
	if err := l.Set(entries); err != nil {
		return nil, err
	}
	go l.refreshLoop()
	return l, nil
}

// Validate checks whether an entry is a valid IP, CIDR, hostname or wildcard.
func Validate(e string) error {
	e = strings.TrimSpace(e)
	if e == "" || e == "*" || e == "any" {
		return nil
	}
	if _, err := netip.ParsePrefix(e); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(e); err == nil {
		return nil
	}
	if strings.ContainsAny(e, "/ :") {
		return fmt.Errorf("invalid allowlist entry: %q", e)
	}
	return nil
}

func (l *List) Set(entries []string) error {
	var prefixes []netip.Prefix
	hosts := map[string][]netip.Addr{}
	var clean []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if err := Validate(e); err != nil {
			return err
		}
		clean = append(clean, e)
		if e == "*" || e == "any" {
			prefixes = append(prefixes, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		hosts[e] = resolve(e)
	}
	l.mu.Lock()
	l.entries, l.prefixes, l.hosts = clean, prefixes, hosts
	l.mu.Unlock()
	return nil
}

func (l *List) Entries() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]string(nil), l.entries...)
}

func resolve(host string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		log.Printf("allowlist: could not resolve %s: %v", host, err)
		return nil
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs
}

func (l *List) refreshLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.RLock()
		names := make([]string, 0, len(l.hosts))
		for h := range l.hosts {
			names = append(names, h)
		}
		l.mu.RUnlock()
		for _, h := range names {
			addrs := resolve(h)
			if addrs == nil {
				continue
			}
			l.mu.Lock()
			if _, ok := l.hosts[h]; ok {
				l.hosts[h] = addrs
			}
			l.mu.Unlock()
		}
	}
}

func (l *List) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.entries) == 0 {
		return true // empty allowlist: open to all
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	for _, addrs := range l.hosts {
		for _, h := range addrs {
			if h == a {
				return true
			}
		}
	}
	return false
}

// Listener drops connections from non-allowed peers immediately after accept,
// before TLS handshake or HTTP parsing.
func (l *List) Listener(ln net.Listener) net.Listener {
	return &filteredListener{Listener: ln, list: l}
}

type filteredListener struct {
	net.Listener
	list *List
}

func (f *filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err == nil {
			if ip, err := netip.ParseAddr(host); err == nil {
				if f.list.Allowed(ip) {
					return c, nil
				}
			}
		}
		log.Printf("connection refused from %s (not in allowlist)", c.RemoteAddr())
		c.Close()
	}
}
