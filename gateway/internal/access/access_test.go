package access

import (
	"net/netip"
	"testing"
)

func TestAccessList(t *testing.T) {
	l, err := New([]string{"192.168.1.0/24", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	// Loopback is always allowed
	if !l.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("loopback should be allowed")
	}
	if !l.Allowed(netip.MustParseAddr("::1")) {
		t.Error("IPv6 loopback should be allowed")
	}

	// In range
	if !l.Allowed(netip.MustParseAddr("192.168.1.50")) {
		t.Error("192.168.1.50 should be allowed")
	}
	if !l.Allowed(netip.MustParseAddr("10.0.0.1")) {
		t.Error("10.0.0.1 should be allowed")
	}

	// Out of range
	if l.Allowed(netip.MustParseAddr("192.168.2.1")) {
		t.Error("192.168.2.1 should not be allowed")
	}
	if l.Allowed(netip.MustParseAddr("10.0.0.2")) {
		t.Error("10.0.0.2 should not be allowed")
	}
}

func TestEmptyListAllowsAll(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Error("empty list should allow all")
	}
}
