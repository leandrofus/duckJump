package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterLocksOutAndResets(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < l.Max; i++ {
		if !l.Allowed("ana|10.0.0.1") {
			t.Fatalf("refused after %d failures", i)
		}
		l.Fail("ana|10.0.0.1")
	}
	if l.Allowed("ana|10.0.0.1") {
		t.Fatal("allowed after Max failures")
	}
	if !l.Allowed("ana|10.0.0.2") {
		t.Fatal("another address locked out too")
	}
	l.Reset("ana|10.0.0.1")
	if !l.Allowed("ana|10.0.0.1") {
		t.Fatal("still locked after reset")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	l := NewLimiter()
	l.Window = 20 * time.Millisecond
	for i := 0; i < l.Max; i++ {
		l.Fail("k")
	}
	if l.Allowed("k") {
		t.Fatal("not locked")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allowed("k") {
		t.Fatal("still locked after the window")
	}
}

// Many distinct keys, each failing once (a distributed attack), do not grow
// the map without bound.
func TestLimiterBoundedMemory(t *testing.T) {
	l := NewLimiter()
	l.MaxKeys = 100
	for i := 0; i < 1000; i++ {
		l.Fail(fmt.Sprintf("user%d|10.0.%d.%d", i, i/256, i%256))
	}
	if n := l.Len(); n > l.MaxKeys {
		t.Fatalf("%d keys tracked, cap %d", n, l.MaxKeys)
	}

	// Expired keys are swept.
	l.Window = time.Millisecond
	time.Sleep(5 * time.Millisecond)
	l.lastSweep = time.Time{}
	l.Allowed("x")
	if n := l.Len(); n != 0 {
		t.Fatalf("%d expired keys left after a sweep", n)
	}
}
