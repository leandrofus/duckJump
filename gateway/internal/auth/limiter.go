package auth

import (
	"sync"
	"time"
)

// Limiter slows down password guessing: after Max failures for a key
// (username + client IP) within Window, further attempts are refused until
// the window passes.
//
// Memory stays bounded under a distributed attack: expired keys are swept
// once a minute, and at MaxKeys tracked keys new ones are not tracked
// (logins for them are still allowed, just not counted) until the sweep
// frees room.
type Limiter struct {
	Max     int
	Window  time.Duration
	MaxKeys int

	mu        sync.Mutex
	fails     map[string][]time.Time
	lastSweep time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{Max: 5, Window: 15 * time.Minute, MaxKeys: 100_000, fails: map[string][]time.Time{}}
}

func (l *Limiter) recent(key string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.fails[key] {
		if now.Sub(t) < l.Window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = keep
	}
	return keep
}

// sweep drops every key whose failures have all expired: once a minute, or
// once a second while full.
func (l *Limiter) sweep(now time.Time) {
	every := time.Minute
	if len(l.fails) >= l.MaxKeys {
		every = time.Second
	}
	if now.Sub(l.lastSweep) < every {
		return
	}
	l.lastSweep = now
	for key, ts := range l.fails {
		if now.Sub(ts[len(ts)-1]) >= l.Window {
			delete(l.fails, key)
		}
	}
}

func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	return len(l.recent(key, now)) < l.Max
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	prev := l.recent(key, now)
	if len(prev) == 0 && len(l.fails) >= l.MaxKeys {
		return
	}
	l.fails[key] = append(prev, now)
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// Len is how many keys are tracked (for tests and metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.fails)
}
