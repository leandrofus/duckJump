package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// GenesisHash is prev_hash of the first audit event.
var GenesisHash = strings.Repeat("0", 64)

// The hash chain alone shows edits by someone who cannot recompute it; with
// write access to the database anyone can. Each event therefore also carries
// mac = HMAC(key, prev_mac || hash) under a key that never touches the
// database (derived from the master key). The first MAC'd event starts the
// MAC chain with an empty prev_mac; its hash covers every event before it.
var auditKey atomic.Pointer[[]byte]

// SetAuditKey sets the key audit MACs are made and checked with. Every
// process writing audit events must set it once the chain is sealed.
func SetAuditKey(k []byte) { auditKey.Store(&k) }

func currentAuditKey() []byte {
	if k := auditKey.Load(); k != nil {
		return *k
	}
	return nil
}

var ErrAuditKey = errors.New("audit: no audit key configured (DUCKJUMP_MASTER_KEY)")

func eventMAC(key []byte, prevMAC, hash string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prevMAC))
	m.Write([]byte(hash))
	return hex.EncodeToString(m.Sum(nil))
}

type Actor struct {
	ID   string
	Name string
	IP   string
}

type Event struct {
	Actor      Actor
	Action     string // e.g. "user.create", "auth.login_failed", "session.start"
	ObjectType string
	ObjectID   string
	Details    any // JSON-marshalable; never secrets
}

// canonical is what the hash covers. Field order is fixed by the struct and
// details are re-encoded with sorted keys, so the same bytes come back when
// the row is read and verified later.
type canonical struct {
	TS         string          `json:"ts"`
	ActorID    string          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	ActorIP    string          `json:"actor_ip"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id"`
	Details    json.RawMessage `json:"details"`
}

func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v) // map keys come out sorted
}

func eventHash(prev string, c canonical) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Audit appends an event to the hash chain. Call it with the Queries of the
// transaction making the change, so the change and its audit record commit
// together.
func Audit(ctx context.Context, q *db.Queries, ev Event) error {
	return appendEvent(ctx, q, ev, false)
}

// appendEvent writes ev. The event gets a MAC when the chain is already
// MAC'd (or empty), or when seal starts the MAC chain on top of older events.
// A chain whose last event has no MAC stays without until it is sealed: a
// gateway never MACs events it did not see being written.
func appendEvent(ctx context.Context, q *db.Queries, ev Event, seal bool) error {
	details := ev.Details
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	if raw, err = canonicalJSON(raw); err != nil {
		return err
	}
	prev, prevMAC, macd := GenesisHash, "", true
	last, err := q.LastAuditEvent(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		prev, prevMAC, macd = last.Hash, last.Mac.String, last.Mac.Valid
	}
	if seal {
		if macd {
			return errors.New("audit: the chain is already sealed")
		}
		prevMAC, macd = "", true
	}
	key := currentAuditKey()
	if macd && key == nil {
		return ErrAuditKey
	}
	ts := Now()
	c := canonical{
		TS: ts.Format(time.RFC3339Nano), ActorID: ev.Actor.ID, ActorName: ev.Actor.Name, ActorIP: ev.Actor.IP,
		Action: ev.Action, ObjectType: ev.ObjectType, ObjectID: ev.ObjectID, Details: raw,
	}
	hash, err := eventHash(prev, c)
	if err != nil {
		return err
	}
	var mac sql.NullString
	if macd {
		mac = NullString(eventMAC(key, prevMAC, hash))
	}
	return q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Ts: ts, ActorID: NullString(ev.Actor.ID), ActorName: ev.Actor.Name, ActorIP: ev.Actor.IP,
		Action: ev.Action, ObjectType: ev.ObjectType, ObjectID: ev.ObjectID, Details: string(raw),
		PrevHash: prev, Hash: hash, Mac: mac,
	})
}

// SealAudit starts the MAC chain on a database whose events predate it
// (audit_events.mac added by migration 00003). The seal event's MAC covers
// its hash, and through prev_hash every event before it.
func (s *Store) SealAudit(ctx context.Context, actor Actor) (int64, error) {
	var n int64
	err := s.Tx(ctx, func(q *db.Queries) error {
		var err error
		if n, err = q.CountAuditEvents(ctx); err != nil {
			return err
		}
		return appendEvent(ctx, q, Event{Actor: actor, Action: "audit.sealed", ObjectType: "audit",
			Details: map[string]any{"previous_events": n}}, true)
	})
	return n, err
}

// AuditTx is Audit in a transaction of its own, for events with no
// accompanying change (logins, session start/end).
func (s *Store) AuditTx(ctx context.Context, ev Event) error {
	return s.Tx(ctx, func(q *db.Queries) error { return Audit(ctx, q, ev) })
}

// openapi:schema AuditVerification
// type: object
// required: [events, ok, authenticated, sealed]
// properties:
//   events: { type: integer, description: Events verified before stopping. }
//   ok: { type: boolean }
//   broken_at: { type: integer, description: Id of the first event that does not verify. }
//   reason: { type: string }
//   authenticated: { type: integer, description: 'Events the MAC chain vouches for (keyed outside the database, so a rewrite with database access alone shows).' }
//   sealed: { type: boolean, description: The chain carries MACs. A chain with events and none does not verify. }

type VerifyResult struct {
	Events   int64  `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"` // id of the first event that does not verify
	Reason   string `json:"reason,omitempty"`
	// Events whose authenticity the MAC chain vouches for (the MAC'd ones and
	// every event before the first).
	Authenticated int64 `json:"authenticated"`
	// Sealed: the chain carries MACs. A chain with events and no MAC (a
	// database from before MACs, or one stripped of them) does not verify.
	Sealed bool `json:"sealed"`
}

// VerifyAudit recomputes the whole chain: hashes, and MACs from the first
// MAC'd event on. It cannot see events removed from the end of the chain;
// an exported copy of the log (duckjump-gw serve -audit-export) can.
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	var res VerifyResult
	key := currentAuditKey()
	prev, prevMAC := GenesisHash, ""
	var after int64
	for {
		rows, err := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{AfterID: after, Lim: 1000})
		if err != nil {
			return res, err
		}
		if len(rows) == 0 {
			if res.Events > 0 && !res.Sealed {
				res.Reason = "the audit chain carries no MACs: run `duckjump-gw audit-seal` (needs the master key)"
				return res, nil
			}
			res.OK = true
			return res, nil
		}
		for _, e := range rows {
			fail := func(why string) (VerifyResult, error) {
				res.BrokenAt, res.Reason = e.ID, why
				return res, nil
			}
			if e.PrevHash != prev {
				return fail("prev_hash does not match the previous event")
			}
			raw, err := canonicalJSON([]byte(e.Details))
			if err != nil {
				return fail("details are not valid JSON")
			}
			ts := e.Ts.UTC().Format(time.RFC3339Nano)
			if e.TsExact.Valid {
				ts = e.TsExact.String
			}
			h, err := eventHash(prev, canonical{
				TS: ts, ActorID: e.ActorID.String, ActorName: e.ActorName,
				ActorIP: e.ActorIP, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: raw,
			})
			if err != nil {
				return res, err
			}
			if h != e.Hash {
				return fail(fmt.Sprintf("content does not match its hash (%s)", e.Action))
			}
			switch {
			case e.Mac.Valid:
				if key == nil {
					return res, ErrAuditKey
				}
				if !hmac.Equal([]byte(eventMAC(key, prevMAC, e.Hash)), []byte(e.Mac.String)) {
					return fail(fmt.Sprintf("MAC does not verify (%s): rewritten without the audit key", e.Action))
				}
				if !res.Sealed {
					res.Sealed = true
					res.Authenticated = res.Events // everything before is covered by this event's hash
				}
				prevMAC = e.Mac.String
				res.Authenticated++
			case res.Sealed:
				return fail(fmt.Sprintf("event has no MAC (%s)", e.Action))
			}
			prev, after = e.Hash, e.ID
			res.Events++
		}
	}
}
