package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/leandrofus/palta/gateway/internal/store/db"
)

// GenesisHash is prev_hash of the first audit event.
var GenesisHash = strings.Repeat("0", 64)

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
	prev, err := q.LastAuditHash(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		prev, err = GenesisHash, nil
	}
	if err != nil {
		return err
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
	return q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Ts: ts, ActorID: NullString(ev.Actor.ID), ActorName: ev.Actor.Name, ActorIP: ev.Actor.IP,
		Action: ev.Action, ObjectType: ev.ObjectType, ObjectID: ev.ObjectID, Details: string(raw),
		PrevHash: prev, Hash: hash,
	})
}

// AuditTx is Audit in a transaction of its own, for events with no
// accompanying change (logins, session start/end).
func (s *Store) AuditTx(ctx context.Context, ev Event) error {
	return s.Tx(ctx, func(q *db.Queries) error { return Audit(ctx, q, ev) })
}

// openapi:schema AuditVerification
// type: object
// required: [events, ok]
// properties:
//   events: { type: integer, description: Events verified before stopping. }
//   ok: { type: boolean }
//   broken_at: { type: integer, description: Id of the first event that does not verify. }
//   reason: { type: string }

type VerifyResult struct {
	Events   int64  `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"` // id of the first event that does not verify
	Reason   string `json:"reason,omitempty"`
}

// VerifyAudit recomputes the whole chain.
func (s *Store) VerifyAudit(ctx context.Context) (VerifyResult, error) {
	var res VerifyResult
	prev := GenesisHash
	var after int64
	for {
		rows, err := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{AfterID: after, Lim: 1000})
		if err != nil {
			return res, err
		}
		if len(rows) == 0 {
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
			h, err := eventHash(prev, canonical{
				TS: e.Ts.UTC().Format(time.RFC3339Nano), ActorID: e.ActorID.String, ActorName: e.ActorName,
				ActorIP: e.ActorIP, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: raw,
			})
			if err != nil {
				return res, err
			}
			if h != e.Hash {
				return fail(fmt.Sprintf("content does not match its hash (%s)", e.Action))
			}
			prev, after = e.Hash, e.ID
			res.Events++
		}
	}
}
