package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

func TestMain(m *testing.M) {
	SetAuditKey([]byte("test audit key, 32 bytes long..."))
	os.Exit(m.Run())
}

func open(t *testing.T) *Store {
	t.Helper()
	s, closeDB, err := OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDB)
	return s
}

// unprotect lets a test play the attacker with direct database access.
func unprotect(t *testing.T, s *Store) {
	t.Helper()
	q := `DROP TRIGGER audit_events_no_update`
	if s.Postgres {
		q = `ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`
	}
	if _, err := s.DB.Exec(q); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestGrants(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	q := s.Q
	now := Now()

	user := func(name string) string {
		id := NewID()
		must(t, q.CreateUser(ctx, db.CreateUserParams{ID: id, Username: name, Source: "local", Role: "user", Now: now}))
		return id
	}
	folder := func(name, parent string) string {
		id := NewID()
		must(t, q.CreateFolder(ctx, db.CreateFolderParams{ID: id, ParentID: NullString(parent), Name: name, Now: now}))
		return id
	}
	conn := func(name, folder string, tags ...string) string {
		id := NewID()
		must(t, q.CreateConnection(ctx, db.CreateConnectionParams{
			ID: id, Name: name, Protocol: "ssh", Host: "h", Port: 22, FolderID: NullString(folder),
			Backend: BackendNative, CredentialMode: "vault", Params: "{}", Now: now,
		}))
		for _, tg := range tags {
			must(t, q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: id, Tag: tg}))
		}
		return id
	}
	grant := func(subjType, subj, objType, ref string, exp time.Time) {
		must(t, q.CreatePolicy(ctx, db.CreatePolicyParams{
			ID: NewID(), SubjectType: subjType, SubjectID: subj, ObjectType: objType, ObjectRef: ref,
			CanConnect: true, ExpiresAt: NullTime(exp), Now: now,
		}))
	}

	ana, beto := user("ana"), user("beto")
	gid := NewID()
	must(t, q.CreateGroup(ctx, db.CreateGroupParams{ID: gid, Name: "ops", Source: "local", Now: now}))
	must(t, q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: gid, UserID: beto}))

	prod := folder("prod", "")
	prodWeb := folder("web", prod)
	web1 := conn("web1", prodWeb)       // reachable via folder subtree grant
	db1 := conn("db1", "", "databases") // via tag grant to group
	direct := conn("jump", "")          // direct user grant
	expired := conn("old", "")          // expired grant
	// Expires on a whole second: stored without fractional digits, which
	// compares wrong as text against a "now" that has them.
	roundExp := conn("round", "")
	future := conn("future", "")        // starts in future
	pastStart := conn("past", "")     // started in past
	conn("hidden", "") // no grant at all

	grant("user", ana, "folder", prod, time.Time{})
	grant("user", ana, "connection", direct, time.Time{})
	grant("user", ana, "connection", expired, now.Add(-time.Minute))
	grant("group", gid, "tag", "databases", now.Add(time.Hour))
	grant("user", beto, "connection", roundExp, now.Add(2*time.Hour).Truncate(time.Second))

	// future start: not active yet
	must(t, q.CreatePolicy(ctx, db.CreatePolicyParams{
		ID: NewID(), SubjectType: "user", SubjectID: ana, ObjectType: "connection", ObjectRef: future,
		CanConnect: true, StartsAt: NullTime(now.Add(time.Hour)), ExpiresAt: NullTime(now.Add(2 * time.Hour)), Now: now,
	}))
	// past start: currently active
	must(t, q.CreatePolicy(ctx, db.CreatePolicyParams{
		ID: NewID(), SubjectType: "user", SubjectID: ana, ObjectType: "connection", ObjectRef: pastStart,
		CanConnect: true, StartsAt: NullTime(now.Add(-time.Hour)), ExpiresAt: NullTime(now.Add(2 * time.Hour)), Now: now,
	}))

	names := func(uid string) string {
		cs, err := s.GrantedConnections(ctx, uid)
		must(t, err)
		var out []string
		for _, c := range cs {
			out = append(out, c.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(ana); got != "jump,past,web1" {
		t.Fatalf("ana sees %q, want jump,past,web1", got)
	}
	if got := names(beto); got != "db1,round" {
		t.Fatalf("beto sees %q", got)
	}
	for _, c := range []struct {
		user, conn string
		want       bool
	}{{ana, web1, true}, {ana, db1, false}, {ana, expired, false}, {ana, future, false}, {ana, pastStart, true}, {beto, db1, true}, {beto, web1, false}} {
		ok, err := s.CanConnect(ctx, c.user, c.conn)
		must(t, err)
		if ok != c.want {
			t.Errorf("CanConnect(%s,%s) = %v, want %v", c.user, c.conn, ok, c.want)
		}
	}
}

func TestAuditChain(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	actor := Actor{ID: NewID(), Name: "ana", IP: "10.0.0.1"}
	for i, a := range []string{"auth.login", "user.create", "session.start"} {
		must(t, s.AuditTx(ctx, Event{Actor: actor, Action: a, ObjectID: "x",
			Details: map[string]any{"n": i, "z": "ñ<b>", "a": []int{1, 2}, "big": 12345678901234567}}))
	}
	res, err := s.VerifyAudit(ctx)
	must(t, err)
	if !res.OK || res.Events != 3 {
		t.Fatalf("verify: %+v", res)
	}

	// Append-only: the triggers refuse changes.
	if _, err := s.DB.Exec(`UPDATE audit_events SET action = 'x' WHERE id = 2`); err == nil {
		t.Fatal("update allowed")
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_events WHERE id = 3`); err == nil {
		t.Fatal("delete allowed")
	}

	// Someone with file access drops the trigger and edits a row: detected.
	unprotect(t, s)
	_, err = s.DB.Exec(`UPDATE audit_events SET details = '{"n":99}' WHERE id = 2`)
	must(t, err)
	res, err = s.VerifyAudit(ctx)
	must(t, err)
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("tampering not detected: %+v", res)
	}
}

// An attacker with the database (not the key) rewrites an event and
// recomputes every hash after it: the hash chain verifies, the MACs do not.
func TestAuditMACDetectsRewrite(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	for _, a := range []string{"auth.login", "user.create", "session.start"} {
		must(t, s.AuditTx(ctx, Event{Actor: Actor{Name: "ana"}, Action: a}))
	}
	unprotect(t, s)
	rows, err := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{Lim: 10})
	must(t, err)
	prev := GenesisHash
	for _, e := range rows {
		if e.ID == 2 {
			e.Action = "user.nothing_to_see"
		}
		b, _ := json.Marshal(canonical{TS: e.Ts.UTC().Format(time.RFC3339Nano), ActorID: e.ActorID.String, ActorName: e.ActorName,
			ActorIP: e.ActorIP, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Details: json.RawMessage(e.Details)})
		sum := sha256.Sum256(append([]byte(prev), b...))
		h := hex.EncodeToString(sum[:])
		_, err := s.DB.Exec(`UPDATE audit_events SET action = $1, prev_hash = $2, hash = $3 WHERE id = $4`, e.Action, prev, h, e.ID)
		must(t, err)
		prev = h
	}
	res, err := s.VerifyAudit(ctx)
	must(t, err)
	if res.OK || res.BrokenAt != 2 || !strings.Contains(res.Reason, "MAC") {
		t.Fatalf("rewrite with recomputed hashes not detected: %+v", res)
	}

	// Stripping the MACs does not help either.
	_, err = s.DB.Exec(`UPDATE audit_events SET mac = NULL`)
	must(t, err)
	if res, _ = s.VerifyAudit(ctx); res.OK || res.Sealed {
		t.Fatalf("chain without MACs verified: %+v", res)
	}
}

// Events from before MACs existed are authenticated by sealing the chain.
func TestAuditSealLegacy(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, err := s.DB.Exec(`INSERT INTO audit_events (ts, actor_name, action, details, prev_hash, hash) VALUES ($1, 'old', 'legacy.event', '{}', $2, 'h1')`,
		Now(), GenesisHash)
	must(t, err)
	// A legacy hash that does not chain: rewrite it so it does.
	rows, _ := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{Lim: 1})
	e := rows[0]
	b, _ := json.Marshal(canonical{TS: e.Ts.UTC().Format(time.RFC3339Nano), ActorName: e.ActorName, Action: e.Action, Details: json.RawMessage("{}")})
	sum := sha256.Sum256(append([]byte(GenesisHash), b...))
	unprotect(t, s)
	_, err = s.DB.Exec(`UPDATE audit_events SET hash = $1 WHERE id = 1`, hex.EncodeToString(sum[:]))
	must(t, err)

	// Unsealed: new events stay without MAC, and verification says why.
	must(t, s.AuditTx(ctx, Event{Action: "auth.login"}))
	if res, _ := s.VerifyAudit(ctx); res.OK || res.Sealed {
		t.Fatalf("unsealed chain verified: %+v", res)
	}
	n, err := s.SealAudit(ctx, Actor{Name: "cli"})
	must(t, err)
	must(t, s.AuditTx(ctx, Event{Action: "auth.login"}))
	res, err := s.VerifyAudit(ctx)
	must(t, err)
	if n != 2 || !res.OK || !res.Sealed || res.Authenticated != 4 {
		t.Fatalf("after seal: n=%d %+v", n, res)
	}
	if _, err := s.SealAudit(ctx, Actor{Name: "cli"}); err == nil {
		t.Fatal("sealed twice")
	}
}

func TestSessionRecordCloseOnly(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	q := s.Q
	must(t, q.StartSessionRecord(ctx, db.StartSessionRecordParams{
		ID: "s1", Username: "ana", ConnectionID: NewID(), ConnectionSnapshot: "{}", Now: Now(),
	}))
	must(t, q.EndSessionRecord(ctx, db.EndSessionRecordParams{ID: "s1", EndReason: "exit", Now: NullTime(Now())}))
	if _, err := s.DB.Exec(`UPDATE audit_sessions SET ended_at = NULL WHERE id = 's1'`); err == nil {
		t.Fatal("reopening a closed session allowed")
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_sessions`); err == nil {
		t.Fatal("delete allowed")
	}
}

func TestFolderSiblingNamesUnique(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := Now()
	must(t, s.Q.CreateFolder(ctx, db.CreateFolderParams{ID: NewID(), Name: "prod", Now: now}))
	err := Classify(s.Q.CreateFolder(ctx, db.CreateFolderParams{ID: NewID(), Name: "prod", Now: now}))
	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("duplicate root folder: %v", err)
	}
}

func TestAuditExport(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	w, err := OpenAuditSink("file://" + path)
	must(t, err)
	defer w.Close()
	for _, a := range []string{"auth.login", "user.create"} {
		must(t, s.AuditTx(ctx, Event{Action: a}))
	}
	must(t, s.exportOnce(ctx, []io.Writer{w}))
	must(t, s.AuditTx(ctx, Event{Action: "session.start"}))
	must(t, s.exportOnce(ctx, []io.Writer{w}))
	must(t, s.exportOnce(ctx, []io.Writer{w})) // nothing new: nothing written

	b, err := os.ReadFile(path)
	must(t, err)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines: %s", len(lines), b)
	}
	var last ExportedEvent
	must(t, json.Unmarshal([]byte(lines[2]), &last))
	if last.ID != 3 || last.Action != "session.start" || last.MAC == "" || last.Hash == "" {
		t.Fatalf("%+v", last)
	}
	if _, err := OpenAuditSink("ftp://x"); err == nil {
		t.Fatal("unknown scheme accepted")
	}
}
