package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leandrofus/palta/gateway/internal/store/db"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
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
			Backend: "paltad", CredentialMode: "vault", Params: "{}", Now: now,
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
	conn("hidden", "") // no grant at all

	grant("user", ana, "folder", prod, time.Time{})
	grant("user", ana, "connection", direct, time.Time{})
	grant("user", ana, "connection", expired, now.Add(-time.Minute))
	grant("group", gid, "tag", "databases", now.Add(time.Hour))
	grant("user", beto, "connection", roundExp, now.Add(2*time.Hour).Truncate(time.Second))

	names := func(uid string) string {
		cs, err := s.GrantedConnections(ctx, uid)
		must(t, err)
		var out []string
		for _, c := range cs {
			out = append(out, c.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(ana); got != "jump,web1" {
		t.Fatalf("ana sees %q", got)
	}
	if got := names(beto); got != "db1,round" {
		t.Fatalf("beto sees %q", got)
	}
	for _, c := range []struct {
		user, conn string
		want       bool
	}{{ana, web1, true}, {ana, db1, false}, {ana, expired, false}, {beto, db1, true}, {beto, web1, false}} {
		ok, err := s.CanConnect(ctx, c.user, c.conn)
		must(t, err)
		if ok != c.want {
			t.Errorf("CanConnect(%s,%s) = %v", c.user, c.conn, ok)
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
	_, err = s.DB.Exec(`DROP TRIGGER audit_events_no_update`)
	must(t, err)
	_, err = s.DB.Exec(`UPDATE audit_events SET details = '{"n":99}' WHERE id = 2`)
	must(t, err)
	res, err = s.VerifyAudit(ctx)
	must(t, err)
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("tampering not detected: %+v", res)
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
