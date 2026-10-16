package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// A SQLite gateway with some of everything moves to PostgreSQL intact: the
// audit chain (nanosecond timestamps from before µs truncation included)
// still verifies, grants still resolve, and new events keep chaining.
func TestCopyToPostgres(t *testing.T) {
	if os.Getenv(TestPostgresEnv) == "" {
		t.Skip(TestPostgresEnv + " not set (make test-postgres)")
	}
	ctx := context.Background()
	src, err := Open(filepath.Join(t.TempDir(), "src.db"))
	must(t, err)
	defer src.Close()
	q := src.Q
	now := Now()
	uid, gid, root, child, conn := NewID(), NewID(), NewID(), NewID(), NewID()
	must(t, q.CreateUser(ctx, db.CreateUserParams{ID: uid, Username: "ana", Source: "local", Role: "user", Now: now}))
	must(t, q.SetUserTOTP(ctx, db.SetUserTOTPParams{ID: uid, TOTPSealed: []byte{1, 2, 3}, TOTPEnabled: true, Now: now}))
	must(t, q.CreateGroup(ctx, db.CreateGroupParams{ID: gid, Name: "ops", Source: "local", Now: now}))
	must(t, q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: gid, UserID: uid}))
	// Child created first: the copy must still insert parents first.
	must(t, q.CreateFolder(ctx, db.CreateFolderParams{ID: root, Name: "prod", Now: now}))
	must(t, q.CreateFolder(ctx, db.CreateFolderParams{ID: child, ParentID: NullString(root), Name: "web", Now: now}))
	must(t, q.CreateConnection(ctx, db.CreateConnectionParams{ID: conn, Name: "web1", Protocol: "ssh", Host: "h", Port: 22,
		FolderID: NullString(child), Backend: BackendNative, CredentialMode: "vault", Params: `{"a":1}`, Record: true, Now: now}))
	must(t, q.AddConnectionTag(ctx, db.AddConnectionTagParams{ConnectionID: conn, Tag: "linux"}))
	must(t, q.CreatePolicy(ctx, db.CreatePolicyParams{ID: NewID(), SubjectType: "group", SubjectID: gid, ObjectType: "folder",
		ObjectRef: root, CanConnect: true, ExpiresAt: NullTime(now.Add(time.Hour)), Now: now}))
	must(t, q.SetSetting(ctx, db.SetSettingParams{Key: "recordings.retention_days", Value: "30", Now: now}))
	must(t, q.StartSessionRecord(ctx, db.StartSessionRecordParams{ID: "s1", Username: "ana", ConnectionID: conn, ConnectionSnapshot: "{}",
		Recording: NullString("s1"), Now: now}))
	must(t, q.EndSessionRecord(ctx, db.EndSessionRecordParams{ID: "s1", EndReason: "exit", Now: NullTime(now)}))
	must(t, q.InsertRecordingPurge(ctx, db.InsertRecordingPurgeParams{SessionID: "s1", Now: now, Reason: "retention", Bytes: 9}))

	// An event as older gateways wrote them: nanosecond timestamp.
	must(t, src.AuditTx(ctx, Event{Action: "auth.login", Details: map[string]any{"n": 1}}))
	ts := time.Now().UTC().Truncate(time.Second).Add(123456789)
	last, err := q.LastAuditEvent(ctx)
	must(t, err)
	c := canonical{TS: ts.Format(time.RFC3339Nano), ActorName: "old", Action: "legacy.event", Details: json.RawMessage("{}")}
	h, err := eventHash(last.Hash, c)
	must(t, err)
	must(t, q.InsertAuditEvent(ctx, db.InsertAuditEventParams{Ts: ts, ActorName: "old", Action: "legacy.event", Details: "{}",
		PrevHash: last.Hash, Hash: h, Mac: NullString(eventMAC(currentAuditKey(), last.Mac.String, h))}))
	must(t, src.AuditTx(ctx, Event{Action: "user.create", ObjectID: uid}))
	if res, _ := src.VerifyAudit(ctx); !res.OK {
		t.Fatalf("source does not verify: %+v", res)
	}

	dst, closeDst, err := OpenTemp(t.TempDir())
	must(t, err)
	defer closeDst()
	counts, err := src.CopyTo(ctx, dst)
	must(t, err)
	if counts["audit_events"] != 3 || counts["config_folders"] != 2 || counts["audit_recording_purges"] != 1 {
		t.Fatalf("counts: %v", counts)
	}
	res, err := dst.VerifyAudit(ctx)
	must(t, err)
	if !res.OK || res.Events != 3 || !res.Sealed {
		t.Fatalf("copied chain: %+v", res)
	}
	got, err := dst.GrantedConnections(ctx, uid)
	must(t, err)
	if len(got) != 1 || got[0].Name != "web1" || got[0].Params != `{"a":1}` || !got[0].Record {
		t.Fatalf("grants after copy: %+v", got)
	}
	u, err := dst.Q.GetUser(ctx, uid)
	must(t, err)
	if !u.TOTPEnabled || string(u.TOTPSealed) != "\x01\x02\x03" {
		t.Fatalf("user: %+v", u)
	}
	// The chain goes on in PostgreSQL.
	must(t, dst.AuditTx(ctx, Event{Action: "auth.login"}))
	if res, _ := dst.VerifyAudit(ctx); !res.OK || res.Events != 4 {
		t.Fatalf("after a new event: %+v", res)
	}
	if _, err := src.CopyTo(ctx, dst); err == nil {
		t.Fatal("copied into a non-empty database")
	}
}
