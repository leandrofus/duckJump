package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

func TestSessionService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	userSvc := NewUserService(st)
	connSvc := NewConnectionService(st)
	sessSvc := NewSessionService(st)

	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	u, err := userSvc.Create(ctx, CreateUserParams{
		Username:    "alice",
		DisplayName: "Alice",
		Role:        "user",
		Password:    "Password12345!",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	c, err := connSvc.Create(ctx, CreateConnectionParams{
		Name:     "Bastion-01",
		Protocol: "ssh",
		Host:     "10.0.0.1",
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Create connection failed: %v", err)
	}

	sessionID := store.NewID()
	now := store.Now()
	err = st.Tx(ctx, func(q *db.Queries) error {
		return q.StartSessionRecord(ctx, db.StartSessionRecordParams{
			ID:           sessionID,
			UserID:       sql.NullString{String: u.ID, Valid: true},
			Username:     u.Username,
			ConnectionID: c.Connection.ID,
			Site:         "",
			ClientIP:     "192.168.1.10",
			Now:          now,
		})
	})
	if err != nil {
		t.Fatalf("StartSessionRecord failed: %v", err)
	}

	// 1. Get session
	sess, err := sessSvc.Get(ctx, sessionID)
	if err != nil {
		t.Fatalf("Get session failed: %v", err)
	}
	if sess.ID != sessionID || sess.UserID.String != u.ID {
		t.Fatalf("unexpected session: %+v", sess)
	}

	// 2. List sessions
	list, err := sessSvc.List(ctx, ListSessionsParams{
		UserID:     u.ID,
		ActiveOnly: true,
	})
	if err != nil {
		t.Fatalf("List sessions failed: %v", err)
	}
	if len(list) != 1 || list[0].ID != sessionID {
		t.Fatalf("unexpected list: %+v", list)
	}

	// 3. Request kill
	killedSess, err := sessSvc.RequestKill(ctx, adminActor, sessionID, "routine rotation")
	if err != nil {
		t.Fatalf("RequestKill failed: %v", err)
	}
	if killedSess.ID != sessionID {
		t.Fatalf("expected killed session ID %s, got %s", sessionID, killedSess.ID)
	}

	// Verify kill request in db
	reqs, err := st.Q.ListSessionKills(ctx)
	if err != nil {
		t.Fatalf("ListSessionKills failed: %v", err)
	}
	if len(reqs) == 0 || reqs[0].SessionID != sessionID || reqs[0].Reason != "routine rotation" {
		t.Fatalf("unexpected kill request: %+v", reqs)
	}

	// 4. Mark session ended
	err = st.Tx(ctx, func(q *db.Queries) error {
		return q.EndSessionRecord(ctx, db.EndSessionRecordParams{
			ID:        sessionID,
			Now:       store.NullTime(store.Now()),
			EndReason: "terminated",
		})
	})
	if err != nil {
		t.Fatalf("EndSessionRecord failed: %v", err)
	}

	// 5. Request kill on ended session should fail with ErrSessionAlreadyEnded
	_, err = sessSvc.RequestKill(ctx, adminActor, sessionID, "kill again")
	if !errors.Is(err, ErrSessionAlreadyEnded) {
		t.Fatalf("expected ErrSessionAlreadyEnded, got %v", err)
	}

	// 6. Test StartSession, Beat, EndSession, AuditShare, AuditUnshare on a new session
	sessionID2 := store.NewID()
	err = sessSvc.StartSession(ctx, StartSessionParams{
		SessionID:          sessionID2,
		UserID:             u.ID,
		Username:           u.Username,
		ConnectionID:       c.Connection.ID,
		ConnectionSnapshot: `{}`,
		Site:               "",
		ClientIP:           "127.0.0.1",
		Actor:              adminActor,
		AuditDetails:       map[string]any{"connection": c.Connection.Name},
		Node:               "node-1",
	})
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}

	if err := sessSvc.Beat(ctx, sessionID2, "node-1"); err != nil {
		t.Fatalf("Beat failed: %v", err)
	}
	if err := sessSvc.AuditShare(ctx, adminActor, sessionID2); err != nil {
		t.Fatalf("AuditShare failed: %v", err)
	}
	if err := sessSvc.AuditUnshare(ctx, adminActor, sessionID2); err != nil {
		t.Fatalf("AuditUnshare failed: %v", err)
	}
	if err := sessSvc.EndSession(ctx, EndSessionParams{
		SessionID: sessionID2,
		Reason:    "closed_by_user",
		BytesSent: 1024,
		BytesRecv: 2048,
		Actor:     adminActor,
		ExtraDetails: map[string]any{
			"connection": c.Connection.Name,
		},
	}); err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}

	endedSess, err := sessSvc.Get(ctx, sessionID2)
	if err != nil {
		t.Fatalf("Get ended session failed: %v", err)
	}
	if !endedSess.EndedAt.Valid || endedSess.EndReason.String != "closed_by_user" {
		t.Fatalf("expected ended session with reason closed_by_user, got %+v", endedSess)
	}

	// 7. AuditJoinDenied, AuditJoin, AuditLeave
	if err := sessSvc.AuditJoinDenied(ctx, adminActor, sessionID2, c.Connection.Name); err != nil {
		t.Fatalf("AuditJoinDenied failed: %v", err)
	}
	if err := sessSvc.AuditJoin(ctx, adminActor, sessionID2, c.Connection.Name, u.Username); err != nil {
		t.Fatalf("AuditJoin failed: %v", err)
	}
	if err := sessSvc.AuditLeave(ctx, adminActor, sessionID2, c.Connection.Name); err != nil {
		t.Fatalf("AuditLeave failed: %v", err)
	}

	// 8. ListKills
	sessionID3 := store.NewID()
	err = sessSvc.StartSession(ctx, StartSessionParams{
		SessionID:          sessionID3,
		UserID:             u.ID,
		Username:           u.Username,
		ConnectionID:       c.Connection.ID,
		ConnectionSnapshot: `{}`,
		ClientIP:           "127.0.0.1",
		Actor:              adminActor,
		AuditDetails:       map[string]any{"connection": c.Connection.Name},
	})
	if err != nil {
		t.Fatalf("StartSession 3 failed: %v", err)
	}
	_, err = sessSvc.RequestKill(ctx, adminActor, sessionID3, "test kill active")
	if err != nil {
		t.Fatalf("RequestKill failed: %v", err)
	}
	kills, err := sessSvc.ListKills(ctx)
	if err != nil {
		t.Fatalf("ListKills failed: %v", err)
	}
	if len(kills) == 0 {
		t.Fatalf("expected at least 1 kill for active session, got 0")
	}

	// 9. CheckSessionAllowed
	why, err := sessSvc.CheckSessionAllowed(ctx, u.ID, c.Connection.ID)
	if err != nil {
		t.Fatalf("CheckSessionAllowed failed: %v", err)
	}
	// user bob has no policy grant to connection c, so not allowed:
	if why != "access to this connection expired or was revoked" {
		t.Fatalf("expected revoked/expired reason, got %q", why)
	}
}

