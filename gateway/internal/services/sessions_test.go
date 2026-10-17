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
}
