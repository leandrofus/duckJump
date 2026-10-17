package services

import (
	"context"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

func TestAuditService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	svc := NewAuditService(st)
	ctx := context.Background()
	adminActor := store.Actor{Name: "admin-auditor"}

	// 1. Audit an event
	err := st.Tx(ctx, func(q *db.Queries) error {
		return store.Audit(ctx, q, store.Event{
			Actor:      adminActor,
			Action:     "test.action",
			ObjectType: "test",
			ObjectID:   "123",
			Details:    map[string]any{"key": "value"},
		})
	})
	if err != nil {
		t.Fatalf("Audit event failed: %v", err)
	}

	// 2. List events
	events, err := svc.ListEvents(ctx, ListAuditEventsParams{
		Action: "test.action",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("ListEvents failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].Action != "test.action" || events[0].ActorName != "admin-auditor" {
		t.Fatalf("unexpected event: %+v", events[0])
	}

	// 3. Verify audit chain
	ver, err := svc.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ver.OK {
		t.Fatalf("expected audit chain to be valid, reason: %s", ver.Reason)
	}
	if ver.Events != 1 {
		t.Fatalf("expected 1 event verified, got %d", ver.Events)
	}

	// 4. Seal audit chain on already sealed chain returns error
	_, err = svc.Seal(ctx, adminActor)
	if err == nil {
		t.Fatalf("expected error sealing already sealed chain")
	}
}
