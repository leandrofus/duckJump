package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestAccessRequestService_Lifecycle(t *testing.T) {
	st := newTestStore(t)
	userSvc := NewUserService(st)
	connSvc := NewConnectionService(st)
	polSvc := NewPolicyService(st)
	reqSvc := NewAccessRequestService(st, polSvc)

	ctx := context.Background()
	adminActor := store.Actor{Name: "test-admin"}

	// Seed user and connection
	u, err := userSvc.Create(ctx, CreateUserParams{
		Username:    "requester",
		DisplayName: "Requester User",
		Role:        "user",
		Password:    "TestPassword123!",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	adminUser, err := userSvc.Create(ctx, CreateUserParams{
		Username:    "admin",
		DisplayName: "Admin User",
		Role:        "admin",
		Password:    "TestPassword123!",
		Actor:       adminActor,
	})
	if err != nil {
		t.Fatalf("Create admin user failed: %v", err)
	}

	c, err := connSvc.Create(ctx, CreateConnectionParams{
		Name:     "Test-Server",
		Protocol: "ssh",
		Host:     "10.0.0.1",
		Actor:    adminActor,
	})
	if err != nil {
		t.Fatalf("Create connection failed: %v", err)
	}

	userActor := store.Actor{Name: u.Username}

	// 1. Validation error: missing reason
	now := time.Now()
	_, err = reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if !errors.Is(err, ErrAccessRequestReasonRequired) {
		t.Fatalf("expected ErrAccessRequestReasonRequired, got %v", err)
	}

	// 2. Validation error: ends_at before starts_at
	_, err = reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "Need DB maintenance",
		StartsAt:   now.Add(2 * time.Hour),
		EndsAt:     now.Add(1 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if !errors.Is(err, ErrAccessRequestEndsAtBeforeStartsAt) {
		t.Fatalf("expected ErrAccessRequestEndsAtBeforeStartsAt, got %v", err)
	}

	// 3. Validation error: no permissions requested
	_, err = reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "Need DB maintenance",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: false,
		Actor:      userActor,
	})
	if !errors.Is(err, ErrAccessRequestNoPermissions) {
		t.Fatalf("expected ErrAccessRequestNoPermissions, got %v", err)
	}

	// 4. Create valid access request
	req1, err := reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Ticket:     "TICK-101",
		Reason:     "Production DB upgrade",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if err != nil {
		t.Fatalf("Create access request failed: %v", err)
	}
	if req1.Status != "pending" || req1.Ticket != "TICK-101" {
		t.Fatalf("unexpected request properties: %+v", req1)
	}

	// 5. Duplicate pending request should fail
	_, err = reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "Another request for same conn",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if !errors.Is(err, ErrAccessRequestAlreadyPending) {
		t.Fatalf("expected ErrAccessRequestAlreadyPending, got %v", err)
	}

	// 6. Approve request
	approved, policyID, err := reqSvc.Approve(ctx, adminActor, req1.ID, adminUser.ID, "Looks good, approved.")
	if err != nil {
		t.Fatalf("Approve request failed: %v", err)
	}
	if approved.Status != "approved" || policyID == "" {
		t.Fatalf("unexpected approved request: %+v, policyID: %s", approved, policyID)
	}

	// Verify policy was created in database
	pol, err := polSvc.Get(ctx, policyID)
	if err != nil {
		t.Fatalf("Get generated policy failed: %v", err)
	}
	if pol.SubjectID != u.ID || pol.ObjectRef != c.Connection.ID || !pol.CanConnect {
		t.Fatalf("unexpected policy created: %+v", pol)
	}

	// 7. Approve again should fail with not pending
	_, _, err = reqSvc.Approve(ctx, adminActor, req1.ID, adminUser.ID, "")
	var notPendingErr *AccessRequestNotPendingError
	if !errors.As(err, &notPendingErr) {
		t.Fatalf("expected AccessRequestNotPendingError, got %v", err)
	}

	// 8. Create another request to test rejection
	req2, err := reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "Emergency fix",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if err != nil {
		t.Fatalf("Create request 2 failed: %v", err)
	}

	rejected, err := reqSvc.Reject(ctx, adminActor, req2.ID, adminUser.ID, "Denied by security policy")
	if err != nil {
		t.Fatalf("Reject request failed: %v", err)
	}
	if rejected.Status != "rejected" {
		t.Fatalf("unexpected status: %s", rejected.Status)
	}

	// 9. Create another request to test cancel
	req3, err := reqSvc.Create(ctx, CreateAccessRequestParams{
		UserID:     u.ID,
		ObjectType: "connection",
		ObjectRef:  c.Connection.ID,
		Reason:     "Misclick request",
		StartsAt:   now,
		EndsAt:     now.Add(2 * time.Hour),
		CanConnect: true,
		Actor:      userActor,
	})
	if err != nil {
		t.Fatalf("Create request 3 failed: %v", err)
	}

	canceled, err := reqSvc.Cancel(ctx, userActor, req3.ID, u.ID, false)
	if err != nil {
		t.Fatalf("Cancel request failed: %v", err)
	}
	if canceled.Status != "canceled" {
		t.Fatalf("unexpected status: %s", canceled.Status)
	}

	// 10. Targets
	targets, err := reqSvc.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets failed: %v", err)
	}
	if len(targets.Connections) == 0 {
		t.Fatalf("expected at least 1 target connection")
	}

	// 11. ListEnriched & GetEnriched
	enrichedList, err := reqSvc.ListEnriched(ctx, u.ID, "")
	if err != nil {
		t.Fatalf("ListEnriched failed: %v", err)
	}
	if len(enrichedList) == 0 {
		t.Fatalf("expected at least 1 enriched request")
	}
	if enrichedList[0].UserUsername != u.Username {
		t.Fatalf("expected username %s, got %s", u.Username, enrichedList[0].UserUsername)
	}

	singleEnriched, err := reqSvc.GetEnriched(ctx, req1.ID)
	if err != nil {
		t.Fatalf("GetEnriched failed: %v", err)
	}
	if singleEnriched.Request.ID != req1.ID {
		t.Fatalf("ID mismatch: %s vs %s", singleEnriched.Request.ID, req1.ID)
	}
}

