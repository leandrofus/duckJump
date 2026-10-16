package server

import (
	"context"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

func TestAccessRequestsFlow(t *testing.T) {
	e := newEnv(t)
	e.mkUser("alice", "user")
	e.mkUser("bob", "user")
	e.mkUser("admin", "admin")

	root := e.as("root")
	alice := e.as("alice")
	bob := e.as("bob")
	adm := e.as("admin")

	// Create test connections
	ctx := context.Background()
	conn1ID := store.NewID()
	if err := e.st.Q.CreateConnection(ctx, db.CreateConnectionParams{
		ID: conn1ID, Name: "prod-db", Protocol: "ssh", Host: "10.0.0.1", Port: 22,
		Backend: store.BackendNative, CredentialMode: "vault", Params: "{}", Record: true, Now: store.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	conn2ID := store.NewID()
	if err := e.st.Q.CreateConnection(ctx, db.CreateConnectionParams{
		ID: conn2ID, Name: "web-srv", Protocol: "rdp", Host: "10.0.0.2", Port: 3389,
		Backend: store.BackendNative, CredentialMode: "vault", Params: "{}", Record: true, Now: store.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Targets endpoint
	var targets accessRequestTargetsDTO
	alice.do("GET", "/access-requests/targets", nil, 200, &targets)
	if len(targets.Connections) < 2 {
		t.Fatalf("expected at least 2 connections, got %d", len(targets.Connections))
	}

	// 2. Validations when creating an access request
	now := time.Now().UTC()
	start := now.Add(time.Hour)
	end := now.Add(4 * time.Hour)

	// Missing reason
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"reason":      "",
		"starts_at":   start.Format(time.RFC3339),
		"ends_at":     end.Format(time.RFC3339),
	}, 400, nil)

	// End before start
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"reason":      "Fixing database bug",
		"starts_at":   end.Format(time.RFC3339),
		"ends_at":     start.Format(time.RFC3339),
	}, 400, nil)

	// End in the past
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"reason":      "Fixing database bug",
		"starts_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"ends_at":     now.Add(-time.Hour).Format(time.RFC3339),
	}, 400, nil)

	// Invalid connection
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  store.NewID(),
		"reason":      "Fixing database bug",
		"starts_at":   start.Format(time.RFC3339),
		"ends_at":     end.Format(time.RFC3339),
	}, 404, nil)

	// 3. Alice successfully creates request for conn1ID
	var req1 accessRequestDTO
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"ticket":      "INC-999",
		"reason":      "Urgent incident INC-999 migration",
		"starts_at":   now.Add(-time.Minute).Format(time.RFC3339), // active immediately
		"ends_at":     end.Format(time.RFC3339),
		"can_connect": true,
		"can_upload":  true,
	}, 201, &req1)

	if req1.Status != "pending" {
		t.Fatalf("expected pending, got %s", req1.Status)
	}
	if req1.ObjectName != "prod-db" {
		t.Fatalf("expected object_name prod-db, got %s", req1.ObjectName)
	}
	if req1.Ticket != "INC-999" {
		t.Fatalf("expected ticket INC-999, got %s", req1.Ticket)
	}
	if req1.Reason != "Urgent incident INC-999 migration" {
		t.Fatalf("unexpected reason: %s", req1.Reason)
	}

	// Duplicate pending request for same target is rejected
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"reason":      "Duplicate request",
		"starts_at":   start.Format(time.RFC3339),
		"ends_at":     end.Format(time.RFC3339),
	}, 409, nil)

	// Alice creates request for conn2ID (to be rejected)
	var req2 accessRequestDTO
	alice.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn2ID,
		"reason":      "Access to web server",
		"starts_at":   start.Format(time.RFC3339),
		"ends_at":     end.Format(time.RFC3339),
	}, 201, &req2)

	// Bob creates request for conn1ID (to be canceled)
	var req3 accessRequestDTO
	bob.do("POST", "/access-requests", map[string]any{
		"object_type": "connection",
		"object_ref":  conn1ID,
		"reason":      "Bob needs db",
		"starts_at":   start.Format(time.RFC3339),
		"ends_at":     end.Format(time.RFC3339),
	}, 201, &req3)

	// 4. Listing requests
	// Alice only sees her own requests
	var aliceReqs []accessRequestDTO
	alice.do("GET", "/access-requests", nil, 200, &aliceReqs)
	if len(aliceReqs) != 2 {
		t.Fatalf("alice should see 2 requests, got %d", len(aliceReqs))
	}

	// Admin sees all 3 requests
	var allReqs []accessRequestDTO
	adm.do("GET", "/access-requests", nil, 200, &allReqs)
	if len(allReqs) != 3 {
		t.Fatalf("admin should see 3 requests, got %d", len(allReqs))
	}

	// 5. Non-admin cannot approve
	alice.do("POST", "/access-requests/"+req1.ID+"/approve", map[string]any{"comment": "self approve"}, 403, nil)

	// 6. Admin approves req1
	var approved1 accessRequestDTO
	adm.do("POST", "/access-requests/"+req1.ID+"/approve", map[string]any{"comment": "Approved for INC-999"}, 200, &approved1)
	if approved1.Status != "approved" {
		t.Fatalf("expected approved, got %s", approved1.Status)
	}
	if approved1.ReviewComment != "Approved for INC-999" {
		t.Fatalf("expected review comment, got %s", approved1.ReviewComment)
	}
	if approved1.CreatedPolicyID == nil || *approved1.CreatedPolicyID == "" {
		t.Fatalf("expected created policy ID to be set")
	}

	var pol policyDTO
	adm.do("GET", "/policies/"+*approved1.CreatedPolicyID, nil, 200, &pol)
	if pol.Description != "Access request [INC-999]: Urgent incident INC-999 migration" {
		t.Fatalf("unexpected policy description: %s", pol.Description)
	}

	// Alice now has access to prod-db in portal connections!
	var portalConns []portalConnectionDTO
	alice.do("GET", "/portal/connections", nil, 200, &portalConns)
	if len(portalConns) != 1 || portalConns[0].ID != conn1ID {
		t.Fatalf("alice should have access to prod-db, got: %+v", portalConns)
	}

	// Cannot approve again
	adm.do("POST", "/access-requests/"+req1.ID+"/approve", nil, 409, nil)

	// 7. Admin rejects req2
	var rejected2 accessRequestDTO
	adm.do("POST", "/access-requests/"+req2.ID+"/reject", map[string]any{"comment": "Not approved: change freeze"}, 200, &rejected2)
	if rejected2.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", rejected2.Status)
	}
	if rejected2.ReviewComment != "Not approved: change freeze" {
		t.Fatalf("expected rejection comment, got %s", rejected2.ReviewComment)
	}

	// 8. Bob cancels req3
	// Alice cannot cancel Bob's request
	alice.do("POST", "/access-requests/"+req3.ID+"/cancel", nil, 403, nil)

	// Bob cancels his own request
	var canceled3 accessRequestDTO
	bob.do("POST", "/access-requests/"+req3.ID+"/cancel", nil, 200, &canceled3)
	if canceled3.Status != "canceled" {
		t.Fatalf("expected canceled, got %s", canceled3.Status)
	}

	// Admin cannot approve a canceled request
	adm.do("POST", "/access-requests/"+req3.ID+"/approve", nil, 409, nil)

	// Verify audit events exist
	var events []auditEventDTO
	root.do("GET", "/audit/events", nil, 200, &events)
	actions := make(map[string]bool)
	for _, ev := range events {
		actions[ev.Action] = true
	}
	for _, want := range []string{"access_request.create", "access_request.approve", "access_request.reject", "access_request.cancel"} {
		if !actions[want] {
			t.Errorf("missing audit action %s", want)
		}
	}
}
