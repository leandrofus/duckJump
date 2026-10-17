package services

import (
	"context"
	"errors"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

type mockSupportNotifier struct {
	closedTokens []string
	closedIDs    []string
	verifiedIDs  []string
}

func (m *mockSupportNotifier) CloseAndUnregisterByToken(token string) {
	m.closedTokens = append(m.closedTokens, token)
}

func (m *mockSupportNotifier) CloseAndUnregisterByID(id string) {
	m.closedIDs = append(m.closedIDs, id)
}

func (m *mockSupportNotifier) NotifyVerified(id string) {
	m.verifiedIDs = append(m.verifiedIDs, id)
}

func TestSupportService(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	notifier := &mockSupportNotifier{}
	svc := NewSupportService(st, notifier)

	userSvc := NewUserService(st)
	u, err := userSvc.Create(ctx, CreateUserParams{
		Username:   "admin",
		Password:   "password1234",
		Role:       "superadmin",
		CallerRole: "superadmin",
		Actor:      store.Actor{Name: "cli"},
	})
	if err != nil {
		t.Fatalf("Create user failed: %v", err)
	}

	adminActor := store.Actor{
		ID:   u.ID,
		Name: u.Username,
	}

	// 1. CreateSession fails without target_name
	_, err = svc.CreateSession(ctx, adminActor, u.ID, CreateSupportSessionParams{})
	if !errors.Is(err, ErrTargetNameRequired) {
		t.Fatalf("expected ErrTargetNameRequired, got %v", err)
	}

	// 2. CreateSession success
	sess, err := svc.CreateSession(ctx, adminActor, u.ID, CreateSupportSessionParams{
		TargetName: "Client Workstation 1",
		Reason:     "VPN issue",
		Ticket:     "INC-100",
		TTLMinutes: 20,
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sess.ID == "" || sess.Token == "" || sess.Status != "pending" {
		t.Fatalf("unexpected created session: %+v", sess)
	}

	// 3. GetSession
	gotSess, err := svc.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if gotSess.ID != sess.ID || gotSess.TargetName != "Client Workstation 1" {
		t.Fatalf("unexpected got session: %+v", gotSess)
	}

	// 4. ListSessions
	list, err := svc.ListSessions(ctx, u.ID, "pending")
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(list) != 1 || list[0].ID != sess.ID {
		t.Fatalf("unexpected list: %+v", list)
	}

	// 5. GetStatusByToken
	byToken, err := svc.GetStatusByToken(ctx, sess.Token)
	if err != nil {
		t.Fatalf("GetStatusByToken failed: %v", err)
	}
	if byToken.ID != sess.ID {
		t.Fatalf("token lookup mismatch: %+v", byToken)
	}

	// 6. VerifyTOTP with invalid code
	_, err = svc.VerifyTOTP(ctx, adminActor, sess.ID, "999999")
	if !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("expected ErrInvalidVerificationCode, got %v", err)
	}

	// 7. VerifyTOTP with valid code (TotpSecret)
	verified, err := svc.VerifyTOTP(ctx, adminActor, sess.ID, sess.TotpSecret)
	if err != nil {
		t.Fatalf("VerifyTOTP with valid code failed: %v", err)
	}
	if verified.Status != "active" {
		t.Fatalf("expected status active, got %s", verified.Status)
	}
	if len(notifier.verifiedIDs) != 1 || notifier.verifiedIDs[0] != sess.ID {
		t.Fatalf("expected notifier.NotifyVerified to be called with %s", sess.ID)
	}

	// 8. EndSession
	ended, err := svc.EndSession(ctx, adminActor, sess.ID)
	if err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}
	if ended.Status != "ended" {
		t.Fatalf("expected status ended, got %s", ended.Status)
	}
	if len(notifier.closedIDs) != 1 || notifier.closedIDs[0] != sess.ID {
		t.Fatalf("expected notifier.CloseAndUnregisterByID to be called with %s", sess.ID)
	}

	// 9. RequestSession from desktop client
	reqSess, code, err := svc.RequestSession(ctx, adminActor, u.ID, "alice", RequestSupportSessionParams{
		TargetName: "alice",
		Reason:     "Need software install",
		Ticket:     "T-200",
		Domain:     "CORP",
	})
	if err != nil {
		t.Fatalf("RequestSession failed: %v", err)
	}
	if reqSess.TargetName != "CORP\\alice" {
		t.Fatalf("expected domain formatted target CORP\\alice, got %s", reqSess.TargetName)
	}
	if code == "" || reqSess.TotpSecret != code {
		t.Fatalf("unexpected code: %s vs %s", code, reqSess.TotpSecret)
	}

	// 10. EndByToken
	err = svc.EndByToken(ctx, reqSess.Token)
	if err != nil {
		t.Fatalf("EndByToken failed: %v", err)
	}
	endedReq, err := svc.GetStatusByToken(ctx, reqSess.Token)
	if err != nil {
		t.Fatalf("GetStatusByToken after end failed: %v", err)
	}
	if endedReq.Status != "ended" {
		t.Fatalf("expected status ended, got %s", endedReq.Status)
	}
	if len(notifier.closedTokens) != 1 || notifier.closedTokens[0] != reqSess.Token {
		t.Fatalf("expected notifier.CloseAndUnregisterByToken to be called with %s", reqSess.Token)
	}

	// 11. MarkConnected and ReleaseSession
	sess3, err := svc.CreateSession(ctx, adminActor, u.ID, CreateSupportSessionParams{
		TargetName: "bob",
		Reason:     "Check release",
		TTLMinutes: 30,
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if err := svc.MarkConnected(ctx, sess3.ID, "127.0.0.1", "linux", "workstation"); err != nil {
		t.Fatalf("MarkConnected failed: %v", err)
	}
	connected, err := svc.GetSession(ctx, sess3.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if connected.Status != "connected" || connected.ClientHostname != "workstation" {
		t.Fatalf("expected connected status and workstation hostname, got %s / %s", connected.Status, connected.ClientHostname)
	}

	oldCode := connected.TotpSecret
	if err := svc.ReleaseSession(ctx, connected); err != nil {
		t.Fatalf("ReleaseSession failed: %v", err)
	}
	released, err := svc.GetSession(ctx, sess3.ID)
	if err != nil {
		t.Fatalf("GetSession after release failed: %v", err)
	}
	if released.Status != "pending" {
		t.Fatalf("expected status pending after release, got %s", released.Status)
	}
	if released.TotpSecret == oldCode {
		t.Fatalf("expected new verification code after release")
	}
}
