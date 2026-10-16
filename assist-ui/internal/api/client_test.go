package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientRequestSupport(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/providers":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"local": true,
				"oidc": map[string]string{
					"name":      "Keycloak SSO",
					"login_url": "/api/v1/auth/oidc/login",
				},
			})

		case "/api/v1/support/request":
			var req RequestSupportReq
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.TargetName != "CORP\\micaela" {
				t.Errorf("unexpected TargetName: %s", req.TargetName)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(SupportSessionDTO{
				ID:               "sess-1234",
				Token:            "test-token-abcdef",
				TargetName:       req.TargetName,
				VerificationCode: "501986",
				Status:           "pending",
			})

		case "/api/v1/support/status/test-token-abcdef":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(SupportStatusDTO{
				ID:         "sess-1234",
				Token:      "test-token-abcdef",
				TargetName: "CORP\\micaela",
				Status:     "active",
			})

		case "/api/v1/support/end/test-token-abcdef":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ended"})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	client := NewClient(mockServer.URL)
	ctx := context.Background()

	// 1. Check providers
	providers, err := client.GetAuthProviders(ctx)
	if err != nil {
		t.Fatalf("failed to get auth providers: %v", err)
	}
	if !providers.Local || providers.OIDC == nil || providers.OIDC.Name != "Keycloak SSO" {
		t.Fatalf("unexpected providers: %+v", providers)
	}

	// 2. Request support
	req := RequestSupportReq{
		TargetName:  "CORP\\micaela",
		Reason:      "Software update issue",
		Ticket:      "INC-001",
		AccountType: "ad",
		Domain:      "CORP",
	}
	sess, err := client.RequestSupport(ctx, req)
	if err != nil {
		t.Fatalf("failed to request support: %v", err)
	}
	if sess.VerificationCode != "501986" || sess.Token != "test-token-abcdef" {
		t.Fatalf("unexpected session response: %+v", sess)
	}

	// 3. Get status
	status, err := client.GetStatus(ctx, sess.Token)
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if status.Status != "active" {
		t.Fatalf("expected active status, got %s", status.Status)
	}

	// 4. End session
	err = client.EndSession(ctx, sess.Token)
	if err != nil {
		t.Fatalf("failed to end session: %v", err)
	}
}
