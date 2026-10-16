package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSupportSessionLifecycle(t *testing.T) {
	e := newEnv(t)
	admin := e.as("root")

	// 1. Create a support session as admin
	createBody := map[string]any{
		"target_name": "Test Client Workstation",
		"reason":      "Urgent assistance needed with VPN config",
		"ticket":      "INC-12345",
		"ttl_minutes": 15,
	}
	var session supportSessionDTO
	admin.do("POST", "/support/sessions", createBody, http.StatusCreated, &session)

	if session.ID == "" || session.Token == "" {
		t.Fatalf("expected non-empty ID and Token, got id=%q token=%q", session.ID, session.Token)
	}
	if session.Status != "pending" {
		t.Fatalf("expected pending status, got %q", session.Status)
	}
	if session.TargetName != "Test Client Workstation" {
		t.Fatalf("unexpected target_name %q", session.TargetName)
	}

	// 2. Fetch public join endpoint using the token (unauthenticated)
	pubClient := e.client()
	resp, body := pubClient.raw("GET", "/../../support/join/"+session.Token, nil, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /support/join, got %d: %s", resp.StatusCode, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "duckJump Assist") || !strings.Contains(bodyStr, "curl -fsSL") {
		t.Fatalf("expected HTML landing page with duckJump Assist and curl command, got: %s", bodyStr)
	}

	// 2b. Test JSON response when requested
	req, _ := http.NewRequest("GET", e.srv.URL+"/support/join/"+session.Token, nil)
	req.Header.Set("Accept", "application/json")
	jsonResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to GET json: %v", err)
	}
	defer jsonResp.Body.Close()
	if jsonResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /support/join json, got %d", jsonResp.StatusCode)
	}
	var jsonBody map[string]any
	if err := json.NewDecoder(jsonResp.Body).Decode(&jsonBody); err != nil {
		t.Fatalf("failed to decode json body: %v", err)
	}
	if jsonBody["curl_command"] == nil {
		t.Fatalf("expected curl_command in json body")
	}

	// 2c. Test launch.sh endpoint
	respLaunch, bodyLaunch := pubClient.raw("GET", "/../../support/launch.sh?token="+session.Token, nil, false)
	if respLaunch.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on launch.sh, got %d: %s", respLaunch.StatusCode, bodyLaunch)
	}
	bodyLaunchStr := string(bodyLaunch)
	if !strings.Contains(bodyLaunchStr, session.Token) || !strings.Contains(bodyLaunchStr, "duckjump-assist") {
		t.Fatalf("launch script missing token or binary reference: %s", bodyLaunchStr)
	}

	// 2d. Test run.ps1 endpoint
	respPs1, bodyPs1 := pubClient.raw("GET", "/../../support/run.ps1?token="+session.Token, nil, false)
	if respPs1.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on run.ps1, got %d: %s", respPs1.StatusCode, bodyPs1)
	}
	bodyPs1Str := string(bodyPs1)
	if !strings.Contains(bodyPs1Str, session.Token) {
		t.Fatalf("powershell script missing token: %s", bodyPs1Str)
	}

	// 3. Retrieve session via API
	var fetchedSession supportSessionDTO
	admin.do("GET", "/support/sessions/"+session.ID, nil, http.StatusOK, &fetchedSession)
	if fetchedSession.ID != session.ID {
		t.Fatalf("expected ID %q, got %q", session.ID, fetchedSession.ID)
	}

	// 4. Test invalid TOTP code
	badTotpBody := map[string]string{"code": "000000"}
	admin.do("POST", "/support/sessions/"+session.ID+"/verify-totp", badTotpBody, http.StatusBadRequest, nil)

	// 5. Test valid verification code
	dbSess, err := e.st.Q.GetSupportSession(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("failed to get session from DB: %v", err)
	}

	validCode := dbSess.TotpSecret
	validTotpBody := map[string]string{"code": validCode}
	var verifiedSession supportSessionDTO
	admin.do("POST", "/support/sessions/"+session.ID+"/verify-totp", validTotpBody, http.StatusOK, &verifiedSession)

	if verifiedSession.Status != "active" {
		t.Fatalf("expected active status, got %q", verifiedSession.Status)
	}

	// 6. End support session
	admin.do("POST", "/support/sessions/"+session.ID+"/end", nil, http.StatusOK, nil)

	// 7. Verify status is ended
	endedDbSess, err := e.st.Q.GetSupportSession(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("failed to fetch ended session: %v", err)
	}
	if endedDbSess.Status != "ended" {
		t.Fatalf("expected status ended, got %q", endedDbSess.Status)
	}
}
