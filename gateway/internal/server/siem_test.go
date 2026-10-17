package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSIEM_SettingsAndTestEndpoint(t *testing.T) {
	e := newEnv(t)
	e.mkUser("admin", "admin")
	e.mkUser("ana", "user")

	root := e.as("root")
	ana := e.as("ana")

	// 1. Ana (non-admin) gets 403 Forbidden
	ana.do("GET", "/settings/siem", nil, 403, nil)

	// 2. Root gets initial settings
	var initial siemSettingsDTO
	root.do("GET", "/settings/siem", nil, 200, &initial)
	if initial.Enabled {
		t.Fatalf("expected SIEM to be disabled initially")
	}

	// 3. Test endpoint against mock HTTP server
	var receivedAuth string
	var receivedBody []byte
	mockSIEM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockSIEM.Close()

	var testResp siemTestResponse
	root.do("POST", "/settings/siem/test", siemSettingsRequest{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   mockSIEM.URL,
		Format:     "cef",
		AuthHeader: "Splunk test-token-1234",
	}, 200, &testResp)

	if !testResp.OK {
		t.Fatalf("test request failed: %s", testResp.Message)
	}
	if receivedAuth != "Splunk test-token-1234" {
		t.Fatalf("unexpected auth header: %q", receivedAuth)
	}
	if !strings.HasPrefix(string(receivedBody), "CEF:0|DuckJump|Bastion|") {
		t.Fatalf("expected CEF formatted body, got: %q", string(receivedBody))
	}

	// 4. Save settings
	var saved siemSettingsDTO
	root.do("PUT", "/settings/siem", siemSettingsRequest{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   mockSIEM.URL,
		Format:     "cef",
		AuthHeader: "Splunk test-token-1234",
	}, 200, &saved)

	if !saved.Enabled || saved.Endpoint != mockSIEM.URL || saved.Format != "cef" {
		t.Fatalf("saved settings mismatch: %+v", saved)
	}
	if saved.AuthHeader != "Splunk ****" {
		t.Fatalf("expected masked auth header, got %q", saved.AuthHeader)
	}

	// 5. Test using saved config (empty request body)
	var testResp2 siemTestResponse
	root.do("POST", "/settings/siem/test", map[string]any{}, 200, &testResp2)
	if !testResp2.OK {
		t.Fatalf("test using saved config failed: %s", testResp2.Message)
	}

	// 6. Verify audit event was logged
	var events []struct {
		Action string          `json:"action"`
		Object string          `json:"object_type"`
		Detail json.RawMessage `json:"details"`
	}
	root.do("GET", "/audit/events?action=settings.siem_updated", nil, 200, &events)
	if len(events) == 0 {
		t.Fatalf("expected settings.siem_updated audit event")
	}
}
