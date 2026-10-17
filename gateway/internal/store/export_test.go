package store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSIEM_Formatters(t *testing.T) {
	now := time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC)
	ev := ExportedEvent{
		ID:         42,
		TS:         now,
		ActorID:    "u-123",
		ActorName:  "ana",
		ActorIP:    "192.168.1.100",
		Action:     "auth.login_failed",
		ObjectType: "user",
		ObjectID:   "u-123",
		Details:    json.RawMessage(`{"reason":"bad password"}`),
	}

	// 1. CEF Format
	cef := FormatCEF(ev)
	if !strings.HasPrefix(cef, "CEF:0|DuckJump|Bastion|1.0|auth.login_failed|auth login_failed|8|") {
		t.Fatalf("unexpected CEF prefix: %q", cef)
	}
	if !strings.Contains(cef, "src=192.168.1.100") || !strings.Contains(cef, "suser=ana") {
		t.Fatalf("CEF missing user or ip: %q", cef)
	}
	if !strings.HasSuffix(cef, "\n") {
		t.Fatalf("CEF must end with newline")
	}

	// 2. RFC 5424 Format
	rfc := FormatRFC5424(ev, "bastion.corp.local")
	if !strings.HasPrefix(rfc, "<86>1 2026-10-17T02:00:00.000000Z bastion.corp.local duckjump-gw") {
		t.Fatalf("unexpected RFC5424 prefix: %q", rfc)
	}
	if !strings.Contains(rfc, `[duckjump@4823 id="42" action="auth.login_failed" actor="ana" ip="192.168.1.100"]`) {
		t.Fatalf("RFC5424 missing structured data: %q", rfc)
	}

	// 3. JSON Format
	jsonBytes := FormatEvent(ev, "json", "")
	var parsed ExportedEvent
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if parsed.ID != 42 || parsed.ActorName != "ana" {
		t.Fatalf("parsed json mismatch: %+v", parsed)
	}
}

func TestSIEM_HTTPWriter(t *testing.T) {
	var receivedBody []byte
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := OpenAuditSinkWithOptions(srv.URL, SinkOptions{
		AuthHeader: "Bearer test-secret-token",
	})
	if err != nil {
		t.Fatalf("OpenAuditSinkWithOptions: %v", err)
	}
	defer sink.Close()

	testMsg := []byte("hello SIEM")
	n, err := sink.Write(testMsg)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(testMsg) {
		t.Fatalf("wrote %d bytes, want %d", n, len(testMsg))
	}
	if receivedAuth != "Bearer test-secret-token" {
		t.Fatalf("expected auth header Bearer test-secret-token, got %q", receivedAuth)
	}
	if !bytes.Equal(receivedBody, testMsg) {
		t.Fatalf("expected body %q, got %q", string(testMsg), string(receivedBody))
	}
}

func TestSIEM_StoreConfigAndStats(t *testing.T) {
	st := open(t)
	ctx := context.Background()

	// Initial config should be empty
	cfg, err := st.GetSIEMConfig(ctx)
	if err != nil {
		t.Fatalf("GetSIEMConfig: %v", err)
	}
	if cfg.Enabled {
		t.Fatalf("expected SIEM to be disabled initially")
	}

	// Save new config
	err = st.SetSIEMConfig(ctx, SIEMConfig{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   "https://siem.corp.internal/api/events",
		Format:     "cef",
		AuthHeader: "Bearer splunk-token",
	}, Actor{Name: "admin"})
	if err != nil {
		t.Fatalf("SetSIEMConfig: %v", err)
	}

	cfg, err = st.GetSIEMConfig(ctx)
	if err != nil {
		t.Fatalf("GetSIEMConfig after save: %v", err)
	}
	if !cfg.Enabled || cfg.Format != "cef" || cfg.AuthHeader != "Bearer splunk-token" {
		t.Fatalf("unexpected saved config: %+v", cfg)
	}

	// Update stats
	now := time.Now().UTC()
	err = st.SetSIEMStats(ctx, SIEMStats{
		LastExportedAt: &now,
		LastExportedID: 100,
		TotalExported:  50,
	})
	if err != nil {
		t.Fatalf("SetSIEMStats: %v", err)
	}

	stats, err := st.GetSIEMStats(ctx)
	if err != nil {
		t.Fatalf("GetSIEMStats: %v", err)
	}
	if stats.LastExportedID != 100 || stats.TotalExported != 50 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}
