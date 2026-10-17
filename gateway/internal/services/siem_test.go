package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func TestSIEMService(t *testing.T) {
	st := newTestStore(t)
	siemSvc := NewSIEMService(st)
	ctx := context.Background()

	adminActor := store.Actor{
		ID:   "admin-1",
		Name: "admin",
		IP:   "127.0.0.1",
	}

	// 1. Initial settings
	cfg, stats, err := siemSvc.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if cfg.Enabled {
		t.Fatalf("expected disabled initially")
	}
	if cfg.Format != "json" || cfg.SinkType != "syslog" {
		t.Fatalf("unexpected defaults: format=%s sink=%s", cfg.Format, cfg.SinkType)
	}
	if stats.TotalExported != 0 {
		t.Fatalf("expected 0 total exported, got %d", stats.TotalExported)
	}

	// 2. Set settings with enabled=true but no endpoint -> error
	_, err = siemSvc.SetSettings(ctx, adminActor, SIEMSettingsInput{
		Enabled:  true,
		Endpoint: "",
	})
	if !errors.Is(err, ErrSIEMEndpointRequired) {
		t.Fatalf("expected ErrSIEMEndpointRequired, got %v", err)
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

	res, err := siemSvc.Test(ctx, adminActor, SIEMSettingsInput{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   mockSIEM.URL,
		Format:     "cef",
		AuthHeader: "Splunk my-secret-token",
	})
	if err != nil {
		t.Fatalf("Test endpoint returned error: %v", err)
	}
	if !res.OK {
		t.Fatalf("Test endpoint not OK: %s", res.Message)
	}
	if receivedAuth != "Splunk my-secret-token" {
		t.Fatalf("unexpected received auth: %s", receivedAuth)
	}
	if !strings.HasPrefix(string(receivedBody), "CEF:0|DuckJump|Bastion|") {
		t.Fatalf("expected CEF format, got: %s", string(receivedBody))
	}

	// 4. Save settings
	savedCfg, err := siemSvc.SetSettings(ctx, adminActor, SIEMSettingsInput{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   mockSIEM.URL,
		Format:     "cef",
		AuthHeader: "Splunk my-secret-token",
	})
	if err != nil {
		t.Fatalf("SetSettings failed: %v", err)
	}
	if !savedCfg.Enabled || savedCfg.Endpoint != mockSIEM.URL || savedCfg.Format != "cef" {
		t.Fatalf("unexpected saved config: %+v", savedCfg)
	}

	// 5. Test with empty request uses saved config
	res2, err := siemSvc.Test(ctx, adminActor, SIEMSettingsInput{})
	if err != nil {
		t.Fatalf("Test with empty input failed: %v", err)
	}
	if !res2.OK {
		t.Fatalf("Test with saved config not OK: %s", res2.Message)
	}

	// 6. Update settings preserving masked auth header
	updatedCfg, err := siemSvc.SetSettings(ctx, adminActor, SIEMSettingsInput{
		Enabled:    true,
		SinkType:   "webhook",
		Endpoint:   mockSIEM.URL,
		Format:     "json",
		AuthHeader: "Splunk **** (masked)",
	})
	if err != nil {
		t.Fatalf("SetSettings with masked auth failed: %v", err)
	}
	if updatedCfg.AuthHeader != "Splunk my-secret-token" {
		t.Fatalf("expected preserved auth header, got %q", updatedCfg.AuthHeader)
	}
}
