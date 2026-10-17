package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

// openapi:schema SIEMStats
// type: object
// properties:
//   last_exported_at: { type: string, format: date-time }
//   last_exported_id: { type: integer }
//   total_exported: { type: integer }
//   last_error: { type: string }
//   last_error_at: { type: string, format: date-time }

type siemStatsDTO struct {
	LastExportedAt *time.Time `json:"last_exported_at,omitempty"`
	LastExportedID int64      `json:"last_exported_id"`
	TotalExported  int64      `json:"total_exported"`
	LastError      string     `json:"last_error,omitempty"`
	LastErrorAt    *time.Time `json:"last_error_at,omitempty"`
}

// openapi:schema SIEMSettings
// type: object
// required: [enabled, sink_type, endpoint, format]
// properties:
//   enabled: { type: boolean }
//   sink_type: { type: string, enum: [syslog, webhook, file] }
//   endpoint: { type: string, description: 'Destination URL (e.g. syslog+tls://siem:6514, https://splunk:8088/services/collector, file:///var/log/audit.jsonl)' }
//   format: { type: string, enum: [json, cef, rfc5424] }
//   auth_header: { type: string, description: 'Masked auth header (e.g. Bearer ****)' }
//   has_auth_header: { type: boolean }
//   tls_insecure: { type: boolean }
//   tls_ca_cert: { type: string }
//   status: { $ref: '#/components/schemas/SIEMStats' }

type siemSettingsDTO struct {
	Enabled       bool         `json:"enabled"`
	SinkType      string       `json:"sink_type"`
	Endpoint      string       `json:"endpoint"`
	Format        string       `json:"format"`
	AuthHeader    string       `json:"auth_header,omitempty"`
	HasAuthHeader bool         `json:"has_auth_header"`
	TLSInsecure   bool         `json:"tls_insecure"`
	TLSCACert     string       `json:"tls_ca_cert,omitempty"`
	Status        siemStatsDTO `json:"status"`
}

// openapi:schema SIEMSettingsRequest
// type: object
// required: [enabled, sink_type, endpoint, format]
// properties:
//   enabled: { type: boolean }
//   sink_type: { type: string, enum: [syslog, webhook, file] }
//   endpoint: { type: string }
//   format: { type: string, enum: [json, cef, rfc5424] }
//   auth_header: { type: string }
//   tls_insecure: { type: boolean }
//   tls_ca_cert: { type: string }

type siemSettingsRequest struct {
	Enabled     bool   `json:"enabled"`
	SinkType    string `json:"sink_type"`
	Endpoint    string `json:"endpoint"`
	Format      string `json:"format"`
	AuthHeader  string `json:"auth_header"`
	TLSInsecure bool   `json:"tls_insecure"`
	TLSCACert   string `json:"tls_ca_cert"`
}

// openapi:schema SIEMTestResponse
// type: object
// required: [ok, message]
// properties:
//   ok: { type: boolean }
//   message: { type: string }

type siemTestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func maskAuth(h string) string {
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 {
		return parts[0] + " ****"
	}
	return "****"
}

// openapi:operation
// summary: Get SIEM forwarding configuration and stats
// tags: [settings]
// responses:
//   '200': { description: Current SIEM settings, schema: SIEMSettings }

func (s *Server) getSIEMSettings(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	cfg, err := s.Store.GetSIEMConfig(ctx)
	if err != nil {
		return err
	}
	st, err := s.Store.GetSIEMStats(ctx)
	if err != nil {
		return err
	}

	if cfg.Format == "" {
		cfg.Format = "json"
	}
	if cfg.SinkType == "" {
		cfg.SinkType = "syslog"
	}

	dto := siemSettingsDTO{
		Enabled:       cfg.Enabled,
		SinkType:      cfg.SinkType,
		Endpoint:      cfg.Endpoint,
		Format:        cfg.Format,
		AuthHeader:    maskAuth(cfg.AuthHeader),
		HasAuthHeader: cfg.AuthHeader != "",
		TLSInsecure:   cfg.TLSInsecure,
		TLSCACert:     cfg.TLSCACert,
		Status: siemStatsDTO{
			LastExportedAt: st.LastExportedAt,
			LastExportedID: st.LastExportedID,
			TotalExported:  st.TotalExported,
			LastError:      st.LastError,
			LastErrorAt:    st.LastErrorAt,
		},
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Update SIEM forwarding configuration
// tags: [settings]
// requestBody: { schema: SIEMSettingsRequest }
// responses:
//   '200': { description: Updated SIEM settings, schema: SIEMSettings }

func (s *Server) setSIEMSettings(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	var req siemSettingsRequest
	if err := decode(r, &req); err != nil {
		return err
	}

	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.SinkType = strings.ToLower(strings.TrimSpace(req.SinkType))
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))

	if req.Enabled && req.Endpoint == "" {
		return badRequest("endpoint is required when SIEM forwarding is enabled")
	}

	switch req.Format {
	case "json", "cef", "rfc5424":
	default:
		req.Format = "json"
	}

	switch req.SinkType {
	case "syslog", "webhook", "file":
	default:
		req.SinkType = "syslog"
	}

	// Preserve existing auth header if masked or left blank
	cur, _ := s.Store.GetSIEMConfig(ctx)
	finalAuth := strings.TrimSpace(req.AuthHeader)
	if finalAuth == "" || strings.Contains(finalAuth, "****") {
		finalAuth = cur.AuthHeader
	}

	newCfg := store.SIEMConfig{
		Enabled:     req.Enabled,
		SinkType:    req.SinkType,
		Endpoint:    req.Endpoint,
		Format:      req.Format,
		AuthHeader:  finalAuth,
		TLSInsecure: req.TLSInsecure,
		TLSCACert:   strings.TrimSpace(req.TLSCACert),
	}

	if err := s.Store.SetSIEMConfig(ctx, newCfg, p.actor()); err != nil {
		return err
	}

	s.triggerSIEM()
	return s.getSIEMSettings(w, r, p)
}

// openapi:operation
// summary: Test SIEM endpoint connectivity by sending a test audit event
// tags: [settings]
// requestBody: { schema: SIEMSettingsRequest, required: false }
// responses:
//   '200': { description: Test result, schema: SIEMTestResponse }

func (s *Server) testSIEMSettings(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	var req siemSettingsRequest
	_ = decode(r, &req)

	endpoint := strings.TrimSpace(req.Endpoint)
	authHeader := strings.TrimSpace(req.AuthHeader)
	format := strings.ToLower(strings.TrimSpace(req.Format))
	tlsInsecure := req.TLSInsecure
	tlsCACert := strings.TrimSpace(req.TLSCACert)

	// Fallback to saved config if request is empty
	if endpoint == "" {
		cur, err := s.Store.GetSIEMConfig(ctx)
		if err != nil {
			return err
		}
		endpoint = cur.Endpoint
		authHeader = cur.AuthHeader
		format = cur.Format
		tlsInsecure = cur.TLSInsecure
		tlsCACert = cur.TLSCACert
	} else if authHeader == "" || strings.Contains(authHeader, "****") {
		cur, _ := s.Store.GetSIEMConfig(ctx)
		authHeader = cur.AuthHeader
	}

	if endpoint == "" {
		return ok(w, siemTestResponse{OK: false, Message: "No endpoint specified"})
	}

	sink, err := store.OpenAuditSinkWithOptions(endpoint, store.SinkOptions{
		TLSInsecure: tlsInsecure,
		TLSCACert:   tlsCACert,
		AuthHeader:  authHeader,
	})
	if err != nil {
		return ok(w, siemTestResponse{OK: false, Message: fmt.Sprintf("Failed to initialize sink: %v", err)})
	}
	defer sink.Close()

	hostname, _ := os.Hostname()
	testEv := store.ExportedEvent{
		ID:         0,
		TS:         time.Now().UTC(),
		ActorID:    p.User.ID,
		ActorName:  p.User.Username,
		ActorIP:    p.IP,
		Action:     "audit.siem_test",
		ObjectType: "settings",
		ObjectID:   "siem",
		Details:    []byte(`{"message":"DuckJump SIEM connectivity test successful"}`),
	}

	payload := store.FormatEvent(testEv, format, hostname)
	if _, err := sink.Write(payload); err != nil {
		return ok(w, siemTestResponse{OK: false, Message: fmt.Sprintf("Failed to send test event: %v", err)})
	}

	return ok(w, siemTestResponse{
		OK:      true,
		Message: fmt.Sprintf("Test event sent successfully to %s in %s format", endpoint, strings.ToUpper(format)),
	})
}

// SIEMLoop continuously ships audit events to static sinks and dynamic SIEM target.
func (s *Server) SIEMLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var dynamicSink io.WriteCloser
	var currentEndpoint string
	var currentAuth string
	var currentFormat string
	var currentInsecure bool
	var currentCA string

	closeDynamic := func() {
		if dynamicSink != nil {
			_ = dynamicSink.Close()
			dynamicSink = nil
			currentEndpoint = ""
		}
	}
	defer closeDynamic()

	hostname, _ := os.Hostname()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.siemNotifyChan():
		}

		// 1. Check dynamic SIEM configuration
		cfg, err := s.Store.GetSIEMConfig(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Debug("siem loop get config", "err", err)
		}

		if !cfg.Enabled || cfg.Endpoint == "" {
			closeDynamic()
		} else {
			// Re-open sink if configuration changed or not connected
			if dynamicSink == nil || currentEndpoint != cfg.Endpoint || currentAuth != cfg.AuthHeader ||
				currentInsecure != cfg.TLSInsecure || currentCA != cfg.TLSCACert {
				closeDynamic()
				w, err := store.OpenAuditSinkWithOptions(cfg.Endpoint, store.SinkOptions{
					TLSInsecure: cfg.TLSInsecure,
					TLSCACert:   cfg.TLSCACert,
					AuthHeader:  cfg.AuthHeader,
				})
				if err != nil {
					slog.Warn("siem open sink error", "endpoint", cfg.Endpoint, "err", err)
					now := time.Now().UTC()
					_ = s.Store.SetSIEMStats(ctx, store.SIEMStats{
						LastError:   err.Error(),
						LastErrorAt: &now,
					})
				} else {
					dynamicSink = w
					currentEndpoint = cfg.Endpoint
					currentAuth = cfg.AuthHeader
					currentFormat = cfg.Format
					currentInsecure = cfg.TLSInsecure
					currentCA = cfg.TLSCACert
					slog.Info("connected to SIEM sink", "endpoint", cfg.Endpoint, "format", cfg.Format)
				}
			}
		}

		// If no static sinks and no dynamic sink, skip
		if len(s.StaticSinks) == 0 && dynamicSink == nil {
			continue
		}

		// 2. Export batch
		var activeSinks []io.Writer
		activeSinks = append(activeSinks, s.StaticSinks...)
		if dynamicSink != nil {
			activeSinks = append(activeSinks, dynamicSink)
		}

		format := currentFormat
		if format == "" {
			format = "json"
		}

		exported, err := s.Store.ExportOnceWithFormat(ctx, activeSinks, format, hostname)
		if err != nil && ctx.Err() == nil {
			slog.Error("siem export error", "err", err)
			now := time.Now().UTC()
			st, _ := s.Store.GetSIEMStats(ctx)
			st.LastError = err.Error()
			st.LastErrorAt = &now
			_ = s.Store.SetSIEMStats(ctx, st)
		} else if exported > 0 {
			now := time.Now().UTC()
			st, _ := s.Store.GetSIEMStats(ctx)
			st.TotalExported += int64(exported)
			st.LastExportedAt = &now
			st.LastError = ""
			st.LastErrorAt = nil
			_ = s.Store.SetSIEMStats(ctx, st)
		}
	}
}

func (s *Server) triggerSIEM() {
	s.siemMu.Lock()
	defer s.siemMu.Unlock()
	if s.siemNotify != nil {
		select {
		case s.siemNotify <- struct{}{}:
		default:
		}
	}
}

func (s *Server) siemNotifyChan() <-chan struct{} {
	s.siemMu.Lock()
	defer s.siemMu.Unlock()
	if s.siemNotify == nil {
		s.siemNotify = make(chan struct{}, 1)
	}
	return s.siemNotify
}
