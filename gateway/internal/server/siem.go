package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/services"
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
	cfg, st, err := s.SIEM.GetSettings(ctx)
	if err != nil {
		return fromService(err, "siem")
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

	_, err := s.SIEM.SetSettings(ctx, p.actor(), services.SIEMSettingsInput{
		Enabled:     req.Enabled,
		SinkType:    req.SinkType,
		Endpoint:    req.Endpoint,
		Format:      req.Format,
		AuthHeader:  req.AuthHeader,
		TLSInsecure: req.TLSInsecure,
		TLSCACert:   req.TLSCACert,
	})
	if err != nil {
		return fromService(err, "siem")
	}

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

	res, err := s.SIEM.Test(ctx, p.actor(), services.SIEMSettingsInput{
		Enabled:     req.Enabled,
		SinkType:    req.SinkType,
		Endpoint:    req.Endpoint,
		Format:      req.Format,
		AuthHeader:  req.AuthHeader,
		TLSInsecure: req.TLSInsecure,
		TLSCACert:   req.TLSCACert,
	})
	if err != nil {
		return fromService(err, "siem")
	}

	return ok(w, siemTestResponse{
		OK:      res.OK,
		Message: res.Message,
	})
}

// SIEMLoop continuously ships audit events to static sinks and dynamic SIEM target.
func (s *Server) SIEMLoop(ctx context.Context) {
	s.SIEM.ForwardLoop(ctx, s.StaticSinks)
}

func (s *Server) triggerSIEM() {
	s.SIEM.Trigger()
}

func (s *Server) siemNotifyChan() <-chan struct{} {
	return s.SIEM.NotifyChan()
}
