package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
)

var (
	ErrSIEMEndpointRequired = errors.New("endpoint is required when SIEM forwarding is enabled")
)

type SIEMSettingsInput struct {
	Enabled     bool
	SinkType    string
	Endpoint    string
	Format      string
	AuthHeader  string
	TLSInsecure bool
	TLSCACert   string
}

type SIEMTestResult struct {
	OK      bool
	Message string
}

type SIEMService struct {
	store      *store.Store
	siemMu     sync.Mutex
	siemNotify chan struct{}
}

func NewSIEMService(st *store.Store) *SIEMService {
	return &SIEMService{
		store:      st,
		siemNotify: make(chan struct{}, 1),
	}
}

func (s *SIEMService) GetSettings(ctx context.Context) (store.SIEMConfig, store.SIEMStats, error) {
	cfg, err := s.store.GetSIEMConfig(ctx)
	if err != nil {
		return cfg, store.SIEMStats{}, err
	}
	st, err := s.store.GetSIEMStats(ctx)
	if err != nil {
		return cfg, st, err
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	}
	if cfg.SinkType == "" {
		cfg.SinkType = "syslog"
	}
	return cfg, st, nil
}

func (s *SIEMService) SetSettings(ctx context.Context, actor store.Actor, req SIEMSettingsInput) (store.SIEMConfig, error) {
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.SinkType = strings.ToLower(strings.TrimSpace(req.SinkType))
	req.Format = strings.ToLower(strings.TrimSpace(req.Format))

	if req.Enabled && req.Endpoint == "" {
		return store.SIEMConfig{}, ErrSIEMEndpointRequired
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
	cur, _ := s.store.GetSIEMConfig(ctx)
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

	if err := s.store.SetSIEMConfig(ctx, newCfg, actor); err != nil {
		return store.SIEMConfig{}, err
	}

	s.Trigger()
	return newCfg, nil
}

func (s *SIEMService) Test(ctx context.Context, actor store.Actor, req SIEMSettingsInput) (SIEMTestResult, error) {
	endpoint := strings.TrimSpace(req.Endpoint)
	authHeader := strings.TrimSpace(req.AuthHeader)
	format := strings.ToLower(strings.TrimSpace(req.Format))
	tlsInsecure := req.TLSInsecure
	tlsCACert := strings.TrimSpace(req.TLSCACert)

	// Fallback to saved config if request is empty
	if endpoint == "" {
		cur, err := s.store.GetSIEMConfig(ctx)
		if err != nil {
			return SIEMTestResult{}, err
		}
		endpoint = cur.Endpoint
		authHeader = cur.AuthHeader
		format = cur.Format
		tlsInsecure = cur.TLSInsecure
		tlsCACert = cur.TLSCACert
	} else if authHeader == "" || strings.Contains(authHeader, "****") {
		cur, _ := s.store.GetSIEMConfig(ctx)
		authHeader = cur.AuthHeader
	}

	if endpoint == "" {
		return SIEMTestResult{OK: false, Message: "No endpoint specified"}, nil
	}

	sink, err := store.OpenAuditSinkWithOptions(endpoint, store.SinkOptions{
		TLSInsecure: tlsInsecure,
		TLSCACert:   tlsCACert,
		AuthHeader:  authHeader,
	})
	if err != nil {
		return SIEMTestResult{OK: false, Message: fmt.Sprintf("Failed to initialize sink: %v", err)}, nil
	}
	defer sink.Close()

	hostname, _ := os.Hostname()
	testEv := store.ExportedEvent{
		ID:         0,
		TS:         time.Now().UTC(),
		ActorID:    actor.ID,
		ActorName:  actor.Name,
		ActorIP:    actor.IP,
		Action:     "audit.siem_test",
		ObjectType: "settings",
		ObjectID:   "siem",
		Details:    []byte(`{"message":"DuckJump SIEM connectivity test successful"}`),
	}

	payload := store.FormatEvent(testEv, format, hostname)
	if _, err := sink.Write(payload); err != nil {
		return SIEMTestResult{OK: false, Message: fmt.Sprintf("Failed to send test event: %v", err)}, nil
	}

	return SIEMTestResult{
		OK:      true,
		Message: fmt.Sprintf("Test event sent successfully to %s in %s format", endpoint, strings.ToUpper(format)),
	}, nil
}

func (s *SIEMService) Trigger() {
	s.siemMu.Lock()
	defer s.siemMu.Unlock()
	if s.siemNotify != nil {
		select {
		case s.siemNotify <- struct{}{}:
		default:
		}
	}
}

func (s *SIEMService) NotifyChan() <-chan struct{} {
	s.siemMu.Lock()
	defer s.siemMu.Unlock()
	if s.siemNotify == nil {
		s.siemNotify = make(chan struct{}, 1)
	}
	return s.siemNotify
}

func (s *SIEMService) ForwardLoop(ctx context.Context, staticSinks []io.Writer) {
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
		case <-s.NotifyChan():
		}

		// 1. Check dynamic SIEM configuration
		cfg, err := s.store.GetSIEMConfig(ctx)
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
					_ = s.store.SetSIEMStats(ctx, store.SIEMStats{
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
		if len(staticSinks) == 0 && dynamicSink == nil {
			continue
		}

		// 2. Export batch
		var activeSinks []io.Writer
		activeSinks = append(activeSinks, staticSinks...)
		if dynamicSink != nil {
			activeSinks = append(activeSinks, dynamicSink)
		}

		format := currentFormat
		if format == "" {
			format = "json"
		}

		exported, err := s.store.ExportOnceWithFormat(ctx, activeSinks, format, hostname)
		if err != nil && ctx.Err() == nil {
			slog.Error("siem export error", "err", err)
			now := time.Now().UTC()
			st, _ := s.store.GetSIEMStats(ctx)
			st.LastError = err.Error()
			st.LastErrorAt = &now
			_ = s.store.SetSIEMStats(ctx, st)
		} else if exported > 0 {
			now := time.Now().UTC()
			st, _ := s.store.GetSIEMStats(ctx)
			st.TotalExported += int64(exported)
			st.LastExportedAt = &now
			st.LastError = ""
			st.LastErrorAt = nil
			_ = s.store.SetSIEMStats(ctx, st)
		}
	}
}
