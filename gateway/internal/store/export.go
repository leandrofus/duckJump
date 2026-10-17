package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Audit export ships every event, as it is committed, to places an attacker
// on the gateway host cannot rewrite: a remote syslog, an external SIEM (Splunk,
// Elastic, Datadog, Sentinel), or a file on append-only / WORM storage.
// Comparing the copy with the database shows events removed from the end of the chain,
// which the chain itself cannot.

const (
	exportCursorKey = "audit.export_cursor"
	SIEMConfigKey   = "audit.siem"
	SIEMStatsKey    = "audit.siem_stats"
)

// ExportedEvent is one exported line: the stored row, hashes and MAC included.
type ExportedEvent struct {
	ID         int64           `json:"id"`
	TS         time.Time       `json:"ts"`
	ActorID    string          `json:"actor_id,omitempty"`
	ActorName  string          `json:"actor_name"`
	ActorIP    string          `json:"actor_ip,omitempty"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type,omitempty"`
	ObjectID   string          `json:"object_id,omitempty"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
	MAC        string          `json:"mac,omitempty"`
}

type SinkOptions struct {
	TLSInsecure bool
	TLSCACert   string
	AuthHeader  string
}

// OpenAuditSink opens an export target with default options (backwards compatible).
func OpenAuditSink(target string) (io.WriteCloser, error) {
	return OpenAuditSinkWithOptions(target, SinkOptions{})
}

// OpenAuditSinkWithOptions opens an export target:
//
//	file:///var/log/duckjump/audit.jsonl   JSON lines, appended and fsynced
//	syslog+udp://host:514                 RFC 3164 / RFC 5424 syslog
//	syslog+tcp://host:514                 TCP syslog with auto-reconnect
//	syslog+tls://host:6514                TLS syslog (RFC 5425) with auto-reconnect
//	syslogs://host:6514                   Alias for syslog+tls
//	syslog:                               Local syslog daemon (/dev/log or /var/run/syslog)
//	http://... or https://...             HTTP Webhook or Splunk HEC collector
func OpenAuditSinkWithOptions(target string, opts SinkOptions) (io.WriteCloser, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("audit export %q: %w", target, err)
	}

	switch u.Scheme {
	case "file":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return nil, err
		}
		return syncWriter{f}, nil

	case "syslog":
		sock := "/dev/log"
		if _, err := os.Stat("/var/run/syslog"); err == nil {
			sock = "/var/run/syslog"
		}
		sw := &syslogWriter{network: "unix", addr: sock, tag: "duckjump-gw-audit"}
		if err := sw.connect(); err != nil {
			return nil, fmt.Errorf("connecting to local syslog %s: %w", sock, err)
		}
		return sw, nil

	case "syslog+udp":
		host := u.Host
		if !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, "514")
		}
		sw := &syslogWriter{network: "udp", addr: host, tag: "duckjump-gw-audit"}
		if err := sw.connect(); err != nil {
			return nil, err
		}
		return sw, nil

	case "syslog+tcp":
		host := u.Host
		if !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, "514")
		}
		sw := &syslogWriter{network: "tcp", addr: host, tag: "duckjump-gw-audit"}
		if err := sw.connect(); err != nil {
			return nil, err
		}
		return sw, nil

	case "syslog+tls", "syslogs":
		host := u.Host
		if !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, "6514")
		}
		serverName, _, _ := net.SplitHostPort(host)
		tlsConf := &tls.Config{
			InsecureSkipVerify: opts.TLSInsecure,
			ServerName:         serverName,
		}
		if opts.TLSCACert != "" {
			cp := x509.NewCertPool()
			if cp.AppendCertsFromPEM([]byte(opts.TLSCACert)) {
				tlsConf.RootCAs = cp
			}
		}
		sw := &syslogWriter{network: "tls", addr: host, tlsConf: tlsConf, tag: "duckjump-gw-audit"}
		if err := sw.connect(); err != nil {
			return nil, err
		}
		return sw, nil

	case "http", "https":
		tlsConf := &tls.Config{InsecureSkipVerify: opts.TLSInsecure}
		if opts.TLSCACert != "" {
			cp := x509.NewCertPool()
			if cp.AppendCertsFromPEM([]byte(opts.TLSCACert)) {
				tlsConf.RootCAs = cp
			}
		}
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConf,
			},
		}
		return &httpWriter{
			endpoint:   target,
			authHeader: opts.AuthHeader,
			client:     client,
		}, nil
	}

	return nil, fmt.Errorf("audit export %q: unsupported scheme (use file://, syslog:, syslog+udp://, syslog+tcp://, syslog+tls://, or http(s)://)", target)
}

type syncWriter struct{ f *os.File }

func (w syncWriter) Write(b []byte) (int, error) {
	n, err := w.f.Write(b)
	if err == nil {
		err = w.f.Sync()
	}
	return n, err
}

func (w syncWriter) Close() error { return w.f.Close() }

type syslogWriter struct {
	network string
	addr    string
	tlsConf *tls.Config
	tag     string
	mu      sync.Mutex
	conn    net.Conn
}

func (s *syslogWriter) connect() error {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	var conn net.Conn
	var err error
	switch s.network {
	case "tls":
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		conn, err = tls.DialWithDialer(dialer, "tcp", s.addr, s.tlsConf)
	case "tcp":
		conn, err = net.DialTimeout("tcp", s.addr, 5*time.Second)
	case "udp":
		conn, err = net.Dial("udp", s.addr)
	case "unix":
		conn, err = net.Dial("unixgram", s.addr)
		if err != nil {
			conn, err = net.Dial("unix", s.addr)
		}
	default:
		return fmt.Errorf("unsupported syslog network %q", s.network)
	}
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *syslogWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		if err := s.connect(); err != nil {
			return 0, err
		}
	}

	n, err := s.conn.Write(p)
	if err != nil {
		if recErr := s.connect(); recErr == nil {
			n, err = s.conn.Write(p)
		}
	}
	return n, err
}

func (s *syslogWriter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

type httpWriter struct {
	endpoint   string
	authHeader string
	client     *http.Client
}

func (h *httpWriter) Write(p []byte) (int, error) {
	body := p
	if strings.Contains(h.endpoint, "/services/collector") {
		var raw json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(p), &raw); err == nil {
			wrapped, _ := json.Marshal(map[string]any{
				"event":      raw,
				"sourcetype": "duckjump:audit",
				"time":       time.Now().Unix(),
			})
			body = wrapped
		}
	}
	req, err := http.NewRequest(http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "duckjump-gw/siem-forwarder")
	if h.authHeader != "" {
		req.Header.Set("Authorization", h.authHeader)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("http status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return len(p), nil
}

func (h *httpWriter) Close() error { return nil }

// Formatters for SIEM standards:

func escapeCEFHeader(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(r, `|`, `\|`)
}

func escapeCEFExt(s string) string {
	r := strings.ReplaceAll(s, `\`, `\\`)
	r = strings.ReplaceAll(r, `=`, `\=`)
	r = strings.ReplaceAll(r, "\n", `\n`)
	return strings.ReplaceAll(r, "\r", `\r`)
}

// FormatCEF formats an event as ArcSight / QRadar Common Event Format (CEF).
func FormatCEF(e ExportedEvent) string {
	severity := 3
	switch e.Action {
	case "auth.login_failed", "auth.totp_failed", "session.denied", "audit.broken":
		severity = 8
	case "user.create", "user.delete", "user.disable", "policy.create", "policy.delete", "secret.delete", "audit.sealed":
		severity = 6
	case "session.start", "session.end", "session.kill":
		severity = 5
	}
	name := strings.ReplaceAll(e.Action, ".", " ")

	var ext strings.Builder
	if e.ActorIP != "" {
		ext.WriteString(fmt.Sprintf("src=%s ", escapeCEFExt(e.ActorIP)))
	}
	if e.ActorName != "" {
		ext.WriteString(fmt.Sprintf("suser=%s ", escapeCEFExt(e.ActorName)))
	}
	if e.ActorID != "" {
		ext.WriteString(fmt.Sprintf("suid=%s ", escapeCEFExt(e.ActorID)))
	}
	ext.WriteString(fmt.Sprintf("act=%s ", escapeCEFExt(e.Action)))
	if e.ObjectType != "" {
		ext.WriteString(fmt.Sprintf("cs1=%s cs1Label=ObjectType ", escapeCEFExt(e.ObjectType)))
	}
	if e.ObjectID != "" {
		ext.WriteString(fmt.Sprintf("cs2=%s cs2Label=ObjectID ", escapeCEFExt(e.ObjectID)))
	}
	ext.WriteString(fmt.Sprintf("rt=%d", e.TS.UnixMilli()))
	if len(e.Details) > 0 && string(e.Details) != "{}" {
		ext.WriteString(fmt.Sprintf(" msg=%s", escapeCEFExt(string(e.Details))))
	}

	return fmt.Sprintf("CEF:0|DuckJump|Bastion|1.0|%s|%s|%d|%s\n",
		escapeCEFHeader(e.Action), escapeCEFHeader(name), severity, strings.TrimSpace(ext.String()))
}

// FormatRFC5424 formats an event as standard structured Syslog (RFC 5424).
func FormatRFC5424(e ExportedEvent, hostname string) string {
	if hostname == "" {
		hostname = "duckjump-bastion"
	}
	ts := e.TS.UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	actor := e.ActorName
	if actor == "" {
		actor = "-"
	}
	ip := e.ActorIP
	if ip == "" {
		ip = "-"
	}
	msg := string(e.Details)
	if msg == "" || msg == "{}" {
		msg = e.Action
	}
	return fmt.Sprintf("<86>1 %s %s duckjump-gw %d audit - [duckjump@4823 id=\"%d\" action=\"%s\" actor=\"%s\" ip=\"%s\"] %s\n",
		ts, hostname, os.Getpid(), e.ID, e.Action, actor, ip, msg)
}

// FormatEvent formats an event according to the requested format ("json", "cef", "rfc5424").
func FormatEvent(e ExportedEvent, format string, hostname string) []byte {
	switch strings.ToLower(format) {
	case "cef":
		return []byte(FormatCEF(e))
	case "rfc5424":
		return []byte(FormatRFC5424(e, hostname))
	default:
		line, _ := json.Marshal(e)
		return append(line, '\n')
	}
}

// SIEM Configuration and Stats models:

type SIEMConfig struct {
	Enabled     bool   `json:"enabled"`
	SinkType    string `json:"sink_type"` // "syslog", "webhook", "file"
	Endpoint    string `json:"endpoint"`
	Format      string `json:"format"` // "json", "cef", "rfc5424"
	AuthHeader  string `json:"auth_header,omitempty"`
	TLSInsecure bool   `json:"tls_insecure"`
	TLSCACert   string `json:"tls_ca_cert,omitempty"`
}

type SIEMStats struct {
	LastExportedAt *time.Time `json:"last_exported_at,omitempty"`
	LastExportedID int64      `json:"last_exported_id"`
	TotalExported  int64      `json:"total_exported"`
	LastError      string     `json:"last_error,omitempty"`
	LastErrorAt    *time.Time `json:"last_error_at,omitempty"`
}

func (s *Store) GetSIEMConfig(ctx context.Context) (SIEMConfig, error) {
	var cfg SIEMConfig
	v, err := s.Q.GetSetting(ctx, SIEMConfigKey)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal([]byte(v), &cfg)
	return cfg, err
}

func (s *Store) SetSIEMConfig(ctx context.Context, cfg SIEMConfig, actor Actor) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetSetting(ctx, db.SetSettingParams{
			Key:       SIEMConfigKey,
			Value:     string(b),
			Now:       Now(),
			UpdatedBy: NullString(actor.Name),
		}); err != nil {
			return err
		}
		return Audit(ctx, q, Event{
			Actor:      actor,
			Action:     "settings.siem_updated",
			ObjectType: "settings",
			ObjectID:   "siem",
			Details: map[string]any{
				"enabled":   cfg.Enabled,
				"sink_type": cfg.SinkType,
				"endpoint":  cfg.Endpoint,
				"format":    cfg.Format,
			},
		})
	})
}

func (s *Store) GetSIEMStats(ctx context.Context) (SIEMStats, error) {
	var stats SIEMStats
	v, err := s.Q.GetSetting(ctx, SIEMStatsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return stats, nil
	}
	if err != nil {
		return stats, err
	}
	err = json.Unmarshal([]byte(v), &stats)
	return stats, err
}

func (s *Store) SetSIEMStats(ctx context.Context, stats SIEMStats) error {
	b, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	return s.Q.SetSetting(ctx, db.SetSettingParams{
		Key:       SIEMStatsKey,
		Value:     string(b),
		Now:       Now(),
		UpdatedBy: NullString("audit-siem"),
	})
}

// ExportAudit copies new audit events to the sinks every interval until ctx
// ends. Delivery is at least once: after a failed write the batch is sent
// again (consumers dedupe by id). The position survives restarts.
func (s *Store) ExportAudit(ctx context.Context, sinks []io.Writer, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.exportOnce(ctx, sinks); err != nil && ctx.Err() == nil {
			slog.Error("audit export", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Store) exportOnce(ctx context.Context, sinks []io.Writer) error {
	_, err := s.ExportOnceWithFormat(ctx, sinks, "json", "")
	return err
}

// ExportOnceWithFormat exports one batch of audit events to the sinks with the specified format.
func (s *Store) ExportOnceWithFormat(ctx context.Context, sinks []io.Writer, format string, hostname string) (int, error) {
	var cursor int64
	v, err := s.Q.GetSetting(ctx, exportCursorKey)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return 0, err
	default:
		if cursor, err = strconv.ParseInt(v, 10, 64); err != nil {
			return 0, fmt.Errorf("%s: %w", exportCursorKey, err)
		}
	}

	exportedCount := 0
	for {
		rows, err := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{AfterID: cursor, Lim: 500})
		if err != nil || len(rows) == 0 {
			return exportedCount, err
		}
		for _, e := range rows {
			ev := ExportedEvent{
				ID:         e.ID,
				TS:         e.Ts.UTC(),
				ActorID:    e.ActorID.String,
				ActorName:  e.ActorName,
				ActorIP:    e.ActorIP,
				Action:     e.Action,
				ObjectType: e.ObjectType,
				ObjectID:   e.ObjectID,
				Details:    json.RawMessage(e.Details),
				PrevHash:   e.PrevHash,
				Hash:       e.Hash,
				MAC:        e.Mac.String,
			}
			line := FormatEvent(ev, format, hostname)
			for _, w := range sinks {
				if _, err := w.Write(line); err != nil {
					return exportedCount, err
				}
			}
			cursor = e.ID
			exportedCount++
		}
		if err := s.Q.SetSetting(ctx, db.SetSettingParams{
			Key:       exportCursorKey,
			Value:     strconv.FormatInt(cursor, 10),
			Now:       Now(),
			UpdatedBy: NullString("audit-export"),
		}); err != nil {
			return exportedCount, err
		}
	}
}
