package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Audit export ships every event, as it is committed, to places an attacker
// on the gateway host cannot rewrite: a remote syslog, or a file on
// append-only / WORM storage. Comparing the copy with the database shows
// events removed from the end of the chain, which the chain itself cannot.

const exportCursorKey = "audit.export_cursor"

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

// OpenAuditSink opens an export target:
//
//	file:///var/log/duckjump/audit.jsonl   JSON lines, appended and fsynced
//	syslog+udp://host:514               RFC 3164 syslog, facility authpriv
//	syslog+tcp://host:514
//	syslog:                             the local syslog daemon
func OpenAuditSink(target string) (io.WriteCloser, error) {
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
	case "syslog", "syslog+udp", "syslog+tcp":
		network := strings.TrimPrefix(u.Scheme, "syslog+")
		if network == "syslog" {
			network = ""
		}
		return syslog.Dial(network, u.Host, syslog.LOG_INFO|syslog.LOG_AUTHPRIV, "duckjump-gw-audit")
	}
	return nil, fmt.Errorf("audit export %q: use file://, syslog:, syslog+udp:// or syslog+tcp://", target)
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
	var cursor int64
	v, err := s.Q.GetSetting(ctx, exportCursorKey)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		if cursor, err = strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("%s: %w", exportCursorKey, err)
		}
	}
	for {
		rows, err := s.Q.AuditEventsFrom(ctx, db.AuditEventsFromParams{AfterID: cursor, Lim: 500})
		if err != nil || len(rows) == 0 {
			return err
		}
		for _, e := range rows {
			line, _ := json.Marshal(ExportedEvent{ID: e.ID, TS: e.Ts.UTC(), ActorID: e.ActorID.String, ActorName: e.ActorName,
				ActorIP: e.ActorIP, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID,
				Details: json.RawMessage(e.Details), PrevHash: e.PrevHash, Hash: e.Hash, MAC: e.Mac.String})
			line = append(line, '\n')
			for _, w := range sinks {
				if _, err := w.Write(line); err != nil {
					return err
				}
			}
			cursor = e.ID
		}
		if err := s.Q.SetSetting(ctx, db.SetSettingParams{Key: exportCursorKey, Value: strconv.FormatInt(cursor, 10),
			Now: Now(), UpdatedBy: NullString("audit-export")}); err != nil {
			return err
		}
	}
}
