package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
)

// Recording files live in RecordingsDir, written by paltad: "<id>.cast"
// (terminal sessions, asciicast) or "<id>.gfx" (graphical sessions) while
// the session runs, gzipped to "<id>.cast.gz" / "<id>.gfx.gz" once it ends.

const retentionKey = "recordings.retention_days"

// recordingFile finds a recording on disk. gz tells which form it is in.
func (s *Server) recordingFile(name string) (path string, gz bool, size int64, err error) {
	if s.RecordingsDir == "" {
		return "", false, 0, os.ErrNotExist
	}
	base := filepath.Join(s.RecordingsDir, filepath.Base(name))
	for _, ext := range []string{".cast.gz", ".gfx.gz", ".cast", ".gfx"} {
		if fi, err := os.Stat(base + ext); err == nil {
			return base + ext, strings.HasSuffix(ext, ".gz"), fi.Size(), nil
		}
	}
	return "", false, 0, os.ErrNotExist
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// openapi:operation
// summary: Download a session recording
// description: >-
//   asciicast v2 for terminal sessions (playable with asciinema); for VNC and
//   RDP the DuckJump graphical format (DJGFX1, see paltad recording.rs).
//   Served gzip-compressed when the
//   client accepts it. For a session still open it returns what has been
//   recorded so far. 410 when the retention policy already deleted it.
//   Allowed to auditors and admins, and to users holding view_recordings on
//   the session's connection. Every download is audited.
// tags: [audit]
// responses:
//   '200':
//     description: The recording
//     content: { application/x-asciicast: { schema: { type: string } } }
//   '410': Error

func (s *Server) getRecording(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	x, err := s.Store.Q.GetSessionRecord(ctx, r.PathValue("id"))
	if err != nil {
		return fromStore(err, "session")
	}
	if !auditors[p.User.Role] && !p.Dev {
		allowed, err := s.Store.CanViewRecordings(ctx, p.User.ID, x.ConnectionID)
		if err != nil {
			return err
		}
		if !allowed {
			return errForbidden
		}
	}
	if !x.Recording.Valid {
		return notFound("recording")
	}
	if purge, err := s.Store.Q.GetRecordingPurge(ctx, x.ID); err == nil {
		return &apiError{http.StatusGone, "purged", fmt.Sprintf("the recording was deleted on %s (%s)", purge.PurgedAt.UTC().Format("2006-01-02"), purge.Reason)}
	}
	path, gz, _, err := s.recordingFile(x.Recording.String)
	if err != nil {
		return notFound("recording file")
	}
	f, err := os.Open(path)
	if err != nil {
		return notFound("recording file")
	}
	defer f.Close()
	if err := s.Store.AuditTx(ctx, store.Event{Actor: p.actor(), Action: "recording.view", ObjectType: "session", ObjectID: x.ID}); err != nil {
		return err
	}

	h := w.Header()
	if strings.Contains(path, ".gfx") {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", `attachment; filename="`+x.ID+`.gfx"`)
	} else {
		h.Set("Content-Type", "application/x-asciicast")
		h.Set("Content-Disposition", `attachment; filename="`+x.ID+`.cast"`)
	}
	h.Set("Cache-Control", "private, no-store")
	h.Set("Vary", "Accept-Encoding")

	if gz {
		if acceptsGzip(r) {
			h.Set("Content-Encoding", "gzip")
			_, err = io.Copy(w, f)
			return nil
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		io.Copy(w, zr)
		return nil
	}

	// Plain file: a session still recording, or one paltad never closed.
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if strings.HasSuffix(path, ".cast") {
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1] // drop a line still being written
		}
	} // .gfx: the player ignores a record still being written
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		zw.Write(data)
		return zw.Close()
	}
	w.Write(data)
	return nil
}

// ---- retention ----

// RetentionDays is the configured retention (0 = keep forever).
func (s *Server) RetentionDays(ctx context.Context) (int, error) {
	v, err := s.Store.Q.GetSetting(ctx, retentionKey)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("setting %s: %w", retentionKey, err)
	}
	return n, nil
}

func retentionCutoff(days int) time.Time {
	return store.Now().Add(-time.Duration(days) * 24 * time.Hour)
}

// openapi:schema RecordingUsage
// type: object
// required: [recordings, bytes, purgeable, purgeable_bytes, oldest_started_at]
// properties:
//   recordings: { type: integer, description: Recordings stored now. }
//   bytes: { type: integer, description: Their size on disk (compressed). }
//   purgeable: { type: integer, description: How many the given retention would delete. }
//   purgeable_bytes: { type: integer }
//   oldest_started_at: { type: [string, 'null'], format: date-time }

type recordingUsage struct {
	Recordings      int        `json:"recordings"`
	Bytes           int64      `json:"bytes"`
	Purgeable       int        `json:"purgeable"`
	PurgeableBytes  int64      `json:"purgeable_bytes"`
	OldestStartedAt *time.Time `json:"oldest_started_at"`
}

func (s *Server) recordingUsage(ctx context.Context, days int) (recordingUsage, error) {
	var u recordingUsage
	rows, err := s.Store.Q.LiveRecordings(ctx)
	if err != nil {
		return u, err
	}
	cutoff := retentionCutoff(days)
	for _, r := range rows {
		_, _, size, err := s.recordingFile(r.Recording.String)
		if err != nil {
			continue // not on disk (or not readable from here)
		}
		u.Recordings++
		u.Bytes += size
		if u.OldestStartedAt == nil {
			t := r.StartedAt.UTC()
			u.OldestStartedAt = &t
		}
		if days > 0 && r.EndedAt.Valid && r.EndedAt.Time.Before(cutoff) {
			u.Purgeable++
			u.PurgeableBytes += size
		}
	}
	return u, nil
}

// PurgeRecordings deletes the recordings older than the retention policy.
// Each deletion is recorded in audit_recording_purges and the audit log.
func (s *Server) PurgeRecordings(ctx context.Context, actor store.Actor) (int, int64, error) {
	days, err := s.RetentionDays(ctx)
	if err != nil || days == 0 {
		return 0, 0, err
	}
	if s.RecordingsDir == "" {
		return 0, 0, errors.New("retention is set but the gateway has no -recordings directory")
	}
	cutoff := retentionCutoff(days)
	reason := fmt.Sprintf("retention policy: %d days", days)
	var n int
	var total int64
	for {
		batch, err := s.Store.Q.RecordingsEndedBefore(ctx, db.RecordingsEndedBeforeParams{Cutoff: store.TS(cutoff), Lim: 200})
		if err != nil {
			return n, total, err
		}
		if len(batch) == 0 {
			return n, total, nil
		}
		for _, r := range batch {
			var size int64
			base := filepath.Join(s.RecordingsDir, filepath.Base(r.Recording.String))
			for _, f := range []string{base + ".cast.gz", base + ".cast", base + ".gfx.gz", base + ".gfx"} {
				fi, err := os.Stat(f)
				if err != nil {
					continue
				}
				if err := os.Remove(f); err != nil {
					return n, total, fmt.Errorf("deleting %s: %w", f, err)
				}
				size += fi.Size()
			}
			err := s.tx(ctx, func(q *db.Queries) error {
				if err := q.InsertRecordingPurge(ctx, db.InsertRecordingPurgeParams{SessionID: r.ID, Reason: reason, Bytes: size, Now: store.Now()}); err != nil {
					return err
				}
				return store.Audit(ctx, q, store.Event{Actor: actor, Action: "recording.purged", ObjectType: "session", ObjectID: r.ID,
					Details: map[string]any{"bytes": size, "retention_days": days}})
			})
			if err != nil {
				return n, total, err
			}
			n++
			total += size
		}
	}
}

// RetentionLoop purges expired recordings now and then every hour.
func (s *Server) RetentionLoop(ctx context.Context) {
	run := func() {
		n, b, err := s.PurgeRecordings(ctx, store.Actor{Name: "retention"})
		if err != nil {
			slog.Error("recording retention", "err", err)
		} else if n > 0 {
			slog.Info("recordings purged by retention", "count", n, "bytes", b)
		}
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// openapi:schema RecordingSettings
// type: object
// required: [retention_days, usage, recordings_dir_configured]
// properties:
//   retention_days: { type: integer, minimum: 0, maximum: 3650, description: 'Days to keep recordings after the session ends; 0 keeps them forever.' }
//   usage: { $ref: '#/components/schemas/RecordingUsage' }
//   recordings_dir_configured: { type: boolean, description: 'false: the gateway cannot see the recording files (no -recordings), so it cannot delete them.' }
//   purged: { type: integer, description: Only after an update; recordings deleted right away. }
//   purged_bytes: { type: integer }

type recordingSettings struct {
	RetentionDays           int            `json:"retention_days"`
	Usage                   recordingUsage `json:"usage"`
	RecordingsDirConfigured bool           `json:"recordings_dir_configured"`
	Purged                  *int           `json:"purged,omitempty"`
	PurgedBytes             *int64         `json:"purged_bytes,omitempty"`
}

// openapi:schema RecordingSettingsRequest
// type: object
// required: [retention_days]
// additionalProperties: false
// properties:
//   retention_days: { type: integer, minimum: 0, maximum: 3650 }

type recordingSettingsRequest struct {
	RetentionDays int `json:"retention_days"`
}

// openapi:operation
// summary: Recording retention and storage
// tags: [settings]
// parameters:
//   - { name: retention_days, in: query, schema: { type: integer }, description: 'Preview: compute usage.purgeable for this value instead of the current one.' }
// responses:
//   '200': { description: Current settings and storage use, schema: RecordingSettings }

func (s *Server) getRecordingSettings(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	days, err := s.RetentionDays(ctx)
	if err != nil {
		return err
	}
	preview := days
	if v := r.URL.Query().Get("retention_days"); v != "" {
		if preview, err = strconv.Atoi(v); err != nil || preview < 0 || preview > 3650 {
			return badRequest("retention_days must be 0-3650")
		}
	}
	u, err := s.recordingUsage(ctx, preview)
	if err != nil {
		return err
	}
	return ok(w, recordingSettings{RetentionDays: days, Usage: u, RecordingsDirConfigured: s.RecordingsDir != ""})
}

// openapi:operation
// summary: Set the recording retention
// description: Recordings already past the new limit are deleted right away; the response says how many.
// tags: [settings]
// requestBody: { schema: RecordingSettingsRequest }
// responses:
//   '200': { description: Saved, schema: RecordingSettings }
//   '409': Error

func (s *Server) setRecordingSettings(w http.ResponseWriter, r *http.Request, p principal) error {
	var req recordingSettingsRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.RetentionDays < 0 || req.RetentionDays > 3650 {
		return badRequest("retention_days must be 0-3650")
	}
	if req.RetentionDays > 0 && s.RecordingsDir == "" {
		return conflict("the gateway runs without -recordings, so it cannot delete recording files")
	}
	ctx := r.Context()
	prev, err := s.RetentionDays(ctx)
	if err != nil {
		return err
	}
	val, _ := json.Marshal(req.RetentionDays)
	err = s.tx(ctx, func(q *db.Queries) error {
		if err := q.SetSetting(ctx, db.SetSettingParams{Key: retentionKey, Value: string(val), Now: store.Now(), UpdatedBy: store.NullString(p.User.ID)}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "settings.update", ObjectType: "setting", ObjectID: retentionKey,
			Details: map[string]any{"from": prev, "to": req.RetentionDays}})
	})
	if err != nil {
		return err
	}
	n, b, err := s.PurgeRecordings(ctx, p.actor())
	if err != nil {
		return err
	}
	u, err := s.recordingUsage(ctx, req.RetentionDays)
	if err != nil {
		return err
	}
	return ok(w, recordingSettings{RetentionDays: req.RetentionDays, Usage: u, RecordingsDirConfigured: true, Purged: &n, PurgedBytes: &b})
}
