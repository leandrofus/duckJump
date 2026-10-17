package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/objstore"
	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store"
)

// Recording files live in RecordingsDir, written by duckjumpd: "<id>.cast"
// (terminal sessions, asciicast) or "<id>.gfx" (graphical sessions) while
// the session runs, gzipped to "<id>.cast.gz" / "<id>.gfx.gz" once it ends.

// recordingsConfigured: recordings can be found somewhere (disk or bucket).
func (s *Server) recordingsConfigured() bool { return s.Recordings.Configured() }

// recordingSize is the stored size of a recording: on disk (still being
// written, or a shared directory) or in the bucket.
func (s *Server) recordingSize(ctx context.Context, name string) (int64, error) {
	return s.Recordings.RecordingSize(ctx, name)
}

// recordingFile finds a recording on disk. gz tells which form it is in.
func (s *Server) recordingFile(name string) (path string, gz bool, size int64, err error) {
	return s.Recordings.RecordingFile(name)
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// openapi:operation
// summary: Download a session recording
// description: >-
//   asciicast v2 for terminal sessions (playable with asciinema); for VNC and
//   RDP the DuckJump graphical format (DJGFX1, see duckjumpd recording.rs).
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
	x, err := s.Recordings.CheckViewRecording(ctx, p.actor(), p.User.ID, p.Dev, auditors[p.User.Role], r.PathValue("id"))
	if err != nil {
		return fromService(err, "session")
	}
	path, gz, _, err := s.recordingFile(x.Recording.String)
	if err != nil {
		// Finished and moved to the bucket by duckjumpd?
		if s.Objects == nil {
			return notFound("recording file")
		}
		o, err := s.Objects.Stat(ctx, filepath.Base(x.Recording.String))
		if errors.Is(err, objstore.ErrNotFound) {
			return notFound("recording file")
		}
		if err != nil {
			return err
		}
		body, err := s.Objects.Open(ctx, o.Key)
		if err != nil {
			return err
		}
		defer body.Close()
		if err := s.Recordings.AuditView(ctx, p.actor(), x.ID); err != nil {
			return err
		}
		recordingHeaders(w, x.ID, o.Gfx)
		return serveGzipped(w, r, body)
	}
	f, err := os.Open(path)
	if err != nil {
		return notFound("recording file")
	}
	defer f.Close()
	if err := s.Recordings.AuditView(ctx, p.actor(), x.ID); err != nil {
		return err
	}

	recordingHeaders(w, x.ID, strings.Contains(path, ".gfx"))
	h := w.Header()

	if gz {
		return serveGzipped(w, r, f)
	}

	// Plain file: a session still recording, or one duckjumpd never closed.
	// Streamed up to what was on disk when the request came, so a recording
	// of many hours never sits in memory.
	n, err := servableLen(f, strings.HasSuffix(path, ".cast"))
	if err != nil {
		return err
	}
	src := io.LimitReader(f, n)
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		if _, err := io.Copy(zw, src); err != nil {
			return nil // client gone; headers are out already
		}
		zw.Close()
		return nil
	}
	h.Set("Content-Length", strconv.FormatInt(n, 10))
	io.Copy(w, src)
	return nil
}

func recordingHeaders(w http.ResponseWriter, id string, gfx bool) {
	h := w.Header()
	if gfx {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", `attachment; filename="`+id+`.gfx"`)
	} else {
		h.Set("Content-Type", "application/x-asciicast")
		h.Set("Content-Disposition", `attachment; filename="`+id+`.cast"`)
	}
	h.Set("Cache-Control", "private, no-store")
	h.Set("Vary", "Accept-Encoding")
}

// serveGzipped sends a gzip stream as is when the client takes gzip, or
// inflated.
func serveGzipped(w http.ResponseWriter, r *http.Request, body io.Reader) error {
	if acceptsGzip(r) {
		w.Header().Set("Content-Encoding", "gzip")
		io.Copy(w, body)
		return nil
	}
	zr, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	io.Copy(w, zr)
	return nil
}

// servableLen is how much of a recording still being written can be served:
// the whole file now, except for an asciicast line still being written
// (everything after the last newline). The player ignores a .gfx record
// still being written.
func servableLen(f *os.File, cast bool) (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	if !cast {
		return size, nil
	}
	buf := make([]byte, 64<<10)
	for end := size; end > 0; {
		start := max(end-int64(len(buf)), 0)
		chunk := buf[:end-start]
		if _, err := f.ReadAt(chunk, start); err != nil {
			return 0, err
		}
		if i := bytes.LastIndexByte(chunk, '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

// ---- retention ----

// RetentionDays is the configured retention (0 = keep forever).
func (s *Server) RetentionDays(ctx context.Context) (int, error) {
	return s.Recordings.RetentionDays(ctx)
}

// PurgeRecordings deletes the recordings older than the retention policy.
// Each deletion is recorded in audit_recording_purges and the audit log.
func (s *Server) PurgeRecordings(ctx context.Context, actor store.Actor) (int, int64, error) {
	return s.Recordings.PurgeRecordings(ctx, actor)
}

// RetentionLoop purges expired recordings now and then every hour.
func (s *Server) RetentionLoop(ctx context.Context) {
	run := func() {
		n, b, err := s.Recordings.PurgeRecordings(ctx, store.Actor{Name: "retention"})
		if err != nil {
			slog.Error("recording retention", "err", err)
		} else if n > 0 {
			slog.Info("recordings purged by retention", "count", n, "bytes", b)
		}
		if n, err := s.PurgeFiles(ctx); err != nil {
			slog.Error("file tray retention", "err", err)
		} else if n > 0 {
			slog.Info("expired tray files deleted", "count", n)
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

func toRecordingUsage(u services.RecordingUsage) recordingUsage {
	return recordingUsage{
		Recordings:      u.Recordings,
		Bytes:           u.Bytes,
		Purgeable:       u.Purgeable,
		PurgeableBytes:  u.PurgeableBytes,
		OldestStartedAt: u.OldestStartedAt,
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
	days, err := s.Recordings.RetentionDays(ctx)
	if err != nil {
		return fromService(err, "retention")
	}
	preview := days
	if v := r.URL.Query().Get("retention_days"); v != "" {
		if preview, err = strconv.Atoi(v); err != nil || preview < 0 || preview > 3650 {
			return badRequest("retention_days must be 0-3650")
		}
	}
	u, err := s.Recordings.Usage(ctx, preview)
	if err != nil {
		return fromService(err, "retention")
	}
	return ok(w, recordingSettings{
		RetentionDays:           days,
		Usage:                   toRecordingUsage(u),
		RecordingsDirConfigured: s.Recordings.Configured(),
	})
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
	ctx := r.Context()
	_, n, b, err := s.Recordings.SetRetention(ctx, p.actor(), p.User.ID, req.RetentionDays)
	if err != nil {
		return fromService(err, "retention")
	}
	u, err := s.Recordings.Usage(ctx, req.RetentionDays)
	if err != nil {
		return fromService(err, "retention")
	}
	return ok(w, recordingSettings{
		RetentionDays:           req.RetentionDays,
		Usage:                   toRecordingUsage(u),
		RecordingsDirConfigured: true,
		Purged:                  &n,
		PurgedBytes:             &b,
	})
}
