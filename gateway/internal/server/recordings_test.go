package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/objstore"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

const castBody = `{"version":2,"width":80,"height":24}` + "\n" + `[0.1,"o","hola\r\n"]` + "\n"

// session inserts a session row whose recording is <id>.cast[.gz] in dir.
func (e *env) session(t *testing.T, id string, ended time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := e.st.Q.StartSessionRecord(ctx, db.StartSessionRecordParams{ID: id, Username: "root", ConnectionID: store.NewID(),
		ConnectionSnapshot: "{}", Recording: store.NullString(id), Now: ended.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if !ended.IsZero() {
		if err := e.st.Q.EndSessionRecord(ctx, db.EndSessionRecordParams{ID: id, EndReason: "exit", Now: store.NullTime(ended)}); err != nil {
			t.Fatal(err)
		}
	}
}

func writeGz(t *testing.T, path, body string) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	io.WriteString(zw, body)
	zw.Close()
	f.Close()
}

func (c *client) download(t *testing.T, id string, gz bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", c.e.srv.URL+"/api/v1/audit/sessions/"+id+"/recording", nil)
	if gz {
		req.Header.Set("Accept-Encoding", "gzip") // set by hand: Go then hands us the raw body
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		r = zr
	}
	b, _ := io.ReadAll(r)
	return resp, string(b)
}

func TestRecordingDownloadForms(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	e.server.RecordingsDir = dir
	root := e.as("root")

	// Finished session: stored gzipped, served gzipped or plain.
	e.session(t, "done", store.Now())
	writeGz(t, filepath.Join(dir, "done.cast.gz"), castBody)
	resp, body := root.download(t, "done", true)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || body != castBody {
		t.Fatalf("gz: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Encoding"), body)
	}
	resp, body = root.download(t, "done", false)
	if resp.Header.Get("Content-Encoding") != "" || body != castBody {
		t.Fatalf("plain: %q %q", resp.Header.Get("Content-Encoding"), body)
	}

	// Session still recording: plain file with a half-written last line.
	e.session(t, "live", time.Time{})
	os.WriteFile(filepath.Join(dir, "live.cast"), []byte(castBody+`[0.5,"o","par`), 0o644)
	if _, body = root.download(t, "live", true); body != castBody {
		t.Fatalf("live recording not cut at the last full line: %q", body)
	}
}

func TestRetentionPurge(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	e.server.RecordingsDir = dir
	root := e.as("root")
	now := store.Now()
	e.session(t, "old", now.Add(-40*24*time.Hour))
	e.session(t, "recent", now.Add(-2*24*time.Hour))
	e.session(t, "open", time.Time{}) // never purged while open
	writeGz(t, filepath.Join(dir, "old.cast.gz"), castBody)
	writeGz(t, filepath.Join(dir, "recent.cast.gz"), castBody)
	os.WriteFile(filepath.Join(dir, "open.cast"), []byte(castBody), 0o644)

	var st recordingSettings
	root.do("GET", "/settings/recordings?retention_days=30", nil, 200, &st)
	if st.RetentionDays != 0 || st.Usage.Recordings != 3 || st.Usage.Purgeable != 1 {
		t.Fatalf("preview: %+v", st)
	}
	root.do("PUT", "/settings/recordings", recordingSettingsRequest{RetentionDays: 30}, 200, &st)
	if st.Purged == nil || *st.Purged != 1 || st.Usage.Recordings != 2 {
		t.Fatalf("after setting retention: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.cast.gz")); !os.IsNotExist(err) {
		t.Fatal("old recording still on disk")
	}

	// The purged session says so, the recent one says when it expires.
	var s sessionDTO
	root.do("GET", "/audit/sessions/old", nil, 200, &s)
	if s.HasRecording || s.PurgedAt == nil {
		t.Fatalf("old: %+v", s)
	}
	root.do("GET", "/audit/sessions/recent", nil, 200, &s)
	if !s.HasRecording || s.ExpiresAt == nil || time.Until(*s.ExpiresAt) < 27*24*time.Hour {
		t.Fatalf("recent: %+v", s)
	}
	if resp, _ := root.download(t, "old", false); resp.StatusCode != http.StatusGone {
		t.Fatalf("purged download: %d", resp.StatusCode)
	}

	// Purges are append-only and audited.
	if _, err := e.st.DB.Exec(`DELETE FROM audit_recording_purges`); err == nil {
		t.Fatal("purge record deleted")
	}
	var evs []auditEventDTO
	root.do("GET", "/audit/events?action=recording.purged", nil, 200, &evs)
	if len(evs) != 1 || evs[0].ObjectID != "old" {
		t.Fatalf("audit: %+v", evs)
	}
	if !strings.Contains(string(root.do("GET", "/audit/events?action=settings.update", nil, 200, nil)), `"to":30`) {
		t.Fatal("settings change not audited")
	}

	// Without a recordings directory retention cannot be enabled.
	e.server.RecordingsDir = ""
	root.do("PUT", "/settings/recordings", recordingSettingsRequest{RetentionDays: 7}, 409, nil)
}

// Recordings duckjumpd moved to the bucket: downloads, sizes, usage and
// retention work from there. Needs DUCKJUMP_TEST_S3 and DUCKJUMP_S3_* (make test-s3).
func TestRecordingsInS3(t *testing.T) {
	if os.Getenv("DUCKJUMP_TEST_S3") == "" {
		t.Skip("DUCKJUMP_TEST_S3 not set (make test-s3 runs MinIO)")
	}
	getenv := func(k string) string {
		if k == "DUCKJUMP_S3_PREFIX" {
			return "gw-test-" + store.NewID() + "/"
		}
		return os.Getenv(k)
	}
	objs, err := objstore.FromEnv(getenv, os.Getenv("DUCKJUMP_S3_SECRET_KEY"))
	if err != nil || objs == nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := objs.Check(ctx); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	e.server.Objects = objs // and no local directory: duckjumpd is elsewhere
	root := e.as("root")

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	io.WriteString(zw, castBody)
	zw.Close()
	old := store.Now().Add(-40 * 24 * time.Hour)
	e.session(t, "s3old", old)
	e.session(t, "s3new", store.Now())
	for _, n := range []string{"s3old", "s3new"} {
		if err := objs.Put(ctx, n+".cast.gz", bytes.NewReader(gz.Bytes()), int64(gz.Len())); err != nil {
			t.Fatal(err)
		}
	}
	for _, accept := range []bool{true, false} {
		resp, body := root.download(t, "s3new", accept)
		if resp.StatusCode != 200 || body != castBody {
			t.Fatalf("download (gzip %v): %d %q", accept, resp.StatusCode, body)
		}
	}
	var s sessionDTO
	root.do("GET", "/audit/sessions/s3new", nil, 200, &s)
	if s.Bytes == nil || *s.Bytes != int64(gz.Len()) {
		t.Fatalf("size: %+v", s.Bytes)
	}
	var st recordingSettings
	root.do("PUT", "/settings/recordings", recordingSettingsRequest{RetentionDays: 30}, 200, &st)
	if st.Purged == nil || *st.Purged != 1 || st.Usage.Recordings != 1 {
		t.Fatalf("retention: %+v", st)
	}
	if _, err := objs.Stat(ctx, "s3old"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("purged recording still in the bucket: %v", err)
	}
	if resp, _ := root.download(t, "s3old", false); resp.StatusCode != http.StatusGone {
		t.Fatalf("purged download: %d", resp.StatusCode)
	}
	objs.Delete(ctx, "s3new")
}
