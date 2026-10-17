package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/djtp"
	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// File transfer. Files never go from host to host: they pass through the
// user's file tray on the gateway, which keeps each one with its hash and
// audits every move. From a computer: upload to the tray. Into a host: push
// from the tray (can_upload). Out of a host: pull into the tray
// (can_download), and from there to a computer or into another host, which
// is how files move between two sessions. Hosts are reached over SFTP, with
// the connection's credentials, through duckjumpd.

const (
	DefaultFileMaxSize = 1 << 30
	DefaultFileTTL     = 7 * 24 * time.Hour
	fileChunk          = 64 << 10
)

func (s *Server) fileMaxSize() int64 {
	return s.FileSvc.MaxSize()
}

func (s *Server) fileTTL() time.Duration {
	return s.FileSvc.TTL()
}

var errNoFiles = &apiError{http.StatusNotImplemented, "not_configured", "file transfer is not configured on this gateway (-files)"}

// openapi:schema TrayFile
// type: object
// required: [id, owner_id, owner_name, name, size, sha256, origin, connection_id, remote_path, created_at, expires_at, deleted_at]
// properties:
//   id: { type: string, format: uuid }
//   owner_id: { type: string }
//   owner_name: { type: string }
//   name: { type: string }
//   size: { type: integer }
//   sha256: { type: string }
//   origin: { type: string, enum: [upload, host], description: 'upload: from a computer; host: pulled out of a connection.' }
//   connection_id: { type: [string, 'null'], description: The host it came from (origin host). }
//   remote_path: { type: string }
//   created_at: { type: string, format: date-time }
//   expires_at: { type: string, format: date-time, description: When its content is deleted (the record stays). }
//   deleted_at: { type: [string, 'null'], format: date-time }

type trayFileDTO struct {
	ID           string     `json:"id"`
	OwnerID      string     `json:"owner_id"`
	OwnerName    string     `json:"owner_name"`
	Name         string     `json:"name"`
	Size         int64      `json:"size"`
	SHA256       string     `json:"sha256"`
	Origin       string     `json:"origin"`
	ConnectionID *string    `json:"connection_id"`
	RemotePath   string     `json:"remote_path"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	DeletedAt    *time.Time `json:"deleted_at"`
}

func toTrayFile(f db.AuditFile) trayFileDTO {
	return trayFileDTO{f.ID, f.OwnerID, f.OwnerName, f.Name, f.Size, f.Sha256, f.Origin, strPtr(f.ConnectionID), f.RemotePath,
		f.CreatedAt.UTC(), f.ExpiresAt.UTC(), timePtr(f.DeletedAt)}
}

// cleanName keeps a file's base name, without control characters.
func cleanName(n string) (string, error) {
	name, err := (&services.FileService{}).CleanName(n)
	if err != nil {
		return "", badRequest("invalid file name")
	}
	return name, nil
}

// spool copies r (at most max bytes) into a temporary file, hashing it.
func (s *Server) spool(r io.Reader, max int64) (tmp string, size int64, sum string, err error) {
	return s.FileSvc.Spool(r, max)
}

// keep stores a spooled file in the tray and records it, audited.
func (s *Server) keep(ctx context.Context, p principal, name, tmp string, size int64, sum, origin string, conn *db.ConfigConnection,
	remotePath, action string) (db.AuditFile, error) {
	var connID, connName string
	if conn != nil {
		connID, connName = conn.ID, conn.Name
	}
	return s.FileSvc.Keep(ctx, p.actor(), p.User.ID, p.User.Username, name, tmp, size, sum, origin, connID, connName, remotePath, action)
}

// ---- the tray ----

// openapi:operation
// summary: My file tray
// description: Files I uploaded or pulled out of hosts, whose content is still kept.
// tags: [files]
// responses:
//   '200': { description: Files, schema: '[]TrayFile' }

func (s *Server) listTray(w http.ResponseWriter, r *http.Request, p principal) error {
	rows, err := s.FileSvc.ListUserFiles(r.Context(), p.User.ID)
	if err != nil {
		return fromService(err, "file")
	}
	out := make([]trayFileDTO, 0, len(rows))
	for _, f := range rows {
		out = append(out, toTrayFile(f))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Upload a file to my tray
// description: The request body is the file's content. Audited with its SHA-256.
// tags: [files]
// parameters:
//   - { name: name, in: query, required: true, schema: { type: string } }
// requestBody:
//   content: { application/octet-stream: { schema: { type: string, format: binary } } }
// responses:
//   '201': { description: Stored, schema: TrayFile }
//   '413': Error

func (s *Server) uploadToTray(w http.ResponseWriter, r *http.Request, p principal) error {
	f, err := s.FileSvc.UploadToTray(r.Context(), p.actor(), p.User.ID, p.User.Username, r.URL.Query().Get("name"), r.Body, r.ContentLength)
	if err != nil {
		return fromService(err, "file")
	}
	return created(w, toTrayFile(f))
}

// trayFile loads a file of the caller's tray (content still kept).
func (s *Server) trayFile(ctx context.Context, p principal, id string) (db.AuditFile, error) {
	f, err := s.FileSvc.GetTrayFile(ctx, p.User.ID, id)
	if err != nil {
		return f, fromService(err, "file")
	}
	return f, nil
}

func serveFile(w http.ResponseWriter, f db.AuditFile, body io.Reader) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+strings.NewReplacer(`"`, "", `\`, "").Replace(f.Name)+`"`)
	h.Set("Content-Length", strconv.FormatInt(f.Size, 10))
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-DuckJump-SHA256", f.Sha256)
	io.Copy(w, body)
}

// openapi:operation
// summary: Download a file from my tray
// description: >-
//   A file pulled out of a host needs can_download on that host still; one I
//   uploaded myself is always mine to take back. Audited.
// tags: [files]
// responses:
//   '200': { description: The content, content: { application/octet-stream: { schema: { type: string, format: binary } } } }
//   '410': Error

func (s *Server) downloadFromTray(w http.ResponseWriter, r *http.Request, p principal) error {
	f, body, err := s.FileSvc.DownloadFromTray(r.Context(), p.actor(), p.User.ID, p.Dev, r.PathValue("id"))
	if err != nil {
		return fromService(err, "file")
	}
	defer body.Close()
	serveFile(w, f, body)
	return nil
}

// openapi:operation
// summary: Delete a file from my tray
// description: Its content goes; the record of it stays.
// tags: [files]
// responses:
//   '204': { description: Deleted }

func (s *Server) deleteFromTray(w http.ResponseWriter, r *http.Request, p principal) error {
	if err := s.FileSvc.DeleteFromTray(r.Context(), p.actor(), p.User.ID, r.PathValue("id")); err != nil {
		return fromService(err, "file")
	}
	return noContent(w)
}

func (s *Server) removeFile(ctx context.Context, f db.AuditFile, actor store.Actor, reason string) error {
	return s.FileSvc.RemoveFile(ctx, f, actor, reason)
}

// PurgeFiles deletes the content of expired files (records stay).
func (s *Server) PurgeFiles(ctx context.Context) (int, error) {
	return s.FileSvc.PurgeFiles(ctx)
}

// ---- hosts ----

// openapi:schema FileCredentials
// type: object
// additionalProperties: false
// required: [username, password]
// properties:
//   username: { type: string }
//   password: { type: string, format: password }

type fileCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// openapi:schema HostListRequest
// type: object
// additionalProperties: false
// properties:
//   path: { type: string, description: Directory; empty for the login directory. }
//   credentials: { $ref: '#/components/schemas/FileCredentials', description: For connections without a vaulted credential. }

type hostListRequest struct {
	Path        string           `json:"path"`
	Credentials *fileCredentials `json:"credentials"`
}

// openapi:schema HostPullRequest
// type: object
// additionalProperties: false
// required: [path]
// properties:
//   path: { type: string, description: File on the host. }
//   credentials: { $ref: '#/components/schemas/FileCredentials' }

type hostPullRequest struct {
	Path        string           `json:"path"`
	Credentials *fileCredentials `json:"credentials"`
}

// openapi:schema HostPushRequest
// type: object
// additionalProperties: false
// required: [file_id, path]
// properties:
//   file_id: { type: string, description: A file of my tray. }
//   path: { type: string, description: 'Where to write it; ending in / puts it in that directory with its own name.' }
//   overwrite: { type: boolean, default: false }
//   credentials: { $ref: '#/components/schemas/FileCredentials' }

type hostPushRequest struct {
	FileID      string           `json:"file_id"`
	Path        string           `json:"path"`
	Overwrite   bool             `json:"overwrite"`
	Credentials *fileCredentials `json:"credentials"`
}

// openapi:schema HostListing
// type: object
// required: [path, entries]
// properties:
//   path: { type: string, description: 'The directory, as the host resolved it.' }
//   entries:
//     type: array
//     items:
//       type: object
//       required: [name, dir, link, size, mtime, mode]
//       properties:
//         name: { type: string }
//         dir: { type: boolean }
//         link: { type: boolean }
//         size: { type: integer }
//         mtime: { type: [integer, 'null'], description: Unix seconds. }
//         mode: { type: [integer, 'null'] }

type hostListing struct {
	Path    string         `json:"path"`
	Entries []djtp.FsEntry `json:"entries"`
}

// fileSession is an SFTP session on duckjumpd for one request.
type fileSession struct {
	pd net.Conn
}

// fileAccess checks the caller may move files to (up) or from (down) the
// connection, or either (list), and returns it.
func (s *Server) fileAccess(ctx context.Context, p principal, connID string, up, down bool) (db.ConfigConnection, error) {
	c, err := s.FileSvc.CheckFileAccess(ctx, p.User.ID, p.Dev, connID, up, down)
	if err != nil {
		return c, fromService(err, "connection")
	}
	return c, nil
}

func (s *Server) openFiles(ctx context.Context, p principal, c db.ConfigConnection, given *fileCredentials) (*fileSession, error) {
	var cr sessionCreds
	switch {
	case given != nil && given.Username != "":
		if c.SecretID.Valid {
			return nil, badRequest("this connection uses a vaulted credential")
		}
		cr = sessionCreds{Username: strings.TrimSpace(given.Username), Password: given.Password, Source: "prompt"}
	case c.SecretID.Valid:
		var err error
		if cr, err = s.vaultCreds(ctx, c); err != nil {
			return nil, err
		}
	default:
		return nil, &apiError{http.StatusConflict, "credentials_required", "this connection needs your credentials"}
	}
	id := "f" + randomID(15)
	log := slog.With("files", id, "user", p.User.Username, "conn", c.Name)
	pd, _, err := s.openDaemon(ctx, c, p, id, "sftp", s.sshParams(c, cr, 0, 0), nil, log)
	if err != nil {
		return nil, daemonErr(err)
	}
	return &fileSession{pd: pd}, nil
}

// daemonErr maps duckjumpd's refusals to API errors.
func daemonErr(err error) error {
	var se *sessionError
	if !errors.As(err, &se) {
		return &apiError{http.StatusBadGateway, "connect_failed", err.Error()}
	}
	switch se.Code {
	case "credentials_required", "host_key_unverified", "host_key_mismatch":
		return &apiError{http.StatusConflict, se.Code, se.Message}
	case "auth_failed":
		return &apiError{http.StatusForbidden, se.Code, se.Message}
	case "fs_failed":
		return &apiError{http.StatusUnprocessableEntity, se.Code, se.Message}
	}
	return &apiError{http.StatusBadGateway, se.Code, se.Message}
}

func (f *fileSession) Close() {
	djtp.WriteControl(f.pd, djtp.Control{Type: "close"})
	f.pd.Close()
}

// reply reads the next control message; daemon errors become API errors.
func (f *fileSession) reply(want string) (djtp.Control, error) {
	f.pd.SetReadDeadline(time.Now().Add(2 * time.Minute))
	defer f.pd.SetReadDeadline(time.Time{})
	for {
		fr, err := djtp.ReadFrame(f.pd)
		if err != nil {
			return djtp.Control{}, &apiError{http.StatusBadGateway, "connect_failed", "the file session ended: " + err.Error()}
		}
		if fr.Kind != djtp.KindControl {
			continue
		}
		c, err := djtp.DecodeControl(fr)
		if err != nil {
			return c, err
		}
		if c.Type == "error" {
			return c, daemonErr(&sessionError{Code: c.Code, Message: c.Message})
		}
		if c.Type == want {
			return c, nil
		}
	}
}

func (f *fileSession) list(dir string) (hostListing, error) {
	if err := djtp.WriteControl(f.pd, djtp.Control{Type: "fs_list", Path: dir}); err != nil {
		return hostListing{}, err
	}
	c, err := f.reply("fs_entries")
	if err != nil {
		return hostListing{}, err
	}
	if c.Entries == nil {
		c.Entries = []djtp.FsEntry{}
	}
	return hostListing{Path: c.Path, Entries: c.Entries}, nil
}

// read copies a host file to w (at most max bytes).
func (f *fileSession) read(file string, w io.Writer, max int64) (int64, error) {
	if err := djtp.WriteControl(f.pd, djtp.Control{Type: "fs_read", Path: file}); err != nil {
		return 0, err
	}
	meta, err := f.reply("fs_meta")
	if err != nil {
		return 0, err
	}
	if int64(meta.Size) > max {
		return 0, &apiError{http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("the file has %d bytes; files are limited to %d", meta.Size, max)}
	}
	var n int64
	for {
		f.pd.SetReadDeadline(time.Now().Add(2 * time.Minute))
		fr, err := djtp.ReadFrame(f.pd)
		if err != nil {
			return n, &apiError{http.StatusBadGateway, "connect_failed", "the file session ended: " + err.Error()}
		}
		switch fr.Kind {
		case djtp.KindOutput:
			n += int64(len(fr.Payload))
			if n > max {
				return n, &apiError{http.StatusRequestEntityTooLarge, "too_large", "the file grew past the size limit"}
			}
			if _, err := w.Write(fr.Payload); err != nil {
				return n, err
			}
		case djtp.KindControl:
			c, _ := djtp.DecodeControl(fr)
			switch c.Type {
			case "fs_done":
				return n, nil
			case "error":
				return n, daemonErr(&sessionError{Code: c.Code, Message: c.Message})
			}
		}
	}
}

// write copies r (size bytes) to a host file.
func (f *fileSession) write(file string, r io.Reader, size int64, overwrite bool) error {
	if err := djtp.WriteControl(f.pd, djtp.Control{Type: "fs_write", Path: file, Size: uint64(size), Overwrite: overwrite}); err != nil {
		return err
	}
	buf := make([]byte, fileChunk)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := djtp.WriteFrame(f.pd, djtp.KindInput, buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := djtp.WriteControl(f.pd, djtp.Control{Type: "fs_end"}); err != nil {
		return err
	}
	_, err := f.reply("fs_done")
	return err
}

// openapi:operation
// summary: Browse a host's files
// description: Needs can_upload or can_download on the connection (SSH, over SFTP).
// tags: [files]
// requestBody: { schema: HostListRequest }
// responses:
//   '200': { description: The directory, schema: HostListing }
//   '409': Error

func (s *Server) hostList(w http.ResponseWriter, r *http.Request, p principal) error {
	var req hostListRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	c, err := s.fileAccess(ctx, p, r.PathValue("id"), false, false)
	if err != nil {
		return err
	}
	fs, err := s.openFiles(ctx, p, c, req.Credentials)
	if err != nil {
		return err
	}
	defer fs.Close()
	l, err := fs.list(req.Path)
	if err != nil {
		return err
	}
	return ok(w, l)
}

// openapi:operation
// summary: Take a file out of a host into my tray
// description: Needs can_download. The file is kept with its SHA-256 and audited (file.pull).
// tags: [files]
// requestBody: { schema: HostPullRequest }
// responses:
//   '201': { description: In the tray, schema: TrayFile }

func (s *Server) hostPull(w http.ResponseWriter, r *http.Request, p principal) error {
	if !s.FileSvc.Configured() {
		return errNoFiles
	}
	var req hostPullRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	name, err := cleanName(req.Path)
	if err != nil {
		return err
	}
	ctx := r.Context()
	c, err := s.fileAccess(ctx, p, r.PathValue("id"), false, true)
	if err != nil {
		return err
	}
	fs, err := s.openFiles(ctx, p, c, req.Credentials)
	if err != nil {
		return err
	}
	defer fs.Close()
	pr, pw := io.Pipe()
	readErr := make(chan error, 1)
	go func() {
		_, err := fs.read(req.Path, pw, s.fileMaxSize())
		pw.CloseWithError(err)
		readErr <- err
	}()
	tmp, size, sum, err := s.spool(pr, s.fileMaxSize())
	pr.Close()
	if rerr := <-readErr; rerr != nil {
		if tmp != "" {
			os.Remove(tmp)
		}
		return rerr
	}
	if err != nil {
		return err
	}
	f, err := s.keep(ctx, p, name, tmp, size, sum, "host", &c, req.Path, "file.pull")
	if err != nil {
		return err
	}
	return created(w, toTrayFile(f))
}

// openapi:operation
// summary: Send a file from my tray into a host
// description: Needs can_upload. Refuses to replace an existing file unless overwrite. Audited (file.push).
// tags: [files]
// requestBody: { schema: HostPushRequest }
// responses:
//   '204': { description: Written }
//   '422': Error

func (s *Server) hostPush(w http.ResponseWriter, r *http.Request, p principal) error {
	if !s.FileSvc.Configured() {
		return errNoFiles
	}
	var req hostPushRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Path) == "" {
		return badRequest("path is required")
	}
	ctx := r.Context()
	f, err := s.trayFile(ctx, p, req.FileID)
	if err != nil {
		return err
	}
	c, err := s.fileAccess(ctx, p, r.PathValue("id"), true, false)
	if err != nil {
		return err
	}
	dest := req.Path
	if strings.HasSuffix(dest, "/") {
		dest += f.Name
	}
	body, err := s.FileSvc.OpenStore(ctx, f.StorageKey)
	if err != nil {
		return err
	}
	defer body.Close()
	fs, err := s.openFiles(ctx, p, c, req.Credentials)
	if err != nil {
		return err
	}
	defer fs.Close()
	// Hash what is actually sent: the stored copy must still be the audited one.
	h := sha256.New()
	if err := fs.write(dest, io.TeeReader(body, h), f.Size, req.Overwrite); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.Sha256 {
		slog.Error("tray file changed in storage", "file", f.ID, "want", f.Sha256, "got", got)
		return fmt.Errorf("file %s does not match its recorded hash", f.ID)
	}
	if err := s.FileSvc.AuditPush(ctx, p.actor(), f, c, dest, req.Overwrite); err != nil {
		return err
	}
	return noContent(w)
}

// ---- auditors ----

// openapi:operation
// summary: File transfers
// description: Every file that went through the gateway, newest first.
// tags: [audit]
// parameters:
//   - { name: owner_id, in: query, schema: { type: string } }
//   - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 500, default: 100 } }
// responses:
//   '200': { description: Files, schema: '[]TrayFile' }

func (s *Server) listFilesAudit(w http.ResponseWriter, r *http.Request, p principal) error {
	lim, err := limitParam(r)
	if err != nil {
		return err
	}
	rows, err := s.FileSvc.ListFilesAudit(r.Context(), r.URL.Query().Get("owner_id"), lim)
	if err != nil {
		return fromService(err, "file")
	}
	out := make([]trayFileDTO, 0, len(rows))
	for _, f := range rows {
		out = append(out, toTrayFile(f))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Download a transferred file (evidence)
// description: For auditors, while its content is kept. Audited (file.view).
// tags: [audit]
// responses:
//   '200': { description: The content, content: { application/octet-stream: { schema: { type: string, format: binary } } } }
//   '410': Error

func (s *Server) downloadFileAudit(w http.ResponseWriter, r *http.Request, p principal) error {
	f, body, err := s.FileSvc.DownloadFileAudit(r.Context(), p.actor(), r.PathValue("id"))
	if err != nil {
		return fromService(err, "file")
	}
	defer body.Close()
	serveFile(w, f, body)
	return nil
}
