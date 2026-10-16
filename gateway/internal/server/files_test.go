package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/djtp"
)

// fakeSFTP is duckjumpd answering file sessions from an in-memory
// filesystem per host.
type fakeSFTP struct {
	mu     sync.Mutex
	files  map[string]map[string][]byte // host -> path -> content
	hellos []djtp.Control
}

func newFakeSFTP(t *testing.T) (*fakeSFTP, string) {
	f := &fakeSFTP{files: map[string]map[string][]byte{}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f, l.Addr().String()
}

func (f *fakeSFTP) host(h string) map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files[h] == nil {
		f.files[h] = map[string][]byte{}
	}
	return f.files[h]
}

func (f *fakeSFTP) serve(c net.Conn) {
	defer c.Close()
	fr, err := djtp.ReadFrame(c)
	if err != nil {
		return
	}
	h, _ := djtp.DecodeControl(fr)
	f.mu.Lock()
	f.hellos = append(f.hellos, h)
	f.mu.Unlock()
	var params struct {
		Host string
		Auth struct{ Password string }
	}
	b, _ := json.Marshal(h.Params)
	json.Unmarshal(b, &params)
	if h.Protocol != "sftp" {
		djtp.WriteControl(c, djtp.Control{Type: "error", Code: "unsupported_protocol", Message: h.Protocol})
		return
	}
	if params.Auth.Password == "wrong" {
		djtp.WriteControl(c, djtp.Control{Type: "error", Code: "auth_failed", Message: "authentication rejected by server"})
		return
	}
	fs := f.host(params.Host)
	djtp.WriteControl(c, djtp.Control{Type: "ready", SessionID: h.SessionID})
	fail := func(msg string) { djtp.WriteControl(c, djtp.Control{Type: "error", Code: "fs_failed", Message: msg}) }
	for {
		fr, err := djtp.ReadFrame(c)
		if err != nil {
			return
		}
		op, _ := djtp.DecodeControl(fr)
		f.mu.Lock()
		switch op.Type {
		case "fs_list":
			var es []djtp.FsEntry
			for p, data := range fs {
				es = append(es, djtp.FsEntry{Name: p, Size: uint64(len(data))})
			}
			djtp.WriteControl(c, djtp.Control{Type: "fs_entries", Path: "/home/u", Entries: es})
		case "fs_read":
			data, ok := fs[op.Path]
			if !ok {
				fail("no such file")
				break
			}
			djtp.WriteControl(c, djtp.Control{Type: "fs_meta", Size: uint64(len(data))})
			for i := 0; i < len(data); i += 1000 {
				djtp.WriteFrame(c, djtp.KindOutput, data[i:min(i+1000, len(data))])
			}
			djtp.WriteControl(c, djtp.Control{Type: "fs_done", Bytes: uint64(len(data))})
		case "fs_write":
			var buf bytes.Buffer
			for {
				fr, err := djtp.ReadFrame(c)
				if err != nil {
					f.mu.Unlock()
					return
				}
				if fr.Kind == djtp.KindInput {
					buf.Write(fr.Payload)
					continue
				}
				break // fs_end
			}
			if _, exists := fs[op.Path]; exists && !op.Overwrite {
				fail(op.Path + " already exists")
				break
			}
			fs[op.Path] = buf.Bytes()
			djtp.WriteControl(c, djtp.Control{Type: "fs_done", Bytes: uint64(buf.Len())})
		case "close":
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
	}
}

func (c *client) rawBody(method, path string, body []byte) (*http.Response, []byte) {
	c.e.t.Helper()
	req, _ := http.NewRequest(method, c.e.srv.URL+"/api/v1"+path, bytes.NewReader(body))
	req.Header.Set(csrfHeader, "1")
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type filesEnv struct {
	*env
	fs         *fakeSFTP
	root, ana  *client
	anaID      string
	web1, web2 connectionDTO
	pol1, pol2 policyDTO
	prompt     connectionDTO
}

// ana can connect to web1 and web2 (vaulted) and to prompt (asks credentials).
func newFilesEnv(t *testing.T) *filesEnv {
	e := newEnv(t)
	fe := &filesEnv{env: e}
	fe.fs, e.server.DaemonAddr = newFakeSFTP(t)
	e.server.Files = DirFileStore{Dir: t.TempDir()}
	e.mkUser("ana", "user")
	fe.root = e.as("root")
	var sec secretDTO
	fe.root.do("POST", "/secrets", secretRequest{Name: "s", Kind: "password", Username: "u", Value: "p"}, 201, &sec)
	fe.root.do("POST", "/connections", connectionRequest{Name: "web1", Protocol: "ssh", Host: "h1", SecretID: &sec.ID}, 201, &fe.web1)
	fe.root.do("POST", "/connections", connectionRequest{Name: "web2", Protocol: "ssh", Host: "h2", SecretID: &sec.ID}, 201, &fe.web2)
	fe.root.do("POST", "/connections", connectionRequest{Name: "ask", Protocol: "ssh", Host: "h3", CredentialMode: "prompt"}, 201, &fe.prompt)
	var users []userDTO
	fe.root.do("GET", "/users", nil, 200, &users)
	for _, u := range users {
		if u.Username == "ana" {
			fe.anaID = u.ID
		}
	}
	for _, c := range []*struct {
		conn *connectionDTO
		pol  *policyDTO
	}{{&fe.web1, &fe.pol1}, {&fe.web2, &fe.pol2}, {&fe.prompt, &policyDTO{}}} {
		fe.root.do("POST", "/policies", policyRequest{SubjectType: "user", SubjectID: fe.anaID, ObjectType: "connection", ObjectRef: c.conn.ID}, 201, c.pol)
	}
	fe.ana = e.as("ana")
	return fe
}

func TestTray(t *testing.T) {
	fe := newFilesEnv(t)
	body := []byte("hello tray")
	resp, b := fe.ana.rawBody("POST", "/files?name=../../etc/notes.txt", body)
	var f trayFileDTO
	json.Unmarshal(b, &f)
	if resp.StatusCode != 201 || f.Name != "notes.txt" || f.Size != int64(len(body)) || f.SHA256 != sum(body) || f.Origin != "upload" {
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	var tray []trayFileDTO
	fe.ana.do("GET", "/files", nil, 200, &tray)
	if len(tray) != 1 {
		t.Fatalf("tray: %+v", tray)
	}
	resp, b = fe.ana.raw("GET", "/files/"+f.ID+"/content", nil, true)
	if resp.StatusCode != 200 || !bytes.Equal(b, body) || resp.Header.Get("X-DuckJump-SHA256") != f.SHA256 {
		t.Fatalf("download: %d %q", resp.StatusCode, b)
	}
	// Somebody else's tray is not reachable.
	fe.root.do("GET", "/files/"+f.ID+"/content", nil, 404, nil)
	fe.root.do("DELETE", "/files/"+f.ID, nil, 404, nil)

	fe.ana.do("DELETE", "/files/"+f.ID, nil, 204, nil)
	fe.ana.do("GET", "/files/"+f.ID+"/content", nil, 410, nil)
	fe.ana.do("GET", "/files", nil, 200, &tray)
	if len(tray) != 0 {
		t.Fatalf("deleted file still in the tray: %+v", tray)
	}
	// The record stays, for auditors.
	var all []trayFileDTO
	fe.root.do("GET", "/audit/files", nil, 200, &all)
	if len(all) != 1 || all[0].DeletedAt == nil {
		t.Fatalf("audit files: %+v", all)
	}
	fe.ana.do("GET", "/audit/files", nil, 403, nil)
	var evs []auditEventDTO
	fe.root.do("GET", "/audit/events?object_id="+f.ID, nil, 200, &evs)
	if len(evs) != 3 { // upload, download, delete
		t.Fatalf("audit events: %+v", evs)
	}

	// Size limit.
	fe.server.FileMaxSize = 4
	if resp, _ := fe.ana.rawBody("POST", "/files?name=big", []byte("12345")); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: %d", resp.StatusCode)
	}
}

func TestFilesBetweenSessions(t *testing.T) {
	fe := newFilesEnv(t)
	secret := bytes.Repeat([]byte("db-dump "), 5000)
	fe.fs.host("h1")["/tmp/dump.sql"] = secret

	// Connect alone does not allow file transfer.
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/list", hostListRequest{}, 403, nil)
	fe.root.do("PATCH", "/policies/"+fe.pol1.ID, map[string]any{"can_download": true}, 200, nil)

	var l hostListing
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/list", hostListRequest{}, 200, &l)
	if l.Path != "/home/u" || len(l.Entries) != 1 {
		t.Fatalf("listing: %+v", l)
	}
	var pulled trayFileDTO
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/pull", hostPullRequest{Path: "/tmp/dump.sql"}, 201, &pulled)
	if pulled.Name != "dump.sql" || pulled.SHA256 != sum(secret) || pulled.Origin != "host" || pulled.ConnectionID == nil || *pulled.ConnectionID != fe.web1.ID {
		t.Fatalf("pulled: %+v", pulled)
	}
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/pull", hostPullRequest{Path: "/nope"}, 422, nil)
	// web1 grants no upload; web2 nothing at all yet.
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/push", hostPushRequest{FileID: pulled.ID, Path: "/tmp/x"}, 403, nil)
	fe.ana.do("POST", "/connections/"+fe.web2.ID+"/files/push", hostPushRequest{FileID: pulled.ID, Path: "/srv/"}, 403, nil)

	// Into the second session's host.
	fe.root.do("PATCH", "/policies/"+fe.pol2.ID, map[string]any{"can_upload": true}, 200, nil)
	fe.ana.do("POST", "/connections/"+fe.web2.ID+"/files/push", hostPushRequest{FileID: pulled.ID, Path: "/srv/"}, 204, nil)
	if got := fe.fs.host("h2")["/srv/dump.sql"]; !bytes.Equal(got, secret) {
		t.Fatalf("pushed %d bytes, want %d", len(got), len(secret))
	}
	// No silent overwrite.
	fe.ana.do("POST", "/connections/"+fe.web2.ID+"/files/push", hostPushRequest{FileID: pulled.ID, Path: "/srv/dump.sql"}, 422, nil)
	fe.ana.do("POST", "/connections/"+fe.web2.ID+"/files/push", hostPushRequest{FileID: pulled.ID, Path: "/srv/dump.sql", Overwrite: true}, 204, nil)

	// To ana's computer, while she may still download from web1.
	resp, b := fe.ana.raw("GET", "/files/"+pulled.ID+"/content", nil, true)
	if resp.StatusCode != 200 || !bytes.Equal(b, secret) {
		t.Fatalf("download: %d", resp.StatusCode)
	}
	fe.root.do("PATCH", "/policies/"+fe.pol1.ID, map[string]any{"can_download": false}, 200, nil)
	fe.ana.do("GET", "/files/"+pulled.ID+"/content", nil, 403, nil)

	// The daemon got SFTP sessions with the vaulted credential, nothing else.
	for _, h := range fe.fs.hellos {
		if h.Protocol != "sftp" || h.Recording != nil {
			t.Fatalf("hello: %+v", h)
		}
	}
	var evs []auditEventDTO
	fe.root.do("GET", "/audit/events?action=file.push", nil, 200, &evs)
	if len(evs) != 2 || !strings.Contains(string(evs[0].Details), sum(secret)) {
		t.Fatalf("push audit: %+v", evs)
	}
	fe.root.do("GET", "/audit/events?action=file.pull", nil, 200, &evs)
	if len(evs) != 1 {
		t.Fatalf("pull audit: %+v", evs)
	}
	// Auditors get the evidence.
	resp, b = fe.root.raw("GET", "/audit/files/"+pulled.ID+"/content", nil, true)
	if resp.StatusCode != 200 || !bytes.Equal(b, secret) {
		t.Fatalf("evidence: %d", resp.StatusCode)
	}
}

func TestFilesPromptedCredentialsAndLimits(t *testing.T) {
	fe := newFilesEnv(t)
	var pols []policyDTO
	fe.root.do("GET", "/policies?object_ref="+fe.prompt.ID, nil, 200, &pols)
	fe.root.do("PATCH", "/policies/"+pols[0].ID, map[string]any{"can_download": true, "can_upload": true}, 200, nil)
	path := "/connections/" + fe.prompt.ID + "/files/list"
	if b := fe.ana.do("POST", path, hostListRequest{}, 409, nil); errCode(b) != "credentials_required" {
		t.Fatalf("got %s", b)
	}
	if b := fe.ana.do("POST", path, hostListRequest{Credentials: &fileCredentials{Username: "u", Password: "wrong"}}, 403, nil); errCode(b) != "auth_failed" {
		t.Fatalf("got %s", b)
	}
	fe.ana.do("POST", path, hostListRequest{Credentials: &fileCredentials{Username: "u", Password: "ok"}}, 200, nil)
	// Credentials sent for a vaulted connection are refused.
	fe.root.do("PATCH", "/policies/"+fe.pol1.ID, map[string]any{"can_download": true}, 200, nil)
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/list", hostListRequest{Credentials: &fileCredentials{Username: "x", Password: "y"}}, 400, nil)

	// The size limit applies to pulls too.
	fe.fs.host("h1")["/big"] = make([]byte, 5000)
	fe.server.FileMaxSize = 4000
	fe.ana.do("POST", "/connections/"+fe.web1.ID+"/files/pull", hostPullRequest{Path: "/big"}, 413, nil)

	// RDP and VNC have no file transfer (yet).
	var rdp connectionDTO
	fe.root.do("POST", "/connections", connectionRequest{Name: "win", Protocol: "rdp", Host: "w"}, 201, &rdp)
	fe.root.do("POST", "/connections/"+rdp.ID+"/files/list", hostListRequest{}, 400, nil)
}

func TestTrayExpiry(t *testing.T) {
	fe := newFilesEnv(t)
	fe.server.FileTTL = time.Millisecond
	_, b := fe.ana.rawBody("POST", "/files?name=a", []byte("x"))
	var f trayFileDTO
	json.Unmarshal(b, &f)
	time.Sleep(5 * time.Millisecond)
	n, err := fe.server.PurgeFiles(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	fe.ana.do("GET", "/files/"+f.ID+"/content", nil, 410, nil)
	got, _ := fe.st.Q.GetFile(context.Background(), f.ID)
	if got.DeleteReason.String != "expired" {
		t.Fatalf("%+v", got)
	}
}
