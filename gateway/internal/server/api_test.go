package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/edge"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/totp"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

func TestMain(m *testing.M) {
	store.SetAuditKey([]byte("server tests audit key.........."))
	os.Exit(m.Run())
}

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *store.Store
	server *Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, closeDB, err := store.OpenTemp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, _ := vault.New(vault.GenerateKey())
	s := &Server{Store: st, Vault: v, Auth: &auth.Service{Store: st, Vault: v}, Hub: edge.NewHub(st.AgentSiteLookup),
		DaemonAddr: "127.0.0.1:1", DaemonToken: "x"}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); closeDB() })
	e := &env{t: t, srv: srv, st: st, server: s}
	e.mkUser("root", "superadmin")
	return e
}

func (e *env) mkUser(name, role string) {
	e.t.Helper()
	h, _ := auth.HashPassword("password-" + name)
	if err := e.st.Q.CreateUser(context.Background(), db.CreateUserParams{ID: store.NewID(), Username: name,
		PasswordHash: store.NullString(h), Source: "local", Role: role, Now: store.Now()}); err != nil {
		e.t.Fatal(err)
	}
}

type client struct {
	e    *env
	http *http.Client
}

func (e *env) client() *client {
	jar, _ := cookiejar.New(nil)
	return &client{e: e, http: &http.Client{Jar: jar}}
}

// login as name (password "password-<name>").
func (e *env) as(name string) *client {
	c := e.client()
	c.do("POST", "/auth/login", map[string]string{"username": name, "password": "password-" + name}, 200, nil)
	return c
}

func (c *client) raw(method, path string, body any, csrf bool) (*http.Response, []byte) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.e.srv.URL+"/api/v1"+path, rd)
	if csrf {
		req.Header.Set(csrfHeader, "1")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// do sends a request with the CSRF header, asserts the status and decodes into out.
func (c *client) do(method, path string, body any, want int, out any) []byte {
	c.e.t.Helper()
	resp, b := c.raw(method, path, body, true)
	if resp.StatusCode != want {
		c.e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			c.e.t.Fatalf("%s %s: decoding %s: %v", method, path, b, err)
		}
	}
	return b
}

func errCode(b []byte) string {
	var e struct{ Error string }
	json.Unmarshal(b, &e)
	return e.Error
}

func TestLoginRolesAndCSRF(t *testing.T) {
	e := newEnv(t)
	e.mkUser("ana", "user")
	e.mkUser("aud", "auditor")
	anon := e.client()

	anon.do("GET", "/users", nil, 401, nil)
	if b := anon.do("POST", "/auth/login", map[string]string{"username": "ana", "password": "nope"}, 401, nil); errCode(b) != "invalid_credentials" {
		t.Fatalf("got %s", b)
	}
	resp, b := anon.raw("POST", "/auth/login", map[string]string{"username": "ana", "password": "password-ana"}, false)
	if resp.StatusCode != 403 || errCode(b) != "csrf" {
		t.Fatalf("login without CSRF header: %d %s", resp.StatusCode, b)
	}

	ana := e.as("ana")
	var me meResponse
	ana.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Username != "ana" || me.MFAPending {
		t.Fatalf("me: %+v", me)
	}
	ana.do("GET", "/users", nil, 403, nil)
	ana.do("GET", "/audit/events", nil, 403, nil)
	ana.do("GET", "/portal/connections", nil, 200, nil)

	aud := e.as("aud")
	aud.do("GET", "/audit/events", nil, 200, nil)
	aud.do("POST", "/users", createUserRequest{Username: "x", Password: "0123456789"}, 403, nil)

	ana.do("POST", "/auth/logout", nil, 204, nil)
	ana.do("GET", "/auth/me", nil, 401, nil)
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	for range 5 {
		c.do("POST", "/auth/login", map[string]string{"username": "root", "password": "bad"}, 401, nil)
	}
	// Locked even with the right password.
	if b := c.do("POST", "/auth/login", map[string]string{"username": "root", "password": "password-root"}, 429, nil); errCode(b) != "too_many_attempts" {
		t.Fatalf("got %s", b)
	}
}

func TestCatalogPoliciesAndPortal(t *testing.T) {
	e := newEnv(t)
	e.mkUser("ana", "user")
	root := e.as("root")

	var prod, web, dbf folderDTO
	root.do("POST", "/folders", folderRequest{Name: "prod"}, 201, &prod)
	root.do("POST", "/folders", folderRequest{Name: "web", ParentID: &prod.ID}, 201, &web)
	root.do("POST", "/folders", folderRequest{Name: "db"}, 201, &dbf)
	root.do("POST", "/folders", folderRequest{Name: "prod"}, 409, nil)
	// Moving prod under its own child is refused.
	root.do("PATCH", "/folders/"+prod.ID, map[string]any{"parent_id": web.ID}, 409, nil)

	var sec secretDTO
	b := root.do("POST", "/secrets", secretRequest{Name: "web-root", Kind: "password", Username: "root", Value: "hunter2-secret"}, 201, &sec)
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("secret value echoed back")
	}
	if all := root.do("GET", "/secrets", nil, 200, nil); strings.Contains(string(all), "hunter2") || strings.Contains(string(all), "sealed") {
		t.Fatal("secret value listed")
	}

	var web1, db1 connectionDTO
	root.do("POST", "/connections", connectionRequest{Name: "web1", Protocol: "ssh", Host: "10.0.0.5", FolderID: &web.ID,
		SecretID: &sec.ID, Tags: []string{"Linux", "linux", "nginx"}}, 201, &web1)
	if web1.Port != 22 || strings.Join(web1.Tags, ",") != "linux,nginx" || !web1.Record {
		t.Fatalf("defaults/tags: %+v", web1)
	}
	root.do("POST", "/connections", connectionRequest{Name: "db1", Protocol: "rdp", Host: "10.0.0.9", FolderID: &dbf.ID}, 201, &db1)
	if db1.Port != 3389 {
		t.Fatalf("rdp default port: %d", db1.Port)
	}
	root.do("POST", "/connections", connectionRequest{Name: "bad", Protocol: "telnet", Host: "h"}, 400, nil)
	root.do("DELETE", "/folders/"+prod.ID, nil, 409, nil) // not empty

	// Group grant on the prod folder: ana, a member, sees web1 (nested) only.
	var ops groupDTO
	root.do("POST", "/groups", groupRequest{Name: "ops"}, 201, &ops)
	var users []userDTO
	root.do("GET", "/users", nil, 200, &users)
	anaID := ""
	for _, u := range users {
		if u.Username == "ana" {
			anaID = u.ID
		}
	}
	root.do("PUT", "/groups/"+ops.ID+"/members/"+anaID, nil, 204, nil)
	var pol policyDTO
	root.do("POST", "/policies", policyRequest{SubjectType: "group", SubjectID: ops.ID, ObjectType: "folder", ObjectRef: prod.ID, TTLSeconds: 3600}, 201, &pol)
	if pol.ExpiresAt == nil || time.Until(*pol.ExpiresAt) < 59*time.Minute {
		t.Fatalf("ttl: %+v", pol)
	}

	ana := e.as("ana")
	var portal []portalConnectionDTO
	ana.do("GET", "/portal/connections", nil, 200, &portal)
	if len(portal) != 1 || portal[0].Name != "web1" || portal[0].FolderPath != "prod / web" {
		t.Fatalf("portal: %+v", portal)
	}
	var access []accessEntry
	root.do("GET", "/users/"+anaID+"/access", nil, 200, &access)
	if len(access) != 1 || access[0].Grants[0].ID != pol.ID {
		t.Fatalf("access: %+v", access)
	}

	// No grant on db1: opening a session is refused and audited.
	ana.do("GET", "/connections/"+db1.ID+"/session", nil, 403, nil)

	// PATCH: moving web1 to the root (folder_id null) drops ana's access.
	var moved connectionDTO
	root.do("PATCH", "/connections/"+web1.ID, map[string]any{"folder_id": nil, "tags": []string{"x"}}, 200, &moved)
	if moved.FolderID != nil || strings.Join(moved.Tags, ",") != "x" || moved.SecretID == nil {
		t.Fatalf("patch: %+v", moved)
	}
	ana.do("GET", "/portal/connections", nil, 200, &portal)
	if len(portal) != 0 {
		t.Fatalf("access survived the move: %+v", portal)
	}

	// Audit: chain verifies and recorded the denial.
	var v store.VerifyResult
	root.do("GET", "/audit/verify", nil, 200, &v)
	if !v.OK || v.Events < 10 {
		t.Fatalf("verify: %+v", v)
	}
	var evs []auditEventDTO
	root.do("GET", "/audit/events?action=session.denied", nil, 200, &evs)
	if len(evs) != 1 || evs[0].ActorName != "ana" {
		t.Fatalf("denial not audited: %+v", evs)
	}
}

func TestSuperadminGuards(t *testing.T) {
	e := newEnv(t)
	e.mkUser("adm", "admin")
	adm := e.as("adm")
	if b := adm.do("POST", "/users", createUserRequest{Username: "boss", Password: "0123456789", Role: "superadmin"}, 403, nil); !strings.Contains(string(b), "superadmin") {
		t.Fatalf("got %s", b)
	}
	root := e.as("root")
	var me meResponse
	root.do("GET", "/auth/me", nil, 200, &me)
	root.do("PATCH", "/users/"+me.User.ID, map[string]any{"role": "admin"}, 409, nil) // last superadmin
	root.do("DELETE", "/users/"+me.User.ID, nil, 409, nil)                            // self
	var u userDTO
	root.do("POST", "/users", createUserRequest{Username: "short", Password: "123"}, 400, nil)
	root.do("POST", "/users", createUserRequest{Username: "Bad Name", Password: "0123456789"}, 400, nil)
	root.do("POST", "/users", createUserRequest{Username: "new", Password: "0123456789"}, 201, &u)
	root.do("POST", "/users", createUserRequest{Username: "new", Password: "0123456789"}, 409, nil)
}

func TestTOTPFlow(t *testing.T) {
	e := newEnv(t)
	e.mkUser("ana", "user")
	ana := e.as("ana")
	var enr totpEnrollment
	ana.do("POST", "/auth/me/totp/enroll", nil, 200, &enr)
	if !strings.HasPrefix(enr.OTPAuthURL, "otpauth://totp/DuckJump:ana?") {
		t.Fatalf("url: %s", enr.OTPAuthURL)
	}
	ana.do("POST", "/auth/me/totp/confirm", codeRequest{Code: "000000"}, 401, nil)
	code, _ := totp.Code(enr.Secret, time.Now())
	ana.do("POST", "/auth/me/totp/confirm", codeRequest{Code: code}, 204, nil)
	ana.do("POST", "/auth/logout", nil, 204, nil)

	var lr loginResponse
	ana.do("POST", "/auth/login", map[string]string{"username": "ana", "password": "password-ana"}, 200, &lr)
	if !lr.MFARequired || lr.User != nil {
		t.Fatalf("login: %+v", lr)
	}
	if b := ana.do("GET", "/portal/connections", nil, 403, nil); errCode(b) != "mfa_required" {
		t.Fatalf("half-open session used: %s", b)
	}
	var me meResponse
	ana.do("GET", "/auth/me", nil, 200, &me)
	if !me.MFAPending {
		t.Fatal("me should report mfa_pending")
	}
	code, _ = totp.Code(enr.Secret, time.Now())
	ana.do("POST", "/auth/totp", codeRequest{Code: code}, 200, &lr)
	if lr.User == nil || lr.User.Username != "ana" {
		t.Fatalf("totp step: %+v", lr)
	}
	ana.do("GET", "/portal/connections", nil, 200, nil)
}

func TestSitesAndTokens(t *testing.T) {
	e := newEnv(t)
	root := e.as("root")
	var site siteDTO
	root.do("POST", "/sites", siteRequest{Name: "edge1", Kind: "agent"}, 201, &site)
	if !strings.HasPrefix(site.AgentToken, "pat_") || site.AgentsOnline == nil {
		t.Fatalf("site: %+v", site)
	}
	var again siteDTO
	root.do("GET", "/sites/"+site.ID, nil, 200, &again)
	if again.AgentToken != "" {
		t.Fatal("token shown again")
	}
	var rot siteDTO
	root.do("POST", "/sites/"+site.ID+"/token", nil, 200, &rot)
	if rot.AgentToken == "" || rot.AgentToken == site.AgentToken {
		t.Fatal("rotation did not issue a new token")
	}
	if _, _, err := e.st.AgentSiteLookup(context.Background(), edge.HashToken(site.AgentToken)); err == nil {
		t.Fatal("old token still valid")
	}
	var direct siteDTO
	root.do("POST", "/sites", siteRequest{Name: "dc1", Kind: "direct"}, 201, &direct)
	root.do("POST", "/sites/"+direct.ID+"/token", nil, 409, nil)
	root.do("POST", "/connections", connectionRequest{Name: "c", Protocol: "ssh", Host: "h", SiteID: &direct.ID}, 201, nil)
	root.do("DELETE", "/sites/"+direct.ID, nil, 409, nil) // in use
}

func TestDuplicateGrantRefused(t *testing.T) {
	e := newEnv(t)
	root := e.as("root")
	var g groupDTO
	root.do("POST", "/groups", groupRequest{Name: "ops"}, 201, &g)
	req := policyRequest{SubjectType: "group", SubjectID: g.ID, ObjectType: "tag", ObjectRef: "linux"}
	root.do("POST", "/policies", req, 201, nil)
	if b := root.do("POST", "/policies", req, 409, nil); !strings.Contains(string(b), "already exists") {
		t.Fatalf("got %s", b)
	}
}

func TestSessionCredentials(t *testing.T) {
	e := newEnv(t)
	root := e.as("root")
	var sec secretDTO
	root.do("POST", "/secrets", secretRequest{Name: "s", Kind: "password", Username: "u", Value: "p"}, 201, &sec)
	var bare, vaulted, rdp connectionDTO
	root.do("POST", "/connections", connectionRequest{Name: "bare-ssh", Protocol: "ssh", Host: "h"}, 201, &bare)
	root.do("POST", "/connections", connectionRequest{Name: "vaulted", Protocol: "ssh", Host: "h", SecretID: &sec.ID}, 201, &vaulted)
	root.do("POST", "/connections", connectionRequest{Name: "win", Protocol: "rdp", Host: "h"}, 201, &rdp)
	var me meResponse
	root.do("GET", "/auth/me", nil, 200, &me)
	for _, c := range []string{bare.ID, vaulted.ID, rdp.ID} {
		root.do("POST", "/policies", policyRequest{SubjectType: "user", SubjectID: me.User.ID, ObjectType: "connection", ObjectRef: c}, 201, nil)
	}

	var portal []portalConnectionDTO
	root.do("GET", "/portal/connections", nil, 200, &portal)
	modes := map[string]string{}
	for _, c := range portal {
		modes[c.Name] = c.Credentials
	}
	if modes["bare-ssh"] != "prompt" || modes["vaulted"] != "vault" || modes["win"] != "none" {
		t.Fatalf("portal credential modes: %v", modes)
	}

	// Opens the session WebSocket and returns the first error message.
	firstError := func(id, query string, send any) map[string]string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		u := strings.Replace(e.srv.URL, "http", "ws", 1) + "/api/v1/connections/" + id + "/session" + query
		hdr := http.Header{}
		for _, ck := range root.http.Jar.Cookies(mustURL(e.srv.URL)) {
			hdr.Add("Cookie", ck.Name+"="+ck.Value)
		}
		ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: hdr})
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		if send != nil {
			b, _ := json.Marshal(send)
			ws.Write(ctx, websocket.MessageText, b)
		}
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		json.Unmarshal(data, &m)
		return m
	}
	if m := firstError(bare.ID, "", nil); m["code"] != "credentials_required" {
		t.Fatalf("bare ssh: %v", m)
	}
	if m := firstError(vaulted.ID, "?credentials=1", map[string]string{"type": "credentials", "username": "x", "password": "y"}); m["code"] != "bad_request" {
		t.Fatalf("prompt over a vaulted credential: %v", m)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
