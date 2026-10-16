package server

import (
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

// Single sign-on against a real Keycloak with the realm in
// deploy/keycloak/duckjump-realm.json. `make test-oidc` starts it
// (deploy/keycloak.sh) and sets DUCKJUMP_TEST_KEYCLOAK to the realm's issuer.

const keycloakGatewayAddr = "127.0.0.1:18090" // registered as the client's redirect URI

func keycloakEnv(t *testing.T) *env {
	issuer := os.Getenv("DUCKJUMP_TEST_KEYCLOAK")
	if issuer == "" {
		t.Skip("DUCKJUMP_TEST_KEYCLOAK not set (make test-oidc runs Keycloak)")
	}
	e := newEnv(t)
	e.mkUser("admin", "superadmin") // the realm has a user "admin" too: it must not log in as this one
	// Serve on the address Keycloak redirects to.
	l, err := net.Listen("tcp", keycloakGatewayAddr)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(e.server.Handler())
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	e.srv = srv
	v, _ := vault.New(vault.GenerateKey())
	roles, _ := auth.ParseRoleMap("duckjump-superadmin=superadmin,duckjump-admin=admin,duckjump-auditor=auditor")
	e.server.OIDC = &auth.OIDC{Issuer: issuer, ClientID: "duckjump", ClientSecret: "duckjump-test-secret",
		RedirectURL: srv.URL + "/api/v1/auth/oidc/callback", RolesClaim: "realm_access.roles", RoleMap: roles, Vault: v}
	return e
}

var kcFormAction = regexp.MustCompile(`<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"|<form[^>]+action="([^"]+)"[^>]+id="kc-form-login"`)

// keycloakLogin signs in on Keycloak's own login page, like a browser.
func keycloakLogin(t *testing.T, e *env, user, password string) (*client, *url.URL) {
	t.Helper()
	c := e.client()
	resp, err := c.http.Get(e.srv.URL + "/api/v1/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(resp.Request.URL.String(), os.Getenv("DUCKJUMP_TEST_KEYCLOAK")) {
		t.Fatalf("not sent to Keycloak: %s", resp.Request.URL)
	}
	m := kcFormAction.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no login form at %s:\n%.2000s", resp.Request.URL, page)
	}
	action := html.UnescapeString(string(m[1]) + string(m[2]))
	resp, err = c.http.PostForm(action, url.Values{"username": {user}, "password": {password}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return c, resp.Request.URL
}

func TestKeycloakSSO(t *testing.T) {
	e := keycloakEnv(t)

	alice, end := keycloakLogin(t, e, "alice", "alice-password")
	if end.Host != keycloakGatewayAddr || end.Query().Get("login_error") != "" {
		t.Fatalf("alice ended at %s", end)
	}
	var me meResponse
	alice.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Username != "alice" || me.User.Source != "oidc" || me.User.Role != "admin" || me.User.DisplayName != "Alice Ops" {
		t.Fatalf("alice: %+v", me.User)
	}
	groups := map[string]bool{}
	for _, g := range me.Groups {
		groups[g.Name+":"+g.Source] = true
	}
	if len(groups) != 2 || !groups["ops:oidc"] || !groups["dba:oidc"] {
		t.Fatalf("alice groups: %+v", me.Groups)
	}
	// An admin from Keycloak administers the gateway.
	alice.do("GET", "/users", nil, 200, nil)

	// Group grants made in the gateway apply to Keycloak groups.
	bob, _ := keycloakLogin(t, e, "bob", "bob-password")
	bob.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Role != "user" || len(me.Groups) != 1 || me.Groups[0].Name != "dev" {
		t.Fatalf("bob: %+v %+v", me.User, me.Groups)
	}
	bob.do("GET", "/users", nil, 403, nil)

	audrey, _ := keycloakLogin(t, e, "audrey", "audrey-password")
	audrey.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Role != "auditor" {
		t.Fatalf("audrey: %+v", me.User)
	}

	// Keycloak's "admin" is not the gateway's local superadmin.
	if _, end := keycloakLogin(t, e, "admin", "admin-password"); !strings.Contains(end.Query().Get("login_error"), "another account") {
		t.Fatalf("realm user took over the local admin: %s", end)
	}

	// A wrong password stays on Keycloak; no session here.
	c, end := keycloakLogin(t, e, "alice", "wrong")
	if end.Host == keycloakGatewayAddr {
		t.Fatalf("wrong password reached the gateway: %s", end)
	}
	c.do("GET", "/auth/me", nil, 401, nil)
}

func TestKeycloakDiscoveryFailureIsReported(t *testing.T) {
	if os.Getenv("DUCKJUMP_TEST_KEYCLOAK") == "" {
		t.Skip("DUCKJUMP_TEST_KEYCLOAK not set")
	}
	e := newEnv(t)
	v, _ := vault.New(vault.GenerateKey())
	e.server.OIDC = &auth.OIDC{Issuer: os.Getenv("DUCKJUMP_TEST_KEYCLOAK") + "-nope", ClientID: "duckjump", RedirectURL: e.srv.URL + "/cb", Vault: v}
	c := e.client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.http.Get(e.srv.URL + "/api/v1/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "login_error=") {
		t.Fatalf("location %q", loc)
	}
}
