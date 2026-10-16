package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

// fakeIdP is a minimal OpenID provider: it logs in whoever `next` says,
// checks PKCE and the client secret, and signs ID tokens with RS256.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu         sync.Mutex
	next       map[string]any // claims of the next login ("sub" required)
	badNonce   bool
	codes      map[string]pendingCode
	tokenCalls int
}

type pendingCode struct {
	claims    map[string]any
	nonce     string
	challenge string
	redirect  string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{t: t, key: k, codes: map[string]pendingCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "duckjump" || !strings.Contains(q.Get("scope"), "openid") {
			http.Error(w, "bad authorization request", 400)
			return
		}
		f.mu.Lock()
		code := randomID(8)
		f.codes[code] = pendingCode{claims: f.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		f.mu.Lock()
		f.tokenCalls++
		pc, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		bad := f.badNonce
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case id != "duckjump" || secret != "s3cret":
			http.Error(w, `{"error":"invalid_client"}`, 401)
			return
		case !ok || pc.redirect != r.PostForm.Get("redirect_uri"):
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"PKCE"}`, 400)
			return
		}
		claims := map[string]any{"iss": f.srv.URL, "aud": "duckjump", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": pc.nonce}
		if bad {
			claims["nonce"] = "something else"
		}
		for k, v := range pc.claims {
			claims[k] = v
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: "k1"}}, nil)
		payload, _ := json.Marshal(claims)
		jws, _ := signer.Sign(payload)
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60, "id_token": idt})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) as(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next = claims
}

func oidcEnv(t *testing.T) (*env, *fakeIdP) {
	e := newEnv(t)
	idp := newFakeIdP(t)
	v, _ := vault.New(vault.GenerateKey())
	roles, _ := auth.ParseRoleMap("duckjump-admin=admin,duckjump-auditor=auditor")
	e.server.OIDC = &auth.OIDC{Issuer: idp.srv.URL, ClientID: "duckjump", ClientSecret: "s3cret",
		RedirectURL: e.srv.URL + "/api/v1/auth/oidc/callback", RolesClaim: "realm_access.roles", RoleMap: roles, Vault: v, Name: "Keycloak"}
	return e, idp
}

// ssoLogin runs the browser side of the flow; returns the client and where
// it ended (the UI, with login_error on failure).
func (e *env) ssoLogin(t *testing.T) (*client, *url.URL) {
	t.Helper()
	c := e.client()
	resp, err := c.http.Get(e.srv.URL + "/api/v1/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return c, resp.Request.URL
}

func TestOIDCProvisioningRolesAndGroups(t *testing.T) {
	e, idp := oidcEnv(t)
	var p authProviders
	e.client().do("GET", "/auth/providers", nil, 200, &p)
	if p.OIDC == nil || p.OIDC.Name != "Keycloak" || !p.Local {
		t.Fatalf("providers: %+v", p)
	}

	idp.as(map[string]any{"sub": "u-1", "preferred_username": "Alice", "name": "Alice Ops", "email": "alice@example.com",
		"realm_access": map[string]any{"roles": []string{"offline_access", "duckjump-admin"}}, "groups": []string{"/ops", "/dba"}})
	alice, end := e.ssoLogin(t)
	if end.Path != "/" || end.Query().Get("login_error") != "" {
		t.Fatalf("ended at %s", end)
	}
	var me meResponse
	alice.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Username != "alice" || me.User.Source != "oidc" || me.User.Role != "admin" || me.User.Email != "alice@example.com" {
		t.Fatalf("me: %+v", me.User)
	}
	names := func(gs []groupDTO) string {
		var n []string
		for _, g := range gs {
			n = append(n, g.Name+":"+g.Source)
		}
		return strings.Join(n, ",")
	}
	if got := names(me.Groups); got != "dba:oidc,ops:oidc" {
		t.Fatalf("groups: %s", got)
	}

	// Next login: the provider dropped a group and the admin role.
	idp.as(map[string]any{"sub": "u-1", "preferred_username": "alice", "email": "alice@example.com", "groups": []string{"ops"}})
	alice, _ = e.ssoLogin(t)
	alice.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Role != "user" || names(me.Groups) != "ops:oidc" {
		t.Fatalf("after sync: role %s groups %s", me.User.Role, names(me.Groups))
	}

	// The provider owns the password, the second factor, the role and the groups.
	alice.do("PUT", "/auth/me/password", changePasswordRequest{Current: "x", New: "0123456789ab"}, 409, nil)
	alice.do("POST", "/auth/me/totp/enroll", nil, 409, nil)
	root := e.as("root")
	root.do("PUT", "/users/"+me.User.ID+"/password", passwordRequest{Password: "0123456789ab"}, 409, nil)
	root.do("PATCH", "/users/"+me.User.ID, map[string]any{"role": "superadmin"}, 409, nil)
	root.do("PUT", "/groups/"+me.Groups[0].ID+"/members/"+me.User.ID, nil, 409, nil)
	// …and the password login does not work for these users.
	e.client().do("POST", "/auth/login", loginRequest{Username: "alice", Password: ""}, 401, nil)

	var evs []auditEventDTO
	root.do("GET", "/audit/events?action=auth.login&actor_id="+me.User.ID, nil, 200, &evs)
	if len(evs) != 2 || !strings.Contains(string(evs[0].Details), `"oidc"`) {
		t.Fatalf("logins not audited: %+v", evs)
	}
	root.do("GET", "/audit/events?action=group.member_remove", nil, 200, &evs)
	if len(evs) != 1 {
		t.Fatalf("group removal not audited: %+v", evs)
	}
}

func TestOIDCRefusals(t *testing.T) {
	e, idp := oidcEnv(t)

	// A local account's name cannot be claimed through the provider.
	idp.as(map[string]any{"sub": "evil", "preferred_username": "root"})
	if _, end := e.ssoLogin(t); !strings.Contains(end.Query().Get("login_error"), "another account") {
		t.Fatalf("took over a local name: %s", end)
	}

	// A disabled user stays out.
	idp.as(map[string]any{"sub": "u-2", "preferred_username": "bob"})
	bob, _ := e.ssoLogin(t)
	var me meResponse
	bob.do("GET", "/auth/me", nil, 200, &me)
	e.as("root").do("PATCH", "/users/"+me.User.ID, map[string]any{"disabled": true}, 200, nil)
	if _, end := e.ssoLogin(t); end.Query().Get("login_error") != "user disabled" {
		t.Fatalf("disabled user: %s", end)
	}

	// An ID token for another login (nonce) is refused.
	idp.as(map[string]any{"sub": "u-3", "preferred_username": "carol"})
	idp.badNonce = true
	if _, end := e.ssoLogin(t); !strings.Contains(end.Query().Get("login_error"), "nonce") {
		t.Fatalf("bad nonce: %s", end)
	}
	idp.badNonce = false

	// A callback without the state cookie (login CSRF, or another browser) never redeems the code.
	before := idp.tokenCalls
	resp, err := e.client().http.Get(e.srv.URL + "/api/v1/auth/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(resp.Request.URL.Query().Get("login_error"), "try again") || idp.tokenCalls != before {
		t.Fatalf("callback without state: %s (token calls %d -> %d)", resp.Request.URL, before, idp.tokenCalls)
	}

	// The provider said no.
	resp, _ = e.client().http.Get(e.srv.URL + "/api/v1/auth/oidc/callback?error=access_denied")
	resp.Body.Close()
	if !strings.Contains(resp.Request.URL.Query().Get("login_error"), "access_denied") {
		t.Fatalf("provider error: %s", resp.Request.URL)
	}

	var evs []auditEventDTO
	e.as("root").do("GET", "/audit/events?action=auth.login_failed", nil, 200, &evs)
	if len(evs) != 5 {
		t.Fatalf("%d failed logins audited, want 5", len(evs))
	}
}

func TestOIDCNotConfigured(t *testing.T) {
	e := newEnv(t)
	var p authProviders
	e.client().do("GET", "/auth/providers", nil, 200, &p)
	if p.OIDC != nil {
		t.Fatal("sso advertised")
	}
	e.client().do("GET", "/auth/oidc/login", nil, 404, nil)
}

func TestParseRoleMap(t *testing.T) {
	m, err := auth.ParseRoleMap(" a=admin , b=auditor,")
	if err != nil || m["a"] != "admin" || m["b"] != "auditor" {
		t.Fatalf("%v %v", m, err)
	}
	for _, bad := range []string{"a", "a=root", "=admin"} {
		if _, err := auth.ParseRoleMap(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
