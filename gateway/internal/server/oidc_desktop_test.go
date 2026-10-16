package server

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// appListener plays duckJump Assist's loopback callback.
func appListener(t *testing.T) (*httptest.Server, chan url.Values) {
	got := make(chan url.Values, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Query()
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func appLoginURL(e *env, redirect, state, verifier string) string {
	q := url.Values{"redirect_uri": {redirect}, "state": {state}, "code_challenge": {challengeOf(verifier)},
		"code_challenge_method": {"S256"}}
	return e.srv.URL + "/api/v1/auth/oidc/login?" + q.Encode()
}

func TestOIDCAppLoopbackLogin(t *testing.T) {
	e, idp := oidcEnv(t)
	idp.as(map[string]any{"sub": "u-7", "preferred_username": "bob", "email": "bob@example.com"})
	app, got := appListener(t)
	verifier := strings.Repeat("v", 43)

	browser := e.client()
	resp, err := browser.http.Get(appLoginURL(e, app.URL+"/callback", "app-state", verifier))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	q := <-got
	if q.Get("state") != "app-state" || q.Get("code") == "" || q.Get("error") != "" {
		t.Fatalf("loopback got %v", q)
	}
	// The browser gets no session: the login belongs to the app.
	if r, _ := browser.raw("GET", "/auth/me", nil, false); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("browser got a session: %d", r.StatusCode)
	}

	c := e.client()
	if r, b := c.raw("POST", "/auth/oidc/token", appTokenRequest{Code: q.Get("code"), Verifier: "wrong"}, true); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong verifier: %d %s", r.StatusCode, b)
	}
	// One attempt per code, even a failed one.
	if r, _ := c.raw("POST", "/auth/oidc/token", appTokenRequest{Code: q.Get("code"), Verifier: verifier}, true); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("code reused after a failed attempt: %d", r.StatusCode)
	}

	// A fresh login, redeemed properly.
	resp, err = browser.http.Get(appLoginURL(e, app.URL+"/callback", "s2", verifier))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	q = <-got
	var tok appTokenResponse
	c.do("POST", "/auth/oidc/token", appTokenRequest{Code: q.Get("code"), Verifier: verifier}, 200, &tok)
	if tok.Token == "" || tok.User.Username != "bob" {
		t.Fatalf("token response: %+v", tok)
	}
	if r, _ := c.raw("POST", "/auth/oidc/token", appTokenRequest{Code: q.Get("code"), Verifier: verifier}, true); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("code redeemed twice: %d", r.StatusCode)
	}

	// The token is a session: it can request support.
	u, _ := url.Parse(e.srv.URL)
	app2 := e.client()
	app2.http.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: tok.Token, Path: "/"}})
	var me meResponse
	app2.do("GET", "/auth/me", nil, 200, &me)
	if me.User.Username != "bob" {
		t.Fatalf("me: %+v", me.User)
	}
	app2.do("POST", "/support/request", map[string]any{"reason": "VPN"}, 201, nil)
}

func TestOIDCAppLoginRefusals(t *testing.T) {
	e, idp := oidcEnv(t)
	verifier := strings.Repeat("v", 43)
	for _, redirect := range []string{
		"https://evil.example.com/callback",
		"http://evil.example.com:8080/callback",
		"http://127.0.0.1/callback", // no port
		"http://user@127.0.0.1:9/callback",
		"javascript:alert(1)",
	} {
		resp, err := e.client().http.Get(appLoginURL(e, redirect, "s", verifier))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", redirect, resp.StatusCode)
		}
	}
	// No PKCE challenge.
	resp, _ := e.client().http.Get(e.srv.URL + "/api/v1/auth/oidc/login?redirect_uri=" + url.QueryEscape("http://127.0.0.1:9/cb") + "&state=s")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing challenge: %d", resp.StatusCode)
	}

	// A provider error goes back to the app, not to the web UI.
	idp.as(map[string]any{"sub": "u-8"}) // no preferred_username: refused
	app, got := appListener(t)
	resp, err := e.client().http.Get(appLoginURL(e, app.URL+"/cb", "st", verifier))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	q := <-got
	if q.Get("error") == "" || q.Get("code") != "" || q.Get("state") != "st" {
		t.Fatalf("loopback got %v", q)
	}

	// A browser login after an abandoned app login still lands in the UI.
	idp.as(map[string]any{"sub": "u-9", "preferred_username": "carol"})
	c := e.client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r1, err := c.http.Get(appLoginURL(e, "http://127.0.0.1:9/never", "s", verifier)) // never goes to the IdP
	if err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	c.http.CheckRedirect = nil
	resp, err = c.http.Get(e.srv.URL + "/api/v1/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Request.URL.Path != "/" || resp.Request.URL.Query().Get("login_error") != "" {
		t.Fatalf("browser login ended at %s", resp.Request.URL)
	}
}
