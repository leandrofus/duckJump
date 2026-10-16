package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Single sign-on for native apps (duckJump Assist), after RFC 8252: the app
// listens on a loopback port and starts the login with redirect_uri, its own
// state and a PKCE challenge. The callback does not set a browser cookie;
// it sends the browser back to the app with a one-time code, which the app
// redeems (with its verifier) for a session token. The token itself never
// appears in a URL.

const (
	oidcAppCookie = "duckjump_oidc_app"
	appStateAAD   = "duckjump-oidc-app-login"
	appCodeTTL    = time.Minute
)

type appLogin struct {
	Redirect  string    `json:"r"`
	State     string    `json:"s"`
	Challenge string    `json:"c"`
	Expires   time.Time `json:"e"`
}

// validLoopbackRedirect accepts only http://127.0.0.1, [::1] or localhost
// with an explicit port: a browser can only reach those on this machine.
func validLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.Fragment != "" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// beginAppLogin reads the native app parameters of /oidc/login. It returns
// the sealed cookie value, "" when the login is a plain browser one.
func (s *Server) beginAppLogin(r *http.Request) (string, error) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		return "", nil
	}
	st, ch := q.Get("state"), q.Get("code_challenge")
	switch {
	case !validLoopbackRedirect(redirect):
		return "", badRequest("redirect_uri must be a loopback http URL with a port")
	case st == "" || len(st) > 128:
		return "", badRequest("state is required")
	case len(ch) != 43 || q.Get("code_challenge_method") != "S256":
		return "", badRequest("a S256 code_challenge is required")
	}
	b, _ := json.Marshal(appLogin{Redirect: redirect, State: st, Challenge: ch, Expires: time.Now().Add(auth.LoginTimeout)})
	return base64.RawURLEncoding.EncodeToString(s.Vault.Seal(b, []byte(appStateAAD))), nil
}

// appLoginFrom returns the native app login of this callback, if any, and
// clears its cookie.
func (s *Server) appLoginFrom(w http.ResponseWriter, r *http.Request) *appLogin {
	c, err := r.Cookie(oidcAppCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: oidcAppCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true,
		Secure: s.secureRequest(r), SameSite: http.SameSiteLaxMode})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	plain, err := s.Vault.Open(raw, []byte(appStateAAD))
	var al appLogin
	if err != nil || json.Unmarshal(plain, &al) != nil || time.Now().After(al.Expires) || !validLoopbackRedirect(al.Redirect) {
		return nil
	}
	return &al
}

// appRedirect sends the browser back to the app with code or error.
func appRedirect(w http.ResponseWriter, r *http.Request, al *appLogin, params url.Values) {
	params.Set("state", al.State)
	to, _ := url.Parse(al.Redirect)
	q := to.Query()
	for k, v := range params {
		q[k] = v
	}
	to.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to.String(), http.StatusSeeOther)
}

type appCode struct {
	token     string
	user      db.ConfigUser
	challenge string
	expires   time.Time
}

// appCodes holds the one-time codes of finished native app logins.
type appCodes struct {
	mu sync.Mutex
	m  map[string]appCode
}

func (a *appCodes) put(c appCode) string {
	b := make([]byte, 24)
	rand.Read(b)
	code := base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]appCode{}
	}
	now := time.Now()
	for k, v := range a.m {
		if now.After(v.expires) {
			delete(a.m, k)
		}
	}
	a.m[code] = c
	return code
}

// take removes the code (whatever the verifier: one attempt per code).
func (a *appCodes) take(code, verifier string) (appCode, bool) {
	a.mu.Lock()
	c, found := a.m[code]
	delete(a.m, code)
	a.mu.Unlock()
	if !found || time.Now().After(c.expires) {
		return appCode{}, false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(c.challenge)) != 1 {
		return appCode{}, false
	}
	return c, true
}

// openapi:schema AppTokenRequest
// type: object
// required: [code, code_verifier]
// additionalProperties: false
// properties:
//   code: { type: string, description: One-time code from the loopback redirect. }
//   code_verifier: { type: string, description: PKCE verifier of the code_challenge sent to /auth/oidc/login. }

type appTokenRequest struct {
	Code     string `json:"code"`
	Verifier string `json:"code_verifier"`
}

// openapi:schema AppTokenResponse
// type: object
// required: [token, user]
// properties:
//   token: { type: string, description: 'Session token; send it as the duckjump_session cookie.' }
//   user: { $ref: '#/components/schemas/User' }

type appTokenResponse struct {
	Token string  `json:"token"`
	User  userDTO `json:"user"`
}

// openapi:operation
// summary: Redeem a native app single sign-on code
// description: >-
//   For duckJump Assist: trades the one-time code of the loopback redirect
//   and the PKCE verifier for a session token. Codes expire after a minute
//   and work once.
// tags: [auth]
// requestBody: { schema: AppTokenRequest }
// responses:
//   '200': { description: Logged in, schema: AppTokenResponse }
//   '401': Error

func (s *Server) oidcAppToken(w http.ResponseWriter, r *http.Request) {
	if err := checkCSRF(r); err != nil {
		writeErr(w, err)
		return
	}
	var req appTokenRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	c, found := s.appCodes.take(req.Code, req.Verifier)
	if !found {
		writeErr(w, &apiError{http.StatusUnauthorized, "invalid_code", "invalid or expired code"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ok(w, appTokenResponse{Token: c.token, User: toUser(c.user)})
}
