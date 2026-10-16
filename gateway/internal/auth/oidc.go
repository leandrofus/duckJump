package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/leandrofus/duckjump/gateway/internal/vault"
)

// OIDC signs users in through an OpenID Connect provider (Keycloak, Entra
// ID, Okta…) with the authorization code flow, PKCE and a nonce. The
// provider is discovered on first use, so the gateway starts even while it
// is unreachable.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL: <public base URL>/api/v1/auth/oidc/callback, registered
	// with the provider.
	RedirectURL string
	// Scopes besides "openid" (default: profile, email).
	Scopes []string
	// RolesClaim is the claim (dotted path, e.g. "realm_access.roles" or
	// "resource_access.duckjump.roles") whose values RoleMap turns into a
	// role. Empty: roles are not taken from the provider; admins set them.
	RolesClaim string
	// RoleMap: provider value -> role. The highest role mapped wins; users
	// with none get "user".
	RoleMap map[string]string
	// GroupsClaim lists the user's groups (default "groups"); they become
	// gateway groups (source oidc) whose membership follows the provider.
	GroupsClaim string
	// UsernameClaim (default "preferred_username").
	UsernameClaim string
	// Name shown on the login button.
	Name string
	// Vault seals the login state cookie.
	Vault *vault.Vault

	mu       sync.Mutex
	provider *oidc.Provider
}

// Identity is what a successful login tells about the user.
type Identity struct {
	Subject     string // "<issuer>|<sub>", stable
	Username    string
	DisplayName string
	Email       string
	Role        string // "" when roles are not taken from the provider
	Groups      []string
}

// loginState travels in a sealed cookie between the redirect to the provider
// and the callback.
type loginState struct {
	State    string    `json:"s"`
	Nonce    string    `json:"n"`
	Verifier string    `json:"v"`
	Expires  time.Time `json:"e"`
}

// LoginTimeout is how long a user has to complete the provider's login.
const LoginTimeout = 10 * time.Minute

var roleRank = map[string]int{"user": 0, "auditor": 1, "admin": 2, "superadmin": 3}

// ParseRoleMap parses "value=role,value=role".
func ParseRoleMap(s string) (map[string]string, error) {
	m := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, known := roleRank[v]; !ok || k == "" || !known {
			return nil, fmt.Errorf("role map entry %q: want <provider value>=<superadmin|admin|auditor|user>", pair)
		}
		m[k] = v
	}
	return m, nil
}

func (o *OIDC) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	// Discovery outlives the request that triggers it.
	p, err := oidc.NewProvider(oidc.ClientContext(context.WithoutCancel(ctx), oidcHTTP), o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery at %s: %w", o.Issuer, err)
	}
	o.provider = p
	return p, nil
}

func (o *OIDC) config(p *oidc.Provider) *oauth2.Config {
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{"profile", "email"}
	}
	return &oauth2.Config{ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: o.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: append([]string{oidc.ScopeOpenID}, scopes...)}
}

func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const stateAAD = "duckjump-oidc-login-state"

// Begin returns where to send the browser and the sealed state cookie value.
func (o *OIDC) Begin(ctx context.Context) (redirect, cookie string, err error) {
	p, err := o.discover(ctx)
	if err != nil {
		return "", "", err
	}
	st := loginState{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(LoginTimeout)}
	b, _ := json.Marshal(st)
	cookie = base64.RawURLEncoding.EncodeToString(o.Vault.Seal(b, []byte(stateAAD)))
	return o.config(p).AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), cookie, nil
}

// ErrLogin is a login the user (or an attacker) got wrong: bad or replayed
// state, expired, denied by the provider. Its message is safe to show.
type ErrLogin struct{ Reason string }

func (e *ErrLogin) Error() string { return e.Reason }

// Finish checks the callback against the state cookie, redeems the code and
// verifies the ID token.
func (o *OIDC) Finish(ctx context.Context, cookie, state, code string) (Identity, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil || cookie == "" {
		return Identity{}, &ErrLogin{"the login expired or was started in another browser; try again"}
	}
	plain, err := o.Vault.Open(raw, []byte(stateAAD))
	var st loginState
	if err != nil || json.Unmarshal(plain, &st) != nil {
		return Identity{}, &ErrLogin{"invalid login state; try again"}
	}
	if time.Now().After(st.Expires) {
		return Identity{}, &ErrLogin{"the login took too long; try again"}
	}
	if state == "" || state != st.State {
		return Identity{}, &ErrLogin{"login state mismatch; try again"}
	}
	p, err := o.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	hctx := oidc.ClientContext(ctx, oidcHTTP)
	tok, err := o.config(p).Exchange(hctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("redeeming the authorization code: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return Identity{}, errors.New("the provider returned no id_token")
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: o.ClientID}).Verify(hctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verifying the id_token: %w", err)
	}
	if idt.Nonce != st.Nonce {
		return Identity{}, &ErrLogin{"id_token nonce mismatch"}
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, err
	}
	return o.identity(idt.Issuer, idt.Subject, claims)
}

func (o *OIDC) identity(issuer, sub string, claims map[string]any) (Identity, error) {
	uc := o.UsernameClaim
	if uc == "" {
		uc = "preferred_username"
	}
	id := Identity{Subject: issuer + "|" + sub}
	id.Username = strings.ToLower(strings.TrimSpace(str(claimAt(claims, uc))))
	if id.Username == "" {
		return id, &ErrLogin{fmt.Sprintf("the provider sent no %s claim", uc)}
	}
	if !ValidUsername(id.Username) {
		return id, &ErrLogin{fmt.Sprintf("username %q is not valid here", id.Username)}
	}
	id.DisplayName = str(claims["name"])
	id.Email = str(claims["email"])
	if o.RolesClaim != "" {
		id.Role = "user"
		for _, v := range strs(claimAt(claims, o.RolesClaim)) {
			if r, ok := o.RoleMap[v]; ok && roleRank[r] > roleRank[id.Role] {
				id.Role = r
			}
		}
	}
	gc := o.GroupsClaim
	if gc == "" {
		gc = "groups"
	}
	for _, g := range strs(claimAt(claims, gc)) {
		// Keycloak sends full paths ("/ops/db") unless told otherwise.
		if g = strings.TrimPrefix(strings.TrimSpace(g), "/"); g != "" {
			id.Groups = append(id.Groups, g)
		}
	}
	return id, nil
}

// ValidUsername: what local usernames allow too.
func ValidUsername(u string) bool {
	if len(u) == 0 || len(u) > 64 {
		return false
	}
	for i, c := range u {
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || !strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

// claimAt follows a dotted path ("realm_access.roles").
func claimAt(claims map[string]any, path string) any {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// oidcHTTP talks to the provider: bounded, so a slow provider cannot hold
// requests forever.
var oidcHTTP = &http.Client{Timeout: 15 * time.Second}
