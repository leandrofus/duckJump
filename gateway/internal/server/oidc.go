package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// Single sign-on with an OpenID Connect provider. Users are created on
// their first login (just in time) and matched afterwards by issuer and
// subject, never by name. Their groups follow the provider's groups claim,
// and their role its roles claim when one is configured. The provider owns
// their password and second factor.

const oidcCookie = "duckjump_oidc"

// oidcActor writes the audit events of provisioning.
var oidcActor = store.Actor{Name: "oidc"}

// openapi:schema OIDCProvider
// type: object
// required: [name, login_url]
// properties:
//   name: { type: string, description: Label for the sign-in button. }
//   login_url: { type: string, description: Navigate the browser here to sign in. }

type oidcProviderDTO struct {
	Name     string `json:"name"`
	LoginURL string `json:"login_url"`
}

// openapi:schema AuthProviders
// type: object
// required: [local, oidc]
// properties:
//   local: { type: boolean, description: Username and password login is available. }
//   oidc: { oneOf: [{ $ref: '#/components/schemas/OIDCProvider' }, { type: 'null' }] }

type authProviders struct {
	Local bool             `json:"local"`
	OIDC  *oidcProviderDTO `json:"oidc"`
}

// openapi:operation
// summary: How users can sign in
// description: For the login page. No authentication needed.
// tags: [auth]
// responses:
//   '200': { description: Sign-in methods, schema: AuthProviders }

func (s *Server) authProviders(w http.ResponseWriter, r *http.Request) {
	res := authProviders{Local: true}
	if s.OIDC != nil {
		name := s.OIDC.Name
		if name == "" {
			name = "Single sign-on"
		}
		res.OIDC = &oidcProviderDTO{Name: name, LoginURL: "/api/v1/auth/oidc/login"}
	}
	ok(w, res)
}

// openapi:operation
// summary: Start single sign-on
// description: Redirects the browser to the identity provider (authorization code flow with PKCE).
// tags: [auth]
// responses:
//   '302': { description: To the identity provider }
//   '404': Error

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeErr(w, &apiError{http.StatusNotFound, "not_found", "single sign-on is not configured"})
		return
	}
	app, err := s.beginAppLogin(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	to, cookie, err := s.OIDC.Begin(r.Context())
	if err != nil {
		slog.Error("oidc login", "err", err)
		s.loginRedirect(w, r, "the identity provider is unreachable")
		return
	}
	// Lax, not Strict: the provider sends the browser back cross-site.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: cookie, Path: "/api/v1/auth/oidc", HttpOnly: true,
		Secure: s.secureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: int(auth.LoginTimeout.Seconds())})
	// Always written: a browser login must not inherit an app login left behind.
	appCookie := &http.Cookie{Name: oidcAppCookie, Value: app, Path: "/api/v1/auth/oidc", HttpOnly: true,
		Secure: s.secureRequest(r), SameSite: http.SameSiteLaxMode, MaxAge: int(auth.LoginTimeout.Seconds())}
	if app == "" {
		appCookie.MaxAge = -1
	}
	http.SetCookie(w, appCookie)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, to, http.StatusFound)
}

// openapi:operation
// summary: Single sign-on callback
// description: >-
//   Where the identity provider returns the browser. Verifies the state,
//   redeems the code, checks the ID token, provisions the user and opens a
//   session; then redirects to the UI (with login_error on failure), or,
//   for a native app login, to its loopback redirect_uri with a one-time
//   code (or error). Audited.
// tags: [auth]
// responses:
//   '303': { description: To the UI }

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeErr(w, &apiError{http.StatusNotFound, "not_found", "single sign-on is not configured"})
		return
	}
	ctx, ip, q := r.Context(), s.clientIP(r), r.URL.Query()
	app := s.appLoginFrom(w, r)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true,
		Secure: s.secureRequest(r), SameSite: http.SameSiteLaxMode})
	fail := func(name, reason string, err error) {
		if err != nil {
			slog.Warn("oidc login failed", "user", name, "reason", reason, "err", err)
		}
		s.Store.AuditTx(ctx, store.Event{Actor: store.Actor{Name: name, IP: ip}, Action: "auth.login_failed", ObjectType: "user",
			Details: map[string]any{"method": "oidc", "reason": reason}})
		if app != nil {
			appRedirect(w, r, app, url.Values{"error": {reason}})
			return
		}
		s.loginRedirect(w, r, reason)
	}
	if e := q.Get("error"); e != "" {
		fail("", "the identity provider refused the login: "+e, nil)
		return
	}
	c, _ := r.Cookie(oidcCookie)
	var cookie string
	if c != nil {
		cookie = c.Value
	}
	id, err := s.OIDC.Finish(ctx, cookie, q.Get("state"), q.Get("code"))
	if err != nil {
		var le *auth.ErrLogin
		if errors.As(err, &le) {
			fail(id.Username, le.Reason, nil)
		} else {
			fail(id.Username, "the identity provider login could not be verified", err)
		}
		return
	}
	u, err := s.provisionOIDC(ctx, id)
	if err != nil {
		var le *auth.ErrLogin
		switch {
		case errors.As(err, &le):
			fail(id.Username, le.Reason, nil)
		case errors.Is(err, auth.ErrDisabled):
			fail(id.Username, "user disabled", nil)
		default:
			fail(id.Username, "the account could not be provisioned", err)
		}
		return
	}
	tok, err := s.Auth.NewSession(ctx, u.ID, false, ip, r.UserAgent())
	if err != nil {
		fail(id.Username, "the session could not be created", err)
		return
	}
	if app != nil {
		code := s.appCodes.put(appCode{token: tok, user: u, challenge: app.Challenge, expires: time.Now().Add(appCodeTTL)})
		s.completeLogin(r, u, "oidc_app")
		appRedirect(w, r, app, url.Values{"code": {code}})
		return
	}
	s.setSessionCookie(w, r, tok)
	s.completeLogin(r, u, "oidc")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/?login_error="+url.QueryEscape(reason), http.StatusSeeOther)
}

// provisionOIDC finds or creates the user of an identity and brings its
// profile, role and provider groups up to date, in one audited transaction.
func (s *Server) provisionOIDC(ctx context.Context, id auth.Identity) (db.ConfigUser, error) {
	var u db.ConfigUser
	err := s.tx(ctx, func(q *db.Queries) error {
		var err error
		u, err = q.GetUserByOIDCSubject(ctx, store.NullString(id.Subject))
		switch {
		case errors.Is(store.Classify(err), store.ErrNotFound):
			if _, err := q.GetUserByUsername(ctx, id.Username); err == nil {
				return &auth.ErrLogin{Reason: "the username " + id.Username + " belongs to another account; ask an admin"}
			}
			role := id.Role
			if role == "" {
				role = "user"
			}
			uid := store.NewID()
			if err := q.CreateOIDCUser(ctx, db.CreateOIDCUserParams{ID: uid, Username: id.Username, DisplayName: id.DisplayName,
				Email: id.Email, Role: role, OidcSubject: store.NullString(id.Subject), Now: store.Now()}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{Actor: oidcActor, Action: "user.create", ObjectType: "user", ObjectID: uid,
				Details: map[string]any{"username": id.Username, "role": role, "source": "oidc", "subject": id.Subject}}); err != nil {
				return err
			}
			if u, err = q.GetUser(ctx, uid); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if u.Disabled {
				return auth.ErrDisabled
			}
			next := u
			next.DisplayName, next.Email = id.DisplayName, id.Email
			if id.Role != "" {
				next.Role = id.Role
			}
			if next.DisplayName != u.DisplayName || next.Email != u.Email || next.Role != u.Role {
				if err := q.SyncOIDCUser(ctx, db.SyncOIDCUserParams{ID: u.ID, DisplayName: next.DisplayName, Email: next.Email,
					Role: next.Role, Now: store.Now()}); err != nil {
					return err
				}
				changes := map[string]any{}
				if next.Role != u.Role {
					changes["role"] = map[string]string{"from": u.Role, "to": next.Role}
				}
				if next.DisplayName != u.DisplayName {
					changes["display_name"] = next.DisplayName
				}
				if next.Email != u.Email {
					changes["email"] = next.Email
				}
				if err := store.Audit(ctx, q, store.Event{Actor: oidcActor, Action: "user.update", ObjectType: "user", ObjectID: u.ID,
					Details: map[string]any{"username": u.Username, "changes": changes}}); err != nil {
					return err
				}
				u = next
			}
		}
		return s.syncOIDCGroups(ctx, q, u, id.Groups)
	})
	if err == nil {
		s.revalidate() // a role or group may have changed under live sessions
	}
	return u, err
}

// syncOIDCGroups makes the user's provider groups (source oidc) match the
// claim. Local groups are never touched, even when a provider group has the
// same name.
func (s *Server) syncOIDCGroups(ctx context.Context, q *db.Queries, u db.ConfigUser, want []string) error {
	have, err := q.ListUserGroups(ctx, u.ID)
	if err != nil {
		return err
	}
	member := map[string]bool{}
	for _, g := range have {
		if g.Source != "oidc" {
			continue
		}
		member[g.Name] = true
		if !slices.Contains(want, g.Name) {
			if _, err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{Actor: oidcActor, Action: "group.member_remove", ObjectType: "group", ObjectID: g.ID,
				Details: map[string]any{"group": g.Name, "user_id": u.ID, "username": u.Username}}); err != nil {
				return err
			}
		}
	}
	for _, name := range want {
		if member[name] {
			continue
		}
		g, err := q.GetGroupByName(ctx, name)
		switch {
		case errors.Is(store.Classify(err), store.ErrNotFound):
			g = db.ConfigGroup{ID: store.NewID(), Name: name, Source: "oidc"}
			if err := q.CreateGroup(ctx, db.CreateGroupParams{ID: g.ID, Name: name, Description: "From the identity provider",
				Source: "oidc", Now: store.Now()}); err != nil {
				return err
			}
			if err := store.Audit(ctx, q, store.Event{Actor: oidcActor, Action: "group.create", ObjectType: "group", ObjectID: g.ID,
				Details: map[string]any{"name": name, "source": "oidc"}}); err != nil {
				return err
			}
		case err != nil:
			return err
		case g.Source != "oidc":
			slog.Warn("identity provider group shadowed by a local group; membership not synced", "group", name, "user", u.Username)
			continue
		}
		if err := q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: g.ID, UserID: u.ID}); err != nil {
			return err
		}
		if err := store.Audit(ctx, q, store.Event{Actor: oidcActor, Action: "group.member_add", ObjectType: "group", ObjectID: g.ID,
			Details: map[string]any{"group": name, "user_id": u.ID, "username": u.Username}}); err != nil {
			return err
		}
	}
	return nil
}
