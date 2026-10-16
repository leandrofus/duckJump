// Package server exposes the REST API (/api/v1) and the WebSocket session
// tunnel. See docs/API.md.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/leandrofus/palta/gateway/internal/auth"
	"github.com/leandrofus/palta/gateway/internal/edge"
	"github.com/leandrofus/palta/gateway/internal/store"
	"github.com/leandrofus/palta/gateway/internal/store/db"
	"github.com/leandrofus/palta/gateway/internal/vault"
)

const (
	sessionCookie = "palta_session"
	// Mutating requests must carry this header. Browsers cannot add custom
	// headers to cross-site requests without a CORS preflight we never
	// answer, so together with SameSite=Strict it stops CSRF.
	csrfHeader = "X-Palta-Request"
)

type Server struct {
	Store         *store.Store
	Vault         *vault.Vault
	Auth          *auth.Service
	Hub           *edge.Hub
	PaltadAddr    string
	PaltadToken   string
	RelayAddr     string
	RecordingsDir string
	// Dev disables user authentication: every request acts as a superadmin
	// that may open any connection. PoC only; never expose it.
	Dev bool

	limiter *auth.Limiter
}

func (s *Server) Handler() http.Handler {
	s.limiter = auth.NewLimiter()
	mux := http.NewServeMux()
	// Methodless so it does not clash with the /api/ catch-all; static() allows only GET/HEAD.
	mux.Handle("/", s.static())

	// Authentication and the caller's own account.
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.Handle("POST /api/v1/auth/totp", s.pending(s.loginTOTP))
	mux.Handle("POST /api/v1/auth/logout", s.pending(s.logout))
	mux.Handle("GET /api/v1/auth/me", s.pending(s.me))
	mux.Handle("PUT /api/v1/auth/me/password", s.authed(anyRole, s.changePassword))
	mux.Handle("POST /api/v1/auth/me/totp/enroll", s.authed(anyRole, s.totpEnroll))
	mux.Handle("POST /api/v1/auth/me/totp/confirm", s.authed(anyRole, s.totpConfirm))
	mux.Handle("DELETE /api/v1/auth/me/totp", s.authed(anyRole, s.totpDisable))

	// Portal: what the caller may open.
	mux.Handle("GET /api/v1/portal/connections", s.authed(anyRole, s.portalConnections))
	mux.Handle("GET /api/v1/connections/{id}/session", s.authed(anyRole, s.tunnel))

	// Administration.
	mux.Handle("GET /api/v1/users", s.authed(admins, s.listUsers))
	mux.Handle("POST /api/v1/users", s.authed(admins, s.createUser))
	mux.Handle("GET /api/v1/users/{id}", s.authed(admins, s.getUser))
	mux.Handle("PATCH /api/v1/users/{id}", s.authed(admins, s.updateUser))
	mux.Handle("DELETE /api/v1/users/{id}", s.authed(admins, s.deleteUser))
	mux.Handle("PUT /api/v1/users/{id}/password", s.authed(admins, s.resetPassword))
	mux.Handle("DELETE /api/v1/users/{id}/totp", s.authed(admins, s.resetTOTP))
	mux.Handle("GET /api/v1/users/{id}/groups", s.authed(admins, s.userGroups))
	mux.Handle("GET /api/v1/users/{id}/access", s.authed(admins, s.userAccess))

	mux.Handle("GET /api/v1/groups", s.authed(admins, s.listGroups))
	mux.Handle("POST /api/v1/groups", s.authed(admins, s.createGroup))
	mux.Handle("GET /api/v1/groups/{id}", s.authed(admins, s.getGroup))
	mux.Handle("PATCH /api/v1/groups/{id}", s.authed(admins, s.updateGroup))
	mux.Handle("DELETE /api/v1/groups/{id}", s.authed(admins, s.deleteGroup))
	mux.Handle("GET /api/v1/groups/{id}/members", s.authed(admins, s.groupMembers))
	mux.Handle("PUT /api/v1/groups/{id}/members/{user}", s.authed(admins, s.addGroupMember))
	mux.Handle("DELETE /api/v1/groups/{id}/members/{user}", s.authed(admins, s.removeGroupMember))

	mux.Handle("GET /api/v1/folders", s.authed(admins, s.listFolders))
	mux.Handle("POST /api/v1/folders", s.authed(admins, s.createFolder))
	mux.Handle("PATCH /api/v1/folders/{id}", s.authed(admins, s.updateFolder))
	mux.Handle("DELETE /api/v1/folders/{id}", s.authed(admins, s.deleteFolder))

	mux.Handle("GET /api/v1/sites", s.authed(admins, s.listSites))
	mux.Handle("POST /api/v1/sites", s.authed(admins, s.createSite))
	mux.Handle("GET /api/v1/sites/{id}", s.authed(admins, s.getSite))
	mux.Handle("PATCH /api/v1/sites/{id}", s.authed(admins, s.updateSite))
	mux.Handle("DELETE /api/v1/sites/{id}", s.authed(admins, s.deleteSite))
	mux.Handle("POST /api/v1/sites/{id}/token", s.authed(admins, s.rotateSiteToken))
	mux.Handle("GET /api/v1/sites/{id}/agents", s.authed(admins, s.siteAgents))

	mux.Handle("GET /api/v1/secrets", s.authed(admins, s.listSecrets))
	mux.Handle("POST /api/v1/secrets", s.authed(admins, s.createSecret))
	mux.Handle("GET /api/v1/secrets/{id}", s.authed(admins, s.getSecret))
	mux.Handle("PATCH /api/v1/secrets/{id}", s.authed(admins, s.updateSecret))
	mux.Handle("DELETE /api/v1/secrets/{id}", s.authed(admins, s.deleteSecret))

	mux.Handle("GET /api/v1/connections", s.authed(admins, s.listConnections))
	mux.Handle("POST /api/v1/connections", s.authed(admins, s.createConnection))
	mux.Handle("GET /api/v1/connections/{id}", s.authed(admins, s.getConnection))
	mux.Handle("PATCH /api/v1/connections/{id}", s.authed(admins, s.updateConnection))
	mux.Handle("DELETE /api/v1/connections/{id}", s.authed(admins, s.deleteConnection))
	mux.Handle("DELETE /api/v1/connections/{id}/host-key", s.authed(admins, s.clearHostKey))

	mux.Handle("GET /api/v1/policies", s.authed(admins, s.listPolicies))
	mux.Handle("POST /api/v1/policies", s.authed(admins, s.createPolicy))
	mux.Handle("GET /api/v1/policies/{id}", s.authed(admins, s.getPolicy))
	mux.Handle("PATCH /api/v1/policies/{id}", s.authed(admins, s.updatePolicy))
	mux.Handle("DELETE /api/v1/policies/{id}", s.authed(admins, s.deletePolicy))

	// Audit.
	mux.Handle("GET /api/v1/audit/events", s.authed(auditors, s.listAuditEvents))
	mux.Handle("GET /api/v1/audit/verify", s.authed(auditors, s.verifyAudit))
	mux.Handle("GET /api/v1/audit/sessions", s.authed(auditors, s.listSessions))
	mux.Handle("GET /api/v1/audit/sessions/{id}", s.authed(auditors, s.getSessionRecord))
	// Auditors, or users with view_recordings on the session's connection.
	mux.Handle("GET /api/v1/audit/sessions/{id}/recording", s.authed(anyRole, s.getRecording))

	// Settings.
	mux.Handle("GET /api/v1/settings/recordings", s.authed(admins, s.getRecordingSettings))
	mux.Handle("PUT /api/v1/settings/recordings", s.authed(admins, s.setRecordingSettings))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &apiError{http.StatusNotFound, "not_found", "no such endpoint"})
	})
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// ---- principals and roles ----

type principal struct {
	User        db.ConfigUser
	SessionHash string
	IP          string
	Dev         bool
}

func (p principal) actor() store.Actor {
	return store.Actor{ID: p.User.ID, Name: p.User.Username, IP: p.IP}
}

type roleSet map[string]bool

var (
	anyRole  = roleSet{"user": true, "auditor": true, "admin": true, "superadmin": true}
	admins   = roleSet{"admin": true, "superadmin": true}
	auditors = roleSet{"auditor": true, "admin": true, "superadmin": true}
)

type handlerFunc func(w http.ResponseWriter, r *http.Request, p principal) error

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) resolve(r *http.Request) (principal, bool, error) {
	ip := clientIP(r)
	if s.Dev {
		return principal{User: db.ConfigUser{Username: "dev", Role: "superadmin"}, IP: ip, Dev: true}, false, nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return principal{}, false, errUnauthorized
	}
	sess, err := s.Auth.Session(r.Context(), c.Value)
	if err != nil {
		return principal{}, false, errUnauthorized
	}
	return principal{User: sess.User, SessionHash: sess.IDHash, IP: ip}, sess.MFAPending, nil
}

func checkCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	if r.Header.Get(csrfHeader) == "" {
		return &apiError{http.StatusForbidden, "csrf", "missing " + csrfHeader + " header"}
	}
	return nil
}

// authed requires a fully authenticated session with one of the roles.
func (s *Server) authed(roles roleSet, h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkCSRF(r); err != nil {
			writeErr(w, err)
			return
		}
		p, pending, err := s.resolve(r)
		switch {
		case err != nil:
			writeErr(w, err)
		case pending:
			writeErr(w, &apiError{http.StatusForbidden, "mfa_required", "complete the TOTP step first"})
		case !roles[p.User.Role]:
			writeErr(w, errForbidden)
		default:
			if err := h(w, r, p); err != nil {
				writeErr(w, err)
			}
		}
	})
}

// pending accepts sessions still waiting for their TOTP step.
func (s *Server) pending(h func(w http.ResponseWriter, r *http.Request, p principal, mfaPending bool) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkCSRF(r); err != nil {
			writeErr(w, err)
			return
		}
		p, pending, err := s.resolve(r)
		if err == nil {
			err = h(w, r, p, pending)
		}
		if err != nil {
			writeErr(w, err)
		}
	})
}

// ---- errors and JSON ----

type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string { return e.Message }

var (
	errUnauthorized = &apiError{http.StatusUnauthorized, "unauthorized", "authentication required"}
	errForbidden    = &apiError{http.StatusForbidden, "forbidden", "not allowed"}
)

func badRequest(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, "bad_request", fmt.Sprintf(format, a...)}
}

func notFound(what string) error {
	return &apiError{http.StatusNotFound, "not_found", what + " not found"}
}

func conflict(format string, a ...any) error {
	return &apiError{http.StatusConflict, "conflict", fmt.Sprintf(format, a...)}
}

// fromStore maps store errors; what names the object for not-found.
func fromStore(err error, what string) error {
	err = store.Classify(err)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return notFound(what)
	case errors.Is(err, store.ErrConflict):
		msg := err.Error()
		switch {
		case strings.Contains(msg, "UNIQUE"):
			return conflict("%s with that name already exists", what)
		case strings.Contains(msg, "FOREIGN KEY"):
			return conflict("%s is referenced by other objects or references a missing one", what)
		}
		return conflict("%s", msg)
	}
	return err
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		slog.Error("api", "err", err)
		ae = &apiError{http.StatusInternalServerError, "internal", "internal error"}
	}
	writeJSON(w, ae.Status, map[string]string{"error": ae.Code, "message": ae.Message})
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, v any) error      { return writeJSON(w, http.StatusOK, v) }
func created(w http.ResponseWriter, v any) error { return writeJSON(w, http.StatusCreated, v) }
func noContent(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON body: %v", err)
	}
	return nil
}

// opt is a PATCH field: Set when present in the body, Null when it was null.
type opt[T any] struct {
	Set  bool
	Null bool
	V    T
}

func (o *opt[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Null = true
		return nil
	}
	return json.Unmarshal(b, &o.V)
}

// tx runs fn in a store transaction.
func (s *Server) tx(ctx context.Context, fn func(q *db.Queries) error) error {
	return s.Store.Tx(ctx, fn)
}
