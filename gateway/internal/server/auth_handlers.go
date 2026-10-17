package server

import (
	"errors"
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var errTooMany = &apiError{http.StatusTooManyRequests, "too_many_attempts", "too many failed attempts, try again later"}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secureRequest(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(auth.SessionAbsolute.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureRequest(r),
		SameSite: http.SameSiteStrictMode})
}

// openapi:schema LoginRequest
// type: object
// required: [username, password]
// additionalProperties: false
// properties:
//   username: { type: string }
//   password: { type: string, format: password }

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// openapi:schema CodeRequest
// type: object
// required: [code]
// additionalProperties: false
// properties:
//   code: { type: string, pattern: '^[0-9]{6}$', description: Current code from the authenticator app. }

type codeRequest struct {
	Code string `json:"code"`
}

// openapi:schema ChangePasswordRequest
// type: object
// required: [current, new]
// additionalProperties: false
// properties:
//   current: { type: string, format: password }
//   new: { type: string, format: password, minLength: 10 }

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// openapi:schema TOTPEnrollment
// type: object
// required: [secret, otpauth_url]
// properties:
//   secret: { type: string, description: 'Base32 secret, for manual entry.' }
//   otpauth_url: { type: string, description: otpauth:// URI to render as a QR code. }

type totpEnrollment struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// openapi:schema Me
// type: object
// required: [user, mfa_pending, dev]
// properties:
//   user: { $ref: '#/components/schemas/User' }
//   mfa_pending: { type: boolean, description: Password accepted; POST /auth/totp to finish logging in. }
//   dev: { type: boolean, description: The gateway runs in dev mode (no authentication). }
//   groups: { type: array, items: { $ref: '#/components/schemas/Group' } }

type meResponse struct {
	User       userDTO    `json:"user"`
	MFAPending bool       `json:"mfa_pending"`
	Dev        bool       `json:"dev"`
	Groups     []groupDTO `json:"groups,omitempty"`
}

// openapi:schema LoginResponse
// type: object
// required: [mfa_required]
// properties:
//   user: { $ref: '#/components/schemas/User' }
//   mfa_required: { type: boolean, description: 'true: no user yet; POST /auth/totp with the code.' }

type loginResponse struct {
	User        *userDTO `json:"user,omitempty"`
	MFARequired bool     `json:"mfa_required"`
}

// openapi:operation
// summary: Log in
// description: >-
//   Sets the duckjump_session cookie. When the user has TOTP enabled the
//   session is only half open (mfa_required) until POST /auth/totp.
//   Five failures per username and address within 15 minutes lock that
//   pair out for the rest of the window.
// tags: [auth]
// requestBody: { schema: LoginRequest }
// responses:
//   '200': { description: 'Logged in, or waiting for the TOTP step', schema: LoginResponse }
//   '401': Error
//   '429': Error

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := s.doLogin(w, r); err != nil {
		writeErr(w, err)
	}
}

func (s *Server) doLogin(w http.ResponseWriter, r *http.Request) error {
	if err := checkCSRF(r); err != nil {
		return err
	}
	var req loginRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, ip := r.Context(), s.clientIP(r)
	key := req.Username + "|" + ip
	if !s.limiter.Allowed(key) {
		return errTooMany
	}
	u, err := s.Auth.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalid) && !errors.Is(err, auth.ErrDisabled) {
			return err
		}
		s.limiter.Fail(key)
		reason := "bad credentials"
		if errors.Is(err, auth.ErrDisabled) {
			reason = "user disabled"
		}
		_ = s.Users.RecordLoginFailure(ctx, req.Username, ip, reason)
		return &apiError{http.StatusUnauthorized, "invalid_credentials", "invalid username or password"}
	}
	s.limiter.Reset(key)
	tok, err := s.Auth.NewSession(ctx, u.ID, u.TOTPEnabled, ip, r.UserAgent())
	if err != nil {
		return err
	}
	s.setSessionCookie(w, r, tok)
	if u.TOTPEnabled {
		return ok(w, loginResponse{MFARequired: true})
	}
	s.completeLogin(r, u, "password")
	dto := toUser(u)
	return ok(w, loginResponse{User: &dto})
}

func (s *Server) completeLogin(r *http.Request, u db.ConfigUser, method string) {
	ctx := r.Context()
	_ = s.Users.RecordLoginSuccess(ctx, store.Actor{ID: u.ID, Name: u.Username, IP: s.clientIP(r)}, u.ID, method)
}

// openapi:operation
// summary: Second login step (TOTP)
// tags: [auth]
// requestBody: { schema: CodeRequest }
// responses:
//   '200': { description: Logged in, schema: LoginResponse }
//   '401': Error
//   '429': Error

func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request, p principal, pending bool) error {
	if !pending {
		return badRequest("this session needs no TOTP step")
	}
	var req codeRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	key := "totp|" + p.User.ID
	if !s.limiter.Allowed(key) {
		return errTooMany
	}
	if !s.Auth.CheckTOTP(p.User, req.Code) {
		s.limiter.Fail(key)
		_ = s.Users.RecordTOTPFailure(r.Context(), p.actor(), p.User.ID)
		return &apiError{http.StatusUnauthorized, "invalid_code", "invalid code"}
	}
	s.limiter.Reset(key)
	if err := s.Auth.CompleteMFA(r.Context(), p.SessionHash); err != nil {
		return err
	}
	s.completeLogin(r, p.User, "password+totp")
	dto := toUser(p.User)
	return ok(w, loginResponse{User: &dto})
}

// openapi:operation
// summary: Log out
// tags: [auth]
// responses:
//   '204': { description: Session closed and cookie cleared }

func (s *Server) logout(w http.ResponseWriter, r *http.Request, p principal, _ bool) error {
	if p.SessionHash != "" {
		if err := s.Auth.EndSession(r.Context(), p.SessionHash); err != nil {
			return err
		}
		_ = s.Users.RecordLogout(r.Context(), p.actor(), p.User.ID)
	}
	s.clearSessionCookie(w, r)
	return noContent(w)
}

// openapi:operation
// summary: Who am I
// tags: [auth]
// responses:
//   '200': { description: The caller, schema: Me }

func (s *Server) me(w http.ResponseWriter, r *http.Request, p principal, pending bool) error {
	resp := meResponse{User: toUser(p.User), MFAPending: pending, Dev: p.Dev}
	if !pending && !p.Dev {
		gs, err := s.Users.ListUserGroups(r.Context(), p.User.ID)
		if err != nil {
			return fromService(err, "user")
		}
		resp.Groups = make([]groupDTO, 0, len(gs))
		for _, g := range gs {
			resp.Groups = append(resp.Groups, toGroup(g))
		}
	}
	return ok(w, resp)
}

// openapi:operation
// summary: Change my password
// description: Ends my other sessions and re-issues this one's cookie.
// tags: [auth]
// requestBody: { schema: ChangePasswordRequest }
// responses:
//   '204': { description: Password changed }

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, p principal) error {
	var req changePasswordRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx := r.Context()
	err := s.Users.ChangePassword(ctx, p.actor(), p.User, p.Dev, req.Current, req.New, s.Auth.Authenticate)
	if err != nil {
		return fromService(err, "user")
	}
	tok, err := s.Auth.NewSession(ctx, p.User.ID, false, p.IP, r.UserAgent())
	if err != nil {
		return err
	}
	s.setSessionCookie(w, r, tok)
	return noContent(w)
}

// openapi:operation
// summary: Start TOTP enrollment
// description: Returns a new secret; it takes effect after POST /auth/me/totp/confirm.
// tags: [auth]
// responses:
//   '200': { description: Secret to load in an authenticator app, schema: TOTPEnrollment }
//   '409': Error

func (s *Server) totpEnroll(w http.ResponseWriter, r *http.Request, p principal) error {
	secret, otpauthURL, err := s.Users.EnrollTOTP(r.Context(), p.User, p.Dev, s.Auth.SealTOTP)
	if err != nil {
		return fromService(err, "user")
	}
	return ok(w, totpEnrollment{Secret: secret, OTPAuthURL: otpauthURL})
}

// openapi:operation
// summary: Confirm TOTP enrollment
// tags: [auth]
// requestBody: { schema: CodeRequest }
// responses:
//   '204': { description: TOTP enabled }
//   '401': Error
//   '409': Error

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request, p principal) error {
	var req codeRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.Users.ConfirmTOTP(r.Context(), p.actor(), p.User, req.Code, s.Auth.CheckTOTP); err != nil {
		return fromService(err, "user")
	}
	return noContent(w)
}

// openapi:operation
// summary: Disable my TOTP
// tags: [auth]
// requestBody: { schema: PasswordRequest }
// responses:
//   '204': { description: TOTP disabled }
//   '401': Error

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, p principal) error {
	var req passwordRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.Users.DisableTOTP(r.Context(), p.actor(), p.User, req.Password, s.Auth.Authenticate); err != nil {
		return fromService(err, "user")
	}
	return noContent(w)
}
