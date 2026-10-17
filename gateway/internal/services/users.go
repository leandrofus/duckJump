package services

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/leandrofus/duckjump/gateway/internal/auth"
	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
	"github.com/leandrofus/duckjump/gateway/internal/totp"
)

var (
	reUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	validRoles = map[string]bool{"superadmin": true, "admin": true, "auditor": true, "user": true}

	ErrInvalidUsername      = errors.New("username must be lowercase letters, digits, . _ - (max 64)")
	ErrUnknownRole          = errors.New("unknown role")
	ErrPasswordTooShort     = errors.New("password must have at least 10 characters")
	ErrCannotSelfDelete     = errors.New("you cannot delete yourself")
	ErrLastSuperadmin       = errors.New("cannot demote, disable, or delete the last superadmin")
	ErrLastSuperadminDemote = fmt.Errorf("%w: cannot demote or disable the last superadmin", ErrLastSuperadmin)
	ErrLastSuperadminDelete = fmt.Errorf("%w: cannot delete the last superadmin", ErrLastSuperadmin)
	ErrSuperadminGuarded    = errors.New("only a superadmin can manage superadmins")
	ErrNotLocalUser         = errors.New("only local users have a password")
	ErrUserNotFound         = errors.New("user not found")

	ErrDevModeNotAllowed    = errors.New("not available in dev mode")
	ErrPasswordManagedByIdP = errors.New("your password is managed by the identity provider")
	ErrTOTPManagedByIdP     = errors.New("your second factor is managed by the identity provider")
	ErrCurrentPasswordWrong = errors.New("current password is wrong")
	ErrPasswordWrong        = errors.New("password is wrong")
	ErrTOTPAlreadyEnabled   = errors.New("TOTP is already enabled; disable it first")
	ErrTOTPAlreadyActive    = errors.New("TOTP is already enabled")
	ErrCallEnrollFirst      = errors.New("call /auth/me/totp/enroll first")
	ErrInvalidCode          = errors.New("invalid code")
)

type OIDCManagedRoleError struct {
	Username   string
	RolesClaim string
}

func (e *OIDCManagedRoleError) Error() string {
	return fmt.Sprintf("the role of %s comes from the identity provider (%s)", e.Username, e.RolesClaim)
}

type CreateUserParams struct {
	Username    string
	DisplayName string
	Email       string
	Password    string
	Role        string
	CallerRole  string
	Actor       store.Actor
}

type UpdateUserParams struct {
	ID          string
	DisplayName *string
	Email       *string
	Role        *string
	Disabled    *bool
	CallerRole  string
	Actor       store.Actor
	OIDCRoles   bool
	RolesClaim  string
}

type UserService struct {
	store *store.Store
}

func NewUserService(st *store.Store) *UserService {
	return &UserService{store: st}
}

func (s *UserService) List(ctx context.Context) ([]db.ConfigUser, error) {
	return s.store.Q.ListUsers(ctx)
}

func (s *UserService) Get(ctx context.Context, id string) (db.ConfigUser, error) {
	u, err := s.store.Q.GetUser(ctx, id)
	if err != nil {
		return db.ConfigUser{}, store.Classify(err)
	}
	return u, nil
}

func (s *UserService) GetByUsername(ctx context.Context, username string) (db.ConfigUser, error) {
	u, err := s.store.Q.GetUserByUsername(ctx, strings.ToLower(username))
	if err != nil {
		return db.ConfigUser{}, store.Classify(err)
	}
	return u, nil
}

func (s *UserService) Create(ctx context.Context, params CreateUserParams) (db.ConfigUser, error) {
	username := strings.ToLower(strings.TrimSpace(params.Username))
	if !reUsername.MatchString(username) {
		return db.ConfigUser{}, ErrInvalidUsername
	}

	role := params.Role
	if role == "" {
		role = "user"
	}
	if !validRoles[role] {
		return db.ConfigUser{}, fmt.Errorf("%w: %q", ErrUnknownRole, role)
	}

	if role == "superadmin" && params.CallerRole != "" && params.CallerRole != "superadmin" {
		return db.ConfigUser{}, ErrSuperadminGuarded
	}

	if err := auth.CheckPasswordPolicy(params.Password); err != nil {
		return db.ConfigUser{}, fmt.Errorf("%w: %s", ErrPasswordTooShort, err.Error())
	}

	hash, err := auth.HashPassword(params.Password)
	if err != nil {
		return db.ConfigUser{}, err
	}

	id := store.NewID()
	var created db.ConfigUser

	err = s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.CreateUser(ctx, db.CreateUserParams{
			ID:           id,
			Username:     username,
			DisplayName:  params.DisplayName,
			Email:        params.Email,
			PasswordHash: store.NullString(hash),
			Source:       "local",
			Role:         role,
			Now:          store.Now(),
		}); err != nil {
			return store.Classify(err)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "user.create",
			ObjectType: "user",
			ObjectID:   id,
			Details:    map[string]any{"username": username, "role": role},
		}); err != nil {
			return err
		}

		u, err := q.GetUser(ctx, id)
		if err != nil {
			return err
		}
		created = u
		return nil
	})

	return created, err
}

func (s *UserService) Update(ctx context.Context, params UpdateUserParams) (db.ConfigUser, error) {
	var updated db.ConfigUser
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		if u.Role == "superadmin" && params.CallerRole != "" && params.CallerRole != "superadmin" {
			return ErrSuperadminGuarded
		}

		changes := map[string]any{}
		next := u

		if params.DisplayName != nil {
			next.DisplayName = *params.DisplayName
			changes["display_name"] = next.DisplayName
		}
		if params.Email != nil {
			next.Email = *params.Email
			changes["email"] = next.Email
		}
		if params.Role != nil && *params.Role != u.Role {
			if u.Source == "oidc" && params.OIDCRoles {
				return &OIDCManagedRoleError{Username: u.Username, RolesClaim: params.RolesClaim}
			}
			newRole := *params.Role
			if !validRoles[newRole] {
				return fmt.Errorf("%w: %q", ErrUnknownRole, newRole)
			}
			if newRole == "superadmin" && params.CallerRole != "" && params.CallerRole != "superadmin" {
				return ErrSuperadminGuarded
			}
			next.Role = newRole
			changes["role"] = map[string]string{"from": u.Role, "to": next.Role}
		}
		if params.Disabled != nil {
			next.Disabled = *params.Disabled
			changes["disabled"] = next.Disabled
		}

		if (next.Role != "superadmin" || next.Disabled) && u.Role == "superadmin" {
			last, err := s.isLastSuperadmin(ctx, q, u)
			if err != nil {
				return err
			}
			if last {
				return ErrLastSuperadminDemote
			}
		}

		if err := q.UpdateUser(ctx, db.UpdateUserParams{
			ID:          params.ID,
			DisplayName: next.DisplayName,
			Email:       next.Email,
			Role:        next.Role,
			Disabled:    next.Disabled,
			Now:         store.Now(),
		}); err != nil {
			return err
		}

		if next.Disabled && !u.Disabled {
			if err := q.DeleteUserWebSessions(ctx, params.ID); err != nil {
				return err
			}
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "user.update",
			ObjectType: "user",
			ObjectID:   params.ID,
			Details:    changes,
		}); err != nil {
			return err
		}

		out, err := q.GetUser(ctx, params.ID)
		if err != nil {
			return err
		}
		updated = out
		return nil
	})

	return updated, err
}

func (s *UserService) Delete(ctx context.Context, actor store.Actor, callerID, callerRole, targetID string) error {
	if callerID != "" && targetID == callerID {
		return ErrCannotSelfDelete
	}

	return s.store.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, targetID)
		if err != nil {
			return store.Classify(err)
		}

		if callerRole != "" && callerRole != "superadmin" && u.Role == "superadmin" {
			return ErrSuperadminGuarded
		}

		last, err := s.isLastSuperadmin(ctx, q, u)
		if err != nil {
			return err
		}
		if last {
			return ErrLastSuperadminDelete
		}

		if err := q.DeletePoliciesForSubject(ctx, db.DeletePoliciesForSubjectParams{
			SubjectType: "user",
			SubjectID:   targetID,
		}); err != nil {
			return err
		}

		if _, err := q.DeleteUser(ctx, targetID); err != nil {
			return err
		}

		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.delete",
			ObjectType: "user",
			ObjectID:   targetID,
			Details:    map[string]any{"username": u.Username},
		})
	})
}

func (s *UserService) SetPassword(ctx context.Context, actor store.Actor, callerRole, targetID, newPassword string) error {
	if err := auth.CheckPasswordPolicy(newPassword); err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordTooShort, err.Error())
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	return s.store.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, targetID)
		if err != nil {
			return store.Classify(err)
		}
		if callerRole != "" && callerRole != "superadmin" && u.Role == "superadmin" {
			return ErrSuperadminGuarded
		}
		if u.Source != "local" {
			return ErrNotLocalUser
		}
		if err := q.SetUserPassword(ctx, db.SetUserPasswordParams{
			ID:           targetID,
			PasswordHash: store.NullString(hash),
			Now:          store.Now(),
		}); err != nil {
			return err
		}
		if err := q.DeleteUserWebSessions(ctx, targetID); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.password_reset",
			ObjectType: "user",
			ObjectID:   targetID,
			Details:    map[string]any{"username": u.Username},
		})
	})
}

func (s *UserService) ResetTOTP(ctx context.Context, actor store.Actor, callerRole, targetID string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		u, err := q.GetUser(ctx, targetID)
		if err != nil {
			return store.Classify(err)
		}
		if callerRole != "" && callerRole != "superadmin" && u.Role == "superadmin" {
			return ErrSuperadminGuarded
		}
		if err := q.SetUserTOTP(ctx, db.SetUserTOTPParams{
			ID:  targetID,
			Now: store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.totp_reset",
			ObjectType: "user",
			ObjectID:   targetID,
			Details:    map[string]any{"username": u.Username},
		})
	})
}

func (s *UserService) isLastSuperadmin(ctx context.Context, q *db.Queries, u db.ConfigUser) (bool, error) {
	if u.Role != "superadmin" || u.Disabled {
		return false, nil
	}
	all, err := q.ListUsers(ctx)
	if err != nil {
		return false, err
	}
	n := 0
	for _, x := range all {
		if x.Role == "superadmin" && !x.Disabled {
			n++
		}
	}
	return n == 1, nil
}

func (s *UserService) ListUserGroups(ctx context.Context, userID string) ([]db.ConfigGroup, error) {
	return s.store.Q.ListUserGroups(ctx, userID)
}

func (s *UserService) ChangePassword(
	ctx context.Context,
	actor store.Actor,
	user db.ConfigUser,
	isDev bool,
	currentPassword, newPassword string,
	authenticateFn func(ctx context.Context, username, password string) (db.ConfigUser, error),
) error {
	if isDev {
		return ErrDevModeNotAllowed
	}
	if user.Source != "local" {
		return ErrPasswordManagedByIdP
	}
	if authenticateFn != nil {
		if _, err := authenticateFn(ctx, user.Username, currentPassword); err != nil {
			return ErrCurrentPasswordWrong
		}
	}
	if err := auth.CheckPasswordPolicy(newPassword); err != nil {
		return fmt.Errorf("%w: %s", ErrPasswordTooShort, err.Error())
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetUserPassword(ctx, db.SetUserPasswordParams{
			ID:           user.ID,
			PasswordHash: store.NullString(hash),
			Now:          store.Now(),
		}); err != nil {
			return err
		}
		if err := q.DeleteUserWebSessions(ctx, user.ID); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.password_changed",
			ObjectType: "user",
			ObjectID:   user.ID,
		})
	})
}

func (s *UserService) EnrollTOTP(
	ctx context.Context,
	user db.ConfigUser,
	isDev bool,
	sealFn func(userID, secret string) []byte,
) (secret, otpauthURL string, err error) {
	if isDev {
		return "", "", ErrDevModeNotAllowed
	}
	if user.TOTPEnabled {
		return "", "", ErrTOTPAlreadyEnabled
	}
	if user.Source != "local" {
		return "", "", ErrTOTPManagedByIdP
	}
	secret = totp.NewSecret()
	var sealed []byte
	if sealFn != nil {
		sealed = sealFn(user.ID, secret)
	}
	err = s.store.Q.SetUserTOTP(ctx, db.SetUserTOTPParams{
		ID:          user.ID,
		TOTPSealed:  sealed,
		TOTPEnabled: false,
		Now:         store.Now(),
	})
	if err != nil {
		return "", "", store.Classify(err)
	}
	return secret, totp.URL("DuckJump", user.Username, secret), nil
}

func (s *UserService) ConfirmTOTP(
	ctx context.Context,
	actor store.Actor,
	user db.ConfigUser,
	code string,
	checkTOTPFn func(user db.ConfigUser, code string) bool,
) error {
	if user.TOTPEnabled {
		return ErrTOTPAlreadyActive
	}
	if len(user.TOTPSealed) == 0 {
		return ErrCallEnrollFirst
	}
	if checkTOTPFn != nil && !checkTOTPFn(user, code) {
		return ErrInvalidCode
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetUserTOTP(ctx, db.SetUserTOTPParams{
			ID:          user.ID,
			TOTPSealed:  user.TOTPSealed,
			TOTPEnabled: true,
			Now:         store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.totp_enabled",
			ObjectType: "user",
			ObjectID:   user.ID,
		})
	})
}

func (s *UserService) DisableTOTP(
	ctx context.Context,
	actor store.Actor,
	user db.ConfigUser,
	password string,
	authenticateFn func(ctx context.Context, username, password string) (db.ConfigUser, error),
) error {
	if authenticateFn != nil {
		if _, err := authenticateFn(ctx, user.Username, password); err != nil {
			return ErrPasswordWrong
		}
	}
	return s.store.Tx(ctx, func(q *db.Queries) error {
		if err := q.SetUserTOTP(ctx, db.SetUserTOTPParams{
			ID:  user.ID,
			Now: store.Now(),
		}); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "user.totp_disabled",
			ObjectType: "user",
			ObjectID:   user.ID,
		})
	})
}
