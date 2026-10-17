package server

import (
	"errors"
	"net/http"

	"github.com/leandrofus/duckjump/gateway/internal/services"
)

// handleOK executes fn to produce a result and writes it with HTTP 200 JSON.
func handleOK[T any](w http.ResponseWriter, fn func() (T, error)) error {
	res, err := fn()
	if err != nil {
		return err
	}
	return ok(w, res)
}

// handleCreated decodes JSON body into Req, executes fn, and writes the response with HTTP 201 Created.
func handleCreated[Req any, Resp any](w http.ResponseWriter, r *http.Request, fn func(req Req) (Resp, error)) error {
	var req Req
	if err := decode(r, &req); err != nil {
		return err
	}
	res, err := fn(req)
	if err != nil {
		return err
	}
	return created(w, res)
}

// handleAction decodes JSON body into Req, executes fn, and writes the response with HTTP 200 OK.
func handleAction[Req any, Resp any](w http.ResponseWriter, r *http.Request, fn func(req Req) (Resp, error)) error {
	var req Req
	if err := decode(r, &req); err != nil {
		return err
	}
	res, err := fn(req)
	if err != nil {
		return err
	}
	return ok(w, res)
}

// handleCommand executes a mutating action without request body and writes HTTP 204 No Content.
func handleCommand(w http.ResponseWriter, fn func() error) error {
	if err := fn(); err != nil {
		return err
	}
	return noContent(w)
}

// fromService maps service layer errors into appropriate HTTP apiError responses.
func fromService(err error, what string) error {
	if err == nil {
		return nil
	}
	var oidcErr *services.OIDCManagedRoleError
	switch {
	case errors.As(err, &oidcErr):
		return conflict("%s", oidcErr.Error())
	case errors.Is(err, services.ErrInvalidUsername):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrUnknownRole):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrPasswordTooShort):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrSuperadminGuarded):
		return forbidden("%s", err.Error())
	case errors.Is(err, services.ErrCannotSelfDelete):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrLastSuperadminDemote):
		return conflict("cannot demote or disable the last superadmin")
	case errors.Is(err, services.ErrLastSuperadminDelete):
		return conflict("cannot delete the last superadmin")
	case errors.Is(err, services.ErrLastSuperadmin):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrNotLocalUser):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrNameInvalid):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrProtocolInvalid):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrPortOutOfRange):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrHostRequired):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrBackendInvalid):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrCredentialModeInvalid):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrParamsNotJSONObject):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrInvalidTag):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrInvalidFingerprint):
		return badRequest("%s", err.Error())
	default:
		return fromStore(err, what)
	}
}
