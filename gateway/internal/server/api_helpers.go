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
	case errors.Is(err, services.ErrDevModeNotAllowed):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrPasswordManagedByIdP),
		errors.Is(err, services.ErrTOTPManagedByIdP),
		errors.Is(err, services.ErrTOTPAlreadyEnabled),
		errors.Is(err, services.ErrTOTPAlreadyActive):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrCallEnrollFirst):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrCurrentPasswordWrong):
		return &apiError{http.StatusUnauthorized, "invalid_credentials", "current password is wrong"}
	case errors.Is(err, services.ErrPasswordWrong):
		return &apiError{http.StatusUnauthorized, "invalid_credentials", "password is wrong"}
	case errors.Is(err, services.ErrInvalidCode):
		return &apiError{http.StatusUnauthorized, "invalid_code", "invalid code"}
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
	case errors.Is(err, services.ErrExpiresAndTTLBothSet):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrExpiresInPast):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrTTLNegative):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrPolicyNoPermissions):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrPolicyAlreadyExists):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrInvalidSubjectType):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrInvalidObjectType):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrGroupSyncedReadOnly):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrMembershipNotFound):
		return notFound("membership")
	case errors.Is(err, services.ErrFolderInsideItself):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrParentFolderNotFound):
		return notFound("parent folder")
	case errors.Is(err, services.ErrSecretKindInvalid),
		errors.Is(err, services.ErrSecretMissingUsernameOrValue),
		errors.Is(err, services.ErrSecretKindRequiredWithValue),
		errors.Is(err, services.ErrSecretValueEmpty),
		errors.Is(err, services.ErrSecretKindRequiresValue),
		errors.Is(err, services.ErrSiteKindInvalid):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrSiteTokenNotAgent),
		errors.Is(err, services.ErrAccessRequestAlreadyPending),
		errors.Is(err, services.ErrRecordingsNotConfigured),
		errors.Is(err, services.ErrSessionAlreadyEnded):
		return conflict("%s", err.Error())
	case errors.Is(err, services.ErrForbidden):
		return errForbidden
	case errors.Is(err, services.ErrAccessRequestReasonRequired),
		errors.Is(err, services.ErrAccessRequestStartsAtRequired),
		errors.Is(err, services.ErrAccessRequestEndsAtRequired),
		errors.Is(err, services.ErrAccessRequestEndsAtBeforeStartsAt),
		errors.Is(err, services.ErrAccessRequestEndsAtInPast),
		errors.Is(err, services.ErrAccessRequestNoPermissions),
		errors.Is(err, services.ErrAccessRequestEndInPast),
		errors.Is(err, services.ErrRetentionDaysInvalid),
		errors.Is(err, services.ErrSIEMEndpointRequired),
		errors.Is(err, services.ErrInvalidFileName),
		errors.Is(err, services.ErrTargetNameRequired),
		errors.Is(err, services.ErrTokenRequired),
		errors.Is(err, services.ErrInvalidVerificationCode):
		return badRequest("%s", err.Error())
	case errors.Is(err, services.ErrFilesNotConfigured):
		return &apiError{http.StatusNotImplemented, "not_configured", "file transfer is not configured on this gateway (-files)"}
	case errors.Is(err, services.ErrFileTooLarge):
		return &apiError{http.StatusRequestEntityTooLarge, "too_large", err.Error()}
	case errors.Is(err, services.ErrFileForbidden):
		return &apiError{http.StatusForbidden, "forbidden", err.Error()}
	case errors.Is(err, services.ErrFileNotFound):
		return notFound("file")
	case errors.Is(err, services.ErrSupportSessionNotFound):
		return notFound("support session not found")
	default:
		var notEmptyErr *services.FolderNotEmptyError
		if errors.As(err, &notEmptyErr) {
			return conflict("%s", notEmptyErr.Error())
		}
		var notPendingErr *services.AccessRequestNotPendingError
		if errors.As(err, &notPendingErr) {
			return conflict("%s", notPendingErr.Error())
		}
		var fileDelErr *services.FileDeletedError
		if errors.As(err, &fileDelErr) {
			return &apiError{http.StatusGone, "deleted", fileDelErr.Error()}
		}
		var invalidStatusErr *services.InvalidSupportStatusError
		if errors.As(err, &invalidStatusErr) {
			return badRequest("%s", invalidStatusErr.Error())
		}
		return fromStore(err, what)
	}
}
