package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrAccessRequestReasonRequired       = errors.New("reason (motivo) is required")
	ErrAccessRequestStartsAtRequired     = errors.New("starts_at (fecha inicio) is required")
	ErrAccessRequestEndsAtRequired       = errors.New("ends_at (fecha fin) is required")
	ErrAccessRequestEndsAtBeforeStartsAt = errors.New("ends_at must be after starts_at")
	ErrAccessRequestEndsAtInPast         = errors.New("ends_at cannot be in the past")
	ErrAccessRequestNoPermissions        = errors.New("an access request must ask for at least one permission")
	ErrAccessRequestAlreadyPending       = errors.New("you already have a pending access request for this target")
	ErrAccessRequestEndInPast            = errors.New("the requested end date is already in the past")
	ErrForbidden                         = errors.New("forbidden")
)

type AccessRequestNotPendingError struct {
	Status string
}

func (e *AccessRequestNotPendingError) Error() string {
	return fmt.Sprintf("access request is not pending (status: %s)", e.Status)
}

type CreateAccessRequestParams struct {
	UserID            string
	ObjectType        string
	ObjectRef         string
	Ticket            string
	CanConnect        bool
	CanViewRecordings bool
	CanUpload         bool
	CanDownload       bool
	CanForward        bool
	Reason            string
	StartsAt          time.Time
	EndsAt            time.Time
	Actor             store.Actor
}

type AccessRequestService struct {
	store    *store.Store
	policies *PolicyService
}

func NewAccessRequestService(st *store.Store, pol *PolicyService) *AccessRequestService {
	return &AccessRequestService{store: st, policies: pol}
}

func (s *AccessRequestService) List(ctx context.Context, userID, status string) ([]db.ConfigAccessRequest, error) {
	return s.store.Q.ListAccessRequests(ctx, db.ListAccessRequestsParams{
		UserID: userID,
		Status: status,
	})
}

func (s *AccessRequestService) Get(ctx context.Context, id string) (db.ConfigAccessRequest, error) {
	req, err := s.store.Q.GetAccessRequest(ctx, id)
	if err != nil {
		return db.ConfigAccessRequest{}, store.Classify(err)
	}
	return req, nil
}

func (s *AccessRequestService) Create(ctx context.Context, params CreateAccessRequestParams) (db.ConfigAccessRequest, error) {
	if params.ObjectType == "" {
		params.ObjectType = "connection"
	}
	reason := strings.TrimSpace(params.Reason)
	if reason == "" {
		return db.ConfigAccessRequest{}, ErrAccessRequestReasonRequired
	}
	ticket := strings.TrimSpace(params.Ticket)
	if params.StartsAt.IsZero() {
		return db.ConfigAccessRequest{}, ErrAccessRequestStartsAtRequired
	}
	if params.EndsAt.IsZero() {
		return db.ConfigAccessRequest{}, ErrAccessRequestEndsAtRequired
	}
	if !params.EndsAt.After(params.StartsAt) {
		return db.ConfigAccessRequest{}, ErrAccessRequestEndsAtBeforeStartsAt
	}
	if !params.EndsAt.After(time.Now()) {
		return db.ConfigAccessRequest{}, ErrAccessRequestEndsAtInPast
	}
	if !params.CanConnect && !params.CanViewRecordings && !params.CanUpload && !params.CanDownload && !params.CanForward {
		return db.ConfigAccessRequest{}, ErrAccessRequestNoPermissions
	}

	id := store.NewID()
	var createdReq db.ConfigAccessRequest
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if s.policies != nil {
			if err := s.policies.CheckRefs(ctx, "user", params.UserID, params.ObjectType, params.ObjectRef); err != nil {
				return err
			}
		}

		pendings, err := q.ListPendingAccessRequestsForUserAndObject(ctx, db.ListPendingAccessRequestsForUserAndObjectParams{
			UserID:     params.UserID,
			ObjectType: params.ObjectType,
			ObjectRef:  params.ObjectRef,
		})
		if err != nil {
			return err
		}
		if len(pendings) > 0 {
			return ErrAccessRequestAlreadyPending
		}

		now := store.Now()
		if err := q.CreateAccessRequest(ctx, db.CreateAccessRequestParams{
			ID:                id,
			UserID:            params.UserID,
			ObjectType:        params.ObjectType,
			ObjectRef:         params.ObjectRef,
			Ticket:            ticket,
			CanConnect:        params.CanConnect,
			CanViewRecordings: params.CanViewRecordings,
			CanUpload:         params.CanUpload,
			CanDownload:       params.CanDownload,
			CanForward:        params.CanForward,
			Reason:            reason,
			StartsAt:          params.StartsAt.UTC(),
			EndsAt:            params.EndsAt.UTC(),
			Now:               now,
		}); err != nil {
			return store.Classify(err)
		}

		d := map[string]any{
			"object":              params.ObjectType + ":" + params.ObjectRef,
			"ticket":              ticket,
			"reason":              reason,
			"starts_at":           params.StartsAt.UTC().Format(time.RFC3339),
			"ends_at":             params.EndsAt.UTC().Format(time.RFC3339),
			"can_connect":         params.CanConnect,
			"can_view_recordings": params.CanViewRecordings,
			"can_upload":          params.CanUpload,
			"can_download":        params.CanDownload,
			"can_forward":         params.CanForward,
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "access_request.create",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		createdReq = db.ConfigAccessRequest{
			ID:                id,
			UserID:            params.UserID,
			ObjectType:        params.ObjectType,
			ObjectRef:         params.ObjectRef,
			Ticket:            ticket,
			CanConnect:        params.CanConnect,
			CanViewRecordings: params.CanViewRecordings,
			CanUpload:         params.CanUpload,
			CanDownload:       params.CanDownload,
			CanForward:        params.CanForward,
			Reason:            reason,
			StartsAt:          params.StartsAt.UTC(),
			EndsAt:            params.EndsAt.UTC(),
			Status:            "pending",
			CreatedAt:         now,
		}
		return nil
	})
	if err != nil {
		return db.ConfigAccessRequest{}, err
	}
	return createdReq, nil
}

func (s *AccessRequestService) Approve(ctx context.Context, actor store.Actor, id, reviewerUserID, comment string) (db.ConfigAccessRequest, string, error) {
	var out db.ConfigAccessRequest
	var policyID string

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if req.Status != "pending" {
			return &AccessRequestNotPendingError{Status: req.Status}
		}
		if !req.EndsAt.After(time.Now()) {
			return ErrAccessRequestEndInPast
		}

		existing, err := q.ListPolicies(ctx, db.ListPoliciesParams{
			SubjectID: req.UserID,
			ObjectRef: req.ObjectRef,
		})
		if err != nil {
			return err
		}

		var existingPolicy *db.ConfigPolicy
		for _, e := range existing {
			if e.SubjectType == "user" && e.ObjectType == req.ObjectType {
				ep := e
				existingPolicy = &ep
				break
			}
		}

		policyID = store.NewID()
		desc := "Access request: " + req.Reason
		if req.Ticket != "" {
			desc = fmt.Sprintf("Access request [%s]: %s", req.Ticket, req.Reason)
		}
		now := store.Now()

		if existingPolicy != nil {
			policyID = existingPolicy.ID
			if err := q.UpdatePolicy(ctx, db.UpdatePolicyParams{
				ID:                policyID,
				CanConnect:        req.CanConnect,
				CanViewRecordings: req.CanViewRecordings,
				CanUpload:         req.CanUpload,
				CanDownload:       req.CanDownload,
				CanForward:        req.CanForward,
				StartsAt:          store.NullTime(req.StartsAt),
				ExpiresAt:         store.NullTime(req.EndsAt),
				Description:       desc,
			}); err != nil {
				return err
			}
		} else {
			if err := q.CreatePolicy(ctx, db.CreatePolicyParams{
				ID:                policyID,
				SubjectType:       "user",
				SubjectID:         req.UserID,
				ObjectType:        req.ObjectType,
				ObjectRef:         req.ObjectRef,
				CanConnect:        req.CanConnect,
				CanViewRecordings: req.CanViewRecordings,
				CanUpload:         req.CanUpload,
				CanDownload:       req.CanDownload,
				CanForward:        req.CanForward,
				StartsAt:          store.NullTime(req.StartsAt),
				ExpiresAt:         store.NullTime(req.EndsAt),
				Description:       desc,
				CreatedBy:         store.NullString(reviewerUserID),
				Now:               now,
			}); err != nil {
				return err
			}
		}

		if err := q.ApproveAccessRequest(ctx, db.ApproveAccessRequestParams{
			ID:              id,
			ReviewedBy:      store.NullString(reviewerUserID),
			ReviewedAt:      store.NullTime(now),
			ReviewComment:   comment,
			CreatedPolicyID: store.NullString(policyID),
		}); err != nil {
			return err
		}

		d := map[string]any{
			"user_id":   req.UserID,
			"object":    req.ObjectType + ":" + req.ObjectRef,
			"policy_id": policyID,
			"starts_at": req.StartsAt.UTC().Format(time.RFC3339),
			"ends_at":   req.EndsAt.UTC().Format(time.RFC3339),
		}
		if req.Ticket != "" {
			d["ticket"] = req.Ticket
		}
		if comment != "" {
			d["comment"] = comment
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "access_request.approve",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		req.Status = "approved"
		req.ReviewedBy = store.NullString(reviewerUserID)
		req.ReviewedAt = store.NullTime(now)
		req.ReviewComment = comment
		req.CreatedPolicyID = store.NullString(policyID)
		out = req
		return nil
	})
	if err != nil {
		return db.ConfigAccessRequest{}, "", err
	}
	return out, policyID, nil
}

func (s *AccessRequestService) Reject(ctx context.Context, actor store.Actor, id, reviewerUserID, comment string) (db.ConfigAccessRequest, error) {
	var out db.ConfigAccessRequest
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if req.Status != "pending" {
			return &AccessRequestNotPendingError{Status: req.Status}
		}

		now := store.Now()
		if err := q.RejectAccessRequest(ctx, db.RejectAccessRequestParams{
			ID:            id,
			ReviewedBy:    store.NullString(reviewerUserID),
			ReviewedAt:    store.NullTime(now),
			ReviewComment: comment,
		}); err != nil {
			return err
		}

		d := map[string]any{
			"user_id": req.UserID,
			"object":  req.ObjectType + ":" + req.ObjectRef,
		}
		if comment != "" {
			d["comment"] = comment
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "access_request.reject",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		req.Status = "rejected"
		req.ReviewedBy = store.NullString(reviewerUserID)
		req.ReviewedAt = store.NullTime(now)
		req.ReviewComment = comment
		out = req
		return nil
	})
	if err != nil {
		return db.ConfigAccessRequest{}, err
	}
	return out, nil
}

func (s *AccessRequestService) Cancel(ctx context.Context, actor store.Actor, id, userID string, isAdmin bool) (db.ConfigAccessRequest, error) {
	var out db.ConfigAccessRequest
	err := s.store.Tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if !isAdmin && req.UserID != userID {
			return ErrForbidden
		}
		if req.Status != "pending" {
			return &AccessRequestNotPendingError{Status: req.Status}
		}

		if err := q.CancelAccessRequest(ctx, id); err != nil {
			return err
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "access_request.cancel",
			ObjectType: "access_request",
			ObjectID:   id,
			Details: map[string]any{
				"user_id": req.UserID,
				"object":  req.ObjectType + ":" + req.ObjectRef,
			},
		}); err != nil {
			return err
		}

		req.Status = "canceled"
		out = req
		return nil
	})
	if err != nil {
		return db.ConfigAccessRequest{}, err
	}
	return out, nil
}
