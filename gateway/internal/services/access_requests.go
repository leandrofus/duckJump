package services

import (
	"context"
	"errors"
	"fmt"
	"sort"
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

type AccessRequestTargetConnection struct {
	ID          string
	Name        string
	Protocol    string
	Environment string
	FolderID    *string
	Tags        []string
}

type AccessRequestTargetFolder struct {
	ID       string
	ParentID *string
	Name     string
}

type AccessRequestTargets struct {
	Connections []AccessRequestTargetConnection
	Folders     []AccessRequestTargetFolder
	Tags        []string
}

type EnrichedAccessRequest struct {
	Request          db.ConfigAccessRequest
	UserUsername     string
	UserDisplayName  string
	ReviewerUsername *string
	ObjectName       string
}

func (s *AccessRequestService) Targets(ctx context.Context) (AccessRequestTargets, error) {
	conns, err := s.store.Q.ListConnections(ctx)
	if err != nil {
		return AccessRequestTargets{}, err
	}
	allTags, err := s.store.Q.ListAllConnectionTags(ctx)
	if err != nil {
		return AccessRequestTargets{}, err
	}
	tagMap := map[string][]string{}
	uniqueTags := map[string]bool{}
	for _, at := range allTags {
		tagMap[at.ConnectionID] = append(tagMap[at.ConnectionID], at.Tag)
		uniqueTags[at.Tag] = true
	}
	connDTOs := make([]AccessRequestTargetConnection, 0, len(conns))
	for _, c := range conns {
		var fID *string
		if c.FolderID.Valid {
			fID = &c.FolderID.String
		}
		connDTOs = append(connDTOs, AccessRequestTargetConnection{
			ID:          c.ID,
			Name:        c.Name,
			Protocol:    c.Protocol,
			Environment: c.Environment,
			FolderID:    fID,
			Tags:        tagMap[c.ID],
		})
	}

	folders, err := s.store.Q.ListFolders(ctx)
	if err != nil {
		return AccessRequestTargets{}, err
	}
	folderDTOs := make([]AccessRequestTargetFolder, 0, len(folders))
	for _, f := range folders {
		var pID *string
		if f.ParentID.Valid {
			pID = &f.ParentID.String
		}
		folderDTOs = append(folderDTOs, AccessRequestTargetFolder{
			ID:       f.ID,
			ParentID: pID,
			Name:     f.Name,
		})
	}

	tags := make([]string, 0, len(uniqueTags))
	for t := range uniqueTags {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	return AccessRequestTargets{
		Connections: connDTOs,
		Folders:     folderDTOs,
		Tags:        tags,
	}, nil
}

func (s *AccessRequestService) Enrich(ctx context.Context, rs []db.ConfigAccessRequest) ([]EnrichedAccessRequest, error) {
	users, _ := s.store.Q.ListUsers(ctx)
	userMap := make(map[string]db.ConfigUser, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}

	conns, _ := s.store.Q.ListConnections(ctx)
	connMap := make(map[string]string, len(conns))
	for _, c := range conns {
		connMap[c.ID] = c.Name
	}

	folders, _ := s.store.Q.ListFolders(ctx)
	folderMap := make(map[string]string, len(folders))
	for _, f := range folders {
		folderMap[f.ID] = f.Name
	}

	out := make([]EnrichedAccessRequest, 0, len(rs))
	for _, r := range rs {
		var userUsername, userDisplayName string
		if u, ok := userMap[r.UserID]; ok {
			userUsername = u.Username
			userDisplayName = u.DisplayName
			if userDisplayName == "" {
				userDisplayName = u.Username
			}
		}

		var reviewerUsername *string
		if r.ReviewedBy.Valid {
			if rev, ok := userMap[r.ReviewedBy.String]; ok {
				name := rev.DisplayName
				if name == "" {
					name = rev.Username
				}
				reviewerUsername = &name
			}
		}

		objectName := r.ObjectRef
		switch r.ObjectType {
		case "connection":
			if name, ok := connMap[r.ObjectRef]; ok {
				objectName = name
			}
		case "folder":
			if name, ok := folderMap[r.ObjectRef]; ok {
				objectName = name
			}
		}

		out = append(out, EnrichedAccessRequest{
			Request:          r,
			UserUsername:     userUsername,
			UserDisplayName:  userDisplayName,
			ReviewerUsername: reviewerUsername,
			ObjectName:       objectName,
		})
	}
	return out, nil
}

func (s *AccessRequestService) ListEnriched(ctx context.Context, userID, status string) ([]EnrichedAccessRequest, error) {
	reqs, err := s.List(ctx, userID, status)
	if err != nil {
		return nil, err
	}
	return s.Enrich(ctx, reqs)
}

func (s *AccessRequestService) GetEnriched(ctx context.Context, id string) (EnrichedAccessRequest, error) {
	req, err := s.Get(ctx, id)
	if err != nil {
		return EnrichedAccessRequest{}, err
	}
	enriched, err := s.Enrich(ctx, []db.ConfigAccessRequest{req})
	if err != nil {
		return EnrichedAccessRequest{}, err
	}
	return enriched[0], nil
}

