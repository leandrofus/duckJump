package server

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

// openapi:schema CreateAccessRequest
// type: object
// required: [object_ref, reason, starts_at, ends_at]
// additionalProperties: false
// properties:
//   object_type: { type: string, enum: [connection, folder, tag], default: connection }
//   object_ref: { type: string }
//   ticket: { type: string, description: 'Optional reference to a ticket or issue ID.' }
//   can_connect: { type: boolean, default: true }
//   can_view_recordings: { type: boolean, default: false }
//   can_upload: { type: boolean, default: false }
//   can_download: { type: boolean, default: false }
//   reason: { type: string }
//   starts_at: { type: string, format: date-time }
//   ends_at: { type: string, format: date-time }

type createAccessRequest struct {
	ObjectType        string    `json:"object_type"`
	ObjectRef         string    `json:"object_ref"`
	Ticket            string    `json:"ticket"`
	CanConnect        *bool     `json:"can_connect"`
	CanViewRecordings bool      `json:"can_view_recordings"`
	CanUpload         bool      `json:"can_upload"`
	CanDownload       bool      `json:"can_download"`
	Reason            string    `json:"reason"`
	StartsAt          time.Time `json:"starts_at"`
	EndsAt            time.Time `json:"ends_at"`
}

// openapi:schema ReviewAccessRequest
// type: object
// additionalProperties: false
// properties:
//   comment: { type: string }

type reviewAccessRequest struct {
	Comment string `json:"comment"`
}

func (s *Server) toAccessRequestDTO(ctx context.Context, r db.ConfigAccessRequest) (accessRequestDTO, error) {
	dtos, err := s.toAccessRequestDTOs(ctx, []db.ConfigAccessRequest{r})
	if err != nil {
		return accessRequestDTO{}, err
	}
	return dtos[0], nil
}

func (s *Server) toAccessRequestDTOs(ctx context.Context, rs []db.ConfigAccessRequest) ([]accessRequestDTO, error) {
	users, _ := s.Store.Q.ListUsers(ctx)
	userMap := make(map[string]db.ConfigUser, len(users))
	for _, u := range users {
		userMap[u.ID] = u
	}

	conns, _ := s.Store.Q.ListConnections(ctx)
	connMap := make(map[string]string, len(conns))
	for _, c := range conns {
		connMap[c.ID] = c.Name
	}

	folders, _ := s.Store.Q.ListFolders(ctx)
	folderMap := make(map[string]string, len(folders))
	for _, f := range folders {
		folderMap[f.ID] = f.Name
	}

	out := make([]accessRequestDTO, 0, len(rs))
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

		out = append(out, accessRequestDTO{
			ID:                r.ID,
			UserID:            r.UserID,
			UserUsername:      userUsername,
			UserDisplayName:   userDisplayName,
			ObjectType:        r.ObjectType,
			ObjectRef:         r.ObjectRef,
			ObjectName:        objectName,
			Ticket:            r.Ticket,
			CanConnect:        r.CanConnect,
			CanViewRecordings: r.CanViewRecordings,
			CanUpload:         r.CanUpload,
			CanDownload:       r.CanDownload,
			Reason:            r.Reason,
			StartsAt:          r.StartsAt.UTC(),
			EndsAt:            r.EndsAt.UTC(),
			Status:            r.Status,
			ReviewedBy:        strPtr(r.ReviewedBy),
			ReviewerUsername:  reviewerUsername,
			ReviewedAt:        timePtr(r.ReviewedAt),
			ReviewComment:     r.ReviewComment,
			CreatedPolicyID:   strPtr(r.CreatedPolicyID),
			CreatedAt:         r.CreatedAt.UTC(),
		})
	}
	return out, nil
}

// openapi:operation
// summary: List access requests
// tags: [access-requests]
// parameters:
//   - { name: user_id, in: query, schema: { type: string }, description: Filter by user id (admins only). }
//   - { name: status, in: query, schema: { type: string, enum: [pending, approved, rejected, canceled] }, description: Filter by request status. }
//   - { name: mine, in: query, schema: { type: boolean }, description: Return only the caller's requests. }
// responses:
//   '200': { description: Access requests, schema: '[]AccessRequest' }

func (s *Server) listAccessRequests(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	qUser := r.URL.Query().Get("user_id")
	qStatus := r.URL.Query().Get("status")
	mine := r.URL.Query().Get("mine") == "true"

	filterUser := ""
	if !admins[p.User.Role] || mine {
		filterUser = p.User.ID
	} else if qUser != "" {
		filterUser = qUser
	}

	reqs, err := s.Store.Q.ListAccessRequests(ctx, db.ListAccessRequestsParams{
		UserID: filterUser,
		Status: qStatus,
	})
	if err != nil {
		return err
	}

	out, err := s.toAccessRequestDTOs(ctx, reqs)
	if err != nil {
		return err
	}
	return ok(w, out)
}

// openapi:operation
// summary: List available targets for access requests
// tags: [access-requests]
// responses:
//   '200': { description: 'Available connections, folders and tags', schema: AccessRequestTargets }

func (s *Server) accessRequestTargets(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	conns, err := s.Store.Q.ListConnections(ctx)
	if err != nil {
		return err
	}
	allTags, err := s.Store.Q.ListAllConnectionTags(ctx)
	if err != nil {
		return err
	}
	tagMap := map[string][]string{}
	uniqueTags := map[string]bool{}
	for _, at := range allTags {
		tagMap[at.ConnectionID] = append(tagMap[at.ConnectionID], at.Tag)
		uniqueTags[at.Tag] = true
	}
	connDTOs := make([]accessRequestConnectionTarget, 0, len(conns))
	for _, c := range conns {
		connDTOs = append(connDTOs, accessRequestConnectionTarget{
			ID:          c.ID,
			Name:        c.Name,
			Protocol:    c.Protocol,
			Environment: c.Environment,
			FolderID:    strPtr(c.FolderID),
			Tags:        tagMap[c.ID],
		})
	}

	folders, err := s.Store.Q.ListFolders(ctx)
	if err != nil {
		return err
	}
	folderDTOs := make([]accessRequestFolderTarget, 0, len(folders))
	for _, f := range folders {
		folderDTOs = append(folderDTOs, accessRequestFolderTarget{
			ID:       f.ID,
			ParentID: strPtr(f.ParentID),
			Name:     f.Name,
		})
	}

	tags := make([]string, 0, len(uniqueTags))
	for t := range uniqueTags {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	return ok(w, accessRequestTargetsDTO{
		Connections: connDTOs,
		Folders:     folderDTOs,
		Tags:        tags,
	})
}

// openapi:operation
// summary: Create an access request
// tags: [access-requests]
// requestBody: { schema: CreateAccessRequest }
// responses:
//   '201': { description: Created, schema: AccessRequest }
//   '409': Error

func (s *Server) createAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	var req createAccessRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.ObjectType == "" {
		req.ObjectType = "connection"
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return badRequest("reason (motivo) is required")
	}
	ticket := strings.TrimSpace(req.Ticket)
	if req.StartsAt.IsZero() {
		return badRequest("starts_at (fecha inicio) is required")
	}
	if req.EndsAt.IsZero() {
		return badRequest("ends_at (fecha fin) is required")
	}
	if !req.EndsAt.After(req.StartsAt) {
		return badRequest("ends_at must be after starts_at")
	}
	if !req.EndsAt.After(time.Now()) {
		return badRequest("ends_at cannot be in the past")
	}
	canConnect := req.CanConnect == nil || *req.CanConnect
	if !canConnect && !req.CanViewRecordings && !req.CanUpload && !req.CanDownload {
		return badRequest("an access request must ask for at least one permission")
	}

	ctx, id := r.Context(), store.NewID()
	var createdReq db.ConfigAccessRequest
	err := s.tx(ctx, func(q *db.Queries) error {
		if err := checkPolicyRefs(ctx, q, policyRequest{
			SubjectType: "user",
			SubjectID:   p.User.ID,
			ObjectType:  req.ObjectType,
			ObjectRef:   req.ObjectRef,
		}); err != nil {
			return err
		}

		pendings, err := q.ListPendingAccessRequestsForUserAndObject(ctx, db.ListPendingAccessRequestsForUserAndObjectParams{
			UserID:     p.User.ID,
			ObjectType: req.ObjectType,
			ObjectRef:  req.ObjectRef,
		})
		if err != nil {
			return err
		}
		if len(pendings) > 0 {
			return conflict("you already have a pending access request for this target")
		}

		now := store.Now()
		if err := q.CreateAccessRequest(ctx, db.CreateAccessRequestParams{
			ID:                id,
			UserID:            p.User.ID,
			ObjectType:        req.ObjectType,
			ObjectRef:         req.ObjectRef,
			Ticket:            ticket,
			CanConnect:        canConnect,
			CanViewRecordings: req.CanViewRecordings,
			CanUpload:         req.CanUpload,
			CanDownload:       req.CanDownload,
			Reason:            reason,
			StartsAt:          req.StartsAt.UTC(),
			EndsAt:            req.EndsAt.UTC(),
			Now:               now,
		}); err != nil {
			return err
		}

		d := map[string]any{
			"object":              req.ObjectType + ":" + req.ObjectRef,
			"ticket":              ticket,
			"reason":              reason,
			"starts_at":           req.StartsAt.UTC().Format(time.RFC3339),
			"ends_at":             req.EndsAt.UTC().Format(time.RFC3339),
			"can_connect":         canConnect,
			"can_view_recordings": req.CanViewRecordings,
			"can_upload":          req.CanUpload,
			"can_download":        req.CanDownload,
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      p.actor(),
			Action:     "access_request.create",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		createdReq = db.ConfigAccessRequest{
			ID:                id,
			UserID:            p.User.ID,
			ObjectType:        req.ObjectType,
			ObjectRef:         req.ObjectRef,
			Ticket:            ticket,
			CanConnect:        canConnect,
			CanViewRecordings: req.CanViewRecordings,
			CanUpload:         req.CanUpload,
			CanDownload:       req.CanDownload,
			Reason:            reason,
			StartsAt:          req.StartsAt.UTC(),
			EndsAt:            req.EndsAt.UTC(),
			Status:            "pending",
			CreatedAt:         now,
		}
		return nil
	})
	if err != nil {
		return err
	}

	dto, err := s.toAccessRequestDTO(ctx, createdReq)
	if err != nil {
		return err
	}
	return created(w, dto)
}

// openapi:operation
// summary: Get an access request
// tags: [access-requests]
// responses:
//   '200': { description: The access request, schema: AccessRequest }

func (s *Server) getAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	req, err := s.Store.Q.GetAccessRequest(ctx, id)
	if err != nil {
		return fromStore(err, "access request")
	}
	if !admins[p.User.Role] && req.UserID != p.User.ID {
		return errForbidden
	}
	dto, err := s.toAccessRequestDTO(ctx, req)
	if err != nil {
		return err
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Approve an access request
// tags: [access-requests]
// requestBody: { schema: ReviewAccessRequest, required: false }
// responses:
//   '200': { description: Approved, schema: AccessRequest }
//   '409': Error

func (s *Server) approveAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	var body reviewAccessRequest
	_ = decode(r, &body) // Optional body

	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigAccessRequest
	err := s.tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return fromStore(err, "access request")
		}
		if req.Status != "pending" {
			return conflict("access request is not pending (status: %s)", req.Status)
		}
		if !req.EndsAt.After(time.Now()) {
			return badRequest("the requested end date is already in the past")
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

		policyID := store.NewID()
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
				StartsAt:          store.NullTime(req.StartsAt),
				ExpiresAt:         store.NullTime(req.EndsAt),
				Description:       desc,
				CreatedBy:         store.NullString(p.User.ID),
				Now:               now,
			}); err != nil {
				return err
			}
		}

		if err := q.ApproveAccessRequest(ctx, db.ApproveAccessRequestParams{
			ID:              id,
			ReviewedBy:      store.NullString(p.User.ID),
			ReviewedAt:      store.NullTime(now),
			ReviewComment:   body.Comment,
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
		if body.Comment != "" {
			d["comment"] = body.Comment
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      p.actor(),
			Action:     "access_request.approve",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		req.Status = "approved"
		req.ReviewedBy = store.NullString(p.User.ID)
		req.ReviewedAt = store.NullTime(now)
		req.ReviewComment = body.Comment
		req.CreatedPolicyID = store.NullString(policyID)
		out = req
		return nil
	})
	if err != nil {
		return err
	}

	dto, err := s.toAccessRequestDTO(ctx, out)
	if err != nil {
		return err
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Reject an access request
// tags: [access-requests]
// requestBody: { schema: ReviewAccessRequest, required: false }
// responses:
//   '200': { description: Rejected, schema: AccessRequest }
//   '409': Error

func (s *Server) rejectAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	var body reviewAccessRequest
	_ = decode(r, &body) // Optional body

	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigAccessRequest
	err := s.tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return fromStore(err, "access request")
		}
		if req.Status != "pending" {
			return conflict("access request is not pending (status: %s)", req.Status)
		}

		now := store.Now()
		if err := q.RejectAccessRequest(ctx, db.RejectAccessRequestParams{
			ID:            id,
			ReviewedBy:    store.NullString(p.User.ID),
			ReviewedAt:    store.NullTime(now),
			ReviewComment: body.Comment,
		}); err != nil {
			return err
		}

		d := map[string]any{
			"user_id": req.UserID,
			"object":  req.ObjectType + ":" + req.ObjectRef,
		}
		if body.Comment != "" {
			d["comment"] = body.Comment
		}
		if err := store.Audit(ctx, q, store.Event{
			Actor:      p.actor(),
			Action:     "access_request.reject",
			ObjectType: "access_request",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		req.Status = "rejected"
		req.ReviewedBy = store.NullString(p.User.ID)
		req.ReviewedAt = store.NullTime(now)
		req.ReviewComment = body.Comment
		out = req
		return nil
	})
	if err != nil {
		return err
	}

	dto, err := s.toAccessRequestDTO(ctx, out)
	if err != nil {
		return err
	}
	return ok(w, dto)
}

// openapi:operation
// summary: Cancel a pending access request
// tags: [access-requests]
// responses:
//   '200': { description: Canceled, schema: AccessRequest }
//   '409': Error

func (s *Server) cancelAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigAccessRequest
	err := s.tx(ctx, func(q *db.Queries) error {
		req, err := q.GetAccessRequest(ctx, id)
		if err != nil {
			return fromStore(err, "access request")
		}
		if !admins[p.User.Role] && req.UserID != p.User.ID {
			return errForbidden
		}
		if req.Status != "pending" {
			return conflict("access request is not pending (status: %s)", req.Status)
		}

		if err := q.CancelAccessRequest(ctx, id); err != nil {
			return err
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      p.actor(),
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
		return err
	}

	dto, err := s.toAccessRequestDTO(ctx, out)
	if err != nil {
		return err
	}
	return ok(w, dto)
}
