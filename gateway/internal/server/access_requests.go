package server

import (
	"context"
	"net/http"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/services"
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
//   can_forward: { type: boolean, default: false }
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
	CanForward        bool      `json:"can_forward"`
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

func toAccessRequestDTO(e services.EnrichedAccessRequest) accessRequestDTO {
	r := e.Request
	return accessRequestDTO{
		ID:                r.ID,
		UserID:            r.UserID,
		UserUsername:      e.UserUsername,
		UserDisplayName:   e.UserDisplayName,
		ObjectType:        r.ObjectType,
		ObjectRef:         r.ObjectRef,
		ObjectName:        e.ObjectName,
		Ticket:            r.Ticket,
		CanConnect:        r.CanConnect,
		CanViewRecordings: r.CanViewRecordings,
		CanUpload:         r.CanUpload,
		CanDownload:       r.CanDownload,
		CanForward:        r.CanForward,
		Reason:            r.Reason,
		StartsAt:          r.StartsAt.UTC(),
		EndsAt:            r.EndsAt.UTC(),
		Status:            r.Status,
		ReviewedBy:        strPtr(r.ReviewedBy),
		ReviewerUsername:  e.ReviewerUsername,
		ReviewedAt:        timePtr(r.ReviewedAt),
		ReviewComment:     r.ReviewComment,
		CreatedPolicyID:   strPtr(r.CreatedPolicyID),
		CreatedAt:         r.CreatedAt.UTC(),
	}
}

func (s *Server) toEnrichedAccessRequestDTO(ctx context.Context, r db.ConfigAccessRequest) (accessRequestDTO, error) {
	enriched, err := s.AccessRequests.Enrich(ctx, []db.ConfigAccessRequest{r})
	if err != nil {
		return accessRequestDTO{}, err
	}
	return toAccessRequestDTO(enriched[0]), nil
}

func toAccessRequestTargetsDTO(t services.AccessRequestTargets) accessRequestTargetsDTO {
	conns := make([]accessRequestConnectionTarget, 0, len(t.Connections))
	for _, c := range t.Connections {
		conns = append(conns, accessRequestConnectionTarget{
			ID:          c.ID,
			Name:        c.Name,
			Protocol:    c.Protocol,
			Environment: c.Environment,
			FolderID:    c.FolderID,
			Tags:        c.Tags,
		})
	}
	folders := make([]accessRequestFolderTarget, 0, len(t.Folders))
	for _, f := range t.Folders {
		folders = append(folders, accessRequestFolderTarget{
			ID:       f.ID,
			ParentID: f.ParentID,
			Name:     f.Name,
		})
	}
	return accessRequestTargetsDTO{
		Connections: conns,
		Folders:     folders,
		Tags:        t.Tags,
	}
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

	rows, err := s.AccessRequests.ListEnriched(ctx, filterUser, qStatus)
	if err != nil {
		return fromService(err, "access request")
	}

	out := make([]accessRequestDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAccessRequestDTO(r))
	}
	return ok(w, out)
}

// openapi:operation
// summary: List available targets for access requests
// tags: [access-requests]
// responses:
//   '200': { description: 'Available connections, folders and tags', schema: AccessRequestTargets }

func (s *Server) accessRequestTargets(w http.ResponseWriter, r *http.Request, p principal) error {
	t, err := s.AccessRequests.Targets(r.Context())
	if err != nil {
		return fromService(err, "targets")
	}
	return ok(w, toAccessRequestTargetsDTO(t))
}

// openapi:operation
// summary: Create an access request
// tags: [access-requests]
// requestBody: { schema: CreateAccessRequest }
// responses:
//   '201': { description: Created, schema: AccessRequest }
//   '409': Error

func (s *Server) createAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req createAccessRequest) (accessRequestDTO, error) {
		canConnect := req.CanConnect == nil || *req.CanConnect
		createdReq, err := s.AccessRequests.Create(r.Context(), services.CreateAccessRequestParams{
			UserID:            p.User.ID,
			ObjectType:        req.ObjectType,
			ObjectRef:         req.ObjectRef,
			Ticket:            req.Ticket,
			CanConnect:        canConnect,
			CanViewRecordings: req.CanViewRecordings,
			CanUpload:         req.CanUpload,
			CanDownload:       req.CanDownload,
			CanForward:        req.CanForward,
			Reason:            req.Reason,
			StartsAt:          req.StartsAt,
			EndsAt:            req.EndsAt,
			Actor:             p.actor(),
		})
		if err != nil {
			return accessRequestDTO{}, fromService(err, req.ObjectType)
		}
		return s.toEnrichedAccessRequestDTO(r.Context(), createdReq)
	})
}

// openapi:operation
// summary: Get an access request
// tags: [access-requests]
// responses:
//   '200': { description: The access request, schema: AccessRequest }

func (s *Server) getAccessRequest(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (accessRequestDTO, error) {
		req, err := s.AccessRequests.GetEnriched(r.Context(), r.PathValue("id"))
		if err != nil {
			return accessRequestDTO{}, fromService(err, "access request")
		}
		if !admins[p.User.Role] && req.Request.UserID != p.User.ID {
			return accessRequestDTO{}, errForbidden
		}
		return toAccessRequestDTO(req), nil
	})
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

	out, _, err := s.AccessRequests.Approve(r.Context(), p.actor(), r.PathValue("id"), p.User.ID, body.Comment)
	if err != nil {
		return fromService(err, "access request")
	}
	dto, err := s.toEnrichedAccessRequestDTO(r.Context(), out)
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

	out, err := s.AccessRequests.Reject(r.Context(), p.actor(), r.PathValue("id"), p.User.ID, body.Comment)
	if err != nil {
		return fromService(err, "access request")
	}
	dto, err := s.toEnrichedAccessRequestDTO(r.Context(), out)
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
	out, err := s.AccessRequests.Cancel(r.Context(), p.actor(), r.PathValue("id"), p.User.ID, admins[p.User.Role])
	if err != nil {
		return fromService(err, "access request")
	}
	dto, err := s.toEnrichedAccessRequestDTO(r.Context(), out)
	if err != nil {
		return err
	}
	return ok(w, dto)
}
