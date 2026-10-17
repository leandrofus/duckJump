package server

import (
	"net/http"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/services"
)

// openapi:schema PolicyRequest
// type: object
// required: [subject_type, subject_id, object_type, object_ref]
// additionalProperties: false
// properties:
//   subject_type: { type: string, enum: [user, group] }
//   subject_id: { type: string, format: uuid }
//   object_type: { type: string, enum: [connection, folder, tag], description: 'folder grants the whole subtree; tag grants every connection carrying it.' }
//   object_ref: { type: string, description: 'Connection or folder id, or the tag name.' }
//   can_connect: { type: boolean, default: true }
//   can_view_recordings: { type: boolean, default: false }
//   can_upload: { type: boolean, default: false, description: Send files from the user's file tray to the host. }
//   can_download: { type: boolean, default: false, description: Take files from the host into the user's file tray (and on to their computer). }
//   can_forward: { type: boolean, default: false, description: Allow TCP port forwarding to the host. }
//   starts_at: { type: [string, 'null'], format: date-time, description: Start of access window. }
//   expires_at: { type: [string, 'null'], format: date-time, description: Just-in-time access. Mutually exclusive with ttl_seconds. }
//   ttl_seconds: { type: integer, minimum: 1, description: Expire this many seconds from now. }
//   description: { type: string }

type policyRequest struct {
	SubjectType       string     `json:"subject_type"`
	SubjectID         string     `json:"subject_id"`
	ObjectType        string     `json:"object_type"`
	ObjectRef         string     `json:"object_ref"`
	CanConnect        *bool      `json:"can_connect"`
	CanViewRecordings bool       `json:"can_view_recordings"`
	CanUpload         bool       `json:"can_upload"`
	CanDownload       bool       `json:"can_download"`
	CanForward        bool       `json:"can_forward"`
	StartsAt          *time.Time `json:"starts_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	TTLSeconds        int64      `json:"ttl_seconds"`
	Description       string     `json:"description"`
}

// openapi:schema UpdatePolicyRequest
// type: object
// additionalProperties: false
// properties:
//   can_connect: { type: boolean }
//   can_view_recordings: { type: boolean }
//   can_upload: { type: boolean }
//   can_download: { type: boolean }
//   can_forward: { type: boolean }
//   starts_at: { type: [string, 'null'], format: date-time }
//   expires_at: { type: [string, 'null'], format: date-time, description: null makes it permanent. }
//   description: { type: string }

type updatePolicyRequest struct {
	CanConnect        opt[bool]      `json:"can_connect"`
	CanViewRecordings opt[bool]      `json:"can_view_recordings"`
	CanUpload         opt[bool]      `json:"can_upload"`
	CanDownload       opt[bool]      `json:"can_download"`
	CanForward        opt[bool]      `json:"can_forward"`
	StartsAt          opt[time.Time] `json:"starts_at"`
	ExpiresAt         opt[time.Time] `json:"expires_at"`
	Description       opt[string]    `json:"description"`
}

// openapi:operation
// summary: List policies
// tags: [policies]
// parameters:
//   - { name: subject_id, in: query, schema: { type: string }, description: Only policies for this user or group. }
//   - { name: object_ref, in: query, schema: { type: string }, description: 'Only policies on this connection, folder or tag.' }
// responses:
//   '200': { description: 'Policies, including expired ones', schema: '[]Policy' }

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() ([]policyDTO, error) {
		ps, err := s.Policies.List(r.Context(), r.URL.Query().Get("subject_id"), r.URL.Query().Get("object_ref"))
		if err != nil {
			return nil, fromService(err, "policy")
		}
		out := make([]policyDTO, 0, len(ps))
		for _, x := range ps {
			out = append(out, toPolicy(x))
		}
		return out, nil
	})
}

// openapi:operation
// summary: Grant access
// tags: [policies]
// requestBody: { schema: PolicyRequest }
// responses:
//   '201': { description: Created, schema: Policy }
//   '409': Error

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCreated(w, r, func(req policyRequest) (policyDTO, error) {
		pol, err := s.Policies.Create(r.Context(), services.CreatePolicyParams{
			SubjectType:       req.SubjectType,
			SubjectID:         req.SubjectID,
			ObjectType:        req.ObjectType,
			ObjectRef:         req.ObjectRef,
			CanConnect:        req.CanConnect,
			CanViewRecordings: req.CanViewRecordings,
			CanUpload:         req.CanUpload,
			CanDownload:       req.CanDownload,
			CanForward:        req.CanForward,
			StartsAt:          req.StartsAt,
			ExpiresAt:         req.ExpiresAt,
			TTLSeconds:        req.TTLSeconds,
			Description:       req.Description,
			CreatedBy:         p.User.ID,
			Actor:             p.actor(),
		})
		if err != nil {
			return policyDTO{}, fromService(err, "policy")
		}
		return toPolicy(pol), nil
	})
}

// openapi:operation
// summary: Get a policy
// tags: [policies]
// responses:
//   '200': { description: The policy, schema: Policy }

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (policyDTO, error) {
		pol, err := s.Policies.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			return policyDTO{}, fromService(err, "policy")
		}
		return toPolicy(pol), nil
	})
}

// openapi:operation
// summary: Update a policy
// description: Subject and object are fixed; delete and recreate to change them.
// tags: [policies]
// requestBody: { schema: UpdatePolicyRequest }
// responses:
//   '200': { description: Updated, schema: Policy }

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleAction(w, r, func(req updatePolicyRequest) (policyDTO, error) {
		var start *time.Time
		if req.StartsAt.Set && !req.StartsAt.Null {
			start = &req.StartsAt.V
		}
		var exp *time.Time
		if req.ExpiresAt.Set && !req.ExpiresAt.Null {
			exp = &req.ExpiresAt.V
		}

		pol, err := s.Policies.Update(r.Context(), services.UpdatePolicyParams{
			ID:                r.PathValue("id"),
			CanConnect:        req.CanConnect.Ptr(),
			CanViewRecordings: req.CanViewRecordings.Ptr(),
			CanUpload:         req.CanUpload.Ptr(),
			CanDownload:       req.CanDownload.Ptr(),
			CanForward:        req.CanForward.Ptr(),
			StartsAt:          start,
			StartsAtSet:       req.StartsAt.Set,
			ExpiresAt:         exp,
			ExpiresAtSet:      req.ExpiresAt.Set,
			Description:       req.Description.Ptr(),
			Actor:             p.actor(),
		})
		if err != nil {
			return policyDTO{}, fromService(err, "policy")
		}
		return toPolicy(pol), nil
	})
}

// openapi:operation
// summary: Revoke a policy
// description: Sessions already open are not cut.
// tags: [policies]
// responses:
//   '204': { description: Deleted }

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleCommand(w, func() error {
		err := s.Policies.Delete(r.Context(), p.actor(), r.PathValue("id"))
		return fromService(err, "policy")
	})
}
