package server

import (
	"context"
	"net/http"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
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
//   expires_at: { type: [string, 'null'], format: date-time, description: null makes it permanent. }
//   description: { type: string }

type updatePolicyRequest struct {
	CanConnect        opt[bool]      `json:"can_connect"`
	CanViewRecordings opt[bool]      `json:"can_view_recordings"`
	CanUpload         opt[bool]      `json:"can_upload"`
	CanDownload       opt[bool]      `json:"can_download"`
	ExpiresAt         opt[time.Time] `json:"expires_at"`
	Description       opt[string]    `json:"description"`
}

func checkPolicyRefs(ctx context.Context, q *db.Queries, req policyRequest) error {
	switch req.SubjectType {
	case "user":
		if _, err := q.GetUser(ctx, req.SubjectID); err != nil {
			return fromStore(err, "user")
		}
	case "group":
		if _, err := q.GetGroup(ctx, req.SubjectID); err != nil {
			return fromStore(err, "group")
		}
	default:
		return badRequest("subject_type must be user or group")
	}
	switch req.ObjectType {
	case "connection":
		if _, err := q.GetConnection(ctx, req.ObjectRef); err != nil {
			return fromStore(err, "connection")
		}
	case "folder":
		if _, err := q.GetFolder(ctx, req.ObjectRef); err != nil {
			return fromStore(err, "folder")
		}
	case "tag":
		if _, err := validTags([]string{req.ObjectRef}); err != nil {
			return err
		}
	default:
		return badRequest("object_type must be connection, folder or tag")
	}
	return nil
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
	ps, err := s.Store.Q.ListPolicies(r.Context(), db.ListPoliciesParams{
		SubjectID: r.URL.Query().Get("subject_id"), ObjectRef: r.URL.Query().Get("object_ref"),
	})
	if err != nil {
		return err
	}
	out := make([]policyDTO, 0, len(ps))
	for _, x := range ps {
		out = append(out, toPolicy(x))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Grant access
// tags: [policies]
// requestBody: { schema: PolicyRequest }
// responses:
//   '201': { description: Created, schema: Policy }
//   '409': Error

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	var req policyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.ObjectType == "tag" {
		if tags, err := validTags([]string{req.ObjectRef}); err == nil {
			req.ObjectRef = tags[0]
		}
	}
	var exp time.Time
	switch {
	case req.ExpiresAt != nil && req.TTLSeconds != 0:
		return badRequest("use expires_at or ttl_seconds, not both")
	case req.ExpiresAt != nil:
		exp = *req.ExpiresAt
		if !exp.After(time.Now()) {
			return badRequest("expires_at is in the past")
		}
	case req.TTLSeconds < 0:
		return badRequest("ttl_seconds must be positive")
	case req.TTLSeconds > 0:
		exp = store.Now().Add(time.Duration(req.TTLSeconds) * time.Second)
	}
	canConnect := req.CanConnect == nil || *req.CanConnect
	if !canConnect && !req.CanViewRecordings && !req.CanUpload && !req.CanDownload {
		return badRequest("a policy must grant at least one permission")
	}
	ctx, id := r.Context(), store.NewID()
	err := s.tx(ctx, func(q *db.Queries) error {
		if err := checkPolicyRefs(ctx, q, req); err != nil {
			return err
		}
		existing, err := q.ListPolicies(ctx, db.ListPoliciesParams{SubjectID: req.SubjectID, ObjectRef: req.ObjectRef})
		if err != nil {
			return err
		}
		for _, e := range existing {
			if e.SubjectType == req.SubjectType && e.ObjectType == req.ObjectType {
				return conflict("this access already exists; edit it instead")
			}
		}
		if err := q.CreatePolicy(ctx, db.CreatePolicyParams{
			ID: id, SubjectType: req.SubjectType, SubjectID: req.SubjectID, ObjectType: req.ObjectType, ObjectRef: req.ObjectRef,
			CanConnect: canConnect, CanViewRecordings: req.CanViewRecordings, CanUpload: req.CanUpload, CanDownload: req.CanDownload,
			ExpiresAt:   store.NullTime(exp),
			Description: req.Description, CreatedBy: store.NullString(p.User.ID), Now: store.Now(),
		}); err != nil {
			return err
		}
		d := map[string]any{"subject": req.SubjectType + ":" + req.SubjectID, "object": req.ObjectType + ":" + req.ObjectRef,
			"can_connect": canConnect, "can_view_recordings": req.CanViewRecordings, "can_upload": req.CanUpload, "can_download": req.CanDownload}
		if !exp.IsZero() {
			d["expires_at"] = exp.UTC().Format(time.RFC3339)
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "policy.create", ObjectType: "policy", ObjectID: id, Details: d})
	})
	if err != nil {
		return err
	}
	pol, err := s.Store.Q.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	return created(w, toPolicy(pol))
}

// openapi:operation
// summary: Get a policy
// tags: [policies]
// responses:
//   '200': { description: The policy, schema: Policy }

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	pol, err := s.Store.Q.GetPolicy(r.Context(), r.PathValue("id"))
	if err != nil {
		return fromStore(err, "policy")
	}
	return ok(w, toPolicy(pol))
}

// openapi:operation
// summary: Update a policy
// description: Subject and object are fixed; delete and recreate to change them.
// tags: [policies]
// requestBody: { schema: UpdatePolicyRequest }
// responses:
//   '200': { description: Updated, schema: Policy }

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	var req updatePolicyRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ctx, id := r.Context(), r.PathValue("id")
	var out db.ConfigPolicy
	err := s.tx(ctx, func(q *db.Queries) error {
		pol, err := q.GetPolicy(ctx, id)
		if err != nil {
			return fromStore(err, "policy")
		}
		if req.CanConnect.Set {
			pol.CanConnect = req.CanConnect.V
		}
		if req.CanViewRecordings.Set {
			pol.CanViewRecordings = req.CanViewRecordings.V
		}
		if req.CanUpload.Set {
			pol.CanUpload = req.CanUpload.V
		}
		if req.CanDownload.Set {
			pol.CanDownload = req.CanDownload.V
		}
		if req.ExpiresAt.Set {
			pol.ExpiresAt = store.NullTime(req.ExpiresAt.V) // zero (null) = permanent
		}
		if req.Description.Set {
			pol.Description = req.Description.V
		}
		if !pol.CanConnect && !pol.CanViewRecordings && !pol.CanUpload && !pol.CanDownload {
			return badRequest("a policy must grant at least one permission")
		}
		if err := q.UpdatePolicy(ctx, db.UpdatePolicyParams{ID: id, CanConnect: pol.CanConnect, CanViewRecordings: pol.CanViewRecordings,
			CanUpload: pol.CanUpload, CanDownload: pol.CanDownload, ExpiresAt: pol.ExpiresAt, Description: pol.Description}); err != nil {
			return err
		}
		d := map[string]any{"can_connect": pol.CanConnect, "can_view_recordings": pol.CanViewRecordings,
			"can_upload": pol.CanUpload, "can_download": pol.CanDownload}
		if pol.ExpiresAt.Valid {
			d["expires_at"] = pol.ExpiresAt.Time.UTC().Format(time.RFC3339)
		}
		if err := store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "policy.update", ObjectType: "policy", ObjectID: id, Details: d}); err != nil {
			return err
		}
		out = pol
		return nil
	})
	if err != nil {
		return err
	}
	return ok(w, toPolicy(out))
}

// openapi:operation
// summary: Revoke a policy
// description: Sessions already open are not cut.
// tags: [policies]
// responses:
//   '204': { description: Deleted }

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx, id := r.Context(), r.PathValue("id")
	err := s.tx(ctx, func(q *db.Queries) error {
		pol, err := q.GetPolicy(ctx, id)
		if err != nil {
			return fromStore(err, "policy")
		}
		if _, err := q.DeletePolicy(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{Actor: p.actor(), Action: "policy.delete", ObjectType: "policy", ObjectID: id,
			Details: map[string]any{"subject": pol.SubjectType + ":" + pol.SubjectID, "object": pol.ObjectType + ":" + pol.ObjectRef}})
	})
	if err != nil {
		return err
	}
	return noContent(w)
}
