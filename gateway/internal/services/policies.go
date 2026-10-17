package services

import (
	"context"
	"errors"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/store"
	"github.com/leandrofus/duckjump/gateway/internal/store/db"
)

var (
	ErrExpiresAndTTLBothSet = errors.New("use expires_at or ttl_seconds, not both")
	ErrExpiresInPast        = errors.New("expires_at is in the past")
	ErrTTLNegative          = errors.New("ttl_seconds must be positive")
	ErrPolicyNoPermissions  = errors.New("a policy must grant at least one permission")
	ErrPolicyAlreadyExists  = errors.New("this access already exists; edit it instead")
	ErrInvalidSubjectType   = errors.New("subject_type must be user or group")
	ErrInvalidObjectType    = errors.New("object_type must be connection, folder or tag")
	ErrPolicyNotFound       = errors.New("policy not found")
)

type CreatePolicyParams struct {
	SubjectType       string
	SubjectID         string
	ObjectType        string
	ObjectRef         string
	CanConnect        *bool
	CanViewRecordings bool
	CanUpload         bool
	CanDownload       bool
	CanForward        bool
	StartsAt          *time.Time
	ExpiresAt         *time.Time
	TTLSeconds        int64
	Description       string
	CreatedBy         string
	Actor             store.Actor
}

type UpdatePolicyParams struct {
	ID                string
	CanConnect        *bool
	CanViewRecordings *bool
	CanUpload         *bool
	CanDownload       *bool
	CanForward        *bool
	StartsAt          *time.Time
	StartsAtSet       bool
	ExpiresAt         *time.Time
	ExpiresAtSet      bool
	Description       *string
	Actor             store.Actor
}

type PolicyService struct {
	store *store.Store
}

func NewPolicyService(st *store.Store) *PolicyService {
	return &PolicyService{store: st}
}

func (s *PolicyService) List(ctx context.Context, subjectID, objectRef string) ([]db.ConfigPolicy, error) {
	return s.store.Q.ListPolicies(ctx, db.ListPoliciesParams{
		SubjectID: subjectID,
		ObjectRef: objectRef,
	})
}

func (s *PolicyService) Get(ctx context.Context, id string) (db.ConfigPolicy, error) {
	p, err := s.store.Q.GetPolicy(ctx, id)
	if err != nil {
		return db.ConfigPolicy{}, store.Classify(err)
	}
	return p, nil
}

func (s *PolicyService) CheckRefs(ctx context.Context, subjectType, subjectID, objectType, objectRef string) error {
	switch subjectType {
	case "user":
		if _, err := s.store.Q.GetUser(ctx, subjectID); err != nil {
			return store.Classify(err)
		}
	case "group":
		if _, err := s.store.Q.GetGroup(ctx, subjectID); err != nil {
			return store.Classify(err)
		}
	default:
		return ErrInvalidSubjectType
	}

	switch objectType {
	case "connection":
		if _, err := s.store.Q.GetConnection(ctx, objectRef); err != nil {
			return store.Classify(err)
		}
	case "folder":
		if _, err := s.store.Q.GetFolder(ctx, objectRef); err != nil {
			return store.Classify(err)
		}
	case "tag":
		if _, err := cleanTags([]string{objectRef}); err != nil {
			return err
		}
	default:
		return ErrInvalidObjectType
	}
	return nil
}

func (s *PolicyService) Create(ctx context.Context, params CreatePolicyParams) (db.ConfigPolicy, error) {
	if params.ObjectType == "tag" {
		tags, err := cleanTags([]string{params.ObjectRef})
		if err != nil {
			return db.ConfigPolicy{}, err
		}
		params.ObjectRef = tags[0]
	}

	var exp time.Time
	switch {
	case params.ExpiresAt != nil && params.TTLSeconds != 0:
		return db.ConfigPolicy{}, ErrExpiresAndTTLBothSet
	case params.ExpiresAt != nil:
		exp = *params.ExpiresAt
		if !exp.After(time.Now()) {
			return db.ConfigPolicy{}, ErrExpiresInPast
		}
	case params.TTLSeconds < 0:
		return db.ConfigPolicy{}, ErrTTLNegative
	case params.TTLSeconds > 0:
		exp = store.Now().Add(time.Duration(params.TTLSeconds) * time.Second)
	}

	canConnect := params.CanConnect == nil || *params.CanConnect
	if !canConnect && !params.CanViewRecordings && !params.CanUpload && !params.CanDownload && !params.CanForward {
		return db.ConfigPolicy{}, ErrPolicyNoPermissions
	}

	id := store.NewID()
	var created db.ConfigPolicy

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		if err := s.CheckRefs(ctx, params.SubjectType, params.SubjectID, params.ObjectType, params.ObjectRef); err != nil {
			return err
		}

		existing, err := q.ListPolicies(ctx, db.ListPoliciesParams{
			SubjectID: params.SubjectID,
			ObjectRef: params.ObjectRef,
		})
		if err != nil {
			return err
		}
		for _, e := range existing {
			if e.SubjectType == params.SubjectType && e.ObjectType == params.ObjectType {
				return ErrPolicyAlreadyExists
			}
		}

		var start time.Time
		if params.StartsAt != nil {
			start = *params.StartsAt
		}

		if err := q.CreatePolicy(ctx, db.CreatePolicyParams{
			ID:                id,
			SubjectType:       params.SubjectType,
			SubjectID:         params.SubjectID,
			ObjectType:        params.ObjectType,
			ObjectRef:         params.ObjectRef,
			CanConnect:        canConnect,
			CanViewRecordings: params.CanViewRecordings,
			CanUpload:         params.CanUpload,
			CanDownload:       params.CanDownload,
			CanForward:        params.CanForward,
			StartsAt:          store.NullTime(start),
			ExpiresAt:         store.NullTime(exp),
			Description:       params.Description,
			CreatedBy:         store.NullString(params.CreatedBy),
			Now:               store.Now(),
		}); err != nil {
			return err
		}

		d := map[string]any{
			"subject":             params.SubjectType + ":" + params.SubjectID,
			"object":              params.ObjectType + ":" + params.ObjectRef,
			"can_connect":         canConnect,
			"can_view_recordings": params.CanViewRecordings,
			"can_upload":          params.CanUpload,
			"can_download":        params.CanDownload,
			"can_forward":         params.CanForward,
		}
		if !exp.IsZero() {
			d["expires_at"] = exp.UTC().Format(time.RFC3339)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "policy.create",
			ObjectType: "policy",
			ObjectID:   id,
			Details:    d,
		}); err != nil {
			return err
		}

		row, err := q.GetPolicy(ctx, id)
		if err != nil {
			return err
		}
		created = row
		return nil
	})

	return created, err
}

func (s *PolicyService) Update(ctx context.Context, params UpdatePolicyParams) (db.ConfigPolicy, error) {
	var updated db.ConfigPolicy

	err := s.store.Tx(ctx, func(q *db.Queries) error {
		pol, err := q.GetPolicy(ctx, params.ID)
		if err != nil {
			return store.Classify(err)
		}

		if params.CanConnect != nil {
			pol.CanConnect = *params.CanConnect
		}
		if params.CanViewRecordings != nil {
			pol.CanViewRecordings = *params.CanViewRecordings
		}
		if params.CanUpload != nil {
			pol.CanUpload = *params.CanUpload
		}
		if params.CanDownload != nil {
			pol.CanDownload = *params.CanDownload
		}
		if params.CanForward != nil {
			pol.CanForward = *params.CanForward
		}
		if params.StartsAtSet {
			if params.StartsAt != nil {
				pol.StartsAt = store.NullTime(*params.StartsAt)
			} else {
				pol.StartsAt = store.NullTime(time.Time{})
			}
		}
		if params.ExpiresAtSet {
			if params.ExpiresAt != nil {
				pol.ExpiresAt = store.NullTime(*params.ExpiresAt)
			} else {
				pol.ExpiresAt = store.NullTime(time.Time{})
			}
		}
		if params.Description != nil {
			pol.Description = *params.Description
		}

		if !pol.CanConnect && !pol.CanViewRecordings && !pol.CanUpload && !pol.CanDownload && !pol.CanForward {
			return ErrPolicyNoPermissions
		}

		if err := q.UpdatePolicy(ctx, db.UpdatePolicyParams{
			ID:                params.ID,
			CanConnect:        pol.CanConnect,
			CanViewRecordings: pol.CanViewRecordings,
			CanUpload:         pol.CanUpload,
			CanDownload:       pol.CanDownload,
			CanForward:        pol.CanForward,
			StartsAt:          pol.StartsAt,
			ExpiresAt:         pol.ExpiresAt,
			Description:       pol.Description,
		}); err != nil {
			return err
		}

		d := map[string]any{
			"can_connect":         pol.CanConnect,
			"can_view_recordings": pol.CanViewRecordings,
			"can_upload":          pol.CanUpload,
			"can_download":        pol.CanDownload,
			"can_forward":         pol.CanForward,
		}
		if pol.ExpiresAt.Valid {
			d["expires_at"] = pol.ExpiresAt.Time.UTC().Format(time.RFC3339)
		}

		if err := store.Audit(ctx, q, store.Event{
			Actor:      params.Actor,
			Action:     "policy.update",
			ObjectType: "policy",
			ObjectID:   params.ID,
			Details:    d,
		}); err != nil {
			return err
		}

		updated = pol
		return nil
	})

	return updated, err
}

func (s *PolicyService) Delete(ctx context.Context, actor store.Actor, id string) error {
	return s.store.Tx(ctx, func(q *db.Queries) error {
		pol, err := q.GetPolicy(ctx, id)
		if err != nil {
			return store.Classify(err)
		}
		if _, err := q.DeletePolicy(ctx, id); err != nil {
			return err
		}
		return store.Audit(ctx, q, store.Event{
			Actor:      actor,
			Action:     "policy.delete",
			ObjectType: "policy",
			ObjectID:   id,
			Details: map[string]any{
				"subject": pol.SubjectType + ":" + pol.SubjectID,
				"object":  pol.ObjectType + ":" + pol.ObjectRef,
			},
		})
	})
}
