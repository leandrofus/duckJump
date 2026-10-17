package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/leandrofus/duckjump/gateway/internal/services"
	"github.com/leandrofus/duckjump/gateway/internal/store"
)

func limitParam(r *http.Request) (int64, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 100, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 || n > 500 {
		return 0, badRequest("limit must be 1-500")
	}
	return n, nil
}

// openapi:operation
// summary: Audit log
// description: Newest first. Page with before_id = the last id received.
// tags: [audit]
// parameters:
//   - { name: before_id, in: query, schema: { type: integer } }
//   - { name: actor_id, in: query, schema: { type: string } }
//   - { name: action, in: query, schema: { type: string }, example: auth.login_failed }
//   - { name: object_id, in: query, schema: { type: string } }
//   - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 500, default: 100 } }
// responses:
//   '200': { description: Events, schema: '[]AuditEvent' }

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request, p principal) error {
	q := r.URL.Query()
	lim, err := limitParam(r)
	if err != nil {
		return err
	}
	var before int64
	if v := q.Get("before_id"); v != "" {
		if before, err = strconv.ParseInt(v, 10, 64); err != nil {
			return badRequest("before_id must be an integer")
		}
	}
	rows, err := s.Audit.ListEvents(r.Context(), services.ListAuditEventsParams{
		BeforeID: before,
		ActorID:  q.Get("actor_id"),
		Action:   q.Get("action"),
		ObjectID: q.Get("object_id"),
		Limit:    lim,
	})
	if err != nil {
		return fromService(err, "audit")
	}
	out := make([]auditEventDTO, 0, len(rows))
	for _, e := range rows {
		out = append(out, toAuditEvent(e))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Verify the audit hash chain
// description: Recomputes every event hash. ok=false points at the first event that was altered or removed.
// tags: [audit]
// responses:
//   '200': { description: Verification result, schema: AuditVerification }

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request, p principal) error {
	return handleOK(w, func() (store.VerifyResult, error) {
		res, err := s.Audit.Verify(r.Context())
		if err != nil {
			return store.VerifyResult{}, fromService(err, "audit")
		}
		return res, nil
	})
}

// openapi:operation
// summary: Session history
// description: Newest first. Page with before = started_at of the last session received.
// tags: [audit]
// parameters:
//   - { name: user_id, in: query, schema: { type: string } }
//   - { name: connection_id, in: query, schema: { type: string } }
//   - { name: active, in: query, schema: { type: boolean }, description: Only sessions still open. }
//   - { name: before, in: query, schema: { type: string, format: date-time } }
//   - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 500, default: 100 } }
// responses:
//   '200': { description: Sessions, schema: '[]Session' }

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, p principal) error {
	q := r.URL.Query()
	lim, err := limitParam(r)
	if err != nil {
		return err
	}
	var before *time.Time
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return badRequest("before must be RFC 3339")
		}
		before = &t
	}
	ctx := r.Context()
	rows, err := s.Sessions.List(ctx, services.ListSessionsParams{
		UserID:       q.Get("user_id"),
		ConnectionID: q.Get("connection_id"),
		ActiveOnly:   q.Get("active") == "true",
		Before:       before,
		Limit:        lim,
	})
	if err != nil {
		return fromService(err, "session")
	}
	days, err := s.RetentionDays(ctx)
	if err != nil {
		return err
	}
	out := make([]sessionDTO, 0, len(rows))
	for _, x := range rows {
		var pt time.Time
		if x.Recording.Valid {
			if p, err := s.Sessions.GetPurge(ctx, x.ID); err == nil {
				pt = p.PurgedAt
			}
		}
		out = append(out, toSession(x, pt, days))
	}
	return ok(w, out)
}

// openapi:operation
// summary: Get a session
// tags: [audit]
// responses:
//   '200': { description: The session, schema: Session }

func (s *Server) getSessionRecord(w http.ResponseWriter, r *http.Request, p principal) error {
	ctx := r.Context()
	x, err := s.Sessions.Get(ctx, r.PathValue("id"))
	if err != nil {
		return fromService(err, "session")
	}
	days, err := s.RetentionDays(ctx)
	if err != nil {
		return err
	}
	var pt time.Time
	if p, err := s.Sessions.GetPurge(ctx, x.ID); err == nil {
		pt = p.PurgedAt
	}
	d := toSession(x, pt, days)
	if d.HasRecording {
		if size, err := s.recordingSize(ctx, x.Recording.String); err == nil {
			d.Bytes = &size
		}
	}
	return ok(w, d)
}
