-- name: CreateAccessRequest :exec
INSERT INTO config_access_requests (
    id, user_id, object_type, object_ref, ticket,
    can_connect, can_view_recordings, can_upload, can_download,
    reason, starts_at, ends_at, status, created_at
) VALUES (
    @id, @user_id, @object_type, @object_ref, @ticket,
    @can_connect, @can_view_recordings, @can_upload, @can_download,
    @reason, @starts_at, @ends_at, 'pending', @now
);

-- name: GetAccessRequest :one
SELECT * FROM config_access_requests WHERE id = @id;

-- name: ListAccessRequests :many
SELECT * FROM config_access_requests
WHERE (CAST(@user_id AS TEXT) = '' OR user_id = @user_id)
  AND (CAST(@status AS TEXT) = '' OR status = @status)
ORDER BY created_at DESC;

-- name: ListPendingAccessRequestsForUserAndObject :many
SELECT * FROM config_access_requests
WHERE user_id = @user_id
  AND object_type = @object_type
  AND object_ref = @object_ref
  AND status = 'pending';

-- name: ApproveAccessRequest :exec
UPDATE config_access_requests
SET status = 'approved',
    reviewed_by = @reviewed_by,
    reviewed_at = @reviewed_at,
    review_comment = @review_comment,
    created_policy_id = @created_policy_id
WHERE id = @id AND status = 'pending';

-- name: RejectAccessRequest :exec
UPDATE config_access_requests
SET status = 'rejected',
    reviewed_by = @reviewed_by,
    reviewed_at = @reviewed_at,
    review_comment = @review_comment
WHERE id = @id AND status = 'pending';

-- name: CancelAccessRequest :exec
UPDATE config_access_requests
SET status = 'canceled'
WHERE id = @id AND status = 'pending';

-- name: CountPendingAccessRequests :one
SELECT count(*) FROM config_access_requests WHERE status = 'pending';
