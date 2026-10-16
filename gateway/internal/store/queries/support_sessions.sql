-- name: CreateSupportSession :exec
INSERT INTO config_support_sessions (
    id, token, created_by, target_name, reason, ticket,
    totp_secret, status, expires_at, created_at
) VALUES (
    @id, @token, @created_by, @target_name, @reason, @ticket,
    @totp_secret, 'pending', @expires_at, @now
);

-- name: GetSupportSession :one
SELECT * FROM config_support_sessions WHERE id = @id;

-- name: GetSupportSessionByToken :one
SELECT * FROM config_support_sessions WHERE token = @token;

-- name: ListSupportSessions :many
SELECT * FROM config_support_sessions
WHERE (CAST(@created_by AS TEXT) = '' OR created_by = @created_by)
  AND (CAST(@status AS TEXT) = '' OR status = @status)
ORDER BY created_at DESC;

-- name: MarkSupportSessionConnected :exec
UPDATE config_support_sessions
SET status = 'connected',
    connected_at = @now,
    client_ip = @client_ip,
    client_os = @client_os,
    client_hostname = @client_hostname
WHERE id = @id AND status = 'pending';

-- name: ActivateSupportSession :exec
UPDATE config_support_sessions
SET status = 'active',
    activated_at = @now
WHERE id = @id AND status IN ('pending', 'connected');

-- name: EndSupportSession :exec
UPDATE config_support_sessions
SET status = 'ended',
    ended_at = @now,
    ended_reason = @ended_reason
WHERE id = @id AND status IN ('pending', 'connected', 'active');

-- name: ExpireStaleSupportSessions :exec
UPDATE config_support_sessions
SET status = 'expired'
WHERE status IN ('pending', 'connected') AND expires_at < @now;

-- name: DeleteSupportSession :exec
DELETE FROM config_support_sessions WHERE id = @id;
