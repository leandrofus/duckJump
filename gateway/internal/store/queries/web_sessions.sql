-- name: CreateWebSession :exec
INSERT INTO config_web_sessions (id_hash, user_id, mfa_pending, ip, user_agent, created_at, last_seen_at, expires_at)
VALUES (@id_hash, @user_id, @mfa_pending, @ip, @user_agent, @now, @now, @expires_at);

-- name: GetWebSession :one
SELECT * FROM config_web_sessions WHERE id_hash = @id_hash;

-- name: TouchWebSession :exec
UPDATE config_web_sessions SET last_seen_at = @now WHERE id_hash = @id_hash;

-- name: CompleteWebSessionMFA :exec
UPDATE config_web_sessions SET mfa_pending = false, last_seen_at = @now WHERE id_hash = @id_hash;

-- name: DeleteWebSession :exec
DELETE FROM config_web_sessions WHERE id_hash = @id_hash;

-- name: DeleteUserWebSessions :exec
DELETE FROM config_web_sessions WHERE user_id = @user_id;

-- name: DeleteExpiredWebSessions :execrows
DELETE FROM config_web_sessions
WHERE julianday(expires_at) <= julianday(CAST(@now AS TEXT))
   OR julianday(last_seen_at) <= julianday(CAST(@idle_before AS TEXT));
