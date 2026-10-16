-- name: CreateUser :exec
INSERT INTO config_users (id, username, display_name, email, password_hash, source, role, created_at, updated_at)
VALUES (@id, @username, @display_name, @email, @password_hash, @source, @role, @now, @now);

-- name: GetUser :one
SELECT * FROM config_users WHERE id = @id;

-- name: GetUserByUsername :one
SELECT * FROM config_users WHERE username = @username;

-- name: ListUsers :many
SELECT * FROM config_users ORDER BY username;

-- name: CountUsers :one
SELECT count(*) FROM config_users;

-- name: UpdateUser :exec
UPDATE config_users
SET display_name = @display_name, email = @email, role = @role, disabled = @disabled, updated_at = @now
WHERE id = @id;

-- name: SetUserPassword :exec
UPDATE config_users SET password_hash = @password_hash, updated_at = @now WHERE id = @id;

-- name: SetUserTOTP :exec
UPDATE config_users SET totp_sealed = @totp_sealed, totp_enabled = @totp_enabled, updated_at = @now WHERE id = @id;

-- name: TouchUserLogin :exec
UPDATE config_users SET last_login_at = @now WHERE id = @id;

-- name: DeleteUser :execrows
DELETE FROM config_users WHERE id = @id;

-- name: GetUserByOIDCSubject :one
SELECT * FROM config_users WHERE oidc_subject = @oidc_subject;

-- name: CreateOIDCUser :exec
INSERT INTO config_users (id, username, display_name, email, source, role, oidc_subject, created_at, updated_at)
VALUES (@id, @username, @display_name, @email, 'oidc', @role, @oidc_subject, @now, @now);

-- name: SyncOIDCUser :exec
-- What the identity provider says about a user, on every login.
UPDATE config_users SET display_name = @display_name, email = @email, role = @role, updated_at = @now WHERE id = @id;
