-- name: CreateSecret :exec
INSERT INTO config_secrets (id, name, kind, username, sealed, created_at, updated_at)
VALUES (@id, @name, @kind, @username, @sealed, @now, @now);

-- name: GetSecret :one
SELECT * FROM config_secrets WHERE id = @id;

-- name: GetSecretByName :one
SELECT * FROM config_secrets WHERE name = @name;

-- name: ListSecrets :many
-- Never selects the sealed value.
SELECT s.id, s.name, s.kind, s.username, s.created_at, s.updated_at,
       (SELECT count(*) FROM config_connections c WHERE c.secret_id = s.id) AS connection_count
FROM config_secrets s ORDER BY s.name;

-- name: UpdateSecretMeta :exec
UPDATE config_secrets SET name = @name, username = @username, updated_at = @now WHERE id = @id;

-- name: UpdateSecretValue :exec
UPDATE config_secrets SET kind = @kind, sealed = @sealed, updated_at = @now WHERE id = @id;

-- name: DeleteSecret :execrows
DELETE FROM config_secrets WHERE id = @id;
