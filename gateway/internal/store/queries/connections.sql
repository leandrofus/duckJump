-- name: CreateConnection :exec
INSERT INTO config_connections (
    id, name, protocol, host, port, folder_id, site_id, environment, description, backend,
    credential_mode, secret_id, params, record, record_input, created_at, updated_at
) VALUES (
    @id, @name, @protocol, @host, @port, @folder_id, @site_id, @environment, @description, @backend,
    @credential_mode, @secret_id, @params, @record, @record_input, @now, @now
);

-- name: GetConnection :one
SELECT * FROM config_connections WHERE id = @id;

-- name: GetConnectionByName :one
SELECT * FROM config_connections WHERE name = @name;

-- name: ListConnections :many
SELECT * FROM config_connections ORDER BY name;

-- name: UpdateConnection :exec
UPDATE config_connections SET
    name = @name, protocol = @protocol, host = @host, port = @port, folder_id = @folder_id,
    site_id = @site_id, environment = @environment, description = @description, backend = @backend,
    credential_mode = @credential_mode, secret_id = @secret_id, params = @params, record = @record,
    record_input = @record_input, host_key = @host_key, host_key_pending = NULL, updated_at = @now
WHERE id = @id;

-- name: PinHostKey :exec
UPDATE config_connections SET host_key = @host_key, host_key_pending = NULL WHERE id = @id AND host_key IS NULL;

-- name: SetPendingHostKey :exec
UPDATE config_connections SET host_key_pending = @host_key_pending WHERE id = @id AND host_key IS NULL;

-- name: ApproveHostKey :execrows
-- Pins a fingerprint an admin checked (replacing any pinned one).
UPDATE config_connections SET host_key = @host_key, host_key_pending = NULL, updated_at = @now WHERE id = @id;

-- name: DeleteConnection :execrows
DELETE FROM config_connections WHERE id = @id;

-- name: ListAllConnectionTags :many
SELECT * FROM config_connection_tags ORDER BY connection_id, tag;

-- name: ListConnectionTags :many
SELECT tag FROM config_connection_tags WHERE connection_id = @connection_id ORDER BY tag;

-- name: ClearConnectionTags :exec
DELETE FROM config_connection_tags WHERE connection_id = @connection_id;

-- name: AddConnectionTag :exec
INSERT INTO config_connection_tags (connection_id, tag) VALUES (@connection_id, @tag) ON CONFLICT DO NOTHING;
