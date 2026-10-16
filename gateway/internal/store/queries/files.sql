-- name: CreateFile :exec
INSERT INTO audit_files (id, owner_id, owner_name, name, size, sha256, storage_key, origin, connection_id, remote_path, created_at, expires_at)
VALUES (@id, @owner_id, @owner_name, @name, @size, @sha256, @storage_key, @origin, @connection_id, @remote_path, @now, @expires_at);

-- name: GetFile :one
SELECT * FROM audit_files WHERE id = @id;

-- name: ListUserFiles :many
-- A user's tray: files whose content is still kept.
SELECT * FROM audit_files WHERE owner_id = @owner_id AND deleted_at IS NULL ORDER BY created_at DESC;

-- name: ListFiles :many
-- Every transfer, newest first (auditors).
SELECT * FROM audit_files
WHERE (CAST(@owner_id AS TEXT) = '' OR owner_id = @owner_id)
ORDER BY created_at DESC
LIMIT CAST(@lim AS BIGINT);

-- name: MarkFileDeleted :execrows
UPDATE audit_files SET deleted_at = @now, delete_reason = CAST(@reason AS TEXT) WHERE id = @id AND deleted_at IS NULL;

-- name: ExpiredFiles :many
SELECT * FROM audit_files
WHERE deleted_at IS NULL AND julianday(expires_at) < julianday(CAST(@now AS TEXT))
LIMIT CAST(@lim AS BIGINT);
