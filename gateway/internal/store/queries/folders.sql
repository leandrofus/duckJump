-- name: CreateFolder :exec
INSERT INTO config_folders (id, parent_id, name, created_at) VALUES (@id, @parent_id, @name, @now);

-- name: GetFolder :one
SELECT * FROM config_folders WHERE id = @id;

-- name: ListFolders :many
SELECT * FROM config_folders ORDER BY name;

-- name: UpdateFolder :exec
UPDATE config_folders SET parent_id = @parent_id, name = @name WHERE id = @id;

-- name: DeleteFolder :execrows
DELETE FROM config_folders WHERE id = @id;

-- name: FolderSubtree :many
-- The folder and every folder below it.
WITH RECURSIVE sub(id) AS (
    SELECT f.id FROM config_folders f WHERE f.id = @id
    UNION
    SELECT f.id FROM config_folders f JOIN sub ON f.parent_id = sub.id
)
SELECT CAST(id AS TEXT) AS id FROM sub;

-- name: CountFolderChildren :one
SELECT
    (SELECT count(*) FROM config_folders f WHERE f.parent_id = CAST(@id AS TEXT)) AS folders,
    (SELECT count(*) FROM config_connections c WHERE c.folder_id = @id) AS connections;
