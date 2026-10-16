-- name: CreatePolicy :exec
INSERT INTO config_policies (
    id, subject_type, subject_id, object_type, object_ref, can_connect, can_view_recordings,
    expires_at, description, created_by, created_at
) VALUES (
    @id, @subject_type, @subject_id, @object_type, @object_ref, @can_connect, @can_view_recordings,
    @expires_at, @description, @created_by, @now
);

-- name: GetPolicy :one
SELECT * FROM config_policies WHERE id = @id;

-- name: ListPolicies :many
SELECT * FROM config_policies
WHERE (CAST(@subject_id AS TEXT) = '' OR subject_id = @subject_id)
  AND (CAST(@object_ref AS TEXT) = '' OR object_ref = @object_ref)
ORDER BY created_at;

-- name: UpdatePolicy :exec
UPDATE config_policies
SET can_connect = @can_connect, can_view_recordings = @can_view_recordings,
    expires_at = @expires_at, description = @description
WHERE id = @id;

-- name: DeletePolicy :execrows
DELETE FROM config_policies WHERE id = @id;

-- name: DeletePoliciesForSubject :exec
DELETE FROM config_policies WHERE subject_type = @subject_type AND subject_id = @subject_id;

-- name: DeletePoliciesForObject :exec
DELETE FROM config_policies WHERE object_type = @object_type AND object_ref = @object_ref;

-- name: ConnectionsGrantedToUser :many
-- Connections a user may open: unexpired grants with can_connect, given to the
-- user or one of their groups, on the connection, an ancestor folder, or a tag.
WITH RECURSIVE
    subj(type, id) AS (
        SELECT 'user', CAST(@user_id AS TEXT)
        UNION ALL
        SELECT 'group', m.group_id FROM config_group_members m WHERE m.user_id = @user_id
    ),
    grants AS (
        SELECT p.object_type, p.object_ref FROM config_policies p
        JOIN subj ON p.subject_type = subj.type AND p.subject_id = subj.id
        WHERE p.can_connect AND (p.expires_at IS NULL OR julianday(p.expires_at) > julianday(CAST(@now AS TEXT)))
    ),
    granted_folders(id) AS (
        SELECT object_ref FROM grants WHERE object_type = 'folder'
        UNION
        SELECT f.id FROM config_folders f JOIN granted_folders g ON f.parent_id = g.id
    )
SELECT c.* FROM config_connections c
WHERE c.id IN (SELECT object_ref FROM grants WHERE object_type = 'connection')
   OR c.folder_id IN (SELECT id FROM granted_folders)
   OR c.id IN (SELECT t.connection_id FROM config_connection_tags t
               JOIN grants g ON g.object_type = 'tag' AND g.object_ref = t.tag)
ORDER BY c.name;

-- name: PoliciesGrantingConnection :many
-- The grants that let a user act on one connection (for checks and "why").
WITH RECURSIVE
    subj(type, id) AS (
        SELECT 'user', CAST(@user_id AS TEXT)
        UNION ALL
        SELECT 'group', m.group_id FROM config_group_members m WHERE m.user_id = @user_id
    ),
    ancestors(id) AS (
        SELECT folder_id FROM config_connections WHERE id = @connection_id AND folder_id IS NOT NULL
        UNION
        SELECT f.parent_id FROM config_folders f JOIN ancestors a ON f.id = a.id WHERE f.parent_id IS NOT NULL
    )
SELECT p.* FROM config_policies p
JOIN subj ON p.subject_type = subj.type AND p.subject_id = subj.id
WHERE (p.expires_at IS NULL OR julianday(p.expires_at) > julianday(CAST(@now AS TEXT)))
  AND (   (p.object_type = 'connection' AND p.object_ref = @connection_id)
       OR (p.object_type = 'folder' AND p.object_ref IN (SELECT id FROM ancestors))
       OR (p.object_type = 'tag' AND p.object_ref IN
              (SELECT tag FROM config_connection_tags WHERE connection_id = @connection_id)))
ORDER BY p.created_at;
