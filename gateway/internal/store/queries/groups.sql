-- name: CreateGroup :exec
INSERT INTO config_groups (id, name, description, source, created_at)
VALUES (@id, @name, @description, @source, @now);

-- name: GetGroup :one
SELECT * FROM config_groups WHERE id = @id;

-- name: ListGroups :many
SELECT g.*, (SELECT count(*) FROM config_group_members m WHERE m.group_id = g.id) AS member_count
FROM config_groups g ORDER BY g.name;

-- name: UpdateGroup :exec
UPDATE config_groups SET name = @name, description = @description WHERE id = @id;

-- name: DeleteGroup :execrows
DELETE FROM config_groups WHERE id = @id;

-- name: AddGroupMember :exec
INSERT INTO config_group_members (group_id, user_id) VALUES (@group_id, @user_id)
ON CONFLICT DO NOTHING;

-- name: RemoveGroupMember :execrows
DELETE FROM config_group_members WHERE group_id = @group_id AND user_id = @user_id;

-- name: ListGroupMembers :many
SELECT u.* FROM config_users u
JOIN config_group_members m ON m.user_id = u.id
WHERE m.group_id = @group_id ORDER BY u.username;

-- name: ListUserGroups :many
SELECT g.* FROM config_groups g
JOIN config_group_members m ON m.group_id = g.id
WHERE m.user_id = @user_id ORDER BY g.name;
