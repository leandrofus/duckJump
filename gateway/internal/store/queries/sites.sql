-- name: CreateSite :exec
INSERT INTO config_sites (id, name, kind, description, agent_token_hash, created_at)
VALUES (@id, @name, @kind, @description, @agent_token_hash, @now);

-- name: GetSite :one
SELECT * FROM config_sites WHERE id = @id;

-- name: GetSiteByName :one
SELECT * FROM config_sites WHERE name = @name;

-- name: GetAgentSiteByToken :one
SELECT * FROM config_sites WHERE kind = 'agent' AND agent_token_hash = @agent_token_hash;

-- name: ListSites :many
SELECT s.*, (SELECT count(*) FROM config_connections c WHERE c.site_id = s.id) AS connection_count
FROM config_sites s ORDER BY s.name;

-- name: UpdateSite :exec
UPDATE config_sites SET name = @name, description = @description WHERE id = @id;

-- name: SetSiteToken :exec
UPDATE config_sites SET agent_token_hash = @agent_token_hash WHERE id = @id AND kind = 'agent';

-- name: DeleteSite :execrows
DELETE FROM config_sites WHERE id = @id;
