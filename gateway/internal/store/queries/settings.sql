-- name: GetSetting :one
SELECT value FROM config_settings WHERE key = @key;

-- name: SetSetting :exec
INSERT INTO config_settings (key, value, updated_at, updated_by) VALUES (@key, @value, @now, @updated_by)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, updated_by = excluded.updated_by;
