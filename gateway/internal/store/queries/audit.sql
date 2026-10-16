-- name: LastAuditHash :one
SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (ts, actor_id, actor_name, actor_ip, action, object_type, object_id, details, prev_hash, hash)
VALUES (@ts, @actor_id, @actor_name, @actor_ip, @action, @object_type, @object_id, @details, @prev_hash, @hash);

-- name: ListAuditEvents :many
-- Newest first, keyset-paginated by id (before_id = 0 for the first page).
SELECT * FROM audit_events
WHERE (CAST(@before_id AS INTEGER) = 0 OR id < @before_id)
  AND (CAST(@actor_id AS TEXT) = '' OR actor_id = @actor_id)
  AND (CAST(@action AS TEXT) = '' OR action = @action)
  AND (CAST(@object_id AS TEXT) = '' OR object_id = @object_id)
ORDER BY id DESC
LIMIT @lim;

-- name: AuditEventsFrom :many
-- Oldest first, for verifying the hash chain in batches.
SELECT * FROM audit_events WHERE id > @after_id ORDER BY id LIMIT @lim;

-- name: StartSessionRecord :exec
INSERT INTO audit_sessions (id, user_id, username, connection_id, connection_snapshot, site, client_ip, reason, recording, started_at)
VALUES (@id, @user_id, @username, @connection_id, @connection_snapshot, @site, @client_ip, @reason, @recording, @now);

-- name: EndSessionRecord :exec
UPDATE audit_sessions SET ended_at = @now, end_reason = CAST(@end_reason AS TEXT) WHERE id = @id AND ended_at IS NULL;

-- name: GetSessionRecord :one
SELECT * FROM audit_sessions WHERE id = @id;

-- name: ListSessionRecords :many
SELECT * FROM audit_sessions
WHERE (CAST(@user_id AS TEXT) = '' OR user_id = @user_id)
  AND (CAST(@connection_id AS TEXT) = '' OR connection_id = @connection_id)
  AND (CAST(@active_only AS BOOLEAN) = 0 OR ended_at IS NULL)
  AND (CAST(@has_before AS BOOLEAN) = 0 OR julianday(started_at) < julianday(CAST(@before AS TEXT)))
ORDER BY started_at DESC
LIMIT @lim;

-- name: GetRecordingPurge :one
SELECT * FROM audit_recording_purges WHERE session_id = @session_id;

-- name: InsertRecordingPurge :exec
INSERT INTO audit_recording_purges (session_id, purged_at, reason, bytes) VALUES (@session_id, @now, @reason, @bytes);

-- name: ListPurgedSessionIDs :many
-- Which of the given sessions had their recording purged (for list views).
SELECT session_id FROM audit_recording_purges
WHERE session_id IN (sqlc.slice('ids'));

-- name: LiveRecordings :many
-- Sessions with a recording that has not been purged, oldest first.
SELECT s.id, s.recording, s.started_at, s.ended_at FROM audit_sessions s
WHERE s.recording IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM audit_recording_purges p WHERE p.session_id = s.id)
ORDER BY s.started_at;

-- name: RecordingsEndedBefore :many
-- Closed sessions whose recording is due for deletion.
SELECT s.id, s.recording, s.ended_at FROM audit_sessions s
WHERE s.recording IS NOT NULL
  AND s.ended_at IS NOT NULL
  AND julianday(s.ended_at) < julianday(CAST(@cutoff AS TEXT))
  AND NOT EXISTS (SELECT 1 FROM audit_recording_purges p WHERE p.session_id = s.id)
ORDER BY s.ended_at
LIMIT @lim;
