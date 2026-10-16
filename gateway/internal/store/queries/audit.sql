-- name: LastAuditEvent :one
SELECT hash, mac FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (ts, actor_id, actor_name, actor_ip, action, object_type, object_id, details, prev_hash, hash, mac)
VALUES (@ts, @actor_id, @actor_name, @actor_ip, @action, @object_type, @object_id, @details, @prev_hash, @hash, @mac);

-- name: CopyAuditEvent :exec
-- migrate-to-postgres: the event exactly as it was, id included.
INSERT INTO audit_events (id, ts, actor_id, actor_name, actor_ip, action, object_type, object_id, details, prev_hash, hash, mac, ts_exact)
OVERRIDING SYSTEM VALUE
VALUES (@id, @ts, @actor_id, @actor_name, @actor_ip, @action, @object_type, @object_id, @details, @prev_hash, @hash, @mac, @ts_exact);

-- name: ListAuditEvents :many
-- Newest first, keyset-paginated by id (before_id = 0 for the first page).
SELECT * FROM audit_events
WHERE (CAST(@before_id AS BIGINT) = 0 OR id < @before_id)
  AND (CAST(@actor_id AS TEXT) = '' OR actor_id = @actor_id)
  AND (CAST(@action AS TEXT) = '' OR action = @action)
  AND (CAST(@object_id AS TEXT) = '' OR object_id = @object_id)
ORDER BY id DESC
LIMIT CAST(@lim AS BIGINT);

-- name: AuditEventsFrom :many
-- Oldest first, for verifying the hash chain in batches.
SELECT * FROM audit_events WHERE id > @after_id ORDER BY id LIMIT CAST(@lim AS BIGINT);

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
  AND (NOT CAST(@active_only AS BOOLEAN) OR ended_at IS NULL)
  AND (NOT CAST(@has_before AS BOOLEAN) OR julianday(started_at) < julianday(CAST(@before AS TEXT)))
ORDER BY started_at DESC
LIMIT CAST(@lim AS BIGINT);

-- name: GetRecordingPurge :one
SELECT * FROM audit_recording_purges WHERE session_id = @session_id;

-- name: InsertRecordingPurge :exec
INSERT INTO audit_recording_purges (session_id, purged_at, reason, bytes) VALUES (@session_id, @now, @reason, @bytes)
ON CONFLICT (session_id) DO NOTHING; -- another gateway purged it first


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
LIMIT CAST(@lim AS BIGINT);

-- name: BeatSession :exec
INSERT INTO runtime_sessions (session_id, node, heartbeat_at) VALUES (@session_id, @node, @now)
ON CONFLICT (session_id) DO UPDATE SET heartbeat_at = excluded.heartbeat_at, node = excluded.node;

-- name: ForgetSession :exec
DELETE FROM runtime_sessions WHERE session_id = @session_id;

-- name: CloseStaleSessions :many
-- Open sessions no gateway is holding: their heartbeat stopped, or never
-- came and they started before the cutoff.
UPDATE audit_sessions SET ended_at = @now, end_reason = 'lost: the gateway holding it stopped'
WHERE ended_at IS NULL
  AND julianday(started_at) < julianday(CAST(@cutoff AS TEXT))
  AND NOT EXISTS (SELECT 1 FROM runtime_sessions r WHERE r.session_id = audit_sessions.id
                  AND julianday(r.heartbeat_at) >= julianday(CAST(@cutoff AS TEXT)))
RETURNING id;

-- name: DeleteStaleHeartbeats :exec
DELETE FROM runtime_sessions WHERE julianday(heartbeat_at) < julianday(CAST(@cutoff AS TEXT));

-- name: RequestSessionKill :exec
INSERT INTO audit_session_kills (session_id, requested_at, requested_by, reason) VALUES (@session_id, @now, @requested_by, @reason)
ON CONFLICT (session_id) DO NOTHING;

-- name: ListSessionKills :many
-- Kill requests for sessions still open (what live gateways act on).
SELECT k.* FROM audit_session_kills k JOIN audit_sessions s ON s.id = k.session_id WHERE s.ended_at IS NULL;

-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events;
