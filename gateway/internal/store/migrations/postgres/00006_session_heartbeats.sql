-- +goose Up
-- Live sessions and the gateway holding them, refreshed while they run. A
-- session whose gateway stopped refreshing it (crashed, killed) is closed by
-- any gateway sharing the database. Not part of the audit trail.
CREATE TABLE runtime_sessions (
    session_id   TEXT PRIMARY KEY,
    node         TEXT NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL
);

-- +goose Down
DROP TABLE runtime_sessions;
