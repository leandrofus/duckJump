-- +goose Up
-- Gateway-wide settings, one JSON value per key (e.g. recordings.retention_days).
CREATE TABLE config_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at DATETIME NOT NULL,
    updated_by TEXT
);

-- Recordings deleted by the retention policy (or by hand). audit_sessions
-- rows never change after closing, so the deletion is recorded here, append-only.
CREATE TABLE audit_recording_purges (
    session_id TEXT PRIMARY KEY REFERENCES audit_sessions (id),
    purged_at  DATETIME NOT NULL,
    reason     TEXT NOT NULL,
    bytes      INTEGER NOT NULL DEFAULT 0
);

-- +goose StatementBegin
CREATE TRIGGER audit_recording_purges_no_update BEFORE UPDATE ON audit_recording_purges
BEGIN SELECT RAISE(ABORT, 'audit_recording_purges is append-only'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_recording_purges_no_delete BEFORE DELETE ON audit_recording_purges
BEGIN SELECT RAISE(ABORT, 'audit_recording_purges is append-only'); END;
-- +goose StatementEnd

-- +goose Down
DROP TABLE audit_recording_purges;
DROP TABLE config_settings;
