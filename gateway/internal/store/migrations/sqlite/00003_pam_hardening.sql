-- +goose Up
-- HMAC of each audit event, keyed outside the database (derived from the
-- master key): mac = HMAC(key, prev_mac || hash). Someone with write access
-- to the database alone can no longer rewrite the chain and recompute it.
-- Events from before this migration have none; `duckjump-gw audit-seal`
-- authenticates them by appending the first MAC'd event on top of them.
ALTER TABLE audit_events ADD COLUMN mac TEXT;

-- Requests to end a live session (from the API or the CLI). The gateway
-- holding the session polls this table, so a request reaches it even when
-- it comes from another process.
CREATE TABLE audit_session_kills (
    session_id   TEXT PRIMARY KEY REFERENCES audit_sessions (id),
    requested_at DATETIME NOT NULL,
    requested_by TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT ''
);

-- +goose StatementBegin
CREATE TRIGGER audit_session_kills_no_update BEFORE UPDATE ON audit_session_kills
BEGIN SELECT RAISE(ABORT, 'audit_session_kills is append-only'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_session_kills_no_delete BEFORE DELETE ON audit_session_kills
BEGIN SELECT RAISE(ABORT, 'audit_session_kills is append-only'); END;
-- +goose StatementEnd

-- Host key (SSH) or certificate key (RDP, VNC over TLS) a server presented
-- while the connection had none pinned. Sessions are refused until an admin
-- approves it, unless the gateway runs with trust on first use.
ALTER TABLE config_connections ADD COLUMN host_key_pending TEXT;

-- +goose Down
ALTER TABLE config_connections DROP COLUMN host_key_pending;
DROP TABLE audit_session_kills;
ALTER TABLE audit_events DROP COLUMN mac;
