-- +goose Up
-- Support sessions: on-demand remote assistance sessions initiated by operators.
-- An agent connects over WSS/yamux, presents a dynamic TOTP code to the remote
-- user, and upon operator TOTP verification + user consent, enables remote control.
CREATE TABLE config_support_sessions (
    id                TEXT PRIMARY KEY,
    token             TEXT NOT NULL UNIQUE,
    created_by        TEXT NOT NULL REFERENCES config_users (id) ON DELETE CASCADE,
    target_name       TEXT NOT NULL DEFAULT '',
    reason            TEXT NOT NULL DEFAULT '',
    ticket            TEXT NOT NULL DEFAULT '',
    totp_secret       TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'active', 'ended', 'expired')),
    expires_at        TIMESTAMPTZ NOT NULL,
    connected_at      TIMESTAMPTZ,
    activated_at      TIMESTAMPTZ,
    ended_at          TIMESTAMPTZ,
    ended_reason      TEXT NOT NULL DEFAULT '',
    client_ip         TEXT NOT NULL DEFAULT '',
    client_os         TEXT NOT NULL DEFAULT '',
    client_hostname   TEXT NOT NULL DEFAULT '',
    recording_id      TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX config_support_sessions_token ON config_support_sessions (token);
CREATE INDEX config_support_sessions_status ON config_support_sessions (status, created_at);
CREATE INDEX config_support_sessions_creator ON config_support_sessions (created_by, created_at);

-- +goose Down
DROP TABLE config_support_sessions;
