-- +goose Up
-- PostgreSQL schema: the SQLite one (migrations/sqlite 00001-00004) in one
-- step. Later migrations are numbered after it in both directories.
-- Every integer is BIGINT so the generated Go types match on both engines;
-- timestamps are written by the app, in UTC.

-- julianday() exists so queries compare timestamps the same way on SQLite
-- (where they are text) and here.
-- +goose StatementBegin
CREATE FUNCTION julianday(t timestamptz) RETURNS double precision
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT extract(epoch FROM t) / 86400.0 + 2440587.5 $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION julianday(t text) RETURNS double precision
LANGUAGE sql STABLE PARALLEL SAFE AS $$ SELECT extract(epoch FROM t::timestamptz) / 86400.0 + 2440587.5 $$;
-- +goose StatementEnd

-- Append-only tables: rows may not change or go away.
-- +goose StatementBegin
CREATE FUNCTION duckjump_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
-- +goose StatementEnd

CREATE TABLE config_users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    totp_sealed   BYTEA,
    totp_enabled  BOOLEAN NOT NULL DEFAULT false,
    source        TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'oidc')),
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('superadmin', 'admin', 'auditor', 'user')),
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    oidc_subject  TEXT
);
CREATE UNIQUE INDEX config_users_oidc_subject ON config_users (oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE config_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'oidc')),
    created_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE config_group_members (
    group_id TEXT NOT NULL REFERENCES config_groups (id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES config_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX config_group_members_user ON config_group_members (user_id);

CREATE TABLE config_folders (
    id         TEXT PRIMARY KEY,
    parent_id  TEXT REFERENCES config_folders (id) ON DELETE RESTRICT,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX config_folders_sibling_name ON config_folders (coalesce(parent_id, ''), name);

CREATE TABLE config_sites (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    kind             TEXT NOT NULL CHECK (kind IN ('direct', 'agent')),
    description      TEXT NOT NULL DEFAULT '',
    agent_token_hash TEXT UNIQUE,
    created_at       TIMESTAMPTZ NOT NULL,
    CHECK ((kind = 'agent') = (agent_token_hash IS NOT NULL))
);

CREATE TABLE config_secrets (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('password', 'private_key')),
    username   TEXT NOT NULL,
    sealed     BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE config_connections (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    protocol         TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc')),
    host             TEXT NOT NULL,
    port             BIGINT NOT NULL CHECK (port BETWEEN 1 AND 65535),
    folder_id        TEXT REFERENCES config_folders (id) ON DELETE SET NULL,
    site_id          TEXT REFERENCES config_sites (id) ON DELETE RESTRICT,
    environment      TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    backend          TEXT NOT NULL DEFAULT 'paltad' CHECK (backend IN ('paltad', 'guacd')),
    credential_mode  TEXT NOT NULL DEFAULT 'vault' CHECK (credential_mode IN ('vault', 'prompt')),
    secret_id        TEXT REFERENCES config_secrets (id) ON DELETE SET NULL,
    params           TEXT NOT NULL DEFAULT '{}' CHECK (params::jsonb IS NOT NULL),
    record           BOOLEAN NOT NULL DEFAULT true,
    record_input     BOOLEAN NOT NULL DEFAULT false,
    host_key         TEXT,
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    host_key_pending TEXT
);
CREATE INDEX config_connections_folder ON config_connections (folder_id);

CREATE TABLE config_connection_tags (
    connection_id TEXT NOT NULL REFERENCES config_connections (id) ON DELETE CASCADE,
    tag           TEXT NOT NULL,
    PRIMARY KEY (connection_id, tag)
);
CREATE INDEX config_connection_tags_tag ON config_connection_tags (tag);

CREATE TABLE config_policies (
    id                  TEXT PRIMARY KEY,
    subject_type        TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
    subject_id          TEXT NOT NULL,
    object_type         TEXT NOT NULL CHECK (object_type IN ('connection', 'folder', 'tag')),
    object_ref          TEXT NOT NULL,
    can_connect         BOOLEAN NOT NULL DEFAULT true,
    can_view_recordings BOOLEAN NOT NULL DEFAULT false,
    expires_at          TIMESTAMPTZ,
    description         TEXT NOT NULL DEFAULT '',
    created_by          TEXT,
    created_at          TIMESTAMPTZ NOT NULL
);
CREATE INDEX config_policies_subject ON config_policies (subject_type, subject_id);
CREATE INDEX config_policies_object ON config_policies (object_type, object_ref);

CREATE TABLE config_web_sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES config_users (id) ON DELETE CASCADE,
    mfa_pending  BOOLEAN NOT NULL DEFAULT false,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX config_web_sessions_user ON config_web_sessions (user_id);

CREATE TABLE config_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL CHECK (value::jsonb IS NOT NULL),
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT
);

CREATE TABLE audit_events (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    actor_id    TEXT,
    actor_name  TEXT NOT NULL DEFAULT '',
    actor_ip    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    object_type TEXT NOT NULL DEFAULT '',
    object_id   TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '{}',
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL UNIQUE,
    mac         TEXT
);
CREATE INDEX audit_events_ts ON audit_events (ts);
CREATE INDEX audit_events_object ON audit_events (object_type, object_id);

CREATE TABLE audit_sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT,
    username            TEXT NOT NULL,
    connection_id       TEXT NOT NULL,
    connection_snapshot TEXT NOT NULL,
    site                TEXT NOT NULL DEFAULT '',
    client_ip           TEXT NOT NULL DEFAULT '',
    reason              TEXT NOT NULL DEFAULT '',
    recording           TEXT,
    started_at          TIMESTAMPTZ NOT NULL,
    ended_at            TIMESTAMPTZ,
    end_reason          TEXT
);
CREATE INDEX audit_sessions_started ON audit_sessions (started_at);
CREATE INDEX audit_sessions_user ON audit_sessions (user_id);

CREATE TABLE audit_recording_purges (
    session_id TEXT PRIMARY KEY REFERENCES audit_sessions (id),
    purged_at  TIMESTAMPTZ NOT NULL,
    reason     TEXT NOT NULL,
    bytes      BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE audit_session_kills (
    session_id   TEXT PRIMARY KEY REFERENCES audit_sessions (id),
    requested_at TIMESTAMPTZ NOT NULL,
    requested_by TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT ''
);

CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION duckjump_append_only();
CREATE TRIGGER audit_recording_purges_append_only BEFORE UPDATE OR DELETE ON audit_recording_purges
FOR EACH ROW EXECUTE FUNCTION duckjump_append_only();
CREATE TRIGGER audit_session_kills_append_only BEFORE UPDATE OR DELETE ON audit_session_kills
FOR EACH ROW EXECUTE FUNCTION duckjump_append_only();
CREATE TRIGGER audit_sessions_no_delete BEFORE DELETE ON audit_sessions
FOR EACH ROW EXECUTE FUNCTION duckjump_append_only();

-- A session may be updated once, to close it; nothing else may change.
-- +goose StatementBegin
CREATE FUNCTION duckjump_session_close_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.username IS DISTINCT FROM OLD.username OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
       OR NEW.connection_snapshot IS DISTINCT FROM OLD.connection_snapshot OR NEW.site IS DISTINCT FROM OLD.site
       OR NEW.client_ip IS DISTINCT FROM OLD.client_ip OR NEW.reason IS DISTINCT FROM OLD.reason
       OR NEW.recording IS DISTINCT FROM OLD.recording OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'audit_sessions only allows closing an open session';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_sessions_close_only BEFORE UPDATE ON audit_sessions
FOR EACH ROW EXECUTE FUNCTION duckjump_session_close_only();

-- +goose Down
DROP TABLE audit_session_kills, audit_recording_purges, audit_sessions, audit_events, config_settings,
    config_web_sessions, config_policies, config_connection_tags, config_connections, config_secrets,
    config_sites, config_folders, config_group_members, config_groups, config_users;
DROP FUNCTION duckjump_session_close_only, duckjump_append_only, julianday(timestamptz), julianday(text);
