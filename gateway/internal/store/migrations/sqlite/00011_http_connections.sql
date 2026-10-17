-- +goose Up
PRAGMA foreign_keys=off;
CREATE TABLE config_connections_new (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    protocol        TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'tcp', 'http', 'https')),
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    folder_id       TEXT REFERENCES config_folders (id) ON DELETE SET NULL,
    site_id         TEXT REFERENCES config_sites (id) ON DELETE RESTRICT,
    environment     TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    backend         TEXT NOT NULL DEFAULT 'paltad' CHECK (backend IN ('paltad', 'guacd')),
    credential_mode TEXT NOT NULL DEFAULT 'vault' CHECK (credential_mode IN ('vault', 'prompt')),
    secret_id       TEXT REFERENCES config_secrets (id) ON DELETE SET NULL,
    params          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
    record          BOOLEAN NOT NULL DEFAULT 1,
    record_input    BOOLEAN NOT NULL DEFAULT 0,
    host_key        TEXT,
    host_key_pending TEXT,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL
);
INSERT INTO config_connections_new SELECT id, name, protocol, host, port, folder_id, site_id, environment, description, backend, credential_mode, secret_id, params, record, record_input, host_key, host_key_pending, created_at, updated_at FROM config_connections;
DROP TABLE config_connections;
ALTER TABLE config_connections_new RENAME TO config_connections;
CREATE INDEX config_connections_folder ON config_connections (folder_id);
PRAGMA foreign_keys=on;

-- +goose Down
PRAGMA foreign_keys=off;
CREATE TABLE config_connections_old (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    protocol        TEXT NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'tcp')),
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    folder_id       TEXT REFERENCES config_folders (id) ON DELETE SET NULL,
    site_id         TEXT REFERENCES config_sites (id) ON DELETE RESTRICT,
    environment     TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    backend         TEXT NOT NULL DEFAULT 'paltad' CHECK (backend IN ('paltad', 'guacd')),
    credential_mode TEXT NOT NULL DEFAULT 'vault' CHECK (credential_mode IN ('vault', 'prompt')),
    secret_id       TEXT REFERENCES config_secrets (id) ON DELETE SET NULL,
    params          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(params)),
    record          BOOLEAN NOT NULL DEFAULT 1,
    record_input    BOOLEAN NOT NULL DEFAULT 0,
    host_key        TEXT,
    host_key_pending TEXT,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL
);
INSERT INTO config_connections_old SELECT id, name, protocol, host, port, folder_id, site_id, environment, description, backend, credential_mode, secret_id, params, record, record_input, host_key, host_key_pending, created_at, updated_at FROM config_connections WHERE protocol IN ('ssh', 'rdp', 'vnc', 'tcp');
DROP TABLE config_connections;
ALTER TABLE config_connections_old RENAME TO config_connections;
CREATE INDEX config_connections_folder ON config_connections (folder_id);
PRAGMA foreign_keys=on;
