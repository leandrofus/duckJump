-- +goose Up
-- File transfer: grants say who may send files to a host (upload) and take
-- files from it (download), apart from connecting.
ALTER TABLE config_policies ADD COLUMN can_upload BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE config_policies ADD COLUMN can_download BOOLEAN NOT NULL DEFAULT 0;

-- The file tray: every file that went through the gateway, from a user's
-- computer or out of a host, with its hash. Content is kept until
-- expires_at (or deleted by its owner); the row stays as evidence.
CREATE TABLE audit_files (
    id            TEXT PRIMARY KEY,
    owner_id      TEXT NOT NULL,
    owner_name    TEXT NOT NULL,
    name          TEXT NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    storage_key   TEXT NOT NULL,
    origin        TEXT NOT NULL CHECK (origin IN ('upload', 'host')),
    connection_id TEXT,                     -- origin host: the connection it came from
    remote_path   TEXT NOT NULL DEFAULT '',
    created_at    DATETIME NOT NULL,
    expires_at    DATETIME NOT NULL,
    deleted_at    DATETIME,
    delete_reason TEXT
);
CREATE INDEX audit_files_owner ON audit_files (owner_id, created_at);

-- +goose Down
DROP TABLE audit_files;
ALTER TABLE config_policies DROP COLUMN can_download;
ALTER TABLE config_policies DROP COLUMN can_upload;
