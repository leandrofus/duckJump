-- +goose Up
-- Access requests: a user asks for access to a connection, folder or tag,
-- for a reason and a start/end time window; an approver approves or denies it,
-- which creates an expiring grant.
ALTER TABLE config_policies ADD COLUMN starts_at DATETIME;

CREATE TABLE config_access_requests (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES config_users (id) ON DELETE CASCADE,
    object_type         TEXT NOT NULL CHECK (object_type IN ('connection', 'folder', 'tag')),
    object_ref          TEXT NOT NULL,
    ticket              TEXT NOT NULL DEFAULT '',
    can_connect         BOOLEAN NOT NULL DEFAULT 1,
    can_view_recordings BOOLEAN NOT NULL DEFAULT 0,
    can_upload          BOOLEAN NOT NULL DEFAULT 0,
    can_download        BOOLEAN NOT NULL DEFAULT 0,
    reason              TEXT NOT NULL,
    starts_at           DATETIME NOT NULL,
    ends_at             DATETIME NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'canceled')),
    reviewed_by         TEXT REFERENCES config_users (id) ON DELETE SET NULL,
    reviewed_at         DATETIME,
    review_comment      TEXT NOT NULL DEFAULT '',
    created_policy_id   TEXT REFERENCES config_policies (id) ON DELETE SET NULL,
    created_at          DATETIME NOT NULL
);
CREATE INDEX config_access_requests_user ON config_access_requests (user_id, created_at);
CREATE INDEX config_access_requests_status ON config_access_requests (status, created_at);

-- +goose Down
DROP TABLE config_access_requests;
ALTER TABLE config_policies DROP COLUMN starts_at;
