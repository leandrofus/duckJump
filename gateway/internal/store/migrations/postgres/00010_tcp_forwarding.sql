-- +goose Up
ALTER TABLE config_connections DROP CONSTRAINT IF EXISTS config_connections_protocol_check;
ALTER TABLE config_connections ADD CONSTRAINT config_connections_protocol_check CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'tcp'));
ALTER TABLE config_policies ADD COLUMN can_forward BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE config_access_requests ADD COLUMN can_forward BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE config_access_requests DROP COLUMN can_forward;
ALTER TABLE config_policies DROP COLUMN can_forward;
ALTER TABLE config_connections DROP CONSTRAINT IF EXISTS config_connections_protocol_check;
ALTER TABLE config_connections ADD CONSTRAINT config_connections_protocol_check CHECK (protocol IN ('ssh', 'rdp', 'vnc'));
