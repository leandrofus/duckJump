-- +goose Up
ALTER TABLE config_connections DROP CONSTRAINT IF EXISTS config_connections_protocol_check;
ALTER TABLE config_connections ADD CONSTRAINT config_connections_protocol_check CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'tcp', 'http', 'https'));

-- +goose Down
ALTER TABLE config_connections DROP CONSTRAINT IF EXISTS config_connections_protocol_check;
ALTER TABLE config_connections ADD CONSTRAINT config_connections_protocol_check CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'tcp'));
