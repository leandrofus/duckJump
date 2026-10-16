-- +goose Up
-- The timestamp an audit event was hashed with, when the ts column cannot
-- hold it exactly: events copied from SQLite (nanoseconds) into PostgreSQL
-- (microseconds). NULL: ts itself is exact.
ALTER TABLE audit_events ADD COLUMN ts_exact TEXT;

-- +goose Down
ALTER TABLE audit_events DROP COLUMN ts_exact;
