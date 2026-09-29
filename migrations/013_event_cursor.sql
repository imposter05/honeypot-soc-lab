-- Hiten | 2026
-- 013_event_cursor.sql
-- Adds a database-assigned sequence to events so a dashboard that lost
-- its connection can ask for everything after the last seq it saw.
-- Existing rows are numbered in timestamp order.

-- +goose Up
CREATE SEQUENCE IF NOT EXISTS events_seq;

ALTER TABLE events ADD COLUMN seq BIGINT;
ALTER TABLE events ADD COLUMN dest_ip TEXT;
ALTER TABLE events ADD COLUMN origin TEXT NOT NULL DEFAULT 'external';

WITH ordered AS (
    SELECT id, timestamp,
           row_number() OVER (ORDER BY timestamp, id) AS rn
    FROM events
)
UPDATE events e
SET seq = ordered.rn
FROM ordered
WHERE e.id = ordered.id AND e.timestamp = ordered.timestamp;

SELECT setval('events_seq', COALESCE((SELECT max(seq) FROM events), 0) + 1, false);

ALTER TABLE events ALTER COLUMN seq SET DEFAULT nextval('events_seq');
ALTER TABLE events ALTER COLUMN seq SET NOT NULL;
CREATE INDEX idx_events_seq ON events (seq);
CREATE INDEX idx_events_origin ON events (origin);

ALTER TABLE sessions ADD COLUMN last_activity TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN rule_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE sessions ADD COLUMN auth_mode TEXT;
ALTER TABLE sessions ADD COLUMN dest_ip TEXT;

ALTER TABLE captured_files ADD COLUMN event_id TEXT;
ALTER TABLE captured_files ADD COLUMN event_timestamp TIMESTAMPTZ;
ALTER TABLE captured_files ADD COLUMN storage_path TEXT;
ALTER TABLE captured_files ADD COLUMN truncated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE captured_files ADD COLUMN size_limit BIGINT;

-- +goose Down
ALTER TABLE captured_files DROP COLUMN IF EXISTS size_limit;
ALTER TABLE captured_files DROP COLUMN IF EXISTS truncated;
ALTER TABLE captured_files DROP COLUMN IF EXISTS storage_path;
ALTER TABLE captured_files DROP COLUMN IF EXISTS event_timestamp;
ALTER TABLE captured_files DROP COLUMN IF EXISTS event_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS dest_ip;
ALTER TABLE sessions DROP COLUMN IF EXISTS auth_mode;
ALTER TABLE sessions DROP COLUMN IF EXISTS rule_ids;
ALTER TABLE sessions DROP COLUMN IF EXISTS last_activity;
DROP INDEX IF EXISTS idx_events_origin;
DROP INDEX IF EXISTS idx_events_seq;
ALTER TABLE events DROP COLUMN IF EXISTS origin;
ALTER TABLE events DROP COLUMN IF EXISTS dest_ip;
ALTER TABLE events DROP COLUMN IF EXISTS seq;
DROP SEQUENCE IF EXISTS events_seq;
