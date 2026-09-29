-- Hiten | 2026
-- 015_observables.sql
-- Extra columns on iocs (shown as "observables") and links from each
-- observable back to the events it was extracted from.

-- +goose Up
ALTER TABLE iocs ADD COLUMN original_value TEXT;
ALTER TABLE iocs ADD COLUMN status TEXT NOT NULL DEFAULT 'observed'
    CHECK (status IN ('observed','suspicious','confirmed','benign'));
ALTER TABLE iocs ADD COLUMN is_internal BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE iocs ADD COLUMN claimed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_iocs_status ON iocs (status);

CREATE TABLE observable_evidence (
    ioc_id          BIGINT NOT NULL REFERENCES iocs (id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    session_id      TEXT NOT NULL,
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (ioc_id, event_id, event_timestamp),
    FOREIGN KEY (event_id, event_timestamp) REFERENCES events (id, timestamp)
);

CREATE INDEX idx_observable_evidence_event ON observable_evidence (event_id, event_timestamp);
CREATE INDEX idx_observable_evidence_session ON observable_evidence (session_id);

-- +goose Down
DROP TABLE IF EXISTS observable_evidence;
DROP INDEX IF EXISTS idx_iocs_status;
ALTER TABLE iocs DROP COLUMN IF EXISTS claimed;
ALTER TABLE iocs DROP COLUMN IF EXISTS is_internal;
ALTER TABLE iocs DROP COLUMN IF EXISTS status;
ALTER TABLE iocs DROP COLUMN IF EXISTS original_value;
