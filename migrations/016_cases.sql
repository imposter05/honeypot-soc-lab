-- Hiten | 2026
-- 016_cases.sql
-- Investigation cases. case_history is append-only: a trigger rejects
-- UPDATE and DELETE. That stops accidental edits from the application,
-- but anyone with database owner rights can still change it, so it is
-- an audit trail, not a tamper-proof log.

-- +goose Up
CREATE TABLE cases (
    id                BIGSERIAL PRIMARY KEY,
    title             TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new','investigating','closed')),
    severity          TEXT NOT NULL
        CHECK (severity IN ('low','medium','high','critical')),
    verdict           TEXT
        CHECK (verdict IS NULL OR verdict IN
            ('suspicious','benign','expected-test','insufficient-evidence')),
    sensor_id         TEXT NOT NULL,
    source_ip         TEXT NOT NULL,
    first_activity    TIMESTAMPTZ NOT NULL,
    last_activity     TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at         TIMESTAMPTZ,
    response_decision TEXT,
    closure_reason    TEXT,
    merged_into       BIGINT REFERENCES cases (id),
    CHECK (status <> 'closed' OR (verdict IS NOT NULL AND closure_reason IS NOT NULL))
);

CREATE INDEX idx_cases_open ON cases (sensor_id, source_ip, last_activity DESC)
    WHERE status <> 'closed';
CREATE INDEX idx_cases_updated ON cases (updated_at DESC);

CREATE TABLE case_detections (
    case_id      BIGINT NOT NULL REFERENCES cases (id),
    detection_id BIGINT NOT NULL REFERENCES detections (id),
    linked_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (detection_id)
);

CREATE INDEX idx_case_detections_case ON case_detections (case_id);

CREATE TABLE case_events (
    case_id         BIGINT NOT NULL REFERENCES cases (id),
    event_id        TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    added_by        TEXT NOT NULL,
    note            TEXT,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, event_id, event_timestamp),
    FOREIGN KEY (event_id, event_timestamp) REFERENCES events (id, timestamp)
);

CREATE TABLE case_notes (
    id      BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases (id),
    at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    author  TEXT NOT NULL,
    body    TEXT NOT NULL
);

CREATE INDEX idx_case_notes_case ON case_notes (case_id, at);

CREATE TABLE case_history (
    id      BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases (id),
    at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    detail  JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_case_history_case ON case_history (case_id, id);

-- +goose StatementBegin
CREATE FUNCTION reject_history_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER case_history_append_only
    BEFORE UPDATE OR DELETE ON case_history
    FOR EACH ROW EXECUTE FUNCTION reject_history_change();

-- +goose Down
DROP TRIGGER IF EXISTS case_history_append_only ON case_history;
DROP TABLE IF EXISTS case_history;
DROP FUNCTION IF EXISTS reject_history_change();
DROP TABLE IF EXISTS case_notes;
DROP TABLE IF EXISTS case_events;
DROP TABLE IF EXISTS case_detections;
DROP TABLE IF EXISTS cases;
