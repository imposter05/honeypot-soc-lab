-- Hiten | 2026
-- 014_detections.sql
-- Rule-based detections with links back to the events that caused
-- them. events has a composite primary key (id, timestamp) because it
-- is partitioned by timestamp, so evidence rows store both columns and
-- the foreign key uses both. The old mitre_detections table is kept
-- for existing data but is no longer written.

-- +goose Up
CREATE TABLE rules (
    id          TEXT NOT NULL,
    version     INTEGER NOT NULL,
    name        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL,
    definition  JSONB NOT NULL,
    loaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, version)
);

CREATE TABLE detections (
    id               BIGSERIAL PRIMARY KEY,
    rule_id          TEXT NOT NULL,
    rule_version     INTEGER NOT NULL,
    rule_name        TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    confidence       TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    sensor_id        TEXT NOT NULL,
    source_ip        TEXT NOT NULL,
    session_id       TEXT,
    service_type     service_type NOT NULL,
    group_key        TEXT NOT NULL,
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL,
    explanation      TEXT NOT NULL,
    matched_values   JSONB NOT NULL DEFAULT '{}',
    mitre            TEXT[] NOT NULL DEFAULT '{}',
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (rule_id, rule_version) REFERENCES rules (id, version)
);

CREATE INDEX idx_detections_rule ON detections (rule_id);
CREATE INDEX idx_detections_source ON detections (source_ip);
CREATE INDEX idx_detections_session ON detections (session_id);
CREATE INDEX idx_detections_detected ON detections (detected_at DESC);
CREATE INDEX idx_detections_mitre ON detections USING GIN (mitre);

CREATE TABLE detection_evidence (
    detection_id    BIGINT NOT NULL REFERENCES detections (id) ON DELETE CASCADE,
    event_id        TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('trigger','contributing','repeat')),
    PRIMARY KEY (detection_id, event_id, event_timestamp),
    FOREIGN KEY (event_id, event_timestamp) REFERENCES events (id, timestamp)
);

CREATE INDEX idx_detection_evidence_event ON detection_evidence (event_id, event_timestamp);

-- +goose Down
DROP TABLE IF EXISTS detection_evidence;
DROP TABLE IF EXISTS detections;
DROP TABLE IF EXISTS rules;
