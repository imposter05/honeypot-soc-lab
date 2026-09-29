-- Hiten | 2026
-- 018_lab_runs.sql
-- Results reported by cmd/labtest. Scenario data is only used for
-- evaluation; detection rules never read this table.

-- +goose Up
CREATE TABLE scenario_runs (
    id          BIGSERIAL PRIMARY KEY,
    run_id      TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    kind        TEXT NOT NULL,
    source_ip   TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    passed      BOOLEAN NOT NULL,
    skipped     BOOLEAN NOT NULL DEFAULT FALSE,
    expected    JSONB NOT NULL DEFAULT '{}',
    observed    JSONB NOT NULL DEFAULT '{}',
    failures    TEXT[] NOT NULL DEFAULT '{}',
    notes       TEXT,
    UNIQUE (run_id, scenario_id)
);

CREATE INDEX idx_scenario_runs_started ON scenario_runs (started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS scenario_runs;
