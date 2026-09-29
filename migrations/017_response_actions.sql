-- Hiten | 2026
-- 017_response_actions.sql
-- Restrict-source playbook runs. Only one pending or active action may
-- exist per sensor and source address; that index is the duplicate
-- trigger protection.

-- +goose Up
CREATE TABLE response_actions (
    id           BIGSERIAL PRIMARY KEY,
    case_id      BIGINT NOT NULL REFERENCES cases (id),
    playbook     TEXT NOT NULL,
    source_ip    TEXT NOT NULL,
    sensor_id    TEXT NOT NULL,
    services     TEXT[] NOT NULL,
    state        TEXT NOT NULL CHECK (state IN
        ('pending_approval','rejected','active','failed','expired','reversed')),
    summary      TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at   TIMESTAMPTZ,
    decided_by   TEXT,
    expires_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ,
    verification JSONB,
    error        TEXT
);

CREATE UNIQUE INDEX idx_actions_one_open
    ON response_actions (playbook, sensor_id, source_ip)
    WHERE state IN ('pending_approval','active');
CREATE INDEX idx_actions_case ON response_actions (case_id);

CREATE TABLE action_history (
    id         BIGSERIAL PRIMARY KEY,
    action_id  BIGINT NOT NULL REFERENCES response_actions (id),
    at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor      TEXT NOT NULL,
    from_state TEXT,
    to_state   TEXT NOT NULL,
    detail     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_action_history_action ON action_history (action_id, id);

CREATE TRIGGER action_history_append_only
    BEFORE UPDATE OR DELETE ON action_history
    FOR EACH ROW EXECUTE FUNCTION reject_history_change();

-- +goose Down
DROP TRIGGER IF EXISTS action_history_append_only ON action_history;
DROP TABLE IF EXISTS action_history;
DROP TABLE IF EXISTS response_actions;
