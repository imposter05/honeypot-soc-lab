/*
Hiten | 2026
actions.go

Storage for response actions. State changes go through Transition,
which locks the row, checks the current state and writes the
history row in the same transaction.
*/

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

var (
	ErrDuplicate         = errors.New("an open action already exists")
	ErrInvalidTransition = errors.New("invalid state change")
)

const actionCols = `id, case_id, playbook, source_ip, sensor_id, services, state,
	summary, requested_at, decided_at, COALESCE(decided_by, ''), expires_at,
	ended_at, verification, COALESCE(error, '')`

func scanAction(row pgx.Row) (*types.ResponseAction, error) {
	var a types.ResponseAction
	var verif []byte
	if err := row.Scan(&a.ID, &a.CaseID, &a.Playbook, &a.SourceIP, &a.SensorID,
		&a.Services, &a.State, &a.Summary, &a.RequestedAt, &a.DecidedAt,
		&a.DecidedBy, &a.ExpiresAt, &a.EndedAt, &verif, &a.Error); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning action: %w", err)
	}
	if len(verif) > 0 {
		_ = json.Unmarshal(verif, &a.Verification)
	}
	return &a, nil
}

func addActionHistory(ctx context.Context, tx pgx.Tx, id int64, actor, from, to string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, _ := json.Marshal(detail)
	_, err := tx.Exec(ctx, `INSERT INTO action_history (action_id, actor, from_state, to_state, detail)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)`, id, actor, from, to, b)
	return err
}

// CreateAction inserts a pending action. If an open action already
// exists for the same playbook, sensor and source, it returns that
// action and ErrDuplicate.
func (s *PgxStore) CreateAction(ctx context.Context, a *types.ResponseAction, actor string) (*types.ResponseAction, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO response_actions
		(case_id, playbook, source_ip, sensor_id, services, state, summary)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		a.CaseID, a.Playbook, a.SourceIP, a.SensorID, a.Services, types.ActionPending, a.Summary,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			_ = tx.Rollback(ctx)
			existing, gerr := scanAction(s.pool.QueryRow(ctx, "SELECT "+actionCols+
				` FROM response_actions WHERE playbook = $1 AND sensor_id = $2 AND source_ip = $3
				AND state IN ('pending_approval','active') LIMIT 1`, a.Playbook, a.SensorID, a.SourceIP))
			if gerr != nil {
				return nil, ErrDuplicate
			}
			return existing, ErrDuplicate
		}
		return nil, fmt.Errorf("creating action: %w", err)
	}
	if err := addActionHistory(ctx, tx, id, actor, "", types.ActionPending, map[string]any{
		"summary": a.Summary, "case_id": a.CaseID,
	}); err != nil {
		return nil, err
	}
	if err := addHistory(ctx, tx, a.CaseID, actor, "response_requested", map[string]any{
		"action_id": id, "playbook": a.Playbook,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetAction(ctx, id)
}

func (s *PgxStore) GetAction(ctx context.Context, id int64) (*types.ResponseAction, error) {
	return scanAction(s.pool.QueryRow(ctx, "SELECT "+actionCols+" FROM response_actions WHERE id = $1", id))
}

type ActionFilter struct {
	CaseID int64
	State  string
	Limit  int
	Offset int
}

func (s *PgxStore) ListActions(ctx context.Context, f ActionFilter) ([]*types.ResponseAction, int64, error) {
	w := &whereBuilder{}
	if f.CaseID > 0 {
		w.add("case_id = ?", f.CaseID)
	}
	if f.State != "" {
		w.add("state = ?", f.State)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM response_actions"+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf("SELECT %s FROM response_actions%s ORDER BY id DESC LIMIT $%d OFFSET $%d",
		actionCols, w.sql(), len(w.args)+1, len(w.args)+2), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*types.ResponseAction{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (s *PgxStore) ActionHistory(ctx context.Context, id int64) ([]types.ActionHistoryEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, action_id, at, actor, COALESCE(from_state, ''),
		to_state, detail FROM action_history WHERE action_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.ActionHistoryEntry{}
	for rows.Next() {
		var h types.ActionHistoryEntry
		var detail []byte
		if err := rows.Scan(&h.ID, &h.ActionID, &h.At, &h.Actor, &h.From, &h.To, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &h.Detail)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ActionUpdate holds fields written alongside a state change.
type ActionUpdate struct {
	DecidedBy    *string
	Decided      bool
	ExpiresAt    *time.Time
	Ended        bool
	Services     []string
	Verification map[string]any
	Error        *string
}

// Transition moves an action from one of the allowed states to the
// new state.
func (s *PgxStore) Transition(
	ctx context.Context, id int64, from []string, to, actor string,
	u ActionUpdate, detail map[string]any,
) (*types.ResponseAction, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cur, err := scanAction(tx.QueryRow(ctx, "SELECT "+actionCols+" FROM response_actions WHERE id = $1 FOR UPDATE", id))
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, f := range from {
		if cur.State == f {
			allowed = true
		}
	}
	if !allowed {
		return cur, fmt.Errorf("%w: action %d is %s, cannot move to %s", ErrInvalidTransition, id, cur.State, to)
	}
	var verif []byte
	if u.Verification != nil {
		verif, _ = json.Marshal(u.Verification)
	}
	if _, err := tx.Exec(ctx, `UPDATE response_actions SET
		state = $2,
		decided_by = COALESCE($3, decided_by),
		decided_at = CASE WHEN $4 THEN NOW() ELSE decided_at END,
		expires_at = COALESCE($5, expires_at),
		ended_at = CASE WHEN $6 THEN NOW() ELSE ended_at END,
		services = COALESCE($7, services),
		verification = COALESCE($8, verification),
		error = COALESCE($9, error)
		WHERE id = $1`,
		id, to, u.DecidedBy, u.Decided, u.ExpiresAt, u.Ended, u.Services, verif, u.Error,
	); err != nil {
		return nil, fmt.Errorf("updating action: %w", err)
	}
	if err := addActionHistory(ctx, tx, id, actor, cur.State, to, detail); err != nil {
		return nil, err
	}
	if err := addHistory(ctx, tx, cur.CaseID, actor, "response_"+to, map[string]any{
		"action_id": id, "from": cur.State,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetAction(ctx, id)
}

// ---- lab runs -----------------------------------------------------------

func (s *PgxStore) InsertScenarioRun(ctx context.Context, r *types.ScenarioRun) error {
	exp, _ := json.Marshal(r.Expected)
	obs, _ := json.Marshal(r.Observed)
	failures := r.Failures
	if failures == nil {
		failures = []string{}
	}
	return s.pool.QueryRow(ctx, `INSERT INTO scenario_runs (run_id, scenario_id, kind, source_ip,
		started_at, finished_at, passed, skipped, expected, observed, failures, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULLIF($12,''))
		ON CONFLICT (run_id, scenario_id) DO UPDATE SET finished_at = EXCLUDED.finished_at,
			passed = EXCLUDED.passed, skipped = EXCLUDED.skipped, observed = EXCLUDED.observed,
			failures = EXCLUDED.failures, notes = EXCLUDED.notes
		RETURNING id`,
		r.RunID, r.ScenarioID, r.Kind, r.SourceIP, r.StartedAt, r.FinishedAt,
		r.Passed, r.Skipped, exp, obs, failures, r.RunnerNotes).Scan(&r.ID)
}

func (s *PgxStore) ListScenarioRuns(ctx context.Context, limit int) ([]*types.ScenarioRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, scenario_id, kind, source_ip, started_at,
		finished_at, passed, skipped, expected, observed, failures, COALESCE(notes, '')
		FROM scenario_runs ORDER BY started_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*types.ScenarioRun{}
	for rows.Next() {
		var r types.ScenarioRun
		var exp, obs []byte
		if err := rows.Scan(&r.ID, &r.RunID, &r.ScenarioID, &r.Kind, &r.SourceIP,
			&r.StartedAt, &r.FinishedAt, &r.Passed, &r.Skipped, &exp, &obs,
			&r.Failures, &r.RunnerNotes); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(exp, &r.Expected)
		_ = json.Unmarshal(obs, &r.Observed)
		out = append(out, &r)
	}
	return out, rows.Err()
}
