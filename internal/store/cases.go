/*
Hiten | 2026
cases.go

Case storage. Every change to a case writes a case_history row in
the same transaction, so the history always matches the case.
*/

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

var ErrConflict = errors.New("conflict")

// caseEventRefsSQL selects every (event_id, event_timestamp) that
// belongs to a case, through its detections or added directly.
// The single ? is the case ID.
const caseEventRefsSQL = `
	SELECT de.event_id, de.event_timestamp FROM detection_evidence de
	JOIN case_detections cdx ON cdx.detection_id = de.detection_id
	WHERE cdx.case_id = ?
	UNION
	SELECT ce.event_id, ce.event_timestamp FROM case_events ce WHERE ce.case_id = ?`

func CaseRef(id int64) string { return fmt.Sprintf("CASE-%05d", id) }

const caseCols = `c.id, c.title, c.status, c.severity, COALESCE(c.verdict, ''),
	c.sensor_id, c.source_ip, c.first_activity, c.last_activity, c.created_at,
	c.updated_at, c.closed_at, COALESCE(c.response_decision, ''),
	COALESCE(c.closure_reason, ''), c.merged_into,
	(SELECT COUNT(*) FROM case_detections x WHERE x.case_id = c.id)`

func scanCase(row pgx.Row) (*types.Case, error) {
	var c types.Case
	if err := row.Scan(&c.ID, &c.Title, &c.Status, &c.Severity, &c.Verdict,
		&c.SensorID, &c.SourceIP, &c.FirstActivity, &c.LastActivity,
		&c.CreatedAt, &c.UpdatedAt, &c.ClosedAt, &c.ResponseDecision,
		&c.ClosureReason, &c.MergedInto, &c.DetectionCount); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning case: %w", err)
	}
	c.Ref = CaseRef(c.ID)
	return &c, nil
}

func addHistory(ctx context.Context, tx pgx.Tx, caseID int64, actor, action string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, _ := json.Marshal(detail)
	_, err := tx.Exec(ctx, `INSERT INTO case_history (case_id, actor, action, detail)
		VALUES ($1, $2, $3, $4)`, caseID, actor, action, b)
	if err != nil {
		return fmt.Errorf("writing case history: %w", err)
	}
	return nil
}

func higher(a, b string) string {
	if config.SeverityRank[b] > config.SeverityRank[a] {
		return b
	}
	return a
}

// AttachResult says which cases were touched and which were new.
type AttachResult struct {
	CaseIDs []int64
	Created []int64
	// Severity holds [before, after] for cases whose severity was
	// set or changed in this call. Created cases have before = "".
	Severity map[int64][2]string
}

// AttachDetections links each detection to an open case for the
// same sensor and source whose last activity is within window,
// or creates a case. Detections already linked only refresh the
// case's last activity.
func (s *PgxStore) AttachDetections(
	ctx context.Context, dets []types.Detection, window time.Duration, actor string,
) (*AttachResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	res := &AttachResult{Severity: map[int64][2]string{}}
	touched := map[int64]bool{}
	for _, d := range dets {
		if d.ID == 0 {
			continue
		}
		var caseID int64
		err := tx.QueryRow(ctx, `SELECT case_id FROM case_detections WHERE detection_id = $1`, d.ID).Scan(&caseID)
		if err == nil {
			if _, err := tx.Exec(ctx, `UPDATE cases SET
				last_activity = GREATEST(last_activity, $2), updated_at = NOW()
				WHERE id = $1`, caseID, d.LastSeen); err != nil {
				return nil, err
			}
			if !touched[caseID] {
				touched[caseID] = true
				res.CaseIDs = append(res.CaseIDs, caseID)
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}

		var sev string
		err = tx.QueryRow(ctx, `
			SELECT id, severity FROM cases
			WHERE status <> 'closed' AND merged_into IS NULL
			  AND sensor_id = $1 AND source_ip = $2 AND last_activity >= $3
			ORDER BY last_activity DESC LIMIT 1 FOR UPDATE`,
			d.SensorID, d.SourceIP, d.FirstSeen.Add(-window)).Scan(&caseID, &sev)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			title := fmt.Sprintf("%s from %s", d.RuleName, d.SourceIP)
			if err := tx.QueryRow(ctx, `
				INSERT INTO cases (title, severity, sensor_id, source_ip, first_activity, last_activity)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
				title, d.Severity, d.SensorID, d.SourceIP, d.FirstSeen, d.LastSeen,
			).Scan(&caseID); err != nil {
				return nil, fmt.Errorf("creating case: %w", err)
			}
			sev = d.Severity
			res.Created = append(res.Created, caseID)
			res.Severity[caseID] = [2]string{"", sev}
			if err := addHistory(ctx, tx, caseID, actor, "case_created", map[string]any{
				"reason":       "no open case for this sensor and source within the correlation window",
				"window":       window.String(),
				"detection_id": d.ID,
			}); err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		}

		if _, err := tx.Exec(ctx, `INSERT INTO case_detections (case_id, detection_id) VALUES ($1, $2)`,
			caseID, d.ID); err != nil {
			return nil, fmt.Errorf("linking detection: %w", err)
		}
		newSev := higher(sev, d.Severity)
		if _, err := tx.Exec(ctx, `UPDATE cases SET
			first_activity = LEAST(first_activity, $2),
			last_activity = GREATEST(last_activity, $3),
			severity = $4, updated_at = NOW() WHERE id = $1`,
			caseID, d.FirstSeen, d.LastSeen, newSev); err != nil {
			return nil, err
		}
		if err := addHistory(ctx, tx, caseID, actor, "detection_linked", map[string]any{
			"detection_id": d.ID, "rule_id": d.RuleID, "explanation": d.Explanation,
		}); err != nil {
			return nil, err
		}
		if newSev != sev {
			before := sev
			if prev, ok := res.Severity[caseID]; ok {
				before = prev[0]
			}
			res.Severity[caseID] = [2]string{before, newSev}
			if err := addHistory(ctx, tx, caseID, actor, "severity_changed", map[string]any{
				"from": sev, "to": newSev, "because": d.RuleID,
			}); err != nil {
				return nil, err
			}
		}
		if !touched[caseID] {
			touched[caseID] = true
			res.CaseIDs = append(res.CaseIDs, caseID)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

type CaseFilter struct {
	Status        string
	Severity      string
	SourceIP      string
	IncludeMerged bool
	Limit         int
	Offset        int
}

func (s *PgxStore) ListCases(ctx context.Context, f CaseFilter) ([]*types.Case, int64, error) {
	w := &whereBuilder{}
	switch f.Status {
	case "":
	case "open":
		w.parts = append(w.parts, "c.status <> 'closed'")
	default:
		w.add("c.status = ?", f.Status)
	}
	if f.Severity != "" {
		w.add("c.severity = ?", f.Severity)
	}
	if f.SourceIP != "" {
		w.add("c.source_ip = ?", f.SourceIP)
	}
	if !f.IncludeMerged {
		w.parts = append(w.parts, "c.merged_into IS NULL")
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM cases c"+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting cases: %w", err)
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM cases c%s
		ORDER BY CASE c.status WHEN 'closed' THEN 1 ELSE 0 END, c.last_activity DESC
		LIMIT $%d OFFSET $%d`, caseCols, w.sql(), len(w.args)+1, len(w.args)+2), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing cases: %w", err)
	}
	defer rows.Close()
	out := []*types.Case{}
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *PgxStore) GetCase(ctx context.Context, id int64) (*types.Case, error) {
	c, err := scanCase(s.pool.QueryRow(ctx, "SELECT "+caseCols+" FROM cases c WHERE c.id = $1", id))
	if err != nil {
		return nil, err
	}
	refs, err := s.CaseEventRefs(ctx, id)
	if err != nil {
		return nil, err
	}
	c.EventCount = len(refs)
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT e.session_id, e.service_type::text FROM events e
		WHERE (e.id, e.timestamp) IN (`+sqlArgs(caseEventRefsSQL, 1)+`)`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions, services := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var sid, svc string
		if err := rows.Scan(&sid, &svc); err != nil {
			return nil, err
		}
		if !sessions[sid] {
			sessions[sid] = true
			c.SessionIDs = append(c.SessionIDs, sid)
		}
		if !services[svc] {
			services[svc] = true
			c.Services = append(c.Services, svc)
		}
	}
	return c, rows.Err()
}

func sqlArgs(q string, n int) string {
	out := []byte{}
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			out = append(out, []byte(fmt.Sprintf("$%d", n))...)
		} else {
			out = append(out, q[i])
		}
	}
	return string(out)
}

func (s *PgxStore) CaseEventRefs(ctx context.Context, id int64) ([]types.EventRef, error) {
	rows, err := s.pool.Query(ctx, sqlArgs(caseEventRefsSQL, 1)+` ORDER BY 2`, id)
	if err != nil {
		return nil, fmt.Errorf("case event refs: %w", err)
	}
	defer rows.Close()
	out := []types.EventRef{}
	for rows.Next() {
		var r types.EventRef
		if err := rows.Scan(&r.ID, &r.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PgxStore) CaseHistory(ctx context.Context, id int64) ([]types.CaseHistoryEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, case_id, at, actor, action, detail
		FROM case_history WHERE case_id = $1 ORDER BY id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.CaseHistoryEntry{}
	for rows.Next() {
		var h types.CaseHistoryEntry
		var detail []byte
		if err := rows.Scan(&h.ID, &h.CaseID, &h.At, &h.Actor, &h.Action, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &h.Detail)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *PgxStore) CaseNotes(ctx context.Context, id int64) ([]types.CaseNote, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, case_id, at, author, body
		FROM case_notes WHERE case_id = $1 ORDER BY at, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.CaseNote{}
	for rows.Next() {
		var n types.CaseNote
		if err := rows.Scan(&n.ID, &n.CaseID, &n.At, &n.Author, &n.Body); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *PgxStore) CaseDirectEvents(ctx context.Context, id int64) ([]types.CaseEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT event_id, event_timestamp, added_by,
		COALESCE(note, ''), added_at FROM case_events WHERE case_id = $1 ORDER BY added_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.CaseEvent{}
	for rows.Next() {
		var e types.CaseEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AddedBy, &e.Note, &e.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CasePatch holds the fields an analyst can change. Nil means
// unchanged.
type CasePatch struct {
	Title            *string
	Status           *string
	Severity         *string
	Verdict          *string
	ResponseDecision *string
	ClosureReason    *string
}

// UpdateCase applies a validated patch and records one history row
// per changed field.
func (s *PgxStore) UpdateCase(ctx context.Context, id int64, p CasePatch, actor string) (*types.Case, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanCase(tx.QueryRow(ctx, "SELECT "+caseCols+" FROM cases c WHERE c.id = $1 FOR UPDATE", id))
	if err != nil {
		return nil, err
	}

	type change struct {
		col, field string
		from       string
		to         *string
	}
	changes := []change{
		{"title", "title", cur.Title, p.Title},
		{"severity", "severity", cur.Severity, p.Severity},
		{"verdict", "verdict", cur.Verdict, p.Verdict},
		{"response_decision", "response_decision", cur.ResponseDecision, p.ResponseDecision},
		{"closure_reason", "closure_reason", cur.ClosureReason, p.ClosureReason},
		{"status", "status", cur.Status, p.Status},
	}
	for _, c := range changes {
		if c.to == nil || *c.to == c.from {
			continue
		}
		q := fmt.Sprintf(`UPDATE cases SET %s = NULLIF($2, ''), updated_at = NOW() WHERE id = $1`, c.col)
		if c.col == "status" {
			q = `UPDATE cases SET status = $2, updated_at = NOW(),
				closed_at = CASE WHEN $2 = 'closed' THEN NOW() ELSE NULL END WHERE id = $1`
		}
		if _, err := tx.Exec(ctx, q, id, *c.to); err != nil {
			return nil, fmt.Errorf("updating %s: %w", c.field, err)
		}
		if err := addHistory(ctx, tx, id, actor, c.field+"_changed", map[string]any{
			"from": c.from, "to": *c.to,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("saving case: %w", err)
	}
	return s.GetCase(ctx, id)
}

func (s *PgxStore) AddCaseNote(ctx context.Context, id int64, author, body string) (*types.CaseNote, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n := types.CaseNote{CaseID: id, Author: author, Body: body}
	if err := tx.QueryRow(ctx, `INSERT INTO case_notes (case_id, author, body)
		VALUES ($1, $2, $3) RETURNING id, at`, id, author, body).Scan(&n.ID, &n.At); err != nil {
		return nil, fmt.Errorf("adding note: %w", err)
	}
	if err := addHistory(ctx, tx, id, author, "note_added", map[string]any{"note_id": n.ID}); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE cases SET updated_at = NOW() WHERE id = $1`, id); err != nil {
		return nil, err
	}
	return &n, tx.Commit(ctx)
}

func (s *PgxStore) AddCaseEvent(ctx context.Context, id int64, ref types.EventRef, actor, note string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO case_events (case_id, event_id, event_timestamp, added_by, note)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')) ON CONFLICT DO NOTHING`,
		id, ref.ID, ref.Timestamp, actor, note)
	if err != nil {
		return fmt.Errorf("linking event: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	if err := addHistory(ctx, tx, id, actor, "evidence_added", map[string]any{
		"event_id": ref.ID, "event_timestamp": ref.Timestamp, "note": note,
	}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE cases SET updated_at = NOW() WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SplitCase moves the given detections into a new case for the same
// sensor and source.
func (s *PgxStore) SplitCase(ctx context.Context, id int64, detIDs []int64, title, actor string) (int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanCase(tx.QueryRow(ctx, "SELECT "+caseCols+" FROM cases c WHERE c.id = $1 FOR UPDATE", id))
	if err != nil {
		return 0, err
	}
	var owned int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM case_detections
		WHERE case_id = $1 AND detection_id = ANY($2)`, id, detIDs).Scan(&owned); err != nil {
		return 0, err
	}
	if owned != len(detIDs) {
		return 0, fmt.Errorf("%w: some detections are not in %s", ErrConflict, cur.Ref)
	}
	if owned >= cur.DetectionCount {
		return 0, fmt.Errorf("%w: a split must leave at least one detection behind", ErrConflict)
	}

	var first, last time.Time
	var sev string
	if err := tx.QueryRow(ctx, `SELECT MIN(first_seen), MAX(last_seen),
		(ARRAY_AGG(severity ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
			WHEN 'medium' THEN 2 ELSE 1 END DESC))[1]
		FROM detections WHERE id = ANY($1)`, detIDs).Scan(&first, &last, &sev); err != nil {
		return 0, err
	}
	if title == "" {
		title = cur.Title + " (split)"
	}
	var newID int64
	if err := tx.QueryRow(ctx, `INSERT INTO cases (title, severity, sensor_id, source_ip,
		first_activity, last_activity) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		title, sev, cur.SensorID, cur.SourceIP, first, last).Scan(&newID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE case_detections SET case_id = $1 WHERE detection_id = ANY($2)`,
		newID, detIDs); err != nil {
		return 0, err
	}
	if err := addHistory(ctx, tx, id, actor, "split_out", map[string]any{
		"new_case": CaseRef(newID), "detection_ids": detIDs,
	}); err != nil {
		return 0, err
	}
	if err := addHistory(ctx, tx, newID, actor, "split_from", map[string]any{
		"from_case": cur.Ref, "detection_ids": detIDs,
	}); err != nil {
		return 0, err
	}
	return newID, tx.Commit(ctx)
}

// MergeCase moves everything from src into dst and marks src as
// merged. The merged case keeps its history and remains readable.
func (s *PgxStore) MergeCase(ctx context.Context, dst, src int64, actor string) error {
	if dst == src {
		return fmt.Errorf("%w: cannot merge a case into itself", ErrConflict)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	d, err := scanCase(tx.QueryRow(ctx, "SELECT "+caseCols+" FROM cases c WHERE c.id = $1 FOR UPDATE", dst))
	if err != nil {
		return err
	}
	sc, err := scanCase(tx.QueryRow(ctx, "SELECT "+caseCols+" FROM cases c WHERE c.id = $1 FOR UPDATE", src))
	if err != nil {
		return err
	}
	if d.MergedInto != nil || sc.MergedInto != nil {
		return fmt.Errorf("%w: one of the cases was already merged", ErrConflict)
	}
	if d.Status == types.CaseClosed {
		return fmt.Errorf("%w: reopen %s before merging into it", ErrConflict, d.Ref)
	}
	if _, err := tx.Exec(ctx, `UPDATE case_detections SET case_id = $1 WHERE case_id = $2`, dst, src); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO case_events (case_id, event_id, event_timestamp, added_by, note, added_at)
		SELECT $1, event_id, event_timestamp, added_by, note, added_at FROM case_events WHERE case_id = $2
		ON CONFLICT DO NOTHING`, dst, src); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE cases SET
		first_activity = LEAST(first_activity, $2), last_activity = GREATEST(last_activity, $3),
		severity = $4, updated_at = NOW() WHERE id = $1`,
		dst, sc.FirstActivity, sc.LastActivity, higher(d.Severity, sc.Severity)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE cases SET merged_into = $1, updated_at = NOW() WHERE id = $2`, dst, src); err != nil {
		return err
	}
	if err := addHistory(ctx, tx, dst, actor, "merged_in", map[string]any{"from_case": sc.Ref}); err != nil {
		return err
	}
	if err := addHistory(ctx, tx, src, actor, "merged_into", map[string]any{"into_case": d.Ref}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordCaseExport writes an export to the case history.
func (s *PgxStore) RecordCaseExport(ctx context.Context, id int64, actor string, detail map[string]any) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := addHistory(ctx, tx, id, actor, "exported", detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
