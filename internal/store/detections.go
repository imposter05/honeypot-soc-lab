/*
Hiten | 2026
detections.go

Reads for detections, rules and observables.
*/

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

// SyncRules records every loaded rule version so detections can
// reference the exact version that produced them.
func (s *PgxStore) SyncRules(ctx context.Context, rules []RuleRow) error {
	for _, r := range rules {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO rules (id, version, name, enabled, definition)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id, version) DO UPDATE SET
				name = EXCLUDED.name, enabled = EXCLUDED.enabled,
				definition = EXCLUDED.definition, loaded_at = NOW()`,
			r.ID, r.Version, r.Name, r.Enabled, r.Definition); err != nil {
			return fmt.Errorf("saving rule %s v%d: %w", r.ID, r.Version, err)
		}
	}
	return nil
}

type RuleRow struct {
	ID         string
	Version    int
	Name       string
	Enabled    bool
	Definition json.RawMessage
}

type RuleStat struct {
	RuleID       string     `json:"rule_id"`
	Detections   int64      `json:"detections"`
	Suppressed   int64      `json:"suppressed_repeats"`
	LastDetected *time.Time `json:"last_detected,omitempty"`
}

func (s *PgxStore) RuleStats(ctx context.Context) (map[string]RuleStat, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rule_id, COUNT(*), COALESCE(SUM(suppressed_count), 0), MAX(detected_at)
		FROM detections GROUP BY rule_id`)
	if err != nil {
		return nil, fmt.Errorf("rule stats: %w", err)
	}
	defer rows.Close()
	out := map[string]RuleStat{}
	for rows.Next() {
		var r RuleStat
		if err := rows.Scan(&r.RuleID, &r.Detections, &r.Suppressed, &r.LastDetected); err != nil {
			return nil, err
		}
		out[r.RuleID] = r
	}
	return out, rows.Err()
}

const detectionCols = `d.id, d.rule_id, d.rule_version, d.rule_name, d.severity,
	d.confidence, d.sensor_id, d.source_ip, COALESCE(d.session_id, ''),
	d.service_type::text, d.group_key, d.first_seen, d.last_seen,
	d.detected_at, d.explanation, d.matched_values, d.mitre,
	d.suppressed_count, cd.case_id`

const detectionFrom = ` FROM detections d LEFT JOIN case_detections cd ON cd.detection_id = d.id`

func scanDetection(row pgx.Row) (*types.Detection, error) {
	var d types.Detection
	var svc string
	var values []byte
	if err := row.Scan(&d.ID, &d.RuleID, &d.RuleVersion, &d.RuleName,
		&d.Severity, &d.Confidence, &d.SensorID, &d.SourceIP, &d.SessionID,
		&svc, &d.GroupKey, &d.FirstSeen, &d.LastSeen, &d.DetectedAt,
		&d.Explanation, &values, &d.MITRE, &d.SuppressedCount, &d.CaseID,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning detection: %w", err)
	}
	d.ServiceType, _ = types.ParseServiceType(svc)
	_ = json.Unmarshal(values, &d.MatchedValues)
	return &d, nil
}

type DetectionFilter struct {
	RuleID    string
	SourceIP  string
	SessionID string
	CaseID    int64
	Severity  string
	Since     time.Time
	Limit     int
	Offset    int
}

func (s *PgxStore) ListDetections(ctx context.Context, f DetectionFilter) ([]*types.Detection, int64, error) {
	w := &whereBuilder{}
	if f.RuleID != "" {
		w.add("d.rule_id = ?", f.RuleID)
	}
	if f.SourceIP != "" {
		w.add("d.source_ip = ?", f.SourceIP)
	}
	if f.SessionID != "" {
		w.add("d.session_id = ?", f.SessionID)
	}
	if f.CaseID > 0 {
		w.add("cd.case_id = ?", f.CaseID)
	}
	if f.Severity != "" {
		w.add("d.severity = ?", f.Severity)
	}
	if !f.Since.IsZero() {
		w.add("d.detected_at >= ?", f.Since)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*)"+detectionFrom+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting detections: %w", err)
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s%s%s ORDER BY d.detected_at DESC, d.id DESC LIMIT $%d OFFSET $%d",
		detectionCols, detectionFrom, w.sql(), len(w.args)+1, len(w.args)+2), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing detections: %w", err)
	}
	defer rows.Close()
	out := []*types.Detection{}
	for rows.Next() {
		d, err := scanDetection(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

func (s *PgxStore) GetDetection(ctx context.Context, id int64) (*types.Detection, error) {
	d, err := scanDetection(s.pool.QueryRow(ctx,
		"SELECT "+detectionCols+detectionFrom+" WHERE d.id = $1", id))
	if err != nil {
		return nil, err
	}
	d.Evidence, err = s.DetectionEvidence(ctx, id)
	return d, err
}

func (s *PgxStore) DetectionEvidence(ctx context.Context, id int64) ([]types.DetectionEvidence, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_timestamp, role FROM detection_evidence
		WHERE detection_id = $1 ORDER BY event_timestamp, event_id`, id)
	if err != nil {
		return nil, fmt.Errorf("loading evidence: %w", err)
	}
	defer rows.Close()
	out := []types.DetectionEvidence{}
	for rows.Next() {
		var e types.DetectionEvidence
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Role); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DetectionsForEvent lists detections that cite an event.
func (s *PgxStore) DetectionsForEvent(ctx context.Context, ref types.EventRef) ([]*types.Detection, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+detectionCols+detectionFrom+`
		JOIN detection_evidence de ON de.detection_id = d.id
		WHERE de.event_id = $1 AND de.event_timestamp = $2
		ORDER BY d.detected_at`, ref.ID, ref.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("detections for event: %w", err)
	}
	defer rows.Close()
	out := []*types.Detection{}
	for rows.Next() {
		d, err := scanDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type TechniqueCount struct {
	TechniqueID string `json:"technique_id"`
	Count       int64  `json:"count"`
}

func (s *PgxStore) TechniqueCounts(ctx context.Context, since time.Time) ([]TechniqueCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t, COUNT(*) FROM detections, unnest(mitre) AS t
		WHERE detected_at >= $1 GROUP BY t ORDER BY 2 DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("technique counts: %w", err)
	}
	defer rows.Close()
	out := []TechniqueCount{}
	for rows.Next() {
		var t TechniqueCount
		if err := rows.Scan(&t.TechniqueID, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- observables -------------------------------------------------------

const iocCols = `id, type::text, value, COALESCE(original_value, ''), first_seen,
	last_seen, sight_count, confidence, source, tags, status, is_internal, claimed`

func scanIOC(row pgx.Row) (*types.IOC, error) {
	var o types.IOC
	var t string
	if err := row.Scan(&o.ID, &t, &o.Value, &o.Original, &o.FirstSeen,
		&o.LastSeen, &o.SightCount, &o.Confidence, &o.Source, &o.Tags,
		&o.Status, &o.Internal, &o.Claimed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning observable: %w", err)
	}
	o.Type, _ = types.ParseIOCType(t)
	return &o, nil
}

type ObservableFilter struct {
	Type      string
	Status    string
	Internal  *bool
	Search    string
	SessionID string
	CaseID    int64
	Limit     int
	Offset    int
}

func (s *PgxStore) ListObservables(ctx context.Context, f ObservableFilter) ([]*types.IOC, int64, error) {
	w := &whereBuilder{}
	if f.Type != "" {
		w.add("type::text = ?", f.Type)
	}
	if f.Status != "" {
		w.add("status = ?", f.Status)
	}
	if f.Internal != nil {
		w.add("is_internal = ?", *f.Internal)
	}
	if f.Search != "" {
		w.add("value ILIKE '%' || ? || '%'", f.Search)
	}
	if f.SessionID != "" {
		w.add("id IN (SELECT ioc_id FROM observable_evidence WHERE session_id = ?)", f.SessionID)
	}
	if f.CaseID > 0 {
		w.add(`id IN (SELECT oe.ioc_id FROM observable_evidence oe
			WHERE (oe.event_id, oe.event_timestamp) IN (`+caseEventRefsSQL+`))`, f.CaseID)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM iocs"+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting observables: %w", err)
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM iocs%s ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d",
		iocCols, w.sql(), len(w.args)+1, len(w.args)+2), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing observables: %w", err)
	}
	defer rows.Close()
	out := []*types.IOC{}
	for rows.Next() {
		o, err := scanIOC(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, o)
	}
	return out, total, rows.Err()
}

func (s *PgxStore) GetObservable(ctx context.Context, id int64) (*types.IOC, error) {
	o, err := scanIOC(s.pool.QueryRow(ctx, "SELECT "+iocCols+" FROM iocs WHERE id = $1", id))
	if err != nil {
		return nil, err
	}
	o.Evidence, err = s.observableEvidence(ctx, id)
	return o, err
}

func (s *PgxStore) observableEvidence(ctx context.Context, id int64) ([]types.ObservableEvidence, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_timestamp, session_id, linked_at FROM observable_evidence
		WHERE ioc_id = $1 ORDER BY event_timestamp`, id)
	if err != nil {
		return nil, fmt.Errorf("observable evidence: %w", err)
	}
	defer rows.Close()
	out := []types.ObservableEvidence{}
	for rows.Next() {
		var e types.ObservableEvidence
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SessionID, &e.LinkedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ObservablesByIDs loads the selected observables with evidence,
// in the order given. Unknown IDs are returned in missing.
func (s *PgxStore) ObservablesByIDs(ctx context.Context, ids []int64) ([]*types.IOC, []int64, error) {
	var out []*types.IOC
	var missing []int64
	for _, id := range ids {
		o, err := s.GetObservable(ctx, id)
		if errors.Is(err, ErrNotFound) {
			missing = append(missing, id)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		out = append(out, o)
	}
	return out, missing, nil
}

func (s *PgxStore) SetObservableStatus(ctx context.Context, id int64, status string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE iocs SET status = $2 WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("updating observable status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
