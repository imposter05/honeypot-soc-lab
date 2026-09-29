/*
Hiten | 2026
analysis.go

Writes one processed event and everything derived from it in a
single transaction: the event row, the source summary, credential,
uploaded-file record, session counters, detections with their
evidence links, and observables with theirs. Either all of it is
stored or none of it is.
*/

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type FileRecord struct {
	types.CapturedFile
	StoragePath string
	Truncated   bool
	SizeLimit   int64
}

type Analysis struct {
	Event       *types.Event
	Matches     []detection.Match
	Observables []*types.IOC
	Credential  *types.Credential
	File        *FileRecord
}

type CommitResult struct {
	Seq int64
	// Detections has one entry per match. Suppressed matches carry
	// the ID of the detection they were added to.
	Detections []types.Detection
}

func (s *PgxStore) CommitAnalysis(ctx context.Context, a *Analysis) (*CommitResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ev := a.Event
	res := &CommitResult{}

	if res.Seq, err = insertEvent(ctx, tx, ev); err != nil {
		return nil, err
	}
	if err := upsertSource(ctx, tx, ev); err != nil {
		return nil, err
	}
	if c := a.Credential; c != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO credentials (session_id, timestamp, service_type, source_ip,
				username, password, public_key, auth_method, success)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			c.SessionID, c.Timestamp, c.ServiceType.String(), c.SourceIP,
			c.Username, c.Password, nullStr(c.PublicKey), c.AuthMethod, c.Success,
		); err != nil {
			return nil, fmt.Errorf("inserting credential: %w", err)
		}
	}
	if f := a.File; f != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO captured_files (session_id, timestamp, source_ip, service,
				filename, size, sha256, md5, event_id, event_timestamp,
				storage_path, truncated, size_limit)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			f.SessionID, f.Timestamp, f.SourceIP, f.Service.String(), f.Filename,
			f.Size, f.SHA256, f.MD5, ev.ID, ev.Timestamp, f.StoragePath,
			f.Truncated, f.SizeLimit,
		); err != nil {
			return nil, fmt.Errorf("inserting file record: %w", err)
		}
	}

	var ruleIDs, mitreIDs []string
	for _, m := range a.Matches {
		d, err := storeMatch(ctx, tx, m)
		if err != nil {
			return nil, err
		}
		res.Detections = append(res.Detections, d)
		if !m.Suppressed {
			ruleIDs = append(ruleIDs, d.RuleID)
			mitreIDs = append(mitreIDs, d.MITRE...)
		}
	}

	isCommand := ev.EventType == types.EventCommand
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET
			last_activity = GREATEST(COALESCE(last_activity, $2), $2),
			command_count = command_count + CASE WHEN $3 THEN 1 ELSE 0 END,
			rule_ids = ARRAY(SELECT DISTINCT unnest(rule_ids || $4::text[])),
			mitre_techniques = ARRAY(SELECT DISTINCT unnest(mitre_techniques || $5::text[]))
		WHERE id = $1`,
		ev.SessionID, ev.Timestamp, isCommand, nonNil(ruleIDs), nonNil(mitreIDs),
	); err != nil {
		return nil, fmt.Errorf("updating session counters: %w", err)
	}

	for _, o := range a.Observables {
		if err := storeObservable(ctx, tx, o, ev); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return res, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func insertEvent(ctx context.Context, tx pgx.Tx, ev *types.Event) (int64, error) {
	var cc, country, city, org *string
	var lat, lon *float64
	var asn *int
	if g := ev.Geo; g != nil && g.CountryCode != "" {
		cc, country, city, org = &g.CountryCode, &g.Country, &g.City, &g.Org
		lat, lon, asn = &g.Latitude, &g.Longitude, &g.ASN
	}
	tags := ev.Tags
	if tags == nil {
		tags = []string{}
	}
	var data any
	if len(ev.ServiceData) > 0 {
		data = ev.ServiceData
	}
	var seq int64
	err := tx.QueryRow(ctx, `
		INSERT INTO events (
			id, session_id, sensor_id, timestamp, received_at,
			service_type, event_type, source_ip, source_port,
			dest_ip, dest_port, protocol, schema_version,
			country_code, country, city, latitude, longitude, asn, org,
			tags, service_data, origin
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
			$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		RETURNING seq`,
		ev.ID, ev.SessionID, ev.SensorID, ev.Timestamp, ev.ReceivedAt,
		ev.ServiceType.String(), ev.EventType.String(), ev.SourceIP, ev.SourcePort,
		nullStr(ev.DestIP), ev.DestPort, ev.Protocol.String(), ev.SchemaVersion,
		cc, country, city, lat, lon, asn, org, tags, data, ev.Origin,
	).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("inserting event: %w", err)
	}
	return seq, nil
}

func upsertSource(ctx context.Context, tx pgx.Tx, ev *types.Event) error {
	newSession := 0
	if ev.EventType == types.EventConnect || ev.EventType == types.EventRequest {
		newSession = 1
	}
	var cc, country, city, org *string
	var lat, lon *float64
	var asn *int
	if g := ev.Geo; g != nil && g.CountryCode != "" {
		cc, country, city, org = &g.CountryCode, &g.Country, &g.City, &g.Org
		lat, lon, asn = &g.Latitude, &g.Longitude, &g.ASN
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO attackers (ip, first_seen, last_seen, total_events, total_sessions,
			country_code, country, city, latitude, longitude, asn, org)
		VALUES ($1, $2, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (ip) DO UPDATE SET
			first_seen = LEAST(attackers.first_seen, EXCLUDED.first_seen),
			last_seen = GREATEST(attackers.last_seen, EXCLUDED.last_seen),
			total_events = attackers.total_events + 1,
			total_sessions = attackers.total_sessions + EXCLUDED.total_sessions,
			country_code = COALESCE(EXCLUDED.country_code, attackers.country_code),
			country = COALESCE(EXCLUDED.country, attackers.country),
			city = COALESCE(EXCLUDED.city, attackers.city),
			latitude = COALESCE(EXCLUDED.latitude, attackers.latitude),
			longitude = COALESCE(EXCLUDED.longitude, attackers.longitude),
			asn = COALESCE(EXCLUDED.asn, attackers.asn),
			org = COALESCE(EXCLUDED.org, attackers.org)`,
		ev.SourceIP, ev.Timestamp, newSession, cc, country, city, lat, lon, asn, org)
	if err != nil {
		return fmt.Errorf("upserting source: %w", err)
	}
	return nil
}

func storeMatch(ctx context.Context, tx pgx.Tx, m detection.Match) (types.Detection, error) {
	d := m.Detection
	if m.Suppressed {
		d.ID = m.ExistingID
		if d.ID == 0 {
			return d, nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE detections SET suppressed_count = suppressed_count + 1,
				last_seen = GREATEST(last_seen, $2)
			WHERE id = $1`, d.ID, d.LastSeen); err != nil {
			return d, fmt.Errorf("updating suppressed detection: %w", err)
		}
		for _, e := range m.Evidence {
			if _, err := tx.Exec(ctx, `
				INSERT INTO detection_evidence (detection_id, event_id, event_timestamp, role)
				VALUES ($1, $2, $3, 'repeat') ON CONFLICT DO NOTHING`,
				d.ID, e.ID, e.Timestamp); err != nil {
				return d, fmt.Errorf("linking repeat evidence: %w", err)
			}
		}
		return d, nil
	}

	values, err := json.Marshal(d.MatchedValues)
	if err != nil {
		return d, fmt.Errorf("encoding matched values: %w", err)
	}
	mitre := d.MITRE
	if mitre == nil {
		mitre = []string{}
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO detections (rule_id, rule_version, rule_name, severity, confidence,
			sensor_id, source_ip, session_id, service_type, group_key,
			first_seen, last_seen, detected_at, explanation, matched_values, mitre)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING id`,
		d.RuleID, d.RuleVersion, d.RuleName, d.Severity, d.Confidence,
		d.SensorID, d.SourceIP, nullStr(d.SessionID), d.ServiceType.String(),
		d.GroupKey, d.FirstSeen, d.LastSeen, d.DetectedAt, d.Explanation,
		values, mitre,
	).Scan(&d.ID)
	if err != nil {
		return d, fmt.Errorf("inserting detection %s: %w", d.RuleID, err)
	}
	for _, e := range m.Evidence {
		if _, err := tx.Exec(ctx, `
			INSERT INTO detection_evidence (detection_id, event_id, event_timestamp, role)
			VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			d.ID, e.ID, e.Timestamp, e.Role); err != nil {
			return d, fmt.Errorf("linking evidence for %s: %w", d.RuleID, err)
		}
	}
	d.Evidence = m.Evidence
	return d, nil
}

func storeObservable(ctx context.Context, tx pgx.Tx, o *types.IOC, ev *types.Event) error {
	tags := o.Tags
	if tags == nil {
		tags = []string{}
	}
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO iocs (type, value, original_value, first_seen, last_seen,
			sight_count, confidence, source, tags, status, is_internal, claimed)
		VALUES ($1, $2, $3, $4, $4, 1, 0, $5, $6, 'observed', $7, $8)
		ON CONFLICT (type, value) DO UPDATE SET
			first_seen = LEAST(iocs.first_seen, EXCLUDED.first_seen),
			last_seen = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
			sight_count = iocs.sight_count + 1,
			original_value = COALESCE(iocs.original_value, EXCLUDED.original_value),
			tags = ARRAY(SELECT DISTINCT unnest(iocs.tags || EXCLUDED.tags)),
			is_internal = iocs.is_internal OR EXCLUDED.is_internal,
			claimed = iocs.claimed OR EXCLUDED.claimed
		RETURNING id`,
		o.Type.String(), o.Value, nullStr(o.Original), ev.Timestamp, o.Source,
		tags, o.Internal, o.Claimed,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("upserting observable %s: %w", o.Type, err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO observable_evidence (ioc_id, event_id, event_timestamp, session_id)
		VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		id, ev.ID, ev.Timestamp, ev.SessionID); err != nil {
		return fmt.Errorf("linking observable evidence: %w", err)
	}
	o.ID = id
	return nil
}
