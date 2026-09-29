/*
©AngelaMos | 2026
Modified by Hiten, 2026: pool settings from config, partitions made
on demand for any month (including credentials, which upstream never
partitioned), a sensor row written at startup (sessions have a
foreign key to it), NULL geography instead of zeros, session updates
that no longer overwrite counters, filtered and cursor-based event
queries, and lookup by event ID.

pgx.go

PostgreSQL access using pgxpool.
*/

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

var ErrNotFound = errors.New("not found")

type PgxStore struct {
	pool       *pgxpool.Pool
	partitions sync.Map // "table|200601" -> true
}

func NewPgxStore(ctx context.Context, db config.DatabaseConfig) (*PgxStore, error) {
	cfg, err := pgxpool.ParseConfig(db.DSN)
	if err != nil {
		return nil, fmt.Errorf("parsing database dsn: %w", err)
	}
	if db.PoolMin > 0 {
		cfg.MinConns = int32(db.PoolMin)
	}
	if db.PoolMax > 0 {
		cfg.MaxConns = int32(db.PoolMax)
	}
	if db.IdleTimeout > 0 {
		cfg.MaxConnIdleTime = db.IdleTimeout
	}
	if db.ConnTimeout > 0 {
		cfg.ConnConfig.ConnectTimeout = db.ConnTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connecting to %s: %w", redactDSN(db.DSN), err)
	}
	return &PgxStore{pool: pool}, nil
}

func redactDSN(dsn string) string {
	if i := strings.Index(dsn, "://"); i >= 0 {
		if at := strings.LastIndex(dsn, "@"); at > i {
			creds := dsn[i+3 : at]
			if c := strings.Index(creds, ":"); c >= 0 {
				return dsn[:i+3] + creds[:c] + ":***" + dsn[at:]
			}
		}
	}
	return dsn
}

func (s *PgxStore) Close()                         { s.pool.Close() }
func (s *PgxStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// SchemaVersion returns the latest applied goose migration.
func (s *PgxStore) SchemaVersion(ctx context.Context) (int64, error) {
	var v int64
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied`,
	).Scan(&v)
	return v, err
}

var partitionedTables = []string{"events", "sessions", "credentials"}

// EnsurePartitions creates partitions for last month through two
// months ahead.
func (s *PgxStore) EnsurePartitions(ctx context.Context) error {
	now := time.Now().UTC()
	for m := -1; m <= 2; m++ {
		t := time.Date(now.Year(), now.Month()+time.Month(m), 1, 0, 0, 0, 0, time.UTC)
		if err := s.EnsurePartitionFor(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

// EnsurePartitionFor creates the monthly partitions that hold t, so
// replayed test events and sessions that cross a month boundary do
// not fail with "no partition of relation found".
func (s *PgxStore) EnsurePartitionFor(ctx context.Context, t time.Time) error {
	t = t.UTC()
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	suffix := start.Format("y2006m01")
	for _, table := range partitionedTables {
		key := table + "|" + suffix
		if _, ok := s.partitions.Load(key); ok {
			continue
		}
		q := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s_%s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			table, suffix, table, start.Format(time.DateOnly), end.Format(time.DateOnly),
		)
		if _, err := s.pool.Exec(ctx, q); err != nil {
			var pgErr *pgconn.PgError
			if !(errors.As(err, &pgErr) && pgErr.Code == "42P07") {
				return fmt.Errorf("creating partition %s_%s: %w", table, suffix, err)
			}
		}
		s.partitions.Store(key, true)
	}
	return nil
}

// UpsertSensor writes the sensor row that sessions reference.
func (s *PgxStore) UpsertSensor(ctx context.Context, sn *types.Sensor) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sensors (id, hostname, region, public_ip, services, started_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname, region = EXCLUDED.region,
			services = EXCLUDED.services, started_at = EXCLUDED.started_at,
			status = EXCLUDED.status`,
		sn.ID, sn.Hostname, sn.Region, sn.PublicIP, sn.Services, sn.StartedAt, sn.Status)
	if err != nil {
		return fmt.Errorf("upserting sensor: %w", err)
	}
	return nil
}

// ---- events -----------------------------------------------------------

const eventCols = `id, session_id, sensor_id, timestamp, received_at,
	service_type::text, event_type::text, source_ip, source_port,
	COALESCE(dest_ip, ''), dest_port, protocol::text, schema_version,
	country_code, country, city, latitude, longitude, asn, org,
	tags, service_data, seq, origin`

func scanEvent(row pgx.Row) (*types.Event, error) {
	var ev types.Event
	var svc, evt, proto string
	var cc, country, city, org *string
	var lat, lon *float64
	var asn *int
	if err := row.Scan(
		&ev.ID, &ev.SessionID, &ev.SensorID, &ev.Timestamp, &ev.ReceivedAt,
		&svc, &evt, &ev.SourceIP, &ev.SourcePort,
		&ev.DestIP, &ev.DestPort, &proto, &ev.SchemaVersion,
		&cc, &country, &city, &lat, &lon, &asn, &org,
		&ev.Tags, &ev.ServiceData, &ev.Seq, &ev.Origin,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning event: %w", err)
	}
	ev.ServiceType, _ = types.ParseServiceType(svc)
	ev.EventType, _ = types.ParseEventType(evt)
	if proto == "udp" {
		ev.Protocol = types.ProtocolUDP
	}
	if cc != nil && *cc != "" {
		ev.Geo = &types.GeoInfo{CountryCode: *cc}
		if country != nil {
			ev.Geo.Country = *country
		}
		if city != nil {
			ev.Geo.City = *city
		}
		if lat != nil && lon != nil {
			ev.Geo.Latitude, ev.Geo.Longitude = *lat, *lon
		}
		if asn != nil {
			ev.Geo.ASN = *asn
		}
		if org != nil {
			ev.Geo.Org = *org
		}
	}
	return &ev, nil
}

func scanEventRows(rows pgx.Rows) ([]*types.Event, error) {
	defer rows.Close()
	out := []*types.Event{}
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

type EventFilter struct {
	SourceIP  string
	Service   string
	EventType string
	SessionID string
	Origin    string
	Since     time.Time
	Until     time.Time
	AfterSeq  int64
	Limit     int
	Offset    int
	Ascending bool
}

type whereBuilder struct {
	parts []string
	args  []any
}

func (w *whereBuilder) add(cond string, arg any) {
	w.args = append(w.args, arg)
	w.parts = append(w.parts, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(w.args))))
}

func (w *whereBuilder) sql() string {
	if len(w.parts) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.parts, " AND ")
}

func (w *whereBuilder) next() string {
	return fmt.Sprintf("$%d", len(w.args)+1)
}

// ListEvents returns matching events and the total that match.
// AfterSeq > 0 returns events stored after that cursor, oldest
// first, which is how a reconnecting dashboard recovers.
func (s *PgxStore) ListEvents(ctx context.Context, f EventFilter) ([]*types.Event, int64, error) {
	w := &whereBuilder{}
	if f.SourceIP != "" {
		w.add("source_ip = ?", f.SourceIP)
	}
	if f.Service != "" {
		w.add("service_type::text = ?", f.Service)
	}
	if f.EventType != "" {
		w.add("event_type::text = ?", f.EventType)
	}
	if f.SessionID != "" {
		w.add("session_id = ?", f.SessionID)
	}
	if f.Origin != "" {
		w.add("origin = ?", f.Origin)
	}
	if !f.Since.IsZero() {
		w.add("timestamp >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		w.add("timestamp <= ?", f.Until)
	}
	order := "timestamp DESC, seq DESC"
	if f.AfterSeq > 0 {
		w.add("seq > ?", f.AfterSeq)
		order = "seq ASC"
	} else if f.Ascending {
		order = "timestamp ASC, seq ASC"
	}

	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM events"+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting events: %w", err)
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	q := fmt.Sprintf("SELECT %s FROM events%s ORDER BY %s LIMIT $%d OFFSET $%d",
		eventCols, w.sql(), order, len(w.args)+1, len(w.args)+2)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing events: %w", err)
	}
	evs, err := scanEventRows(rows)
	return evs, total, err
}

// GetEvent finds an event by ID. IDs are UUIDv7 values generated by
// the application; the database only enforces (id, timestamp)
// uniqueness, so the newest match is returned.
func (s *PgxStore) GetEvent(ctx context.Context, id string) (*types.Event, error) {
	return scanEvent(s.pool.QueryRow(ctx,
		"SELECT "+eventCols+" FROM events WHERE id = $1 ORDER BY timestamp DESC LIMIT 1", id))
}

// EventsByRefs loads events by (id, timestamp), oldest first.
func (s *PgxStore) EventsByRefs(ctx context.Context, refs []types.EventRef) ([]*types.Event, error) {
	if len(refs) == 0 {
		return []*types.Event{}, nil
	}
	ids := make([]string, len(refs))
	ts := make([]time.Time, len(refs))
	for i, r := range refs {
		ids[i], ts[i] = r.ID, r.Timestamp
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+eventCols+` FROM events
		WHERE (id, timestamp) IN (SELECT * FROM unnest($1::text[], $2::timestamptz[]))
		ORDER BY timestamp, seq`, ids, ts)
	if err != nil {
		return nil, fmt.Errorf("loading events by reference: %w", err)
	}
	return scanEventRows(rows)
}

func (s *PgxStore) CountByService(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT service_type::text, COUNT(*) FROM events
		WHERE timestamp >= $1 GROUP BY service_type`, since)
	if err != nil {
		return nil, fmt.Errorf("counting by service: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var svc string
		var n int64
		if err := rows.Scan(&svc, &n); err != nil {
			return nil, err
		}
		out[svc] = n
	}
	return out, rows.Err()
}

func (s *PgxStore) CountByOrigin(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT origin, COUNT(*) FROM events WHERE timestamp >= $1 GROUP BY origin`, since)
	if err != nil {
		return nil, fmt.Errorf("counting by origin: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var o string
		var n int64
		if err := rows.Scan(&o, &n); err != nil {
			return nil, err
		}
		out[o] = n
	}
	return out, rows.Err()
}

func (s *PgxStore) CountByCountry(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(country_code, ''), 'unavailable'), COUNT(*)
		FROM events WHERE timestamp >= $1
		GROUP BY 1 ORDER BY 2 DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("counting by country: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var c string
		var n int64
		if err := rows.Scan(&c, &n); err != nil {
			return nil, err
		}
		out[c] = n
	}
	return out, rows.Err()
}

func (s *PgxStore) TotalEvents(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

func (s *PgxStore) MaxSeq(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM events`).Scan(&n)
	return n, err
}

// ---- sessions ---------------------------------------------------------

const sessionCols = `id, sensor_id, started_at, ended_at, service_type::text,
	source_ip, source_port, COALESCE(dest_ip, ''), dest_port,
	COALESCE(client_version, ''), login_success, COALESCE(username, ''),
	COALESCE(auth_mode, ''), command_count, mitre_techniques, rule_ids,
	last_activity, threat_score, tags`

func scanSession(row pgx.Row) (*types.Session, error) {
	var s types.Session
	var svc string
	if err := row.Scan(
		&s.ID, &s.SensorID, &s.StartedAt, &s.EndedAt, &svc,
		&s.SourceIP, &s.SourcePort, new(string), &s.DestPort,
		&s.ClientVersion, &s.LoginSuccess, &s.Username,
		&s.AuthMode, &s.CommandCount, &s.MITRETechniques, &s.RuleIDs,
		&s.LastActivity, &s.ThreatScore, &s.Tags,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning session: %w", err)
	}
	s.ServiceType, _ = types.ParseServiceType(svc)
	return &s, nil
}

func (s *PgxStore) InsertSession(ctx context.Context, sess *types.Session, destIP string) error {
	if err := s.EnsurePartitionFor(ctx, sess.StartedAt); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (
			id, sensor_id, started_at, service_type, source_ip, source_port,
			dest_ip, dest_port, client_version, login_success, username,
			auth_mode, last_activity
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$3)`,
		sess.ID, sess.SensorID, sess.StartedAt, sess.ServiceType.String(),
		sess.SourceIP, sess.SourcePort, destIP, sess.DestPort,
		sess.ClientVersion, sess.LoginSuccess, sess.Username, nullStr(sess.AuthMode))
	if err != nil {
		return fmt.Errorf("inserting session: %w", err)
	}
	return nil
}

// UpdateSession writes the fields the network handler knows about.
// Command counts and rule IDs are maintained by the processor from
// stored events, so they are not written here.
func (s *PgxStore) UpdateSession(ctx context.Context, sess *types.Session) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sessions SET
			ended_at = $3,
			login_success = $4,
			username = NULLIF($5, ''),
			client_version = NULLIF($6, ''),
			auth_mode = COALESCE(NULLIF($7, ''), auth_mode),
			last_activity = GREATEST(COALESCE(last_activity, $3), COALESCE($3, last_activity))
		WHERE id = $1 AND started_at = $2`,
		sess.ID, sess.StartedAt, sess.EndedAt, sess.LoginSuccess,
		sess.Username, sess.ClientVersion, sess.AuthMode)
	if err != nil {
		return fmt.Errorf("updating session: %w", err)
	}
	return nil
}

func (s *PgxStore) GetSession(ctx context.Context, id string) (*types.Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		"SELECT "+sessionCols+" FROM sessions WHERE id = $1 LIMIT 1", id))
}

type SessionFilter struct {
	Service  string
	SourceIP string
	Limit    int
	Offset   int
}

func (s *PgxStore) ListSessions(ctx context.Context, f SessionFilter) ([]*types.Session, int64, error) {
	w := &whereBuilder{}
	if f.Service != "" {
		w.add("service_type::text = ?", f.Service)
	}
	if f.SourceIP != "" {
		w.add("source_ip = ?", f.SourceIP)
	}
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sessions"+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting sessions: %w", err)
	}
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		"SELECT %s FROM sessions%s ORDER BY started_at DESC LIMIT $%d OFFSET $%d",
		sessionCols, w.sql(), len(w.args)+1, len(w.args)+2), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing sessions: %w", err)
	}
	defer rows.Close()
	out := []*types.Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sess)
	}
	return out, total, rows.Err()
}

// ---- sources (the attackers table) -----------------------------------

const sourceCols = `id, ip, first_seen, last_seen, total_events, total_sessions,
	country_code, country, city, latitude, longitude, asn, org,
	threat_score, COALESCE(tool_family, ''), tags`

func scanSource(row pgx.Row) (*types.Attacker, error) {
	var a types.Attacker
	var cc, country, city, org *string
	var lat, lon *float64
	var asn *int
	if err := row.Scan(&a.ID, &a.IP, &a.FirstSeen, &a.LastSeen,
		&a.TotalEvents, &a.TotalSessions, &cc, &country, &city,
		&lat, &lon, &asn, &org, &a.ThreatScore, &a.ToolFamily, &a.Tags,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scanning source: %w", err)
	}
	if cc != nil {
		a.Geo.CountryCode = *cc
	}
	if country != nil {
		a.Geo.Country = *country
	}
	if city != nil {
		a.Geo.City = *city
	}
	if lat != nil && lon != nil && a.Geo.CountryCode != "" {
		a.Geo.Latitude, a.Geo.Longitude = *lat, *lon
	}
	if asn != nil {
		a.Geo.ASN = *asn
	}
	if org != nil {
		a.Geo.Org = *org
	}
	return &a, nil
}

func (s *PgxStore) ListSources(ctx context.Context, since time.Time, limit, offset int) ([]*types.Attacker, int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM attackers WHERE last_seen >= $1`, since).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting sources: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+sourceCols+` FROM attackers
		WHERE last_seen >= $1 ORDER BY last_seen DESC LIMIT $2 OFFSET $3`, since, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("listing sources: %w", err)
	}
	defer rows.Close()
	out := []*types.Attacker{}
	for rows.Next() {
		a, err := scanSource(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (s *PgxStore) GetSource(ctx context.Context, id int64) (*types.Attacker, error) {
	return scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceCols+` FROM attackers WHERE id = $1`, id))
}

func (s *PgxStore) GetSourceByIP(ctx context.Context, ip string) (*types.Attacker, error) {
	return scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceCols+` FROM attackers WHERE ip = $1`, ip))
}

// ---- credentials ------------------------------------------------------

type CredentialCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type CredentialPairCount struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Count    int64  `json:"count"`
}

func (s *PgxStore) topCredential(ctx context.Context, col string, limit int) ([]CredentialCount, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s, COUNT(*) FROM credentials GROUP BY 1 ORDER BY 2 DESC LIMIT $1`, col), limit)
	if err != nil {
		return nil, fmt.Errorf("querying top %s: %w", col, err)
	}
	defer rows.Close()
	out := []CredentialCount{}
	for rows.Next() {
		var c CredentialCount
		if err := rows.Scan(&c.Value, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PgxStore) TopUsernames(ctx context.Context, limit int) ([]CredentialCount, error) {
	return s.topCredential(ctx, "username", limit)
}

func (s *PgxStore) TopPasswords(ctx context.Context, limit int) ([]CredentialCount, error) {
	return s.topCredential(ctx, "password", limit)
}

func (s *PgxStore) TopPairs(ctx context.Context, limit int) ([]CredentialPairCount, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT username, password, COUNT(*) FROM credentials
		GROUP BY 1, 2 ORDER BY 3 DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top pairs: %w", err)
	}
	defer rows.Close()
	out := []CredentialPairCount{}
	for rows.Next() {
		var c CredentialPairCount
		if err := rows.Scan(&c.Username, &c.Password, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
