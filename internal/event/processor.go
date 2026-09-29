/*
©AngelaMos | 2026
Modified by Hiten, 2026: rewritten as a single ordered worker. Each
event is validated, stored with its detections, observables and
evidence links in one transaction, attached to a case, and only then
published to live subscribers. Persistence errors are retried, then
counted and written to a spool file instead of being logged and
ignored. The Redis stream was removed.

processor.go

Order of work for each event:

 1. validate and fill missing fields
 2. GeoIP lookup (optional, skipped for internal addresses)
 3. evaluate rules without changing rule state
 4. extract observables
 5. one database transaction: event, detections, evidence links,
    observables, credential, uploaded file record, session counters
 6. on success, record the event in rule state
 7. attach new detections to cases, run the response playbook
 8. publish the committed result

One worker keeps the database sequence in the same order as rule
evaluation, which keeps correlation predictable. Concurrency can be
added later if measurements show it is needed.
*/

package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type GeoResolver interface {
	Resolve(ip string) (*types.GeoInfo, error)
}

type Extractor interface {
	Extract(ev *types.Event) []*types.IOC
}

type DataStore interface {
	EnsurePartitionFor(ctx context.Context, t time.Time) error
	CommitAnalysis(ctx context.Context, a *store.Analysis) (*store.CommitResult, error)
}

// CaseAttacher links detections to cases. It returns the IDs of
// the cases touched.
type CaseAttacher interface {
	Attach(ctx context.Context, dets []types.Detection) ([]int64, error)
}

// SessionLookup returns a copy of a live or recently ended session.
type SessionLookup interface {
	Get(sessionID string) *types.Session
}

type ProcessorStats struct {
	Processed       uint64    `json:"processed"`
	PersistFailures uint64    `json:"persist_failures"`
	CaseFailures    uint64    `json:"case_failures"`
	Spooled         uint64    `json:"spooled"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorAt     time.Time `json:"last_error_at,omitzero"`
	LastSeq         int64     `json:"last_seq"`
	LastStoredAt    time.Time `json:"last_stored_at,omitzero"`
}

type ProcessorDeps struct {
	Bus         *Bus
	Store       DataStore
	Geo         GeoResolver
	Engine      *detection.Engine
	Extractor   Extractor
	Cases       CaseAttacher
	Broadcaster *Broadcaster
	Logger      zerolog.Logger
	Config      *config.Config
	LabRanges   []netip.Prefix
	SpoolPath   string
	Sessions    SessionLookup
}

type Processor struct {
	d ProcessorDeps

	processed   atomic.Uint64
	persistFail atomic.Uint64
	caseFail    atomic.Uint64
	spooled     atomic.Uint64
	lastSeq     atomic.Int64

	errMu     sync.Mutex
	lastErr   string
	lastErrAt time.Time
	lastOKAt  time.Time
}

func NewProcessor(d ProcessorDeps) *Processor {
	return &Processor{d: d}
}

// Run processes events until the bus is closed and drained. It
// uses its own context for database work so that events already
// queued at shutdown are still written; the caller bounds that with
// pipeline.drain_timeout.
func (p *Processor) Run(ctx context.Context) error {
	for ev := range p.d.Bus.Events() {
		if ctx.Err() != nil {
			p.spool(ev, "shutdown drain timeout")
			continue
		}
		p.Handle(ctx, ev)
	}
	return nil
}

func (p *Processor) Stats() ProcessorStats {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return ProcessorStats{
		Processed:       p.processed.Load(),
		PersistFailures: p.persistFail.Load(),
		CaseFailures:    p.caseFail.Load(),
		Spooled:         p.spooled.Load(),
		LastError:       p.lastErr,
		LastErrorAt:     p.lastErrAt,
		LastSeq:         p.lastSeq.Load(),
		LastStoredAt:    p.lastOKAt,
	}
}

func (p *Processor) setErr(err error) {
	p.errMu.Lock()
	p.lastErr = err.Error()
	p.lastErrAt = time.Now().UTC()
	p.errMu.Unlock()
}

// Handle processes one event. It is exported for tests.
func (p *Processor) Handle(ctx context.Context, ev *types.Event) {
	p.validate(ev)
	p.enrichGeo(ev)

	eval := p.d.Engine.Evaluate(ev)
	var obs []*types.IOC
	if p.d.Extractor != nil {
		obs = p.d.Extractor.Extract(ev)
	}

	a := &store.Analysis{
		Event:       ev,
		Matches:     eval.Matches,
		Observables: obs,
		Credential:  extractCredential(ev),
		File:        extractFile(ev),
	}

	res, err := p.commitWithRetry(ctx, a)
	if err != nil {
		p.persistFail.Add(1)
		p.setErr(err)
		p.d.Logger.Error().Err(err).
			Str("event_id", ev.ID).
			Str("event_type", ev.EventType.String()).
			Msg("event not stored; written to spool")
		p.spool(ev, err.Error())
		return
	}

	ids := make([]int64, len(res.Detections))
	for i, d := range res.Detections {
		if !eval.Matches[i].Suppressed {
			ids[i] = d.ID
		}
	}
	eval.Apply(ids)

	ev.Seq = res.Seq
	p.lastSeq.Store(res.Seq)
	p.errMu.Lock()
	p.lastOKAt = time.Now().UTC()
	p.errMu.Unlock()
	p.processed.Add(1)

	var caseIDs []int64
	if p.d.Cases != nil && len(res.Detections) > 0 {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		caseIDs, err = p.d.Cases.Attach(cctx, res.Detections)
		cancel()
		if err != nil {
			p.caseFail.Add(1)
			p.setErr(fmt.Errorf("case correlation: %w", err))
			p.d.Logger.Error().Err(err).
				Str("event_id", ev.ID).
				Msg("detections stored but not attached to a case")
		}
	}

	if p.d.Broadcaster != nil {
		var fresh []types.Detection
		for i, d := range res.Detections {
			if !eval.Matches[i].Suppressed {
				fresh = append(fresh, d)
			}
		}
		p.d.Broadcaster.Publish(Result{
			Seq: res.Seq, Event: ev, Detections: fresh, CaseIDs: caseIDs,
		})
	}
}

func (p *Processor) commitWithRetry(ctx context.Context, a *store.Analysis) (*store.CommitResult, error) {
	attempts := 1
	if p.d.Config != nil && p.d.Config.Pipeline.PersistRetry > 0 {
		attempts = p.d.Config.Pipeline.PersistRetry
	}
	backoff := 100 * time.Millisecond
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, errors.Join(lastErr, ctx.Err())
			}
			backoff *= 4
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := p.d.Store.EnsurePartitionFor(cctx, a.Event.Timestamp)
		var res *store.CommitResult
		if err == nil {
			res, err = p.d.Store.CommitAnalysis(cctx, a)
		}
		cancel()
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempt(s): %w", attempts, lastErr)
}

func (p *Processor) validate(ev *types.Event) {
	now := time.Now().UTC()
	if ev.ID == "" {
		ev.ID = uuid.Must(uuid.NewV7()).String()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = now
	}
	ev.Timestamp = ev.Timestamp.UTC()
	ev.ReceivedAt = now
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = config.SchemaVersion
	}
	if p.d.Config != nil {
		if ev.SensorID == "" {
			ev.SensorID = p.d.Config.Sensor.ID
		}
		if ev.DestIP == "" {
			ev.DestIP = p.d.Config.Network.HoneypotHost
		}
	}
	if ev.SessionID == "" {
		ev.SessionID = "none"
	}
	// Some services publish auth and command events without ports;
	// the session knows them.
	if p.d.Sessions != nil && (ev.SourcePort == 0 || ev.DestPort == 0) {
		if s := p.d.Sessions.Get(ev.SessionID); s != nil {
			if ev.SourcePort == 0 {
				ev.SourcePort = s.SourcePort
			}
			if ev.DestPort == 0 {
				ev.DestPort = s.DestPort
			}
		}
	}
	ev.Origin = "external"
	if a, err := netip.ParseAddr(ev.SourceIP); err == nil {
		a = a.Unmap()
		for _, r := range p.d.LabRanges {
			if r.Contains(a) {
				ev.Origin = "lab"
				break
			}
		}
	}
}

func (p *Processor) enrichGeo(ev *types.Event) {
	if p.d.Geo == nil {
		return
	}
	g, err := p.d.Geo.Resolve(ev.SourceIP)
	if err != nil {
		p.d.Logger.Debug().Err(err).Str("ip", ev.SourceIP).Msg("geoip lookup failed")
		return
	}
	ev.Geo = g
}

type spoolRecord struct {
	SpooledAt time.Time    `json:"spooled_at"`
	Reason    string       `json:"reason"`
	Event     *types.Event `json:"event"`
}

// spool appends an event that could not be stored to a JSON lines
// file, so a database outage leaves a visible record instead of a
// silent gap. The file is not re-imported automatically.
func (p *Processor) spool(ev *types.Event, reason string) {
	if p.d.SpoolPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.d.SpoolPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(p.d.SpoolPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		p.d.Logger.Error().Err(err).Msg("cannot open spool file")
		return
	}
	defer func() { _ = f.Close() }()
	line, _ := json.Marshal(spoolRecord{SpooledAt: time.Now().UTC(), Reason: reason, Event: ev})
	if _, err := f.Write(append(line, '\n')); err == nil {
		p.spooled.Add(1)
	}
}

func extractCredential(ev *types.Event) *types.Credential {
	if ev.EventType != types.EventLoginSuccess && ev.EventType != types.EventLoginFailed {
		return nil
	}
	var f map[string]any
	if len(ev.ServiceData) == 0 || json.Unmarshal(ev.ServiceData, &f) != nil {
		return nil
	}
	s := func(k string) string { v, _ := f[k].(string); return v }
	method := s("auth_method")
	if method == "" {
		method = "password"
	}
	return &types.Credential{
		SessionID:   ev.SessionID,
		Timestamp:   ev.Timestamp,
		ServiceType: ev.ServiceType,
		SourceIP:    ev.SourceIP,
		Username:    s("username"),
		Password:    s("password"),
		PublicKey:   s("public_key"),
		AuthMethod:  method,
		Success:     ev.EventType == types.EventLoginSuccess,
	}
}

// extractFile builds the captured_files row for an upload event.
// The bytes themselves were already written to the uploads
// directory by the FTP service; only metadata is stored here.
func extractFile(ev *types.Event) *store.FileRecord {
	if ev.EventType != types.EventFileUpload {
		return nil
	}
	var f struct {
		Filename    string `json:"filename"`
		Size        int64  `json:"size"`
		SHA256      string `json:"sha256"`
		MD5         string `json:"md5"`
		StoragePath string `json:"storage_path"`
		Truncated   bool   `json:"truncated"`
		SizeLimit   int64  `json:"size_limit"`
	}
	if json.Unmarshal(ev.ServiceData, &f) != nil || f.SHA256 == "" {
		return nil
	}
	return &store.FileRecord{
		CapturedFile: types.CapturedFile{
			SessionID: ev.SessionID,
			Timestamp: ev.Timestamp,
			SourceIP:  ev.SourceIP,
			Service:   ev.ServiceType,
			Filename:  f.Filename,
			Size:      f.Size,
			SHA256:    f.SHA256,
			MD5:       f.MD5,
		},
		StoragePath: f.StoragePath,
		Truncated:   f.Truncated,
		SizeLimit:   f.SizeLimit,
	}
}
