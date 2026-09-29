package event

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/internal/intel"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

// fakeStore fails while fail is true.
type fakeStore struct {
	fail    bool
	commits []*store.Analysis
	seq     int64
}

func (f *fakeStore) EnsurePartitionFor(context.Context, time.Time) error { return nil }

func (f *fakeStore) CommitAnalysis(_ context.Context, a *store.Analysis) (*store.CommitResult, error) {
	if f.fail {
		return nil, errors.New("database unavailable")
	}
	f.seq++
	f.commits = append(f.commits, a)
	res := &store.CommitResult{Seq: f.seq}
	for i, m := range a.Matches {
		d := m.Detection
		d.ID = int64(100 + len(f.commits)*10 + i)
		if m.Suppressed {
			d.ID = m.ExistingID
		}
		res.Detections = append(res.Detections, d)
	}
	return res, nil
}

func newTestProcessor(t *testing.T, st *fakeStore) (*Processor, *Subscription, string) {
	t.Helper()
	rules, _, err := detection.LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Pipeline.PersistRetry = 2
	spool := filepath.Join(t.TempDir(), "spool.jsonl")
	br := NewBroadcaster(64)
	sub := br.Subscribe()
	log := zerolog.Nop()
	p := NewProcessor(ProcessorDeps{
		Bus: NewBus(8, 0, &log), Store: st, Engine: detection.NewEngine(rules),
		Extractor: intel.NewExtractor(), Broadcaster: br, Logger: log,
		Config: cfg, LabRanges: cfg.LabPrefixes(), SpoolPath: spool,
	})
	return p, sub, spool
}

func login(i int) *types.Event {
	data, _ := json.Marshal(map[string]string{"username": "root", "password": "x"})
	return &types.Event{
		SessionID: "s1", SourceIP: "127.0.0.1", ServiceType: types.ServiceSSH,
		EventType:   types.EventLoginSuccess,
		Timestamp:   time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
		ServiceData: data,
	}
}

// A failed write must not reach the dashboard, must be spooled,
// and must not count toward later rule matches.
func TestPersistFailureIsNotBroadcastOrCounted(t *testing.T) {
	st := &fakeStore{}
	p, sub, spool := newTestProcessor(t, st)
	ctx := context.Background()

	p.Handle(ctx, login(0))
	p.Handle(ctx, login(1))
	st.fail = true
	p.Handle(ctx, login(2))
	st.fail = false
	p.Handle(ctx, login(3))
	p.Handle(ctx, login(4))

	if got := len(st.commits); got != 4 {
		t.Fatalf("stored %d events, want 4", got)
	}
	for _, c := range st.commits {
		if len(c.Matches) > 0 {
			t.Fatalf("threshold of 5 reached with only 4 stored events: %s", c.Matches[0].Detection.Explanation)
		}
	}
	if n := len(sub.C); n != 4 {
		t.Fatalf("broadcast %d results, want 4 (the failed event must not be sent)", n)
	}
	s := p.Stats()
	if s.PersistFailures != 1 || s.Spooled != 1 {
		t.Fatalf("stats %+v", s)
	}
	f, err := os.Open(spool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	lines := 0
	for sc := bufio.NewScanner(f); sc.Scan(); lines++ {
	}
	if lines != 1 {
		t.Fatalf("spool has %d lines, want 1", lines)
	}

	p.Handle(ctx, login(5))
	if len(st.commits[len(st.commits)-1].Matches) != 1 {
		t.Fatal("fifth stored event should trigger the volume rule")
	}
}

func TestOriginAndDefaults(t *testing.T) {
	st := &fakeStore{}
	p, sub, _ := newTestProcessor(t, st)
	ev := login(0)
	ev.SourceIP = "198.51.100.9"
	p.Handle(context.Background(), ev)
	r := <-sub.C
	if r.Event.Origin != "external" || r.Event.ID == "" || r.Event.SensorID == "" || r.Seq != 1 {
		t.Fatalf("unexpected event %+v", r.Event)
	}
	p.Handle(context.Background(), login(1))
	if r := <-sub.C; r.Event.Origin != "lab" {
		t.Fatalf("127.0.0.1 should be lab origin, got %s", r.Event.Origin)
	}
}
