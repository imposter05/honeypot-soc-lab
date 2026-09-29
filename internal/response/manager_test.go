/*
Hiten | 2026
manager_test.go

Tests for the restrict-lab-source playbook. Decoys are real TCP
listeners wrapped by the real connection guard, and the probe opens
real connections from 127.x source addresses (Linux allows any
address in 127.0.0.0/8). The store is an in-memory fake with the
same state rules as the database version, which has its own tests in
internal/store.
*/

package response

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/netguard"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

// ---- fake store ----------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	actions map[int64]*types.ResponseAction
	history map[int64][]string
	cases   map[int64]*types.Case
	next    int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{actions: map[int64]*types.ResponseAction{}, history: map[int64][]string{},
		cases: map[int64]*types.Case{}}
}

func (f *fakeStore) CreateAction(_ context.Context, a *types.ResponseAction, _ string) (*types.ResponseAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.actions {
		if x.SourceIP == a.SourceIP && x.Playbook == a.Playbook &&
			(x.State == types.ActionPending || x.State == types.ActionActive) {
			c := *x
			return &c, store.ErrDuplicate
		}
	}
	f.next++
	c := *a
	c.ID, c.State, c.RequestedAt = f.next, types.ActionPending, time.Now().UTC()
	f.actions[c.ID] = &c
	f.history[c.ID] = []string{"->" + types.ActionPending}
	out := c
	return &out, nil
}

func (f *fakeStore) GetAction(_ context.Context, id int64) (*types.ResponseAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actions[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c := *a
	return &c, nil
}

func (f *fakeStore) ListActions(_ context.Context, flt store.ActionFilter) ([]*types.ResponseAction, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*types.ResponseAction
	for _, a := range f.actions {
		if flt.State == "" || a.State == flt.State {
			c := *a
			out = append(out, &c)
		}
	}
	return out, int64(len(out)), nil
}

func (f *fakeStore) Transition(_ context.Context, id int64, from []string, to, _ string,
	u store.ActionUpdate, _ map[string]any) (*types.ResponseAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.actions[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	allowed := false
	for _, s := range from {
		allowed = allowed || a.State == s
	}
	if !allowed {
		c := *a
		return &c, fmt.Errorf("%w: %s to %s", store.ErrInvalidTransition, a.State, to)
	}
	f.history[id] = append(f.history[id], a.State+"->"+to)
	a.State = to
	if u.ExpiresAt != nil {
		a.ExpiresAt = u.ExpiresAt
	}
	if u.Services != nil {
		a.Services = u.Services
	}
	if u.Verification != nil {
		a.Verification = u.Verification
	}
	if u.Error != nil {
		a.Error = *u.Error
	}
	c := *a
	return &c, nil
}

func (f *fakeStore) GetCase(_ context.Context, id int64) (*types.Case, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.cases[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cc := *c
	return &cc, nil
}

// ---- lab setup -------------------------------------------------------------

type lab struct {
	cfg   *config.Config
	deny  *Denylist
	guard *netguard.Guard
	store *fakeStore
	mgr   *Manager
	ln    net.Listener
}

// newLab starts an SSH-like decoy (sends a banner) behind the guard.
// If running is false the port is reserved and then closed, so the
// service is "stopped".
func newLab(t *testing.T, running bool) *lab {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("needs 127.x source addresses, which only Linux provides by default")
	}
	l := &lab{deny: NewDenylist(), store: newFakeStore()}
	l.guard = netguard.New(l.deny, 16, time.Second, time.Minute, nil)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := raw.Addr().(*net.TCPAddr).Port
	if running {
		l.ln = l.guard.Wrap(raw, "ssh")
		go func() {
			for {
				c, err := l.ln.Accept()
				if err != nil {
					return
				}
				_, _ = c.Write([]byte("SSH-2.0-test\r\n"))
				time.Sleep(200 * time.Millisecond)
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = raw.Close() })
	} else {
		_ = raw.Close()
	}

	cfg := config.Default()
	cfg.Network.HoneypotHost = "127.0.0.1"
	cfg.SSH.Port = port
	cfg.HTTP.Enabled, cfg.FTP.Enabled, cfg.SMB.Enabled = false, false, false
	cfg.MySQL.Enabled, cfg.Redis.Enabled = false, false
	cfg.Response.DefaultExpiry = time.Hour
	l.cfg = cfg
	l.mgr = NewManager(l.store, l.deny, cfg, zerolog.Nop(),
		LiveProber(cfg, func(s string) uint64 { return l.guard.Stats()[s].Denied }))
	return l
}

func (l *lab) request(t *testing.T, src string) *types.ResponseAction {
	t.Helper()
	l.store.cases[1] = &types.Case{ID: 1, Ref: "CASE-00001", SourceIP: src, SensorID: "s",
		Severity: "high", Services: []string{"ssh"}}
	a, err := l.mgr.Request(context.Background(), l.store.cases[1], "test")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func status(a *types.ResponseAction) string {
	if a.Verification == nil {
		return ""
	}
	s, _ := a.Verification["status"].(string)
	return s
}

// ---- tests -------------------------------------------------------------------

func TestApproveIsVerifiedByGuardRefusal(t *testing.T) {
	l := newLab(t, true)
	a := l.request(t, "127.0.0.71")
	a, err := l.mgr.Approve(context.Background(), a.ID, "analyst", []string{"ssh"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != types.ActionActive || status(a) != VerifyVerified {
		t.Fatalf("state=%s verification=%s error=%q", a.State, status(a), a.Error)
	}
	if l.guard.Stats()["ssh"].Denied == 0 {
		t.Fatal("the probe should have been refused by the guard")
	}
	// Another address is not affected.
	c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.72")}}).
		Dial("tcp", l.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 4)
	if n, _ := c.Read(buf); n == 0 {
		t.Fatal("an unrestricted address should still get the banner")
	}
}

// Regression test: a stopped service used to be reported as a
// successful block because any connection error counted as denied.
func TestStoppedServiceIsUnverifiedNotSuccess(t *testing.T) {
	l := newLab(t, false)
	a := l.request(t, "127.0.0.73")
	a, err := l.mgr.Approve(context.Background(), a.ID, "analyst", []string{"ssh"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if status(a) != VerifyUnverified {
		t.Fatalf("verification = %q, want unverified", status(a))
	}
	if a.Verification["passed"] != false || a.Error == "" {
		t.Fatalf("an unverified action must not read as passed: %+v", a.Verification)
	}
	if a.State != types.ActionActive || !l.deny.Denied(netip.MustParseAddr("127.0.0.73"), "ssh") {
		t.Fatal("the restriction should stay in place while unverified")
	}
}

// If a live connection from the source is accepted, the restriction
// is not working: the action fails and the entry is removed.
func TestAcceptedConnectionFailsAndRemovesEntry(t *testing.T) {
	l := newLab(t, true)
	a := l.request(t, "127.0.0.74")
	// Probe that sees the service answer, as if the guard were bypassed.
	l.mgr.probe = func(context.Context, netip.Addr, string) ProbeResult {
		return ProbeResult{Service: "ssh", Outcome: OutcomeAccepted, Detail: "the service sent 14 bytes"}
	}
	a, err := l.mgr.Approve(context.Background(), a.ID, "analyst", []string{"ssh"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != types.ActionFailed || status(a) != VerifyFailed {
		t.Fatalf("state=%s verification=%s", a.State, status(a))
	}
	if l.deny.Denied(netip.MustParseAddr("127.0.0.74"), "ssh") {
		t.Fatal("a failed restriction must be removed from the denylist")
	}
}

func TestClosedWithoutDenialIsUnverified(t *testing.T) {
	l := newLab(t, true)
	a := l.request(t, "127.0.0.75")
	l.mgr.probe = func(context.Context, netip.Addr, string) ProbeResult {
		return ProbeResult{Service: "ssh", Outcome: OutcomeClosedUncount}
	}
	a, _ = l.mgr.Approve(context.Background(), a.ID, "analyst", []string{"ssh"}, 10*time.Minute)
	if status(a) != VerifyUnverified {
		t.Fatalf("verification = %q", status(a))
	}
}

func TestRejectReverseAndInvalidMoves(t *testing.T) {
	l := newLab(t, true)
	ctx := context.Background()
	a := l.request(t, "127.0.0.76")
	if _, err := l.mgr.Reject(ctx, a.ID, "analyst", " "); err == nil {
		t.Fatal("reject needs a reason")
	}
	if _, err := l.mgr.Reverse(ctx, a.ID, "analyst", "x"); err == nil {
		t.Fatal("a pending action cannot be reversed")
	}
	a, err := l.mgr.Approve(ctx, a.ID, "analyst", []string{"ssh"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.mgr.Reverse(ctx, a.ID, "analyst", "test finished"); err != nil {
		t.Fatal(err)
	}
	if l.deny.Denied(netip.MustParseAddr("127.0.0.76"), "ssh") {
		t.Fatal("reversal must remove the entry")
	}
	if _, err := l.mgr.Approve(ctx, a.ID, "analyst", nil, time.Hour); err == nil {
		t.Fatal("a reversed action cannot be approved again")
	}
	b := l.request(t, "127.0.0.77")
	if _, err := l.mgr.Reject(ctx, b.ID, "analyst", "expected test"); err != nil {
		t.Fatal(err)
	}
	got, _ := l.store.GetAction(ctx, b.ID)
	if got.State != types.ActionRejected {
		t.Fatalf("state %s", got.State)
	}
}

func TestExpiryRemovesEntry(t *testing.T) {
	l := newLab(t, true)
	ctx := context.Background()
	a := l.request(t, "127.0.0.78")
	if _, err := l.mgr.Approve(ctx, a.ID, "analyst", []string{"ssh"}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.78")
	later := time.Now().Add(6 * time.Minute)
	l.mgr.now = func() time.Time { return later }
	l.mgr.ExpireDue(ctx)
	got, _ := l.store.GetAction(ctx, a.ID)
	if got.State != types.ActionExpired {
		t.Fatalf("state %s, want expired", got.State)
	}
	if l.deny.Denied(ip, "ssh") {
		t.Fatal("expired entry still in the denylist")
	}
}

func TestRestartRestoresActiveAndExpiresStale(t *testing.T) {
	l := newLab(t, true)
	ctx := context.Background()
	keep := l.request(t, "127.0.0.79")
	if _, err := l.mgr.Approve(ctx, keep.ID, "analyst", []string{"ssh"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	stale := l.request(t, "127.0.0.80")
	if _, err := l.mgr.Approve(ctx, stale.ID, "analyst", []string{"ssh"}, 2*time.Minute); err != nil {
		t.Fatal(err)
	}

	// Simulated restart: a new denylist and manager on the same store,
	// started after the short restriction ran out.
	deny := NewDenylist()
	m2 := NewManager(l.store, deny, l.cfg, zerolog.Nop(), nil)
	later := time.Now().Add(3 * time.Minute)
	m2.now = func() time.Time { return later }
	deny.now = func() time.Time { return later }
	if err := m2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if !deny.Denied(netip.MustParseAddr("127.0.0.79"), "ssh") {
		t.Fatal("active restriction was not restored")
	}
	if deny.Denied(netip.MustParseAddr("127.0.0.80"), "ssh") {
		t.Fatal("restriction that expired while stopped was restored")
	}
	got, _ := l.store.GetAction(ctx, stale.ID)
	if got.State != types.ActionExpired {
		t.Fatalf("stale action state %s, want expired", got.State)
	}
}

// A request is made when a case is created at the threshold or rises
// to it, not when it was already above it.
func TestRequestsOnReachingThreshold(t *testing.T) {
	l := newLab(t, true)
	l.cfg.Response.MinSeverity = "high"
	for id, ip := range map[int64]string{5: "127.0.0.81", 6: "127.0.0.82", 7: "127.0.0.83", 8: "127.0.0.84"} {
		l.store.cases[id] = &types.Case{ID: id, SourceIP: ip, Severity: "high"}
	}
	l.mgr.OnSeverityChange(context.Background(), map[int64][2]string{
		5: {"", "medium"},       // new, below threshold
		6: {"", "high"},         // new, at threshold
		7: {"medium", "high"},   // rose to threshold
		8: {"high", "critical"}, // already above
	})
	acts, _, _ := l.store.ListActions(context.Background(), store.ActionFilter{})
	got := map[string]bool{}
	for _, a := range acts {
		got[a.SourceIP] = true
	}
	if len(acts) != 2 || !got["127.0.0.82"] || !got["127.0.0.83"] {
		t.Fatalf("requests for %v, want 127.0.0.82 and 127.0.0.83", got)
	}
	if _, err := l.mgr.Request(context.Background(), l.store.cases[6], "x"); err == nil {
		t.Fatal("a second request for the same source should report store.ErrDuplicate")
	}
}
