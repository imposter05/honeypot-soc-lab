/*
Hiten | 2026
manager.go

The one response playbook: restrict a lab source.

 1. A new case at or above response.min_severity creates a pending
    action with a summary built from the case fields.
 2. Nothing is enforced until an analyst approves it.
 3. On approval the source is added to the application denylist for
    the chosen decoy services, with an expiry.
 4. The restriction is verified for each service: the denylist is
    asked directly, and where the host can open a connection from
    that address (any 127.x on Linux, aliased addresses on macOS) a
    real connection is made. It only counts as verified when the
    connection guard records that it refused the connection.
 5. If any service still accepts the source, the entry is removed
    and the action is marked failed. If a service could not be tested
    (stopped, unreachable, no probe possible) the restriction stays
    but the action is marked unverified. Expiry and reversal remove
    the entry.

Scope, stated plainly: this blocks new connections to this
application's decoys. It does not change the host firewall, isolate
a machine, or close sessions that are already open.
*/

package response

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const Playbook = "restrict-lab-source"

type Store interface {
	CreateAction(ctx context.Context, a *types.ResponseAction, actor string) (*types.ResponseAction, error)
	GetAction(ctx context.Context, id int64) (*types.ResponseAction, error)
	ListActions(ctx context.Context, f store.ActionFilter) ([]*types.ResponseAction, int64, error)
	Transition(ctx context.Context, id int64, from []string, to, actor string,
		u store.ActionUpdate, detail map[string]any) (*types.ResponseAction, error)
	GetCase(ctx context.Context, id int64) (*types.Case, error)
}

// Probe outcomes. Only OutcomeDenied is proof that the restriction
// works: the connection reached the decoy's listener and the
// connection guard counted it as refused by the denylist.
const (
	OutcomeDenied        = "denied"           // closed by the guard, denial counted
	OutcomeAccepted      = "accepted"         // the service answered or kept it open
	OutcomeNoConnection  = "no-connection"    // refused, timed out or failed to connect
	OutcomeClosedUncount = "closed-uncounted" // closed, but not by the denylist
	OutcomeNotPossible   = "not-possible"     // this host cannot send from the source
)

// Verification results for one service and for the whole action.
const (
	VerifyVerified   = "verified"
	VerifyFailed     = "failed"
	VerifyUnverified = "unverified"
)

// ProbeResult describes one live connection attempt.
type ProbeResult struct {
	Service string `json:"service"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// Prober opens a connection from src to a decoy service.
type Prober func(ctx context.Context, src netip.Addr, service string) ProbeResult

type Manager struct {
	store    Store
	deny     *Denylist
	cfg      *config.Config
	logger   zerolog.Logger
	probe    Prober
	services []string
	now      func() time.Time
}

func NewManager(st Store, deny *Denylist, cfg *config.Config, logger zerolog.Logger, probe Prober) *Manager {
	var svcs []string
	for _, l := range cfg.Listeners() {
		if l.Enabled && l.Name != "api" {
			svcs = append(svcs, l.Name)
		}
	}
	return &Manager{store: st, deny: deny, cfg: cfg, logger: logger,
		probe: probe, services: svcs, now: time.Now}
}

func (m *Manager) Denylist() *Denylist { return m.deny }

// Load restores active restrictions after a restart and expires
// any that ran out while the application was stopped.
func (m *Manager) Load(ctx context.Context) error {
	acts, _, err := m.store.ListActions(ctx, store.ActionFilter{State: types.ActionActive, Limit: 1000})
	if err != nil {
		return err
	}
	for _, a := range acts {
		ip, perr := netip.ParseAddr(a.SourceIP)
		if perr != nil {
			continue
		}
		if a.ExpiresAt != nil && !m.now().Before(*a.ExpiresAt) {
			_, _ = m.store.Transition(ctx, a.ID, []string{types.ActionActive}, types.ActionExpired,
				"system", store.ActionUpdate{Ended: true}, map[string]any{"reason": "expired while stopped"})
			continue
		}
		var exp time.Time
		if a.ExpiresAt != nil {
			exp = *a.ExpiresAt
		}
		m.deny.Add(a.ID, ip, a.Services, exp)
	}
	return nil
}

// OnSeverityChange creates a pending request when a case is created
// at, or rises to, response.min_severity. A case that was already at
// or above the threshold does not get a second request from later
// detections; the analyst can still request one by hand.
func (m *Manager) OnSeverityChange(ctx context.Context, changes map[int64][2]string) {
	if !m.cfg.Response.Enabled {
		return
	}
	min := config.SeverityRank[m.cfg.Response.MinSeverity]
	for id, ch := range changes {
		before, after := config.SeverityRank[ch[0]], config.SeverityRank[ch[1]]
		if after < min || (ch[0] != "" && before >= min) {
			continue
		}
		c, err := m.store.GetCase(ctx, id)
		if err != nil {
			m.logger.Error().Err(err).Int64("case_id", id).Msg("response: cannot load case")
			continue
		}
		if _, err := m.Request(ctx, c, "playbook"); err != nil && !errors.Is(err, store.ErrDuplicate) {
			m.logger.Error().Err(err).Int64("case_id", id).Msg("response: request failed")
		}
	}
}

// Request creates a pending action for a case. A second request for
// the same source while one is pending or active returns the
// existing action and store.ErrDuplicate.
func (m *Manager) Request(ctx context.Context, c *types.Case, actor string) (*types.ResponseAction, error) {
	if _, err := netip.ParseAddr(c.SourceIP); err != nil {
		return nil, fmt.Errorf("case source %q is not an IP address", c.SourceIP)
	}
	svcs := c.Services
	if len(svcs) == 0 {
		svcs = m.services
	}
	a := &types.ResponseAction{
		CaseID:   c.ID,
		Playbook: Playbook,
		SourceIP: c.SourceIP,
		SensorID: c.SensorID,
		Services: m.services,
		Summary:  summary(c, svcs),
	}
	return m.store.CreateAction(ctx, a, actor)
}

func summary(c *types.Case, observed []string) string {
	s := append([]string(nil), observed...)
	sort.Strings(s)
	return fmt.Sprintf(
		"When this was requested, %s had %d detection(s), severity %s, for %s on sensor %s between %s and %s. Services involved: %s. "+
			"Approving adds %s to the application denylist so new connections to the selected decoys are closed. "+
			"It does not change the host firewall or end sessions that are already open.",
		c.Ref, c.DetectionCount, c.Severity, c.SourceIP, c.SensorID,
		c.FirstActivity.UTC().Format(time.RFC3339), c.LastActivity.UTC().Format(time.RFC3339),
		orNone(strings.Join(s, ", ")), c.SourceIP)
}

func orNone(s string) string {
	if s == "" {
		return "none recorded"
	}
	return s
}

// Approve enforces and verifies a pending action.
func (m *Manager) Approve(ctx context.Context, id int64, actor string, services []string, expiresIn time.Duration) (*types.ResponseAction, error) {
	a, err := m.store.GetAction(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		services = a.Services
	}
	for _, s := range services {
		if !m.known(s) {
			return nil, fmt.Errorf("unknown or disabled service %q", s)
		}
	}
	if expiresIn <= 0 {
		expiresIn = m.cfg.Response.DefaultExpiry
	}
	if expiresIn > 7*24*time.Hour {
		return nil, fmt.Errorf("expiry longer than 7 days is not allowed")
	}
	ip, err := netip.ParseAddr(a.SourceIP)
	if err != nil {
		return nil, err
	}
	exp := m.now().Add(expiresIn).UTC()
	a, err = m.store.Transition(ctx, id, []string{types.ActionPending}, types.ActionActive, actor,
		store.ActionUpdate{DecidedBy: &actor, Decided: true, ExpiresAt: &exp, Services: services},
		map[string]any{"services": services, "expires_at": exp})
	if err != nil {
		return a, err
	}

	m.deny.Add(id, ip, services, exp)
	verif, status := m.verify(ctx, ip, services)
	switch status {
	case VerifyFailed:
		m.deny.Remove(id)
		msg := "verification failed: the restriction is not in effect for at least one service; it was removed"
		return m.store.Transition(ctx, id, []string{types.ActionActive}, types.ActionFailed, "system",
			store.ActionUpdate{Ended: true, Verification: verif, Error: &msg}, verif)
	case VerifyUnverified:
		// The restriction stays in place, but the record says it
		// could not be confirmed so nobody reads it as proven.
		msg := "restriction applied but not confirmed for every service; see verification"
		return m.store.Transition(ctx, id, []string{types.ActionActive}, types.ActionActive, "system",
			store.ActionUpdate{Verification: verif, Error: &msg}, map[string]any{"verification": status})
	}
	return m.store.Transition(ctx, id, []string{types.ActionActive}, types.ActionActive, "system",
		store.ActionUpdate{Verification: verif}, map[string]any{"verification": status})
}

func (m *Manager) known(s string) bool {
	for _, x := range m.services {
		if x == s {
			return true
		}
	}
	return false
}

// verify checks each service and returns the verification record and
// the overall result. A check is:
//
//	failed      the denylist does not contain the source, or a live
//	            connection from the source was accepted
//	verified    the denylist contains it and a live connection was
//	            refused by the guard, which counted the denial
//	unverified  anything in between: no live probe was possible, the
//	            service did not accept a TCP connection at all (it may
//	            be stopped), or the connection closed for another reason
//
// A refused or timed-out connection is never treated as proof: a
// stopped service would look the same as a blocked one.
func (m *Manager) verify(ctx context.Context, ip netip.Addr, services []string) (map[string]any, string) {
	var checks []map[string]any
	overall := VerifyVerified
	for _, svc := range services {
		c := map[string]any{"service": svc}
		inList := m.deny.Denied(ip, svc)
		c["denylist_check"] = inList
		result, reason := VerifyUnverified, ""
		switch {
		case !inList:
			result, reason = VerifyFailed, "the denylist does not contain this source for this service"
		case m.probe == nil:
			reason = "no live probe is configured; only the denylist was checked"
		default:
			pr := m.probe(ctx, ip, svc)
			c["probe"] = pr
			switch pr.Outcome {
			case OutcomeDenied:
				result, reason = VerifyVerified, "a live connection was refused by the denylist"
			case OutcomeAccepted:
				result, reason = VerifyFailed, "a live connection from the source was accepted"
			case OutcomeNoConnection:
				reason = "the service did not accept a TCP connection, so the block could not be tested; the service may be stopped"
			case OutcomeClosedUncount:
				reason = "the connection closed, but the guard did not record a denylist refusal (for example the connection limit was reached)"
			default:
				reason = pr.Detail
			}
		}
		c["result"], c["reason"] = result, reason
		switch {
		case result == VerifyFailed:
			overall = VerifyFailed
		case result == VerifyUnverified && overall != VerifyFailed:
			overall = VerifyUnverified
		}
		checks = append(checks, c)
	}
	return map[string]any{
		"checked_at": m.now().UTC(),
		"checks":     checks,
		"status":     overall,
		"passed":     overall == VerifyVerified,
	}, overall
}

func (m *Manager) Reject(ctx context.Context, id int64, actor, reason string) (*types.ResponseAction, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("a reason is required to reject")
	}
	return m.store.Transition(ctx, id, []string{types.ActionPending}, types.ActionRejected, actor,
		store.ActionUpdate{DecidedBy: &actor, Decided: true, Ended: true},
		map[string]any{"reason": reason})
}

func (m *Manager) Reverse(ctx context.Context, id int64, actor, reason string) (*types.ResponseAction, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("a reason is required to reverse")
	}
	a, err := m.store.Transition(ctx, id, []string{types.ActionActive}, types.ActionReversed, actor,
		store.ActionUpdate{Ended: true}, map[string]any{"reason": reason})
	if err != nil {
		return a, err
	}
	m.deny.Remove(id)
	return a, nil
}

// ExpireDue moves active actions past their expiry to expired.
func (m *Manager) ExpireDue(ctx context.Context) {
	acts, _, err := m.store.ListActions(ctx, store.ActionFilter{State: types.ActionActive, Limit: 1000})
	if err != nil {
		m.logger.Error().Err(err).Msg("response: listing active actions")
		return
	}
	for _, a := range acts {
		if a.ExpiresAt == nil || m.now().Before(*a.ExpiresAt) {
			continue
		}
		m.deny.Remove(a.ID)
		if _, err := m.store.Transition(ctx, a.ID, []string{types.ActionActive}, types.ActionExpired,
			"system", store.ActionUpdate{Ended: true}, map[string]any{"expired_at": a.ExpiresAt}); err != nil {
			m.logger.Error().Err(err).Int64("action_id", a.ID).Msg("response: expiring action")
		}
	}
}

func (m *Manager) Run(ctx context.Context) error {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.ExpireDue(ctx)
		}
	}
}

// DenialCounter returns how many connections the guard has refused
// for a service because of the denylist.
type DenialCounter func(service string) uint64

// LiveProber opens a TCP connection from src to the decoy and reads
// what happens. The guard closes a denied connection before any data
// and counts it; the prober compares that counter before and after,
// so it can tell a denylist refusal apart from a stopped service,
// a connection limit, or a network error.
func LiveProber(cfg *config.Config, denied DenialCounter) Prober {
	return func(ctx context.Context, src netip.Addr, service string) ProbeResult {
		pr := ProbeResult{Service: service}
		port := 0
		for _, l := range cfg.Listeners() {
			if l.Name == service {
				port = l.Port
			}
		}
		pr.Target = config.Addr(cfg.Network.HoneypotHost, port)
		before := denied(service)
		d := net.Dialer{
			Timeout:   2 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.IP(src.AsSlice())},
		}
		conn, err := d.DialContext(ctx, "tcp", pr.Target)
		if err != nil {
			if errors.Is(err, syscall.EADDRNOTAVAIL) || strings.Contains(err.Error(), "assign requested address") {
				pr.Outcome = OutcomeNotPossible
				pr.Detail = "this host cannot open a connection from " + src.String() + "; only the denylist was checked"
				return pr
			}
			pr.Outcome = OutcomeNoConnection
			pr.Detail = "could not connect: " + err.Error()
			return pr
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 64)
		n, rerr := conn.Read(buf)
		switch {
		case n > 0:
			pr.Outcome = OutcomeAccepted
			pr.Detail = fmt.Sprintf("the service sent %d bytes", n)
			return pr
		case rerr != nil && isTimeout(rerr):
			pr.Outcome = OutcomeAccepted
			pr.Detail = "the connection stayed open"
			return pr
		}
		// Closed without data. The guard increments its counter just
		// after closing, so allow it a moment.
		for i := 0; i < 20; i++ {
			if denied(service) > before {
				pr.Outcome = OutcomeDenied
				pr.Detail = "closed before any data, and the guard counted a denylist refusal"
				return pr
			}
			time.Sleep(25 * time.Millisecond)
		}
		pr.Outcome = OutcomeClosedUncount
		pr.Detail = "closed before any data, but no denylist refusal was counted"
		return pr
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
