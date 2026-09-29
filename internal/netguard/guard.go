/*
Hiten | 2026
guard.go

Listener wrapper used by every TCP decoy.

For each accepted connection it:
  - closes it at once if the source is on the application denylist
  - closes it at once if the service already has its maximum number
    of open connections
  - sets read and write deadlines so an idle client is dropped after
    limits.idle_timeout and any client after limits.max_session_duration

The denylist only affects new connections to this application's
decoys. It does not touch the host firewall, and connections that
were already open when an address was added stay open.
*/

package netguard

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Denylist interface {
	Denied(ip netip.Addr, service string) bool
}

// DeniedFunc is called for each denied connection, after it is closed.
type DeniedFunc func(service string, src netip.AddrPort, dst netip.AddrPort)

type ServiceStats struct {
	Accepted  uint64 `json:"accepted"`
	Denied    uint64 `json:"denied"`
	OverLimit uint64 `json:"over_limit"`
	Active    int64  `json:"active"`
}

type counters struct {
	accepted, denied, overLimit atomic.Uint64
	active                      atomic.Int64
}

type Guard struct {
	deny     Denylist
	onDenied DeniedFunc
	maxConns int
	idle     time.Duration
	maxLife  time.Duration

	mu    sync.Mutex
	stats map[string]*counters
}

func New(deny Denylist, maxConns int, idle, maxLife time.Duration, onDenied DeniedFunc) *Guard {
	return &Guard{
		deny: deny, onDenied: onDenied, maxConns: maxConns,
		idle: idle, maxLife: maxLife, stats: map[string]*counters{},
	}
}

func (g *Guard) counters(service string) *counters {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.stats[service]
	if c == nil {
		c = &counters{}
		g.stats[service] = c
	}
	return c
}

func (g *Guard) Stats() map[string]ServiceStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]ServiceStats{}
	for k, c := range g.stats {
		out[k] = ServiceStats{
			Accepted: c.accepted.Load(), Denied: c.denied.Load(),
			OverLimit: c.overLimit.Load(), Active: c.active.Load(),
		}
	}
	return out
}

// Allows reports whether a new connection from ip to service would
// be accepted by the denylist. Used by response verification.
func (g *Guard) Allows(ip netip.Addr, service string) bool {
	return g.deny == nil || !g.deny.Denied(ip, service)
}

// Wrap returns a listener that applies the guard to ln.
func (g *Guard) Wrap(ln net.Listener, service string) net.Listener {
	return &listener{
		Listener: ln, g: g, service: service, c: g.counters(service),
		sem: make(chan struct{}, g.maxConns),
	}
}

type listener struct {
	net.Listener
	g       *Guard
	service string
	c       *counters
	sem     chan struct{}
}

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		src := addrPort(conn.RemoteAddr())
		if l.g.deny != nil && l.g.deny.Denied(src.Addr().Unmap(), l.service) {
			_ = conn.Close()
			l.c.denied.Add(1)
			if l.g.onDenied != nil {
				l.g.onDenied(l.service, src, addrPort(conn.LocalAddr()))
			}
			continue
		}
		select {
		case l.sem <- struct{}{}:
		default:
			_ = conn.Close()
			l.c.overLimit.Add(1)
			continue
		}
		l.c.accepted.Add(1)
		l.c.active.Add(1)
		return &guardedConn{
			Conn: conn, l: l, start: time.Now(),
			idle: l.g.idle, maxLife: l.g.maxLife,
		}, nil
	}
}

type guardedConn struct {
	net.Conn
	l       *listener
	start   time.Time
	idle    time.Duration
	maxLife time.Duration
	once    sync.Once
}

func (c *guardedConn) deadline() time.Time {
	d := time.Now().Add(c.idle)
	if end := c.start.Add(c.maxLife); c.maxLife > 0 && end.Before(d) {
		return end
	}
	return d
}

func (c *guardedConn) Read(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(c.deadline())
	}
	return c.Conn.Read(b)
}

func (c *guardedConn) Write(b []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(c.deadline())
	}
	return c.Conn.Write(b)
}

func (c *guardedConn) Close() error {
	c.once.Do(func() {
		<-c.l.sem
		c.l.c.active.Add(-1)
	})
	return c.Conn.Close()
}

// NetConn exposes the wrapped connection.
func (c *guardedConn) NetConn() net.Conn { return c.Conn }
