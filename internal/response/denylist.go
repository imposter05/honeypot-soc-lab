/*
Hiten | 2026
denylist.go

In-memory application denylist, loaded from active response actions
at startup and changed only through the response manager.
*/

package response

import (
	"net/netip"
	"sync"
	"time"
)

type entry struct {
	actionID int64
	services map[string]bool
	expires  time.Time
}

type Denylist struct {
	mu      sync.RWMutex
	entries map[netip.Addr][]entry
	now     func() time.Time
}

func NewDenylist() *Denylist {
	return &Denylist{entries: map[netip.Addr][]entry{}, now: time.Now}
}

func (d *Denylist) Add(actionID int64, ip netip.Addr, services []string, expires time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	set := map[string]bool{}
	for _, s := range services {
		set[s] = true
	}
	d.remove(actionID)
	d.entries[ip.Unmap()] = append(d.entries[ip.Unmap()], entry{actionID, set, expires})
}

func (d *Denylist) Remove(actionID int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.remove(actionID)
}

func (d *Denylist) remove(actionID int64) {
	for ip, es := range d.entries {
		kept := es[:0]
		for _, e := range es {
			if e.actionID != actionID {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(d.entries, ip)
		} else {
			d.entries[ip] = kept
		}
	}
}

// Denied is checked by netguard for every new connection. Expired
// entries stop applying immediately, even before the expiry job
// records the state change.
func (d *Denylist) Denied(ip netip.Addr, service string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	now := d.now()
	for _, e := range d.entries[ip.Unmap()] {
		if !e.expires.IsZero() && !now.Before(e.expires) {
			continue
		}
		if e.services[service] {
			return true
		}
	}
	return false
}

type Entry struct {
	ActionID int64     `json:"action_id"`
	IP       string    `json:"ip"`
	Services []string  `json:"services"`
	Expires  time.Time `json:"expires_at"`
}

func (d *Denylist) List() []Entry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []Entry
	for ip, es := range d.entries {
		for _, e := range es {
			var svcs []string
			for s := range e.services {
				svcs = append(svcs, s)
			}
			out = append(out, Entry{e.actionID, ip.String(), svcs, e.expires})
		}
	}
	return out
}
