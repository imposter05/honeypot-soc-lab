/*
Hiten | 2026
broadcaster.go

Live delivery of stored results to dashboard connections.

Only results that were committed to the database are published.
Each subscriber has its own buffer. When a buffer is full the
result is not delivered to that subscriber and the subscription is
marked as lagged; the WebSocket handler then tells the browser to
fetch what it missed from the database using the seq cursor. A slow
browser therefore loses live updates, never stored evidence.
*/

package event

import (
	"sync"
	"sync/atomic"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

// Result is what the processor publishes after a commit.
type Result struct {
	Seq        int64             `json:"seq"`
	Event      *types.Event      `json:"event"`
	Detections []types.Detection `json:"detections,omitempty"`
	CaseIDs    []int64           `json:"case_ids,omitempty"`
}

type Subscription struct {
	C      chan Result
	lagged atomic.Bool
}

// TakeLagged reports whether deliveries were missed since the last
// call and clears the flag.
func (s *Subscription) TakeLagged() bool {
	return s.lagged.Swap(false)
}

type BroadcastStats struct {
	Subscribers       int    `json:"subscribers"`
	Delivered         uint64 `json:"delivered"`
	DroppedDeliveries uint64 `json:"dropped_deliveries"`
	LastSeq           int64  `json:"last_seq"`
}

type Broadcaster struct {
	mu        sync.RWMutex
	subs      map[*Subscription]struct{}
	buf       int
	delivered atomic.Uint64
	dropped   atomic.Uint64
	lastSeq   atomic.Int64
}

func NewBroadcaster(buffer int) *Broadcaster {
	if buffer < 1 {
		buffer = 1
	}
	return &Broadcaster{subs: map[*Subscription]struct{}{}, buf: buffer}
}

func (b *Broadcaster) Subscribe() *Subscription {
	s := &Subscription{C: make(chan Result, b.buf)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

func (b *Broadcaster) Unsubscribe(s *Subscription) {
	b.mu.Lock()
	delete(b.subs, s)
	b.mu.Unlock()
}

func (b *Broadcaster) Publish(r Result) {
	b.lastSeq.Store(r.Seq)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		select {
		case s.C <- r:
			b.delivered.Add(1)
		default:
			s.lagged.Store(true)
			b.dropped.Add(1)
		}
	}
}

func (b *Broadcaster) Stats() BroadcastStats {
	b.mu.RLock()
	n := len(b.subs)
	b.mu.RUnlock()
	return BroadcastStats{
		Subscribers:       n,
		Delivered:         b.delivered.Load(),
		DroppedDeliveries: b.dropped.Load(),
		LastSeq:           b.lastSeq.Load(),
	}
}
