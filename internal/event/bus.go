/*
©AngelaMos | 2026
Modified by Hiten, 2026: replaced the fan-out pub/sub with a single
bounded ingestion queue. The old bus dropped events silently when a
subscriber was slow, and the dashboard read the same event objects
the processor was changing. Live delivery now goes through
Broadcaster, after events are stored.

bus.go

Ingestion queue between the decoy services and the processor.

Publish waits up to the configured time for room in the queue. If
the queue is still full the event is counted as dropped and logged.
Nothing is dropped without being counted, but this is not lossless
collection: a sustained flood larger than the queue will lose
events, and the counters say how many.
*/

package event

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type BusStats struct {
	Accepted uint64 `json:"accepted"`
	Dropped  uint64 `json:"dropped"`
	Queued   int    `json:"queued"`
	Capacity int    `json:"capacity"`
	Closed   bool   `json:"closed"`
}

type Bus struct {
	mu       sync.RWMutex
	ch       chan *types.Event
	wait     time.Duration
	closed   bool
	accepted atomic.Uint64
	dropped  atomic.Uint64
	logger   *zerolog.Logger
}

func NewBus(size int, wait time.Duration, logger *zerolog.Logger) *Bus {
	if size < 1 {
		size = 1
	}
	return &Bus{
		ch:     make(chan *types.Event, size),
		wait:   wait,
		logger: logger,
	}
}

// Publish queues ev for processing. The topic is kept for the
// existing service code and logging; routing no longer depends on
// it. It returns false if the event was dropped.
func (b *Bus) Publish(topic string, ev *types.Event) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		b.drop(topic, ev, "queue closed")
		return false
	}

	select {
	case b.ch <- ev:
		b.accepted.Add(1)
		return true
	default:
	}

	if b.wait > 0 {
		t := time.NewTimer(b.wait)
		defer t.Stop()
		select {
		case b.ch <- ev:
			b.accepted.Add(1)
			return true
		case <-t.C:
		}
	}

	b.drop(topic, ev, "queue full")
	return false
}

func (b *Bus) drop(topic string, ev *types.Event, reason string) {
	b.dropped.Add(1)
	if b.logger != nil {
		b.logger.Warn().
			Str("reason", reason).
			Str("topic", topic).
			Str("event_id", ev.ID).
			Str("event_type", ev.EventType.String()).
			Str("source_ip", ev.SourceIP).
			Msg("event dropped before processing")
	}
}

// Events is read by the processor. It is closed by Close.
func (b *Bus) Events() <-chan *types.Event {
	return b.ch
}

// Close stops new events. Events already queued stay readable so
// the processor can drain them.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.ch)
	}
}

func (b *Bus) Stats() BusStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return BusStats{
		Accepted: b.accepted.Load(),
		Dropped:  b.dropped.Load(),
		Queued:   len(b.ch),
		Capacity: cap(b.ch),
		Closed:   b.closed,
	}
}
