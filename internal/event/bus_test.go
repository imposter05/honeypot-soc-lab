package event

import (
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func TestBusCountsDropsWhenFull(t *testing.T) {
	log := zerolog.Nop()
	b := NewBus(2, 10*time.Millisecond, &log)
	for i := 0; i < 5; i++ {
		b.Publish("t", &types.Event{ID: "x"})
	}
	st := b.Stats()
	if st.Accepted != 2 || st.Dropped != 3 {
		t.Fatalf("accepted=%d dropped=%d, want 2 and 3", st.Accepted, st.Dropped)
	}
}

func TestBusDrainsAfterClose(t *testing.T) {
	log := zerolog.Nop()
	b := NewBus(4, 0, &log)
	b.Publish("t", &types.Event{ID: "a"})
	b.Publish("t", &types.Event{ID: "b"})
	b.Close()
	if b.Publish("t", &types.Event{ID: "c"}) {
		t.Fatal("publish after close should fail")
	}
	var got []string
	for ev := range b.Events() {
		got = append(got, ev.ID)
	}
	if len(got) != 2 {
		t.Fatalf("drained %v, want a and b", got)
	}
}

func TestBroadcasterMarksLagged(t *testing.T) {
	br := NewBroadcaster(1)
	sub := br.Subscribe()
	br.Publish(Result{Seq: 1})
	br.Publish(Result{Seq: 2})
	if !sub.TakeLagged() {
		t.Fatal("second publish should mark the subscriber as lagged")
	}
	if r := <-sub.C; r.Seq != 1 {
		t.Fatalf("got seq %d", r.Seq)
	}
	if sub.TakeLagged() {
		t.Fatal("TakeLagged should clear the flag")
	}
}
