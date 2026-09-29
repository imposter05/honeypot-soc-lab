/*
©AngelaMos | 2026
Modified by Hiten, 2026: subscribes to stored results instead of raw
events, checks the Origin header against the same allow list as the
API, and tells the browser to resync from the database when it fell
behind instead of silently skipping events.

websocket.go

Messages sent to the browser:

  {"type":"hello","last_seq":N}      on connect
  {"type":"result", ...Result}        one per stored event
  {"type":"resync"}                   the browser missed results and
                                      should call /api/events?after_seq=
*/

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/CarterPerez-dev/hive/internal/redact"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && !s.guard.OriginAllowed(o) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The origin was checked above against the allow list.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

	sub := s.d.Broadcaster.Subscribe()
	defer s.d.Broadcaster.Unsubscribe(sub)

	ctx := conn.CloseRead(r.Context())
	last, _ := s.d.Store.MaxSeq(ctx)

	send := func(v any) bool {
		data, err := json.Marshal(v)
		if err != nil {
			return true
		}
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, data) == nil
	}

	if !send(map[string]any{"type": "hello", "last_seq": last}) {
		return
	}
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "")
			return
		case <-ping.C:
			if sub.TakeLagged() && !send(map[string]string{"type": "resync"}) {
				return
			}
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		case res := <-sub.C:
			if sub.TakeLagged() && !send(map[string]string{"type": "resync"}) {
				return
			}
			if !send(map[string]any{
				"type": "result", "seq": res.Seq, "event": redact.Event(res.Event),
				"detections": redactDetections(detPtrs(res.Detections)), "case_ids": res.CaseIDs,
			}) {
				return
			}
		}
	}
}

// The live feed is always masked; unmasked values are only available
// through an explicit, logged API request.
func detPtrs(ds []types.Detection) []*types.Detection {
	out := make([]*types.Detection, len(ds))
	for i := range ds {
		out[i] = &ds[i]
	}
	return out
}
