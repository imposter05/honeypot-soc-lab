// Hiten | 2026
// live.ts
//
// Live updates over /api/ws. The server only sends events that are
// already stored. If this tab falls behind, the server says
// "resync" and the missed events are fetched from /api/events using
// the last seq seen, so nothing is skipped silently. After a
// reconnect the same catch-up runs.

import { create } from 'zustand'
import { api } from '@/api/client'
import type { Detection, LabEvent, Page } from '@/api/types'

const KEEP = 200

type Status = 'connecting' | 'live' | 'catching-up' | 'offline'

interface LiveState {
  status: Status
  lastSeq: number
  events: LabEvent[]
  newDetections: number
  paused: boolean
  setPaused: (p: boolean) => void
  clearDetections: () => void
}

type Listener = (d: Detection[]) => void
const detectionListeners = new Set<Listener>()
export function onDetections(fn: Listener): () => void {
  detectionListeners.add(fn)
  return () => detectionListeners.delete(fn)
}

export const useLive = create<LiveState>((set) => ({
  status: 'connecting',
  lastSeq: 0,
  events: [],
  newDetections: 0,
  paused: false,
  setPaused: (paused) => set({ paused }),
  clearDetections: () => set({ newDetections: 0 }),
}))

function addEvents(evs: LabEvent[]) {
  if (evs.length === 0) return
  useLive.setState((s) => {
    const seen = new Set(s.events.map((e) => e.seq))
    const fresh = evs.filter((e) => !seen.has(e.seq))
    const events = [...fresh.reverse(), ...s.events]
      .sort((a, b) => b.seq - a.seq)
      .slice(0, KEEP)
    const lastSeq = Math.max(s.lastSeq, ...evs.map((e) => e.seq))
    return { events, lastSeq }
  })
}

async function catchUp() {
  const from = useLive.getState().lastSeq
  if (from === 0) return
  useLive.setState({ status: 'catching-up' })
  let after = from
  for (let i = 0; i < 20; i++) {
    const page = await api.get<Page<LabEvent>>(
      `/events?after_seq=${after}&limit=500`
    )
    addEvents(page.data)
    if (page.data.length < 500) break
    after = page.data[page.data.length - 1]?.seq ?? after
  }
}

let started = false
let retry = 1000

export function startLive(): void {
  if (started) return
  started = true
  connect()
}

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/api/ws`)
  useLive.setState({ status: 'connecting' })

  ws.onmessage = (msg) => {
    const m = JSON.parse(msg.data as string) as {
      type: string
      last_seq?: number
      seq?: number
      event?: LabEvent
      detections?: Detection[]
    }
    if (m.type === 'hello') {
      retry = 1000
      const had = useLive.getState().lastSeq
      if (had > 0) {
        void catchUp().finally(() => useLive.setState({ status: 'live' }))
      } else {
        useLive.setState({ status: 'live', lastSeq: m.last_seq ?? 0 })
      }
    } else if (m.type === 'resync') {
      void catchUp().finally(() => useLive.setState({ status: 'live' }))
    } else if (m.type === 'result' && m.event) {
      if (!useLive.getState().paused)
        addEvents([{ ...m.event, seq: m.seq ?? m.event.seq }])
      else useLive.setState((s) => ({ lastSeq: Math.max(s.lastSeq, m.seq ?? 0) }))
      if (m.detections && m.detections.length > 0) {
        useLive.setState((s) => ({
          newDetections: s.newDetections + (m.detections?.length ?? 0),
        }))
        const dets = m.detections
        for (const fn of detectionListeners) fn(dets)
      }
    }
  }
  ws.onclose = () => {
    useLive.setState({ status: 'offline' })
    setTimeout(connect, retry)
    retry = Math.min(retry * 2, 15000)
  }
}
