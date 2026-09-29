// Hiten | 2026
// timeline.tsx
//
// The case timeline. Every event linked to the case sits on a time
// spine. A filled mark means a detection fired on that event; an
// outlined mark means the event counted toward a detection. The
// detection's explanation is shown under the event that triggered it.
// Events are matched by ID: timestamps can differ by microseconds,
// which JavaScript dates cannot tell apart.

import { Link } from 'react-router-dom'
import type { Detection, LabEvent } from '@/api/types'
import { eventDetail, Sev, Tag } from '@/components/ui'

const SEV_VAR: Record<string, string> = {
  low: 'var(--sev-low)',
  medium: 'var(--sev-medium)',
  high: 'var(--sev-high)',
  critical: 'var(--sev-critical)',
}
const RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 }
const GAP_MS = 10 * 60 * 1000

function duration(ms: number) {
  const m = Math.round(ms / 60000)
  if (m < 60) return `${m} minutes`
  const h = Math.round(m / 6) / 10
  return `${h} hours`
}

export function Timeline({
  events,
  detections,
}: {
  events: LabEvent[]
  detections: Detection[]
}) {
  const role = new Map<string, { role: string; sev: string }>()
  const triggers = new Map<string, Detection[]>()
  for (const d of detections) {
    for (const e of d.evidence ?? []) {
      const k = e.event_id
      const cur = role.get(k)
      const better =
        !cur ||
        (e.role === 'trigger' && cur.role !== 'trigger') ||
        (e.role === cur.role && (RANK[d.severity] ?? 0) > (RANK[cur.sev] ?? 0))
      if (better && e.role !== 'repeat')
        role.set(k, { role: e.role, sev: d.severity })
      if (e.role === 'trigger') triggers.set(k, [...(triggers.get(k) ?? []), d])
    }
  }

  let lastDay = ''
  return (
    <>
      <div className="legend" style={{ marginBottom: 8 }}>
        <span className="t">detection fired on this event</span>
        <span>counted toward a detection</span>
      </div>
      <ol className="ledger">
        {events.map((ev, i) => {
          const k = ev.id
          const r = role.get(k)
          const fired = triggers.get(k) ?? []
          const prev = events[i - 1]
          const gap = prev
            ? new Date(ev.timestamp).getTime() -
              new Date(prev.timestamp).getTime()
            : 0
          const day = ev.timestamp.slice(0, 10)
          const newDay = day !== lastDay
          lastDay = day
          return (
            <li key={k} style={{ display: 'contents' }}>
              {newDay && (
                <div className="entry gap">
                  <span className="time">{day}</span>
                  <span className="spine" />
                  <span className="what">UTC</span>
                </div>
              )}
              {!newDay && gap > GAP_MS && (
                <div className="entry gap">
                  <span className="time" />
                  <span className="spine" />
                  <span className="what">nothing for {duration(gap)}</span>
                </div>
              )}
              <div
                className={`entry ${r?.role ?? ''}`}
                style={
                  r
                    ? ({ '--sev-color': SEV_VAR[r.sev] } as React.CSSProperties)
                    : undefined
                }
              >
                <span className="time">{ev.timestamp.slice(11, 19)}</span>
                <span className="spine">
                  <span className="mark" />
                </span>
                <div className="what">
                  <div className="line">
                    <strong>{ev.service_type}</strong>
                    <span>{ev.event_type}</span>
                    <Link className="small" to={`/sessions/${ev.session_id}`}>
                      session {ev.session_id.slice(0, 8)}
                    </Link>
                    {ev.origin === 'lab' && <Tag kind="lab">lab</Tag>}
                  </div>
                  <div className="detail">
                    {eventDetail(ev.service_data, ev.event_type)}
                  </div>
                  {fired.map((d) => (
                    <div
                      key={d.id}
                      className="finding"
                      style={
                        {
                          '--sev-color': SEV_VAR[d.severity],
                        } as React.CSSProperties
                      }
                    >
                      <div className="line row">
                        <Sev level={d.severity} />
                        <Link to={`/detections/${d.id}`}>
                          {d.rule_id} {d.rule_name}
                        </Link>
                        <span className="small muted">
                          confidence {d.confidence}
                        </span>
                      </div>
                      <div style={{ marginTop: 4 }}>{d.explanation}</div>
                    </div>
                  ))}
                </div>
              </div>
            </li>
          )
        })}
      </ol>
    </>
  )
}
