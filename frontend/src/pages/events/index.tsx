// Hiten | 2026
// Events: stored events with filters, plus the live feed.

import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useEvent, useEvents } from '@/api/hooks/useData'
import type { LabEvent } from '@/api/types'
import {
  Empty,
  ErrorBox,
  eventDetail,
  Loading,
  Pager,
  SERVICES,
  Section,
  Select,
  Sev,
  Tag,
  Time,
} from '@/components/ui'
import { useLive } from '@/core/live'

const LIMIT = 100

const TYPES: [string, string][] = [
  ['', 'All types'],
  ['connect', 'connect'],
  ['disconnect', 'disconnect'],
  ['login.success', 'login.success'],
  ['login.failed', 'login.failed'],
  ['command.input', 'command.input'],
  ['request', 'request'],
  ['file.upload', 'file.upload'],
  ['exploit.attempt', 'exploit.attempt'],
  ['scan.detected', 'scan.detected'],
  ['connection.denied', 'connection.denied'],
]

function EventTable({ events }: { events: LabEvent[] }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Service</th>
            <th>Type</th>
            <th>Source</th>
            <th>Detail</th>
            <th>Session</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={`${e.id}-${e.seq}`}>
              <td style={{ whiteSpace: 'nowrap' }}>
                <Link to={`/events/${e.id}`}>
                  <Time at={e.timestamp} />
                </Link>
              </td>
              <td>{e.service_type}</td>
              <td>{e.event_type}</td>
              <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                {e.source_ip}:{e.source_port}{' '}
                {e.origin === 'lab' && <Tag kind="lab">lab</Tag>}
              </td>
              <td className="mono wrap">
                {eventDetail(e.service_data, e.event_type)}
              </td>
              <td>
                <Link to={`/sessions/${e.session_id}`} className="mono small">
                  {e.session_id.slice(0, 8)}
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function EventsPage() {
  const [sp, setSp] = useSearchParams()
  const [tab, setTab] = useState<'history' | 'live'>('history')
  const [offset, setOffset] = useState(0)
  const f = {
    service: sp.get('service') ?? '',
    type: sp.get('type') ?? '',
    source: sp.get('source') ?? '',
    origin: sp.get('origin') ?? '',
  }
  const set = (k: string, v: string) => {
    const n = new URLSearchParams(sp)
    if (v) n.set(k, v)
    else n.delete(k)
    setSp(n)
    setOffset(0)
  }
  const q = useEvents({ ...f, limit: LIMIT, offset })
  const live = useLive()

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Events</h1>
          <p className="sub">
            Everything the decoys recorded, after it was stored.
          </p>
        </div>
        <div className="row">
          <button
            type="button"
            className={tab === 'history' ? 'primary' : ''}
            onClick={() => setTab('history')}
          >
            Stored events
          </button>
          <button
            type="button"
            className={tab === 'live' ? 'primary' : ''}
            onClick={() => setTab('live')}
          >
            Live feed
          </button>
        </div>
      </div>

      {tab === 'live' ? (
        <Section
          title="Live feed"
          aside={
            <span className="row">
              <span>
                {live.status === 'live'
                  ? `last seq ${live.lastSeq}`
                  : live.status}
              </span>
              <button type="button" onClick={() => live.setPaused(!live.paused)}>
                {live.paused ? 'Resume' : 'Pause'}
              </button>
            </span>
          }
          flush
        >
          {live.events.length === 0 ? (
            <Empty>
              Waiting for new events. Connect to a decoy or run the lab scenarios.
            </Empty>
          ) : (
            <EventTable events={live.events} />
          )}
        </Section>
      ) : (
        <Section
          title="Stored events"
          aside={q.data ? `${q.data.meta.total} matching` : undefined}
          flush
        >
          <div className="filters">
            <Select
              label="Service"
              value={f.service}
              options={SERVICES}
              onChange={(v) => set('service', v)}
            />
            <Select
              label="Type"
              value={f.type}
              options={TYPES}
              onChange={(v) => set('type', v)}
            />
            <Select
              label="Origin"
              value={f.origin}
              options={[
                ['', 'Any'],
                ['lab', 'Lab ranges'],
                ['external', 'Other addresses'],
              ]}
              onChange={(v) => set('origin', v)}
            />
            <label className="field">
              Source address
              <input
                defaultValue={f.source}
                onBlur={(e) => set('source', e.target.value.trim())}
                placeholder="127.0.0.1"
              />
            </label>
          </div>
          {q.isLoading && <Loading what="events" />}
          {q.error && (
            <div className="body">
              <ErrorBox error={q.error} />
            </div>
          )}
          {q.data && q.data.data.length === 0 && (
            <Empty>No events match these filters.</Empty>
          )}
          {q.data && q.data.data.length > 0 && (
            <EventTable events={q.data.data} />
          )}
          {q.data && (
            <Pager
              total={q.data.meta.total}
              limit={LIMIT}
              offset={offset}
              onChange={setOffset}
            />
          )}
        </Section>
      )}
    </>
  )
}

export function EventPage() {
  const id = useParams().id ?? ''
  const [reveal, setReveal] = useState(false)
  const q = useEvent(id, reveal)
  if (q.isLoading) return <Loading what="event" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const { event: e, detections } = q.data
  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted">
            <Link to="/events">Events</Link> / {e.id}
          </div>
          <h1 style={{ marginTop: 4 }}>
            {e.service_type} {e.event_type}
          </h1>
        </div>
      </div>
      <div className="cols">
        <Section
          title="Recorded data"
          aside={
            <button type="button" onClick={() => setReveal(!reveal)}>
              {reveal ? 'Mask secrets' : 'Show masked values'}
            </button>
          }
        >
          <pre className="block">
            {JSON.stringify(e.service_data ?? {}, null, 2)}
          </pre>
        </Section>
        <div>
          <Section title="Event">
            <dl className="kv">
              <dt>Time</dt>
              <dd>
                <Time at={e.timestamp} />
              </dd>
              <dt>Stored</dt>
              <dd>
                <Time at={e.received_at} /> (seq {e.seq})
              </dd>
              <dt>Source</dt>
              <dd className="mono">
                {e.source_ip}:{e.source_port}
              </dd>
              <dt>Destination</dt>
              <dd className="mono">
                {e.dest_ip ?? '?'}:{e.dest_port}
              </dd>
              <dt>Origin</dt>
              <dd>{e.origin === 'lab' ? 'lab range' : 'other address'}</dd>
              <dt>Session</dt>
              <dd>
                <Link to={`/sessions/${e.session_id}`} className="mono">
                  {e.session_id}
                </Link>
              </dd>
              <dt>Sensor</dt>
              <dd>{e.sensor_id}</dd>
              <dt>Location</dt>
              <dd>
                {e.geo ? `${e.geo.country} ${e.geo.city}` : 'not available'}
              </dd>
            </dl>
          </Section>
          <Section title="Detections citing this event">
            {detections.length === 0 ? (
              <p className="muted">None.</p>
            ) : (
              detections.map((d) => (
                <p key={d.id} className="row">
                  <Sev level={d.severity} />
                  <Link to={`/detections/${d.id}`}>
                    {d.rule_id} {d.rule_name}
                  </Link>
                </p>
              ))
            )}
          </Section>
        </div>
      </div>
    </>
  )
}
