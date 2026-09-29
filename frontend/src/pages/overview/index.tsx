// Hiten | 2026
// Overview: what needs attention now.

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useDetections, useOverview, useReady } from '@/api/hooks/useData'
import { useIncidents } from '@/api/hooks/useIncidents'
import {
  Empty,
  ErrorBox,
  Loading,
  Section,
  Select,
  Sev,
  Time,
} from '@/components/ui'

const RANGES: [string, string][] = [
  ['1h', 'Last hour'],
  ['24h', 'Last 24 hours'],
  ['168h', 'Last 7 days'],
]

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

export function OverviewPage() {
  const [range, setRange] = useState('24h')
  const nav = useNavigate()
  const ov = useOverview(range)
  const ready = useReady()
  const cases = useIncidents({ status: 'open', limit: 8 })
  const dets = useDetections({ limit: 8 })

  if (ov.isLoading) return <Loading what="overview" />
  if (ov.error) return <ErrorBox error={ov.error} />
  if (!ov.data) return null
  const o = ov.data
  const byService = Object.entries(o.events_by_service).sort(
    (a, b) => b[1] - a[1]
  )
  const max = Math.max(1, ...byService.map(([, n]) => n))

  return (
    <>
      <div className="page-head">
        <p className="headline">
          {o.open_cases === 0 ? (
            'No open cases.'
          ) : (
            <>
              <Link to="/incidents">{plural(o.open_cases, 'open case')}</Link>
              {o.pending_actions > 0 && (
                <>
                  , <Link to="/lab">{plural(o.pending_actions, 'action')}</Link>{' '}
                  waiting for approval
                </>
              )}
              .
            </>
          )}{' '}
          <span className="muted">
            {plural(o.events, 'event')} from {plural(o.sources, 'source')}.
          </span>
        </p>
        <Select
          label="Time range"
          value={range}
          options={RANGES}
          onChange={setRange}
        />
      </div>

      {ready.data && !ready.data.ready && (
        <div className="notice warn" style={{ marginBottom: 20 }}>
          The lab is not fully ready:{' '}
          {ready.data.checks
            .filter((c) => !c.ok)
            .map((c) => `${c.name} (${c.detail})`)
            .join('; ')}
          .
        </div>
      )}

      <div className="cols">
        <div>
          <Section
            title="Open cases"
            aside={<Link to="/incidents">All cases</Link>}
            flush
          >
            {cases.data && cases.data.data.length === 0 && (
              <Empty>
                Nothing open. Cases appear here when a detection fires.
              </Empty>
            )}
            {cases.data && cases.data.data.length > 0 && (
              <table className="data">
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th className="num">Detections</th>
                    <th>Last activity</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.data.data.map((c) => (
                    <tr
                      key={c.id}
                      className="clickable"
                      onClick={() => nav(`/incidents/${c.id}`)}
                    >
                      <td>
                        <Link to={`/incidents/${c.id}`}>{c.ref}</Link>
                        <div className="small muted">{c.title}</div>
                      </td>
                      <td>
                        <Sev level={c.severity} />
                      </td>
                      <td className="mono">{c.source_ip}</td>
                      <td className="num">{c.detection_count}</td>
                      <td>
                        <Time at={c.last_activity} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          <Section
            title="Latest detections"
            aside={<Link to="/detections">All detections</Link>}
            flush
          >
            {dets.data && dets.data.data.length === 0 && (
              <Empty>No detections yet.</Empty>
            )}
            {dets.data && dets.data.data.length > 0 && (
              <table className="data">
                <tbody>
                  {dets.data.data.map((d) => (
                    <tr
                      key={d.id}
                      className="clickable"
                      onClick={() => nav(`/detections/${d.id}`)}
                    >
                      <td style={{ width: 110 }}>
                        <Sev level={d.severity} />
                      </td>
                      <td>
                        <Link to={`/detections/${d.id}`}>{d.rule_name}</Link>
                        <div className="small muted">{d.explanation}</div>
                      </td>
                      <td style={{ width: 150 }}>
                        <Time at={d.detected_at} short />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
        </div>

        <div>
          <Section title="Events by service">
            {byService.length === 0 ? (
              <p className="muted">
                No events in this range. Run the lab scenarios to create some (see
                the Lab page).
              </p>
            ) : (
              <div className="bars">
                {byService.map(([svc, n]) => (
                  <div key={svc} style={{ display: 'contents' }}>
                    <Link to={`/events?service=${svc}`}>{svc}</Link>
                    <div
                      className="bar"
                      style={{ width: `${(n / max) * 100}%` }}
                    />
                    <span className="num small">{n}</span>
                  </div>
                ))}
              </div>
            )}
            <p className="small muted" style={{ marginTop: 12 }}>
              {o.events_by_origin.lab ?? 0} from lab ranges,{' '}
              {o.events_by_origin.external ?? 0} from other addresses.{' '}
              {plural(o.active_sessions, 'session')} open now.
            </p>
          </Section>

          <Section title="Lab status" aside={<Link to="/settings">Details</Link>}>
            {ready.data ? (
              <ul
                className="checks"
                style={{ margin: 0, padding: 0, listStyle: 'none' }}
              >
                {ready.data.checks.map((c) => (
                  <li key={c.name}>
                    <span className={`tag ${c.ok ? 'ok' : 'bad'}`}>
                      {c.ok ? 'ok' : 'problem'}
                    </span>
                    <span>
                      {c.name.replace('service:', '')}
                      <span className="small muted"> {c.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <Loading what="status" />
            )}
          </Section>
        </div>
      </div>
    </>
  )
}
