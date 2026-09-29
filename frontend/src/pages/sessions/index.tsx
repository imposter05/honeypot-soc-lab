// Hiten | 2026
// Sessions list and session page.

import { lazy, Suspense, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useReplay, useSession, useSessions } from '@/api/hooks/useData'
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

const LIMIT = 50

// The terminal emulator is large, so it loads only when a replay is opened.
const SessionPlayer = lazy(() =>
  import('@/components/session-player').then((m) => ({
    default: m.SessionPlayer,
  }))
)

function span(a: string, b?: string | null) {
  if (!b) return 'open'
  const s = Math.round((new Date(b).getTime() - new Date(a).getTime()) / 1000)
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`
}

export function SessionsPage() {
  const nav = useNavigate()
  const [service, setService] = useState('')
  const [source, setSource] = useState('')
  const [offset, setOffset] = useState(0)
  const q = useSessions({ service, source, limit: LIMIT, offset })
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sessions</h1>
          <p className="sub">
            One row per connection to a decoy. HTTP counts each request as a
            session.
          </p>
        </div>
      </div>
      <Section
        title="Sessions"
        aside={q.data ? `${q.data.meta.total} matching` : undefined}
        flush
      >
        <div className="filters">
          <Select
            label="Service"
            value={service}
            options={SERVICES}
            onChange={(v) => {
              setService(v)
              setOffset(0)
            }}
          />
          <label className="field">
            Source address
            <input
              value={source}
              onChange={(e) => {
                setSource(e.target.value.trim())
                setOffset(0)
              }}
            />
          </label>
        </div>
        {q.isLoading && <Loading what="sessions" />}
        {q.error && (
          <div className="body">
            <ErrorBox error={q.error} />
          </div>
        )}
        {q.data && q.data.data.length === 0 && <Empty>No sessions yet.</Empty>}
        {q.data && q.data.data.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Service</th>
                  <th>Source</th>
                  <th>Login</th>
                  <th className="num">Commands</th>
                  <th>Length</th>
                  <th>Rules</th>
                </tr>
              </thead>
              <tbody>
                {q.data.data.map((s) => (
                  <tr
                    key={s.id}
                    className="clickable"
                    onClick={() => nav(`/sessions/${s.id}`)}
                  >
                    <td>
                      <Link to={`/sessions/${s.id}`}>
                        <Time at={s.started_at} />
                      </Link>
                    </td>
                    <td>{s.service_type}</td>
                    <td className="mono">
                      {s.source_ip}:{s.source_port}
                    </td>
                    <td>
                      {s.login_success ? (
                        s.username || 'yes'
                      ) : (
                        <span className="muted">no</span>
                      )}
                    </td>
                    <td className="num">{s.command_count}</td>
                    <td>{span(s.started_at, s.ended_at)}</td>
                    <td className="small">{s.rule_ids?.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
    </>
  )
}

export function SessionPage() {
  const id = useParams().id ?? ''
  const q = useSession(id)
  const [showReplay, setShowReplay] = useState(false)
  const replay = useReplay(id, showReplay)
  if (q.isLoading) return <Loading what="session" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const { session: s, events, events_total, detections, has_replay } = q.data
  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted">
            <Link to="/sessions">Sessions</Link> / {s.id}
          </div>
          <h1 style={{ marginTop: 4 }}>
            {s.service_type} session from{' '}
            <span className="mono">{s.source_ip}</span>
          </h1>
        </div>
      </div>
      <div className="cols">
        <div>
          <Section title="Events" aside={`${events_total} in this session`} flush>
            <table className="data">
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td style={{ width: 90 }}>
                      <Time at={e.timestamp} short />
                    </td>
                    <td style={{ width: 130 }}>{e.event_type}</td>
                    <td className="mono wrap">
                      {eventDetail(e.service_data, e.event_type)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          {has_replay && (
            <Section title="Terminal replay">
              {!showReplay ? (
                <button type="button" onClick={() => setShowReplay(true)}>
                  Load replay
                </button>
              ) : replay.data ? (
                <Suspense fallback={<Loading what="player" />}>
                  <SessionPlayer castData={replay.data} />
                </Suspense>
              ) : replay.error ? (
                <ErrorBox error={replay.error} />
              ) : (
                <Loading what="replay" />
              )}
            </Section>
          )}
        </div>
        <div>
          <Section title="Session">
            <dl className="kv">
              <dt>Started</dt>
              <dd>
                <Time at={s.started_at} />
              </dd>
              <dt>Ended</dt>
              <dd>
                <Time at={s.ended_at} />
              </dd>
              <dt>Source</dt>
              <dd className="mono">
                {s.source_ip}:{s.source_port}
              </dd>
              <dt>Decoy port</dt>
              <dd>{s.dest_port}</dd>
              <dt>Login</dt>
              <dd>
                {s.login_success ? `accepted as ${s.username}` : 'none accepted'}
              </dd>
              {s.auth_mode && (
                <>
                  <dt>Auth mode</dt>
                  <dd>{s.auth_mode}</dd>
                </>
              )}
              {s.client_version && (
                <>
                  <dt>Client says</dt>
                  <dd className="mono">{s.client_version}</dd>
                </>
              )}
              <dt>Commands</dt>
              <dd>{s.command_count}</dd>
            </dl>
            {s.auth_mode === 'accept-all' && (
              <p className="small muted" style={{ marginTop: 8 }}>
                In accept-all mode every password is accepted, so a login here
                does not mean a real password was right.
              </p>
            )}
          </Section>
          <Section title="Detections">
            {detections.length === 0 ? (
              <p className="muted">None.</p>
            ) : (
              detections.map((d) => (
                <p key={d.id} className="row">
                  <Sev level={d.severity} />
                  <Link to={`/detections/${d.id}`}>
                    {d.rule_id} {d.rule_name}
                  </Link>
                  {d.case_id && (
                    <Tag>
                      <Link to={`/incidents/${d.case_id}`}>case {d.case_id}</Link>
                    </Tag>
                  )}
                </p>
              ))
            )}
          </Section>
        </div>
      </div>
    </>
  )
}
