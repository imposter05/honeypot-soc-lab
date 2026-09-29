// Hiten | 2026
// Sources: addresses that connected to the decoys.

import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useCountries, useSource, useSources } from '@/api/hooks/useData'
import {
  Empty,
  ErrorBox,
  Loading,
  Pager,
  Section,
  Sev,
  Tag,
  Time,
} from '@/components/ui'

const LIMIT = 50

export function SourcesPage() {
  const nav = useNavigate()
  const [offset, setOffset] = useState(0)
  const q = useSources({ range: '720h', limit: LIMIT, offset })
  const countries = useCountries()
  const rows = Object.entries(countries.data?.countries ?? {})
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sources</h1>
          <p className="sub">
            Addresses that contacted a decoy in the last 30 days. An address is
            not a person: several people can share one, and one person can use
            many.
          </p>
        </div>
      </div>
      <div className="cols">
        <Section
          title="Addresses"
          aside={q.data ? `${q.data.meta.total} addresses` : undefined}
          flush
        >
          {q.isLoading && <Loading what="sources" />}
          {q.error && (
            <div className="body">
              <ErrorBox error={q.error} />
            </div>
          )}
          {q.data && q.data.data.length === 0 && <Empty>No sources yet.</Empty>}
          {q.data && q.data.data.length > 0 && (
            <table className="data">
              <thead>
                <tr>
                  <th>Address</th>
                  <th className="num">Events</th>
                  <th className="num">Sessions</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {q.data.data.map((s) => (
                  <tr
                    key={s.id}
                    className="clickable"
                    onClick={() => nav(`/sources/${s.id}`)}
                  >
                    <td>
                      <Link to={`/sources/${s.id}`} className="mono">
                        {s.ip}
                      </Link>{' '}
                      {s.internal && <Tag>internal</Tag>}
                      {s.geo && (
                        <span className="small muted"> {s.geo.country}</span>
                      )}
                    </td>
                    <td className="num">{s.total_events}</td>
                    <td className="num">{s.total_sessions}</td>
                    <td>
                      <Time at={s.last_seen} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
        <Section title="Where events came from">
          {countries.data && !countries.data.geoip_loaded && (
            <p className="muted" style={{ marginBottom: 8 }}>
              GeoIP is off, so no locations are shown. Set geoip.db_path to a
              GeoLite2-City database to turn it on.
            </p>
          )}
          <table className="data">
            <tbody>
              {rows.map(([cc, n]) => (
                <tr key={cc}>
                  <td>
                    {cc === 'unavailable'
                      ? 'No location (internal address or no GeoIP)'
                      : cc}
                  </td>
                  <td className="num">{n}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="small muted" style={{ marginTop: 8 }}>
            {countries.data?.note}
          </p>
        </Section>
      </div>
    </>
  )
}

export function SourcePage() {
  const id = Number(useParams().id)
  const q = useSource(id)
  if (q.isLoading) return <Loading what="source" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const { source: s, sessions, cases } = q.data
  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted">
            <Link to="/sources">Sources</Link> / {s.ip}
          </div>
          <h1 style={{ marginTop: 4 }} className="mono">
            {s.ip}
          </h1>
          <p className="sub">
            {s.internal ? 'Internal or loopback address. ' : ''}
            {s.total_events} events in {s.total_sessions} sessions, first seen{' '}
            <Time at={s.first_seen} />.
          </p>
        </div>
        <Link className="button" to={`/events?source=${s.ip}`}>
          View events
        </Link>
      </div>
      <div className="cols">
        <Section title="Sessions" flush>
          <table className="data">
            <tbody>
              {sessions.map((x) => (
                <tr key={x.id}>
                  <td>
                    <Link to={`/sessions/${x.id}`}>
                      <Time at={x.started_at} />
                    </Link>
                  </td>
                  <td>{x.service_type}</td>
                  <td className="small">{x.rule_ids?.join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
        <Section title="Cases">
          {cases.length === 0 ? (
            <p className="muted">None.</p>
          ) : (
            cases.map((c) => (
              <p key={c.id} className="row">
                <Sev level={c.severity} />{' '}
                <Link to={`/incidents/${c.id}`}>{c.ref}</Link>{' '}
                <Tag>{c.status}</Tag>
              </p>
            ))
          )}
        </Section>
      </div>
    </>
  )
}
