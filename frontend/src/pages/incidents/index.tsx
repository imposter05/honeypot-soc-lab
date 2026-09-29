// Hiten | 2026
// Incidents list.

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useIncidents } from '@/api/hooks/useIncidents'
import {
  Empty,
  ErrorBox,
  Loading,
  Pager,
  Section,
  Select,
  Sev,
  Tag,
  Time,
} from '@/components/ui'

const LIMIT = 50

export function IncidentsPage() {
  const nav = useNavigate()
  const [status, setStatus] = useState('open')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [offset, setOffset] = useState(0)
  const q = useIncidents({ status, severity, source, limit: LIMIT, offset })

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p className="sub">
            A case groups detections from one source on one sensor that happened
            close together. Split or merge cases on the case page when the
            grouping is wrong.
          </p>
        </div>
      </div>
      <Section
        title="Cases"
        aside={q.data ? `${q.data.meta.total} matching` : undefined}
        flush
      >
        <div className="filters">
          <Select
            label="Status"
            value={status}
            onChange={(v) => {
              setStatus(v)
              setOffset(0)
            }}
            options={[
              ['open', 'Open'],
              ['new', 'New'],
              ['investigating', 'Investigating'],
              ['closed', 'Closed'],
              ['', 'All'],
            ]}
          />
          <Select
            label="Severity"
            value={severity}
            onChange={(v) => {
              setSeverity(v)
              setOffset(0)
            }}
            options={[
              ['', 'Any'],
              ['critical', 'Critical'],
              ['high', 'High'],
              ['medium', 'Medium'],
              ['low', 'Low'],
            ]}
          />
          <label className="field">
            Source address
            <input
              value={source}
              onChange={(e) => {
                setSource(e.target.value.trim())
                setOffset(0)
              }}
              placeholder="127.0.0.1"
            />
          </label>
        </div>
        {q.isLoading && <Loading what="cases" />}
        {q.error && (
          <div className="body">
            <ErrorBox error={q.error} />
          </div>
        )}
        {q.data && q.data.data.length === 0 && (
          <Empty>No cases match these filters.</Empty>
        )}
        {q.data && q.data.data.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Source</th>
                  <th className="num">Detections</th>
                  <th>First activity</th>
                  <th>Last activity</th>
                </tr>
              </thead>
              <tbody>
                {q.data.data.map((c) => (
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
                      <Tag>{c.status}</Tag>{' '}
                      {c.verdict && (
                        <span className="small muted">{c.verdict}</span>
                      )}
                    </td>
                    <td>
                      <Sev level={c.severity} />
                    </td>
                    <td className="mono">{c.source_ip}</td>
                    <td className="num">{c.detection_count}</td>
                    <td>
                      <Time at={c.first_activity} />
                    </td>
                    <td>
                      <Time at={c.last_activity} />
                    </td>
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
