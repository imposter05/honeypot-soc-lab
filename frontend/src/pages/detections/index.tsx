// Hiten | 2026
// Detections, a detection's evidence, and the rule list.

import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useDetection, useDetections, useRules } from '@/api/hooks/useData'
import type { Rule } from '@/api/types'
import {
  Empty,
  ErrorBox,
  eventDetail,
  Loading,
  Pager,
  Section,
  Select,
  Sev,
  Tag,
  Time,
} from '@/components/ui'

const LIMIT = 50

export function DetectionsPage() {
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const tab = sp.get('tab') === 'rules' ? 'rules' : 'detections'
  const [rule, setRule] = useState(sp.get('rule') ?? '')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const q = useDetections({ rule, severity, limit: LIMIT, offset })
  const rules = useRules()
  const ruleOptions: [string, string][] = [
    ['', 'All rules'],
    ...(rules.data?.rules.map((r): [string, string] => [
      r.rule.id,
      `${r.rule.id} ${r.rule.name}`,
    ]) ?? []),
  ]

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Detections</h1>
          <p className="sub">
            Each detection names the rule version, the events it counted and the
            threshold it crossed.
          </p>
        </div>
        <div className="row">
          <button
            type="button"
            className={tab === 'detections' ? 'primary' : ''}
            onClick={() => setSp({})}
          >
            Detections
          </button>
          <button
            type="button"
            className={tab === 'rules' ? 'primary' : ''}
            onClick={() => setSp({ tab: 'rules' })}
          >
            Rules
          </button>
        </div>
      </div>

      {tab === 'rules' ? (
        <RulesList />
      ) : (
        <Section
          title="Detections"
          aside={q.data ? `${q.data.meta.total} matching` : undefined}
          flush
        >
          <div className="filters">
            <Select
              label="Rule"
              value={rule}
              options={ruleOptions}
              onChange={(v) => {
                setRule(v)
                setOffset(0)
              }}
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
          </div>
          {q.isLoading && <Loading what="detections" />}
          {q.error && (
            <div className="body">
              <ErrorBox error={q.error} />
            </div>
          )}
          {q.data && q.data.data.length === 0 && (
            <Empty>No detections match.</Empty>
          )}
          {q.data && q.data.data.length > 0 && (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Detected</th>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Source</th>
                    <th>Case</th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.data.map((d) => (
                    <tr
                      key={d.id}
                      className="clickable"
                      onClick={() => nav(`/detections/${d.id}`)}
                    >
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <Time at={d.detected_at} />
                      </td>
                      <td>
                        <Sev level={d.severity} />
                      </td>
                      <td>
                        <Link to={`/detections/${d.id}`}>
                          {d.rule_id} {d.rule_name}
                        </Link>
                        <div className="small muted">{d.explanation}</div>
                      </td>
                      <td className="mono">{d.source_ip}</td>
                      <td>
                        {d.case_id ? (
                          <Link to={`/incidents/${d.case_id}`}>{d.case_id}</Link>
                        ) : (
                          '-'
                        )}
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
      )}
    </>
  )
}

function RuleBody({ r }: { r: Rule }) {
  const params = Object.entries(r.params).filter(
    ([, v]) => v !== 0 && v !== null && !(Array.isArray(v) && v.length === 0)
  )
  return (
    <div className="stack">
      <p>{r.description}</p>
      <dl className="kv">
        <dt>Why it matters</dt>
        <dd>{r.rationale}</dd>
        <dt>Confidence</dt>
        <dd>
          {r.confidence}: {r.confidence_rationale}
        </dd>
        <dt>Settings</dt>
        <dd className="mono small">
          {params.map(([k, v]) => (
            <div key={k}>
              {k}:{' '}
              {k === 'window'
                ? `${Number(v) / 1e9}s`
                : Array.isArray(v)
                  ? v.join(', ')
                  : String(v)}
            </div>
          ))}
          <div>suppress repeats for: {r.suppress_for / 1e9}s</div>
        </dd>
        <dt>Needs fields</dt>
        <dd className="mono small">{r.required_fields.join(', ')}</dd>
        <dt>ATT&amp;CK</dt>
        <dd>{r.mitre.length ? r.mitre.join(', ') : 'none'}</dd>
        <dt>False positives</dt>
        <dd>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {r.false_positives.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
        </dd>
        <dt>What to check</dt>
        <dd>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {r.guidance.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
        </dd>
        <dt>Tests</dt>
        <dd className="small">
          fires on: {r.tests.positive.join(', ')}
          <br />
          stays quiet on: {r.tests.negative.join(', ')}
        </dd>
      </dl>
    </div>
  )
}

function RulesList() {
  const q = useRules()
  if (q.isLoading) return <Loading what="rules" />
  if (q.error) return <ErrorBox error={q.error} />
  return (
    <>
      <p className="muted" style={{ marginBottom: 16 }}>
        Loaded from {q.data?.source}. Thresholds are lab starting points, not
        industry standards.
      </p>
      {(q.data?.rules ?? []).map(({ rule: r, stats }) => (
        <Section
          key={r.id}
          title={
            <span className="row">
              <Sev level={r.severity} /> {r.id} v{r.version}: {r.name}{' '}
              {!r.enabled && <Tag>disabled</Tag>}
            </span>
          }
          aside={
            <Link to={`/detections?rule=${r.id}`}>
              {stats?.detections ?? 0} detections,{' '}
              {stats?.suppressed_repeats ?? 0} repeats
            </Link>
          }
        >
          <RuleBody r={r} />
        </Section>
      ))}
    </>
  )
}

export function DetectionPage() {
  const id = Number(useParams().id)
  const q = useDetection(id)
  if (q.isLoading) return <Loading what="detection" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const { detection: d, events, rule } = q.data
  const roleOf = new Map((d.evidence ?? []).map((e) => [e.event_id, e.role]))
  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted">
            <Link to="/detections">Detections</Link> / {d.id}
          </div>
          <h1 style={{ marginTop: 4 }}>
            {d.rule_id} {d.rule_name}
          </h1>
          <p className="sub row">
            <Sev level={d.severity} /> <span>confidence {d.confidence}</span>
            <span>rule version {d.rule_version}</span>
            {d.case_id && (
              <Link to={`/incidents/${d.case_id}`}>open case {d.case_id}</Link>
            )}
          </p>
        </div>
      </div>
      <div className="cols">
        <div>
          <Section title="What happened">
            <p>{d.explanation}</p>
            {d.suppressed_count > 0 && (
              <p className="small muted" style={{ marginTop: 8 }}>
                The same pattern repeated {d.suppressed_count} more times inside
                the suppression window. Those events are linked as repeats instead
                of new detections.
              </p>
            )}
          </Section>
          <Section title="Evidence" aside={`${events.length} events`} flush>
            <table className="data">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Role</th>
                  <th>Type</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <Link to={`/events/${e.id}`}>
                        <Time at={e.timestamp} short />
                      </Link>
                    </td>
                    <td>
                      <Tag>{roleOf.get(e.id) ?? '?'}</Tag>
                    </td>
                    <td>
                      {e.service_type} {e.event_type}
                    </td>
                    <td className="mono wrap">
                      {eventDetail(e.service_data, e.event_type)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          <Section title="Matched values">
            <pre className="block">
              {JSON.stringify(d.matched_values, null, 2)}
            </pre>
          </Section>
        </div>
        <div>
          {rule ? (
            <Section title="About this rule">
              <RuleBody r={rule} />
            </Section>
          ) : (
            <div className="notice warn">
              This rule is no longer loaded. The detection keeps the version that
              produced it.
            </div>
          )}
        </div>
      </div>
    </>
  )
}
