// Hiten | 2026
// Lab: scenario results, response actions and pipeline counters.

import { Link } from 'react-router-dom'
import { useLabRuns, useSystem } from '@/api/hooks/useData'
import { useActions } from '@/api/hooks/useIncidents'
import {
  Empty,
  ErrorBox,
  Loading,
  Section,
  StateTag,
  Tag,
  Time,
} from '@/components/ui'

export function LabPage() {
  const runs = useLabRuns()
  const actions = useActions({ limit: 50 })
  const sys = useSystem()
  const byRun = new Map<string, typeof runs.data>()
  for (const r of runs.data ?? [])
    byRun.set(r.run_id, [...(byRun.get(r.run_id) ?? []), r])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Lab</h1>
          <p className="sub">
            Run <code>go run ./cmd/labtest</code> (or <code>./bin/labtest</code>)
            while the lab is running. Each scenario connects to the decoys from
            its own 127.x address and checks what was detected.
          </p>
        </div>
      </div>

      <Section title="Scenario runs" flush>
        {runs.isLoading && <Loading what="runs" />}
        {runs.error && (
          <div className="body">
            <ErrorBox error={runs.error} />
          </div>
        )}
        {runs.data && runs.data.length === 0 && (
          <Empty>No runs recorded yet.</Empty>
        )}
        {[...byRun.entries()].map(([id, rs]) => {
          const list = rs ?? []
          const failed = list.filter((r) => !r.passed && !r.skipped).length
          const skipped = list.filter((r) => r.skipped).length
          return (
            <details
              key={id}
              className="body"
              style={{ borderTop: '1px solid var(--rule-soft)' }}
            >
              <summary className="row">
                <strong className="mono">{id}</strong>
                <Time at={list[0]?.started_at} />
                {failed === 0 ? (
                  <Tag kind="ok">all passed</Tag>
                ) : (
                  <Tag kind="bad">{failed} failed</Tag>
                )}
                {skipped > 0 && <Tag>{skipped} skipped</Tag>}
              </summary>
              <table className="data" style={{ marginTop: 8 }}>
                <tbody>
                  {list.map((r) => (
                    <tr key={r.id}>
                      <td>
                        {r.skipped ? (
                          <Tag>skipped</Tag>
                        ) : r.passed ? (
                          <Tag kind="ok">pass</Tag>
                        ) : (
                          <Tag kind="bad">fail</Tag>
                        )}
                      </td>
                      <td>
                        {r.scenario_id}
                        <div className="small muted">{r.kind}</div>
                      </td>
                      <td className="mono">
                        <Link to={`/events?source=${r.source_ip}`}>
                          {r.source_ip}
                        </Link>
                      </td>
                      <td className="small">
                        {r.failures?.map((f) => (
                          <div key={f}>{f}</div>
                        ))}
                        {r.notes && <div className="muted">{r.notes}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          )
        })}
      </Section>

      <div className="cols">
        <Section title="Response actions" flush>
          {actions.data && actions.data.data.length === 0 && (
            <Empty>No restrictions requested.</Empty>
          )}
          {actions.data && actions.data.data.length > 0 && (
            <table className="data">
              <tbody>
                {actions.data.data.map((a) => (
                  <tr key={a.id}>
                    <td>{a.id}</td>
                    <td>
                      <StateTag state={a.state} />
                    </td>
                    <td className="mono">{a.source_ip}</td>
                    <td className="small">{a.services.join(', ')}</td>
                    <td>
                      <Link to={`/incidents/${a.case_id}`}>case {a.case_id}</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
        <Section title="Pipeline">
          {sys.data ? (
            <dl className="kv">
              <dt>Stored</dt>
              <dd>
                {sys.data.processor.processed} events (last seq{' '}
                {sys.data.processor.last_seq})
              </dd>
              <dt>Not stored</dt>
              <dd>
                {sys.data.processor.persist_failures} failed writes,{' '}
                {sys.data.processor.spooled} written to the spool file,{' '}
                {sys.data.queue.dropped} dropped because the queue was full
              </dd>
              <dt>Queue</dt>
              <dd>
                {sys.data.queue.queued} of {sys.data.queue.capacity}
              </dd>
              <dt>Live tabs</dt>
              <dd>
                {sys.data.live.subscribers} connected,{' '}
                {sys.data.live.dropped_deliveries} updates sent late through
                catch-up
              </dd>
              {sys.data.processor.last_error && (
                <>
                  <dt>Last error</dt>
                  <dd className="small">
                    {sys.data.processor.last_error} (
                    <Time at={sys.data.processor.last_error_at} />)
                  </dd>
                </>
              )}
              <dt>Denylist</dt>
              <dd>
                {(sys.data.denylist ?? []).length === 0
                  ? 'empty'
                  : (sys.data.denylist ?? []).map((d) => (
                      <div key={d.action_id} className="small">
                        <span className="mono">{d.ip}</span> on{' '}
                        {d.services.join(', ')} until{' '}
                        <Time at={d.expires_at} short />
                      </div>
                    ))}
              </dd>
            </dl>
          ) : (
            <Loading what="pipeline" />
          )}
        </Section>
      </div>
    </>
  )
}
