// Hiten | 2026
// Case page.

import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { downloadGet } from '@/api/client'
import { useSystem } from '@/api/hooks/useData'
import {
  type CasePatch,
  useActionHistory,
  useAddEvidence,
  useAddNote,
  useDecideAction,
  useIncident,
  useIncidentTimeline,
  useMergeIncident,
  useRequestAction,
  useSplitIncident,
  useUpdateIncident,
} from '@/api/hooks/useIncidents'
import type { Case, Detection, ResponseAction } from '@/api/types'
import {
  Empty,
  ErrorBox,
  Loading,
  Section,
  Sev,
  StateTag,
  Tag,
  Time,
} from '@/components/ui'
import { Timeline } from './timeline'

export function IncidentPage() {
  const id = Number(useParams().id)
  const q = useIncident(id)
  const tl = useIncidentTimeline(id)
  const [withSecrets, setWithSecrets] = useState(false)
  const events = tl.data?.pages.flatMap((p) => p.data) ?? []
  const total = tl.data?.pages[0]?.meta.total ?? 0
  const secretParam = withSecrets ? '&reveal=secrets' : ''

  if (q.isLoading) return <Loading what="case" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const b = q.data
  const c = b.case

  return (
    <>
      <div className="page-head">
        <div>
          <div className="row small muted">
            <Link to="/incidents">Incidents</Link>
            <span>/</span>
            <span>{c.ref}</span>
          </div>
          <h1 style={{ marginTop: 4 }}>{c.title}</h1>
          <p className="sub row">
            <Sev level={c.severity} />
            <Tag>{c.status}</Tag>
            {c.verdict && <Tag>{c.verdict}</Tag>}
            <span className="mono">{c.source_ip}</span>
            <span>
              <Time at={c.first_activity} /> to{' '}
              <Time at={c.last_activity} short />
            </span>
          </p>
        </div>
        <div className="row">
          <label className="row small" title="Recorded in the case history">
            <input
              type="checkbox"
              checked={withSecrets}
              onChange={(e) => setWithSecrets(e.target.checked)}
            />
            include passwords
          </label>
          <button
            type="button"
            onClick={() =>
              void downloadGet(`/incidents/${id}/export?format=md${secretParam}`)
            }
          >
            Export report
          </button>
          <button
            type="button"
            onClick={() =>
              void downloadGet(
                `/incidents/${id}/export?format=json${secretParam}`
              )
            }
          >
            Export JSON
          </button>
        </div>
      </div>

      {c.merged_into && (
        <div className="notice warn" style={{ marginBottom: 20 }}>
          This case was merged into{' '}
          <Link to={`/incidents/${c.merged_into}`}>case {c.merged_into}</Link>. It
          stays readable here, but changes go to that case.
        </div>
      )}

      <div className="cols">
        <div>
          <Section
            title="Timeline"
            aside={`${c.event_count ?? 0} events, ${c.session_ids?.length ?? 0} sessions, ${
              c.services?.join(', ') || 'no services'
            }`}
          >
            {tl.isLoading && <Loading what="timeline" />}
            {tl.error && <ErrorBox error={tl.error} />}
            {tl.data && events.length === 0 && (
              <Empty>No events linked to this case.</Empty>
            )}
            {events.length > 0 && (
              <>
                <Timeline events={events} detections={b.detections} />
                <div className="row small muted" style={{ marginTop: 8 }}>
                  <span>
                    Showing {events.length} of {total} events.
                  </span>
                  {tl.hasNextPage && (
                    <button
                      type="button"
                      disabled={tl.isFetchingNextPage}
                      onClick={() => void tl.fetchNextPage()}
                    >
                      Load more
                    </button>
                  )}
                </div>
              </>
            )}
            <AddEvidence caseId={id} />
          </Section>

          <DetectionsPanel caseData={c} detections={b.detections} />

          <Section title="Observables" aside="values seen in this case's events">
            {b.observables.length === 0 ? (
              <p className="muted">None.</p>
            ) : (
              <table className="data">
                <tbody>
                  {b.observables.map((o) => (
                    <tr key={o.id}>
                      <td style={{ width: 100 }}>{o.type}</td>
                      <td className="mono wrap">
                        <Link
                          to={`/observables?q=${encodeURIComponent(o.value)}`}
                        >
                          {o.value}
                        </Link>
                      </td>
                      <td style={{ width: 170 }} className="small">
                        <Tag>{o.status}</Tag> {o.internal && <Tag>internal</Tag>}{' '}
                        {o.claimed && <Tag>client-set</Tag>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
        </div>

        <div>
          <DecisionPanel c={c} />
          <ResponsePanel c={c} actions={b.actions} />
          <NotesPanel caseId={id} notes={b.notes} />
          <MergePanel c={c} />
          <Section title="History" aside="append-only">
            <ul style={{ margin: 0, paddingLeft: 18 }} className="small">
              {b.history.map((h) => (
                <li key={h.id} style={{ marginBottom: 4 }}>
                  <Time at={h.at} short /> <strong>{h.actor}</strong>{' '}
                  {h.action.replaceAll('_', ' ')}
                  {'from' in h.detail && 'to' in h.detail && (
                    <span className="muted">
                      {' '}
                      {String(h.detail.from || '(empty)')} to{' '}
                      {String(h.detail.to)}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </Section>
        </div>
      </div>
    </>
  )
}

const VERDICTS: [string, string][] = [
  ['', 'No verdict yet'],
  ['suspicious', 'Suspicious'],
  ['benign', 'Benign'],
  ['expected-test', 'Expected test activity'],
  ['insufficient-evidence', 'Insufficient evidence'],
]

function DecisionPanel({ c }: { c: Case }) {
  const upd = useUpdateIncident(c.id)
  const [status, setStatus] = useState<string>(c.status)
  const [verdict, setVerdict] = useState<string>(c.verdict ?? '')
  const [severity, setSeverity] = useState<string>(c.severity)
  const [decision, setDecision] = useState(c.response_decision ?? '')
  const [reason, setReason] = useState(c.closure_reason ?? '')
  const closing = status === 'closed'
  const blocked = closing && (!verdict || !reason.trim())

  function save() {
    const p: CasePatch = {}
    if (status !== c.status) p.status = status as Case['status']
    if (verdict !== (c.verdict ?? '')) p.verdict = verdict as Case['verdict']
    if (severity !== c.severity) p.severity = severity as Case['severity']
    if (decision !== (c.response_decision ?? '')) p.response_decision = decision
    if (reason !== (c.closure_reason ?? '')) p.closure_reason = reason
    if (Object.keys(p).length === 0) {
      toast('Nothing changed')
      return
    }
    upd.mutate(p, {
      onSuccess: () => toast.success('Case saved'),
      onError: (e) => toast.error(e.message),
    })
  }

  return (
    <Section title="Decision">
      <div className="stack">
        <div className="row">
          <label className="field">
            Status
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              disabled={!!c.merged_into}
            >
              {c.status === 'closed' ? (
                <>
                  <option value="closed">Closed</option>
                  <option value="investigating">Reopen (investigating)</option>
                </>
              ) : (
                <>
                  <option value="new">New</option>
                  <option value="investigating">Investigating</option>
                  <option value="closed">Closed</option>
                </>
              )}
            </select>
          </label>
          <label className="field">
            Severity
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {['low', 'medium', 'high', 'critical'].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Verdict
            <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
              {VERDICTS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          Response decision
          <input
            value={decision}
            onChange={(e) => setDecision(e.target.value)}
            placeholder="For example: restricted source for 1 hour, no further action"
          />
        </label>
        <label className="field">
          Closure explanation {closing && <span>(required to close)</span>}
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        {blocked && (
          <p className="small muted">
            A closed case needs a verdict and an explanation.
          </p>
        )}
        <div>
          <button
            type="button"
            className="primary"
            onClick={save}
            disabled={blocked || upd.isPending}
          >
            Save case
          </button>
        </div>
      </div>
    </Section>
  )
}

const EXPIRY: [string, string][] = [
  ['15m', '15 minutes'],
  ['1h', '1 hour'],
  ['4h', '4 hours'],
  ['24h', '24 hours'],
]

function ResponsePanel({ c, actions }: { c: Case; actions: ResponseAction[] }) {
  const req = useRequestAction(c.id)
  const open = actions.some(
    (a) => a.state === 'pending_approval' || a.state === 'active'
  )
  return (
    <Section title="Response" aside="restrict this source">
      <div className="stack">
        <p className="small muted">
          Approving adds the source to this app's denylist, so new connections to
          the chosen decoys are closed. It does not change the host firewall or
          end sessions already open.
        </p>
        {actions.length === 0 && (
          <p className="muted">No restriction requested.</p>
        )}
        {actions.map((a) => (
          <ActionCard key={a.id} a={a} caseId={c.id} />
        ))}
        {!open && c.status !== 'closed' && (
          <div>
            <button
              type="button"
              onClick={() =>
                req.mutate(undefined, {
                  onSuccess: () => toast.success('Restriction requested'),
                  onError: (e) => toast.error(e.message),
                })
              }
            >
              Request restriction
            </button>
          </div>
        )}
      </div>
    </Section>
  )
}

function ActionCard({ a, caseId }: { a: ResponseAction; caseId: number }) {
  const sys = useSystem()
  const decide = useDecideAction(caseId)
  const [services, setServices] = useState<string[]>(a.services)
  const [expiry, setExpiry] = useState('1h')
  const [reason, setReason] = useState('')
  const [showLog, setShowLog] = useState(false)
  const log = useActionHistory(a.id, showLog)
  const all =
    sys.data?.listeners
      .filter((l) => l.name !== 'api' && l.state === 'listening')
      .map((l) => l.name) ?? a.services

  const run = (kind: 'approve' | 'reject' | 'reverse', ok: string) =>
    decide.mutate(
      { id: a.id, kind, services, expires_in: expiry, reason },
      {
        onSuccess: () => toast.success(ok),
        onError: (e) => toast.error(e.message),
      }
    )

  return (
    <div
      style={{ borderTop: '1px solid var(--rule-soft)', paddingTop: 10 }}
      className="stack"
    >
      <div className="row">
        <strong>Action {a.id}</strong>
        <StateTag state={a.state} />
        {a.expires_at && a.state === 'active' && (
          <span className="small muted">
            until <Time at={a.expires_at} short />
          </span>
        )}
      </div>
      <p className="small">{a.summary}</p>
      {a.error && <div className="notice error small">{a.error}</div>}
      {a.verification && (
        <div className="small">
          Verification <VerifyTag status={a.verification.status} />
          <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {a.verification.checks.map((ch) => (
              <li key={ch.service}>
                {ch.service}: <VerifyTag status={ch.result} /> {ch.reason}
                {ch.probe && (
                  <div className="muted">test connection: {ch.probe.detail}</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {a.state === 'pending_approval' && (
        <>
          <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="small muted">Decoys to restrict</legend>
            <div className="row">
              {all.map((s) => (
                <label key={s} className="row small">
                  <input
                    type="checkbox"
                    checked={services.includes(s)}
                    onChange={(e) =>
                      setServices(
                        e.target.checked
                          ? [...services, s]
                          : services.filter((x) => x !== s)
                      )
                    }
                  />
                  {s}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="row">
            <label className="field">
              Expires after
              <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
                {EXPIRY.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="primary"
              disabled={services.length === 0 || decide.isPending}
              onClick={() => run('approve', 'Restriction approved')}
            >
              Approve
            </button>
          </div>
          <div className="row">
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason for rejecting"
            />
            <button
              type="button"
              disabled={!reason.trim()}
              onClick={() => run('reject', 'Request rejected')}
            >
              Reject
            </button>
          </div>
        </>
      )}

      {a.state === 'active' && (
        <div className="row">
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason for lifting it"
          />
          <button
            type="button"
            className="danger"
            disabled={!reason.trim()}
            onClick={() => run('reverse', 'Restriction lifted')}
          >
            Lift restriction
          </button>
        </div>
      )}

      <button
        type="button"
        className="small"
        onClick={() => setShowLog(!showLog)}
      >
        {showLog ? 'Hide' : 'Show'} action history
      </button>
      {showLog && log.data && (
        <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
          {log.data.history.map((h) => (
            <li key={h.id}>
              <Time at={h.at} short /> {h.actor}: {h.from_state || 'requested'} to{' '}
              {h.to_state}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function VerifyTag({ status }: { status?: string }) {
  if (status === 'verified') return <Tag kind="ok">verified</Tag>
  if (status === 'failed') return <Tag kind="bad">failed</Tag>
  return <Tag kind="warn">not confirmed</Tag>
}

function DetectionsPanel({
  caseData,
  detections,
}: {
  caseData: Case
  detections: Detection[]
}) {
  const nav = useNavigate()
  const split = useSplitIncident(caseData.id)
  const [picked, setPicked] = useState<number[]>([])
  return (
    <Section title="Detections" aside={`${detections.length} linked`}>
      <table className="data">
        <tbody>
          {detections.map((d) => (
            <tr key={d.id}>
              <td style={{ width: 28 }}>
                <input
                  type="checkbox"
                  aria-label={`Select detection ${d.id}`}
                  checked={picked.includes(d.id)}
                  onChange={(e) =>
                    setPicked(
                      e.target.checked
                        ? [...picked, d.id]
                        : picked.filter((x) => x !== d.id)
                    )
                  }
                />
              </td>
              <td style={{ width: 100 }}>
                <Sev level={d.severity} />
              </td>
              <td>
                <Link to={`/detections/${d.id}`}>
                  {d.rule_id} {d.rule_name}
                </Link>
                {d.suppressed_count > 0 && (
                  <span className="small muted">
                    {' '}
                    and {d.suppressed_count} repeats
                  </span>
                )}
                <div className="small muted">
                  {d.mitre.join(', ') || 'no ATT&CK mapping'}
                </div>
              </td>
              <td style={{ width: 90 }}>
                <Time at={d.detected_at} short />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row" style={{ marginTop: 10 }}>
        <button
          type="button"
          disabled={
            picked.length === 0 ||
            picked.length === detections.length ||
            split.isPending
          }
          onClick={() =>
            split.mutate(
              { detection_ids: picked, title: '' },
              {
                onSuccess: (r) => {
                  toast.success(`Moved to ${r.data.ref}`)
                  setPicked([])
                  nav(`/incidents/${r.data.id}`)
                },
                onError: (e) => toast.error(e.message),
              }
            )
          }
        >
          Move selected to a new case
        </button>
        <span className="small muted">
          Use this when the selected detections are a separate incident.
        </span>
      </div>
    </Section>
  )
}

function MergePanel({ c }: { c: Case }) {
  const merge = useMergeIncident(c.id)
  const [from, setFrom] = useState('')
  if (c.merged_into || c.status === 'closed') return null
  return (
    <Section title="Merge another case into this one">
      <div className="row">
        <input
          value={from}
          onChange={(e) => setFrom(e.target.value)}
          placeholder="Case number, for example 12"
        />
        <button
          type="button"
          disabled={!/^\d+$/.test(from) || merge.isPending}
          onClick={() =>
            merge.mutate(Number(from), {
              onSuccess: () => {
                toast.success('Cases merged')
                setFrom('')
              },
              onError: (e) => toast.error(e.message),
            })
          }
        >
          Merge
        </button>
      </div>
    </Section>
  )
}

function NotesPanel({
  caseId,
  notes,
}: {
  caseId: number
  notes: { id: number; at: string; author: string; body: string }[]
}) {
  const add = useAddNote(caseId)
  const [body, setBody] = useState('')
  return (
    <Section title="Notes">
      <div className="stack">
        {notes.length === 0 && <p className="muted">No notes yet.</p>}
        {notes.map((n) => (
          <div key={n.id}>
            <div className="small muted">
              {n.author}, <Time at={n.at} />
            </div>
            <p style={{ whiteSpace: 'pre-wrap' }}>{n.body}</p>
          </div>
        ))}
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="What you checked and what you found"
        />
        <div>
          <button
            type="button"
            disabled={!body.trim() || add.isPending}
            onClick={() =>
              add.mutate(body, {
                onSuccess: () => {
                  setBody('')
                  toast.success('Note added')
                },
                onError: (e) => toast.error(e.message),
              })
            }
          >
            Add note
          </button>
        </div>
      </div>
    </Section>
  )
}

function AddEvidence({ caseId }: { caseId: number }) {
  const add = useAddEvidence(caseId)
  const [eventId, setEventId] = useState('')
  const [note, setNote] = useState('')
  return (
    <details style={{ marginTop: 12 }}>
      <summary className="small">Add an event to this case by hand</summary>
      <div className="row" style={{ marginTop: 8 }}>
        <input
          value={eventId}
          onChange={(e) => setEventId(e.target.value.trim())}
          placeholder="Event ID"
          style={{ minWidth: 280 }}
        />
        <input
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Why it belongs here"
        />
        <button
          type="button"
          disabled={!eventId || add.isPending}
          onClick={() =>
            add.mutate(
              { event_id: eventId, note },
              {
                onSuccess: () => {
                  setEventId('')
                  setNote('')
                  toast.success('Event added')
                },
                onError: (e) => toast.error(e.message),
              }
            )
          }
        >
          Add event
        </button>
      </div>
    </details>
  )
}
