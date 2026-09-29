// Hiten | 2026
// Observables: values pulled from events. An analyst decides which
// ones matter; nothing is marked malicious automatically.

import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { toast } from 'sonner'
import { download } from '@/api/client'
import {
  useObservable,
  useObservables,
  useSetObservableStatus,
} from '@/api/hooks/useData'
import type { Observable } from '@/api/types'
import {
  Empty,
  ErrorBox,
  Loading,
  Pager,
  Section,
  Select,
  Tag,
  Time,
} from '@/components/ui'

const LIMIT = 100

const TYPES: [string, string][] = [
  ['', 'All types'],
  ['ipv4', 'IPv4'],
  ['ipv6', 'IPv6'],
  ['domain', 'Domain'],
  ['url', 'URL'],
  ['sha256', 'SHA-256'],
  ['md5', 'MD5'],
  ['user-agent', 'User-Agent'],
  ['ssh-client', 'SSH client'],
]
const STATUSES: [string, string][] = [
  ['observed', 'Observed'],
  ['suspicious', 'Suspicious'],
  ['confirmed', 'Confirmed malicious'],
  ['benign', 'Benign'],
]
const FORMATS: [string, string][] = [
  ['stix', 'STIX 2.1 bundle'],
  ['plain', 'IP list (plain)'],
  ['csv', 'IP list (CSV)'],
  ['iptables', 'iptables rules'],
  ['nginx', 'nginx deny list'],
]

export function ObservablesPage() {
  const [sp] = useSearchParams()
  const [type, setType] = useState('')
  const [status, setStatus] = useState('')
  const [internal, setInternal] = useState('')
  const [search, setSearch] = useState(sp.get('q') ?? '')
  const [offset, setOffset] = useState(0)
  const [picked, setPicked] = useState<Set<number>>(new Set())
  const [format, setFormat] = useState('stix')
  const [incInternal, setIncInternal] = useState(false)
  const [open, setOpen] = useState<number | null>(null)
  const [lastExport, setLastExport] = useState('')
  const q = useObservables({
    type,
    status,
    internal,
    q: search,
    limit: LIMIT,
    offset,
  })
  const setSt = useSetObservableStatus()

  const toggle = (id: number) => {
    const n = new Set(picked)
    if (n.has(id)) n.delete(id)
    else n.add(id)
    setPicked(n)
  }
  const rows = q.data?.data ?? []
  const allOnPage = rows.length > 0 && rows.every((o) => picked.has(o.id))

  async function runExport() {
    try {
      const r = await download('/observables/export', {
        ids: [...picked],
        format,
        include_internal: incInternal,
      })
      const msg = `Exported ${r.written} of ${r.selected} selected${r.skipped ? `; left out: ${r.skipped.replaceAll('_', ' ')}` : ''}.`
      setLastExport(msg)
      toast.success(msg)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  function markAll(st: string) {
    for (const id of picked) setSt.mutate({ id, status: st })
    toast.success(`Marked ${picked.size} as ${st}`)
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Observables</h1>
          <p className="sub">
            Addresses, domains, URLs, hashes and client strings seen in events.
            Values marked client-set are chosen by the client and can be faked.
            Internal addresses are kept for investigation and left out of exports
            unless you include them.
          </p>
        </div>
      </div>

      <Section
        title="Observables"
        aside={q.data ? `${q.data.meta.total} matching` : undefined}
        flush
      >
        <div className="filters">
          <Select
            label="Type"
            value={type}
            options={TYPES}
            onChange={(v) => {
              setType(v)
              setOffset(0)
            }}
          />
          <Select
            label="Status"
            value={status}
            options={[['', 'Any'], ...STATUSES]}
            onChange={(v) => {
              setStatus(v)
              setOffset(0)
            }}
          />
          <Select
            label="Address kind"
            value={internal}
            options={[
              ['', 'Any'],
              ['false', 'Public'],
              ['true', 'Internal'],
            ]}
            onChange={(v) => {
              setInternal(v)
              setOffset(0)
            }}
          />
          <label className="field">
            Contains
            <input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setOffset(0)
              }}
            />
          </label>
        </div>

        <div className="filters" style={{ background: '#f7f8f9' }}>
          <span className="small">{picked.size} selected</span>
          <Select
            label="Mark selected as"
            value=""
            options={[['', 'Choose'], ...STATUSES]}
            onChange={(v) => v && markAll(v)}
          />
          <Select
            label="Export format"
            value={format}
            options={FORMATS}
            onChange={setFormat}
          />
          <label className="row small">
            <input
              type="checkbox"
              checked={incInternal}
              onChange={(e) => setIncInternal(e.target.checked)}
            />
            include internal addresses
          </label>
          <button
            type="button"
            className="primary"
            disabled={picked.size === 0}
            onClick={() => void runExport()}
          >
            Export selected
          </button>
          {picked.size > 0 && (
            <button type="button" onClick={() => setPicked(new Set())}>
              Clear selection
            </button>
          )}
          {lastExport && <span className="small muted">{lastExport}</span>}
        </div>

        {q.isLoading && <Loading what="observables" />}
        {q.error && (
          <div className="body">
            <ErrorBox error={q.error} />
          </div>
        )}
        {q.data && rows.length === 0 && <Empty>Nothing matches.</Empty>}
        {rows.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      aria-label="Select all on this page"
                      checked={allOnPage}
                      onChange={() => {
                        const n = new Set(picked)
                        for (const o of rows)
                          allOnPage ? n.delete(o.id) : n.add(o.id)
                        setPicked(n)
                      }}
                    />
                  </th>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Status</th>
                  <th className="num">Seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((o) => (
                  <Row
                    key={o.id}
                    o={o}
                    picked={picked.has(o.id)}
                    toggle={() => toggle(o.id)}
                    open={open === o.id}
                    setOpen={() => setOpen(open === o.id ? null : o.id)}
                  />
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

function Row({
  o,
  picked,
  toggle,
  open,
  setOpen,
}: {
  o: Observable
  picked: boolean
  toggle: () => void
  open: boolean
  setOpen: () => void
}) {
  const setSt = useSetObservableStatus()
  return (
    <>
      <tr>
        <td>
          <input
            type="checkbox"
            checked={picked}
            onChange={toggle}
            aria-label={`Select ${o.value}`}
          />
        </td>
        <td>{o.type}</td>
        <td className="mono wrap">
          <button
            type="button"
            onClick={setOpen}
            style={{
              border: 0,
              padding: 0,
              background: 'none',
              color: 'var(--link)',
              textAlign: 'left',
            }}
            className="mono"
          >
            {o.value}
          </button>
          <div className="row" style={{ marginTop: 2 }}>
            {o.internal && <Tag>internal</Tag>}
            {o.claimed && <Tag>client-set</Tag>}
          </div>
        </td>
        <td>
          <select
            value={o.status}
            onChange={(e) =>
              setSt.mutate(
                { id: o.id, status: e.target.value },
                { onError: (err) => toast.error(err.message) }
              )
            }
            aria-label="Status"
          >
            {STATUSES.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </td>
        <td className="num">{o.sight_count}</td>
        <td style={{ whiteSpace: 'nowrap' }}>
          <Time at={o.last_seen} />
        </td>
      </tr>
      {open && (
        <tr>
          <td />
          <td colSpan={5}>
            <ObservableDetail id={o.id} />
          </td>
        </tr>
      )}
    </>
  )
}

function ObservableDetail({ id }: { id: number }) {
  const q = useObservable(id)
  if (!q.data) return <Loading what="evidence" />
  const o = q.data
  return (
    <div className="small stack">
      {o.original_value && o.original_value !== o.value && (
        <div>
          As written: <span className="mono">{o.original_value}</span>
        </div>
      )}
      <div>
        First seen <Time at={o.first_seen} />. Tags: {o.tags.join(', ') || 'none'}
        .
      </div>
      <div>
        Seen in:{' '}
        {(o.evidence ?? []).slice(0, 20).map((e) => (
          <Link
            key={e.event_id}
            to={`/events/${e.event_id}`}
            className="mono"
            style={{ marginRight: 8 }}
          >
            {e.event_id.slice(0, 8)}
          </Link>
        ))}
        {(o.evidence?.length ?? 0) > 20 && (
          <span className="muted">and {(o.evidence?.length ?? 0) - 20} more</span>
        )}
      </div>
    </div>
  )
}
