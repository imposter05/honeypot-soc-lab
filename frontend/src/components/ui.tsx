// Hiten | 2026
// ui.tsx
//
// Small shared pieces used by every page.

import type { ReactNode } from 'react'
import { ApiError } from '@/api/client'
import type { Severity } from '@/api/types'

export function Sev({ level }: { level: Severity | string }) {
  return <span className={`sev ${level}`}>{level}</span>
}

export function Tag({ children, kind }: { children: ReactNode; kind?: string }) {
  return <span className={`tag ${kind ?? ''}`}>{children}</span>
}

export function StateTag({ state }: { state: string }) {
  return <span className={`tag state-${state}`}>{state.replace('_', ' ')}</span>
}

const fmt = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
  timeZone: 'UTC',
})

// Time shows UTC, the same as the database and exports, so times
// in the dashboard match reports and logs.
export function Time({ at, short }: { at?: string | null; short?: boolean }) {
  if (!at) return <span className="muted">-</span>
  const d = new Date(at)
  if (short) {
    return <time dateTime={at}>{d.toISOString().slice(11, 19)}</time>
  }
  return (
    <time dateTime={at} title={d.toString()}>
      {fmt.format(d)} UTC
    </time>
  )
}

export function Loading({ what }: { what: string }) {
  return (
    <div className="empty">
      <p>Loading {what}.</p>
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg =
    error instanceof ApiError || error instanceof Error
      ? error.message
      : String(error)
  return <div className="notice error">{msg}</div>
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="empty">
      <p>{children}</p>
    </div>
  )
}

export function Pager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number
  limit: number
  offset: number
  onChange: (offset: number) => void
}) {
  if (total === 0) return null
  const end = Math.min(offset + limit, total)
  return (
    <div className="pager">
      <span>
        {offset + 1} to {end} of {total}
      </span>
      <span className="row">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Previous
        </button>
        <button
          type="button"
          disabled={end >= total}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </button>
      </span>
    </div>
  )
}

export function Section({
  title,
  aside,
  children,
  flush,
}: {
  title: ReactNode
  aside?: ReactNode
  children: ReactNode
  flush?: boolean
}) {
  return (
    <section className="section">
      <h2>
        <span>{title}</span>
        {aside && <span className="small muted">{aside}</span>}
      </h2>
      {flush ? children : <div className="body">{children}</div>}
    </section>
  )
}

export function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: string
  options: [string, string][]
  onChange: (v: string) => void
}) {
  return (
    <label className="field">
      {label}
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </label>
  )
}

export const SERVICES: [string, string][] = [
  ['', 'All services'],
  ['ssh', 'SSH'],
  ['http', 'HTTP'],
  ['ftp', 'FTP'],
  ['smb', 'SMB'],
  ['mysql', 'MySQL'],
  ['redis', 'Redis'],
]

// eventDetail turns an event's service data into one readable line.
export function eventDetail(
  sd: Record<string, unknown> | undefined,
  type: string
): string {
  if (!sd) return ''
  const s = (k: string) => (typeof sd[k] === 'string' ? (sd[k] as string) : '')
  switch (type) {
    case 'command.input':
      return [s('command'), s('arg')].filter(Boolean).join(' ')
    case 'request':
      return `${s('method')} ${s('path')}${s('query') ? `?${s('query')}` : ''} -> ${String(sd.status ?? '')}`
    case 'login.success':
    case 'login.failed':
      return `user ${s('username')}${s('auth_method') === 'publickey' ? ' (key)' : ''}`
    case 'file.upload':
      return `${s('filename')}, ${String(sd.size ?? '?')} bytes, sha256 ${s('sha256').slice(0, 16)}...`
    case 'scan.detected':
      return `claims to be ${s('scanner')}`
    case 'connection.denied':
      return 'closed by the application denylist'
    default:
      return s('raw') || s('target') || s('command')
  }
}
