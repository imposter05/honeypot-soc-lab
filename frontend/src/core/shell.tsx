// Hiten | 2026
// shell.tsx

import { NavLink, Outlet } from 'react-router-dom'
import { useOverview } from '@/api/hooks/useData'
import { useLive } from './live'

const NAV: [string, string][] = [
  ['/', 'Overview'],
  ['/incidents', 'Incidents'],
  ['/events', 'Events'],
  ['/sessions', 'Sessions'],
  ['/detections', 'Detections'],
  ['/observables', 'Observables'],
  ['/sources', 'Sources'],
  ['/lab', 'Lab'],
  ['/settings', 'Settings'],
]

const STATUS_TEXT = {
  connecting: 'Connecting',
  live: 'Live',
  'catching-up': 'Catching up',
  offline: 'Offline, retrying',
} as const

export function Shell() {
  const status = useLive((s) => s.status)
  const { data } = useOverview('24h')
  return (
    <div className="shell">
      <nav className="rail" aria-label="Main">
        <div className="brand">Honeypot SOC Investigation Lab</div>
        {NAV.map(([to, label]) => (
          <NavLink key={to} to={to} end={to === '/'}>
            <span>{label}</span>
            {to === '/incidents' && data && data.open_cases > 0 && (
              <span className="count" title="Open cases">
                {data.open_cases}
              </span>
            )}
          </NavLink>
        ))}
        <div className="foot">
          <span
            className={`live-dot ${status === 'live' ? 'live' : status === 'offline' ? 'offline' : ''}`}
          />
          {STATUS_TEXT[status]}
        </div>
      </nav>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
