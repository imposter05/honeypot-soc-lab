// Hiten | 2026
// Settings: how this lab is configured. Values come from config.yaml
// and are read-only here; change the file and restart.

import { useState } from 'react'
import { toast } from 'sonner'
import { getAnalyst, setAnalyst } from '@/api/client'
import { useCredentials, useSystem } from '@/api/hooks/useData'
import { ErrorBox, Loading, Section, Tag, Time } from '@/components/ui'

export function SettingsPage() {
  const q = useSystem()
  const [reveal, setReveal] = useState(false)
  const creds = useCredentials(reveal)
  const [name, setName] = useState(getAnalyst())
  if (q.isLoading) return <Loading what="settings" />
  if (q.error) return <ErrorBox error={q.error} />
  if (!q.data) return null
  const s = q.data
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="sub">
            Read from <span className="mono">{s.config_source}</span>. Edit that
            file and restart to change them.
          </p>
        </div>
      </div>
      <div className="cols">
        <div>
          <Section title="Listeners">
            <table className="data">
              <tbody>
                {s.listeners.map((l) => (
                  <tr key={l.name}>
                    <td>{l.name}</td>
                    <td className="mono">{l.address}</td>
                    <td>
                      <Tag kind={l.state === 'listening' ? 'ok' : 'bad'}>
                        {l.state}
                      </Tag>
                    </td>
                    <td className="small muted">
                      {connText(s.connections[l.name])}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          <Section title="Limits">
            <dl className="kv mono small">
              {Object.entries(s.limits).map(([k, v]) => (
                <div key={k} style={{ display: 'contents' }}>
                  <dt>{k}</dt>
                  <dd>{String(v)}</dd>
                </div>
              ))}
            </dl>
          </Section>
          <Section
            title="Most tried credentials"
            aside={
              <button type="button" onClick={() => setReveal(!reveal)}>
                {reveal ? 'Hide passwords' : 'Show passwords'}
              </button>
            }
          >
            <p className="small muted" style={{ marginBottom: 8 }}>
              Passwords are masked by default. Showing them is written to the
              server log with your name.
            </p>
            {creds.data ? (
              <table className="data">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Password</th>
                    <th className="num">Tries</th>
                  </tr>
                </thead>
                <tbody>
                  {creds.data.pairs.map((p) => (
                    <tr key={`${p.username}/${p.password}`}>
                      <td className="mono">{p.username}</td>
                      <td className="mono">{p.password}</td>
                      <td className="num">{p.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Loading what="credentials" />
            )}
          </Section>
        </div>
        <div>
          <Section title="This lab">
            <dl className="kv">
              <dt>Version</dt>
              <dd>{s.version}</dd>
              <dt>Sensor</dt>
              <dd>{s.sensor}</dd>
              <dt>Started</dt>
              <dd>
                <Time at={s.started_at} />
              </dd>
              <dt>Database</dt>
              <dd>
                migration {s.schema_version} (needs {s.required_schema})
              </dd>
              <dt>SSH logins</dt>
              <dd>
                {s.ssh_auth_mode === 'accept-all'
                  ? 'accept-all: every password works'
                  : 'test-credentials: only the configured test accounts work'}
              </dd>
              <dt>Lab ranges</dt>
              <dd className="mono">{s.lab_ranges.join(', ')}</dd>
              <dt>Rules</dt>
              <dd>{s.rules_source}</dd>
              <dt>GeoIP</dt>
              <dd>{s.geoip ? 'on' : 'off'}</dd>
              <dt>Response</dt>
              <dd>
                {s.response_enabled
                  ? 'requests are created for new cases'
                  : 'off'}
              </dd>
            </dl>
          </Section>
          <Section title="Your name in case history">
            <div className="stack">
              <p className="small muted">
                The lab has no login. This name is sent with your changes and
                stored in this browser only.
              </p>
              <div className="row">
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="analyst"
                  maxLength={64}
                />
                <button
                  type="button"
                  onClick={() => {
                    setAnalyst(name.trim())
                    toast.success('Name saved')
                  }}
                >
                  Save name
                </button>
              </div>
            </div>
          </Section>
        </div>
      </div>
    </>
  )
}

function connText(c?: { accepted: number; denied: number; over_limit: number }) {
  if (!c) return ''
  return `${c.accepted} accepted, ${c.denied} denied, ${c.over_limit} over limit`
}
