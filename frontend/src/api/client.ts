// Hiten | 2026
// client.ts
//
// Small fetch wrapper. Every write sends JSON (the API rejects
// anything else) and the analyst name for the case history.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown
  ) {
    super(message)
  }
}

const ANALYST_KEY = 'soc-lab.analyst'

export function getAnalyst(): string {
  try {
    return localStorage.getItem(ANALYST_KEY) ?? ''
  } catch {
    return ''
  }
}

export function setAnalyst(name: string): void {
  try {
    localStorage.setItem(ANALYST_KEY, name)
  } catch {
    // storage unavailable; the server default name is used
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const analyst = getAnalyst()
  if (analyst) headers['X-Analyst'] = analyst

  let res: Response
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the lab server. Is `hive serve` running?')
  }
  const text = await res.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : undefined
  } catch {
    parsed = text
  }
  if (!res.ok) {
    const fromBody = (parsed as { error?: string } | undefined)?.error
    const msg =
      fromBody ?? (typeof parsed === 'string' && parsed ? parsed : res.statusText)
    throw new ApiError(res.status, msg, parsed)
  }
  return parsed as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body: unknown = {}) => request<T>('POST', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
}

export function qs(
  params: Record<string, string | number | boolean | undefined>
): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

// download posts a JSON body and saves the response as a file. It
// returns the export counters the server puts in headers.
export async function download(
  path: string,
  body: unknown
): Promise<{ written: string; skipped: string; selected: string }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const analyst = getAnalyst()
  if (analyst) headers['X-Analyst'] = analyst
  const res = await fetch(`/api${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const t = await res.text()
    let msg = t
    try {
      msg = (JSON.parse(t) as { error: string }).error
    } catch {
      // plain text error
    }
    throw new ApiError(res.status, msg)
  }
  saveBlob(await res.blob(), filenameFrom(res))
  return {
    written: res.headers.get('X-Export-Written') ?? '?',
    skipped: res.headers.get('X-Export-Skipped') ?? '',
    selected: res.headers.get('X-Export-Selected') ?? '?',
  }
}

export async function downloadGet(path: string): Promise<void> {
  const res = await fetch(`/api${path}`)
  if (!res.ok) throw new ApiError(res.status, await res.text())
  saveBlob(await res.blob(), filenameFrom(res))
}

function filenameFrom(res: Response): string {
  const cd = res.headers.get('Content-Disposition') ?? ''
  return /filename="([^"]+)"/.exec(cd)?.[1] ?? 'export'
}

function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
