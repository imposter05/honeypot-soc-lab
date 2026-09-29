// Hiten | 2026
// useData.ts
//
// Read hooks for events, sessions, detections, rules, observables,
// sources, lab runs and system state.

import {
  keepPreviousData,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { api, qs } from '../client'
import type {
  Check,
  Detection,
  LabEvent,
  Observable,
  Overview,
  Page,
  Rule,
  RuleStat,
  ScenarioRun,
  Session,
  Source,
  SystemInfo,
} from '../types'

type Params = Record<string, string | number | boolean | undefined>

function usePage<T>(key: string, path: string, params: Params, refetch?: number) {
  return useQuery({
    queryKey: [key, params],
    queryFn: () => api.get<Page<T>>(`${path}${qs(params)}`),
    placeholderData: keepPreviousData,
    refetchInterval: refetch,
  })
}

export const useEvents = (p: Params) => usePage<LabEvent>('events', '/events', p)
export const useSessions = (p: Params) =>
  usePage<Session>('sessions', '/sessions', p)
export const useDetections = (p: Params) =>
  usePage<Detection>('detections', '/detections', p)
export const useObservables = (p: Params) =>
  usePage<Observable>('observables', '/observables', p)
export const useSources = (p: Params) => usePage<Source>('sources', '/sources', p)

// reveal asks the server for unmasked values. The server logs it.
export function useEvent(id: string, reveal = false) {
  return useQuery({
    queryKey: ['event', id, reveal],
    queryFn: () =>
      api
        .get<{ data: { event: LabEvent; detections: Detection[] } }>(
          `/events/${encodeURIComponent(id)}${reveal ? '?reveal=secrets' : ''}`
        )
        .then((r) => r.data),
  })
}

export function useSession(id: string) {
  return useQuery({
    queryKey: ['session', id],
    queryFn: () =>
      api
        .get<{
          data: {
            session: Session
            events: LabEvent[]
            events_total: number
            detections: Detection[]
            has_replay: boolean
          }
        }>(`/sessions/${id}`)
        .then((r) => r.data),
  })
}

export function useReplay(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ['replay', id],
    enabled,
    queryFn: async () => {
      const res = await fetch(`/api/sessions/${id}/replay`)
      if (!res.ok) throw new Error('No replay recorded for this session')
      return res.text()
    },
  })
}

export function useDetection(id: number) {
  return useQuery({
    queryKey: ['detection', id],
    queryFn: () =>
      api
        .get<{
          data: { detection: Detection; events: LabEvent[]; rule: Rule | null }
        }>(`/detections/${id}`)
        .then((r) => r.data),
  })
}

export function useRules() {
  return useQuery({
    queryKey: ['rules'],
    queryFn: () =>
      api
        .get<{
          data: { source: string; rules: { rule: Rule; stats: RuleStat }[] }
        }>('/rules')
        .then((r) => r.data),
  })
}

export function useObservable(id: number) {
  return useQuery({
    queryKey: ['observable', id],
    queryFn: () =>
      api.get<{ data: Observable }>(`/observables/${id}`).then((r) => r.data),
  })
}

export function useSetObservableStatus() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { id: number; status: string }) =>
      api.patch(`/observables/${v.id}`, { status: v.status }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['observables'] })
      void qc.invalidateQueries({ queryKey: ['observable'] })
    },
  })
}

export function useSource(id: number) {
  return useQuery({
    queryKey: ['source', id],
    queryFn: () =>
      api
        .get<{
          data: {
            source: Source
            sessions: Session[]
            cases: import('../types').Case[]
          }
        }>(`/sources/${id}`)
        .then((r) => r.data),
  })
}

export function useCountries() {
  return useQuery({
    queryKey: ['countries'],
    queryFn: () =>
      api
        .get<{
          data: {
            countries: Record<string, number>
            geoip_loaded: boolean
            note: string
          }
        }>('/stats/countries?range=720h')
        .then((r) => r.data),
  })
}

export function useCredentials(reveal = false) {
  return useQuery({
    queryKey: ['credentials', reveal],
    queryFn: () =>
      api
        .get<{
          data: {
            secrets_masked: boolean
            usernames: { value: string; count: number }[]
            passwords: { value: string; count: number }[]
            pairs: { username: string; password: string; count: number }[]
          }
        }>(`/stats/credentials${reveal ? '?reveal=secrets' : ''}`)
        .then((r) => r.data),
  })
}

export function useOverview(range: string) {
  return useQuery({
    queryKey: ['overview', range],
    queryFn: () =>
      api
        .get<{ data: Overview }>(`/stats/overview?range=${range}`)
        .then((r) => r.data),
    refetchInterval: 15000,
  })
}

export function useSystem() {
  return useQuery({
    queryKey: ['system'],
    queryFn: () => api.get<{ data: SystemInfo }>('/system').then((r) => r.data),
    refetchInterval: 10000,
  })
}

// Readiness returns 503 with a body when not ready, so it is read
// directly instead of through the error path.
export function useReady() {
  return useQuery({
    queryKey: ['ready'],
    queryFn: async () => {
      try {
        const res = await fetch('/api/ready')
        const body = (await res.json()) as {
          data: { ready: boolean; checks: Check[] }
        }
        return body.data
      } catch {
        return {
          ready: false,
          checks: [{ name: 'server', ok: false, detail: 'not reachable' }],
        }
      }
    },
    refetchInterval: 10000,
  })
}

export function useLabRuns() {
  return useQuery({
    queryKey: ['lab-runs'],
    queryFn: () =>
      api.get<{ data: ScenarioRun[] }>('/lab/runs').then((r) => r.data),
  })
}
