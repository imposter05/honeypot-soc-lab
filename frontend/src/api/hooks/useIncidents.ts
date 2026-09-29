// Hiten | 2026
// useIncidents.ts

import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { api, qs } from '../client'
import type {
  ActionHistoryEntry,
  Case,
  CaseBundle,
  LabEvent,
  Page,
  ResponseAction,
} from '../types'

export interface IncidentFilter {
  status?: string
  severity?: string
  source?: string
  limit?: number
  offset?: number
}

export function useIncidents(f: IncidentFilter) {
  return useQuery({
    queryKey: ['incidents', f],
    queryFn: () => api.get<Page<Case>>(`/incidents${qs({ ...f })}`),
  })
}

export function useIncident(id: number) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: () =>
      api.get<{ data: CaseBundle }>(`/incidents/${id}`).then((r) => r.data),
  })
}

// The timeline is read 500 events at a time; "Load more" fetches the
// next page, so large cases are complete without one huge request.
export function useIncidentTimeline(id: number) {
  return useInfiniteQuery({
    queryKey: ['incident', id, 'timeline'],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get<Page<LabEvent>>(
        `/incidents/${id}/timeline?limit=500&offset=${pageParam}`
      ),
    getNextPageParam: (last) => {
      const next = last.meta.offset + last.data.length
      return next < last.meta.total ? next : undefined
    },
  })
}

function useInvalidateIncident(id: number) {
  const qc = useQueryClient()
  return () => {
    void qc.invalidateQueries({ queryKey: ['incident', id] })
    void qc.invalidateQueries({ queryKey: ['incidents'] })
    void qc.invalidateQueries({ queryKey: ['overview'] })
    void qc.invalidateQueries({ queryKey: ['actions'] })
  }
}

export type CasePatch = Partial<
  Pick<
    Case,
    | 'title'
    | 'status'
    | 'severity'
    | 'verdict'
    | 'response_decision'
    | 'closure_reason'
  >
>

export function useUpdateIncident(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: (p: CasePatch) =>
      api.patch<{ data: Case }>(`/incidents/${id}`, p),
    onSuccess: done,
  })
}

export function useAddNote(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: (body: string) => api.post(`/incidents/${id}/notes`, { body }),
    onSuccess: done,
  })
}

export function useAddEvidence(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: (v: { event_id: string; note: string }) =>
      api.post(`/incidents/${id}/evidence`, v),
    onSuccess: done,
  })
}

export function useSplitIncident(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: (v: { detection_ids: number[]; title: string }) =>
      api.post<{ data: Case }>(`/incidents/${id}/split`, v),
    onSuccess: done,
  })
}

export function useMergeIncident(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: (from_case_id: number) =>
      api.post(`/incidents/${id}/merge`, { from_case_id }),
    onSuccess: done,
  })
}

export function useRequestAction(id: number) {
  const done = useInvalidateIncident(id)
  return useMutation({
    mutationFn: () =>
      api.post<{ data: ResponseAction }>(`/incidents/${id}/actions`, {}),
    onSettled: done,
  })
}

export function useActions(f: {
  state?: string
  case?: number
  limit?: number
  offset?: number
}) {
  return useQuery({
    queryKey: ['actions', f],
    queryFn: () => api.get<Page<ResponseAction>>(`/actions${qs({ ...f })}`),
  })
}

export function useActionHistory(id: number, enabled: boolean) {
  return useQuery({
    queryKey: ['action', id],
    enabled,
    queryFn: () =>
      api
        .get<{ data: { action: ResponseAction; history: ActionHistoryEntry[] } }>(
          `/actions/${id}`
        )
        .then((r) => r.data),
  })
}

export function useDecideAction(caseId: number) {
  const done = useInvalidateIncident(caseId)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: {
      id: number
      kind: 'approve' | 'reject' | 'reverse'
      services?: string[]
      expires_in?: string
      reason?: string
    }) => {
      const body =
        v.kind === 'approve'
          ? { services: v.services, expires_in: v.expires_in }
          : { reason: v.reason }
      return api.post<{ data: ResponseAction }>(
        `/actions/${v.id}/${v.kind}`,
        body
      )
    },
    onSettled: () => {
      done()
      void qc.invalidateQueries({ queryKey: ['system'] })
    },
  })
}
