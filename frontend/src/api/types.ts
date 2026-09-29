// Hiten | 2026
// types.ts
//
// Shapes returned by the Go API. Field names match the JSON tags in
// pkg/types/types.go.

export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Confidence = 'low' | 'medium' | 'high'
export type CaseStatus = 'new' | 'investigating' | 'closed'
export type Verdict =
  | 'suspicious'
  | 'benign'
  | 'expected-test'
  | 'insufficient-evidence'
export type ObservableStatus = 'observed' | 'suspicious' | 'confirmed' | 'benign'
export type ActionState =
  | 'pending_approval'
  | 'rejected'
  | 'active'
  | 'failed'
  | 'expired'
  | 'reversed'

export interface Page<T> {
  data: T[]
  meta: { total: number; limit: number; offset: number }
}

export interface Geo {
  country_code: string
  country: string
  city: string
}

export interface LabEvent {
  id: string
  seq: number
  session_id: string
  sensor_id: string
  timestamp: string
  received_at: string
  service_type: string
  event_type: string
  source_ip: string
  source_port: number
  dest_ip?: string
  dest_port: number
  origin: 'lab' | 'external'
  geo?: Geo
  tags?: string[]
  service_data?: Record<string, unknown>
}

// Evidence links use these names (Go type EventRef).
export interface EventRef {
  event_id: string
  event_timestamp: string
}

export interface Evidence extends EventRef {
  role: 'trigger' | 'contributing' | 'repeat'
}

export interface Detection {
  id: number
  rule_id: string
  rule_version: number
  rule_name: string
  severity: Severity
  confidence: Confidence
  sensor_id: string
  source_ip: string
  session_id?: string
  service_type: string
  first_seen: string
  last_seen: string
  detected_at: string
  explanation: string
  matched_values: Record<string, unknown>
  mitre: string[]
  suppressed_count: number
  case_id?: number | null
  evidence?: Evidence[]
}

export interface Rule {
  id: string
  version: number
  name: string
  kind: string
  enabled: boolean
  severity: Severity
  confidence: Confidence
  confidence_rationale: string
  description: string
  rationale: string
  required_fields: string[]
  params: Record<string, unknown>
  suppress_for: number
  mitre: string[]
  false_positives: string[]
  guidance: string[]
  tests: { positive: string[]; negative: string[] }
}

export interface RuleStat {
  detections: number
  suppressed_repeats: number
  last_detected?: string
}

export interface Session {
  id: string
  sensor_id: string
  started_at: string
  ended_at?: string | null
  service_type: string
  source_ip: string
  source_port: number
  dest_port: number
  client_version?: string
  login_success: boolean
  username?: string
  auth_mode?: string
  command_count: number
  rule_ids?: string[]
  last_activity?: string
}

export interface Observable {
  id: number
  type: string
  value: string
  original_value?: string
  first_seen: string
  last_seen: string
  sight_count: number
  source: string
  tags: string[]
  status: ObservableStatus
  internal: boolean
  claimed: boolean
  evidence?: (EventRef & { session_id: string })[]
}

export interface Case {
  id: number
  ref: string
  title: string
  status: CaseStatus
  severity: Severity
  verdict?: Verdict | ''
  sensor_id: string
  source_ip: string
  first_activity: string
  last_activity: string
  created_at: string
  updated_at: string
  closed_at?: string | null
  response_decision?: string
  closure_reason?: string
  merged_into?: number | null
  detection_count: number
  event_count?: number
  session_ids?: string[]
  services?: string[]
}

export interface CaseNote {
  id: number
  at: string
  author: string
  body: string
}

export interface HistoryEntry {
  id: number
  at: string
  actor: string
  action: string
  detail: Record<string, unknown>
}

export interface ResponseAction {
  id: number
  case_id: number
  playbook: string
  source_ip: string
  sensor_id: string
  services: string[]
  state: ActionState
  summary: string
  requested_at: string
  decided_at?: string | null
  decided_by?: string
  expires_at?: string | null
  ended_at?: string | null
  verification?: {
    status: 'verified' | 'unverified' | 'failed'
    passed: boolean
    checked_at: string
    checks: {
      service: string
      denylist_check: boolean
      result: 'verified' | 'unverified' | 'failed'
      reason: string
      probe?: { outcome: string; detail: string; target: string }
    }[]
  }
  error?: string
}

export interface ActionHistoryEntry {
  id: number
  at: string
  actor: string
  from_state: string
  to_state: string
  detail: Record<string, unknown>
}

export interface CaseBundle {
  case: Case
  detections: Detection[]
  notes: CaseNote[]
  history: HistoryEntry[]
  added_evidence: (EventRef & { added_by: string; note?: string })[]
  actions: ResponseAction[]
  observables: Observable[]
  secrets_masked: boolean
}

export interface Source {
  id: number
  ip: string
  internal: boolean
  first_seen: string
  last_seen: string
  total_events: number
  total_sessions: number
  geo: Geo | null
}

export interface ScenarioRun {
  id: number
  run_id: string
  scenario_id: string
  kind: string
  source_ip: string
  started_at: string
  finished_at: string
  passed: boolean
  skipped: boolean
  failures?: string[]
  notes?: string
  observed?: Record<string, unknown>
}

export interface Check {
  name: string
  ok: boolean
  detail: string
}

export interface SystemInfo {
  version: string
  sensor: string
  config_source: string
  started_at: string
  schema_version: number
  required_schema: number
  listeners: { name: string; address: string; state: string }[]
  ssh_auth_mode: string
  lab_ranges: string[]
  rules_source: string
  geoip: boolean
  queue: { accepted: number; dropped: number; queued: number; capacity: number }
  processor: {
    processed: number
    persist_failures: number
    case_failures: number
    spooled: number
    last_error?: string
    last_error_at?: string
    last_seq: number
  }
  live: { subscribers: number; delivered: number; dropped_deliveries: number }
  connections: Record<
    string,
    { accepted: number; denied: number; over_limit: number; active: number }
  >
  denylist:
    | { action_id: number; ip: string; services: string[]; expires_at: string }[]
    | null
  limits: Record<string, unknown>
  response_enabled: boolean
}

export interface Overview {
  range_start: string
  events: number
  events_by_service: Record<string, number>
  events_by_origin: Record<string, number>
  open_cases: number
  detections: number
  pending_actions: number
  sources: number
  active_sessions: number
}
