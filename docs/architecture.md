# Architecture

## Processes and addresses

One program, `hive serve`, runs everything:

| Part | Address (default) | Notes |
|---|---|---|
| Dashboard and API | 127.0.0.1:8000 | `network.management_host`, `api.port` |
| SSH decoy | 127.0.0.1:2222 | `network.honeypot_host` |
| HTTP decoy | 127.0.0.1:8080 | |
| FTP decoy | 127.0.0.1:2121, passive data 30000-30009 | |
| SMB decoy | 127.0.0.1:4450 | |
| MySQL decoy | 127.0.0.1:3307 | |
| Redis decoy | 127.0.0.1:6380 | |
| PostgreSQL | 127.0.0.1:5432 | not started by hive |

The dashboard and the decoys have separate address settings so the decoys
can be moved to a lab network while the dashboard stays on loopback.

## Path of one event

1. A decoy handles a connection. `internal/netguard` has already checked
   the application denylist and the per-service connection limit, and
   sets idle and maximum-length deadlines.
2. The decoy publishes an event to the ingestion queue
   (`internal/event/bus.go`). If the queue is full it waits up to
   `pipeline.enqueue_wait`, then counts the event as dropped and logs it.
3. One worker (`internal/event/processor.go`) takes events in order and:
   - fills missing fields and marks the origin as `lab` or `external`
     from `lab.source_ranges`
   - looks up GeoIP if a database is configured (never for internal
     addresses)
   - evaluates the rules without changing rule state
   - extracts observables
   - writes the event, source summary, credential, file record, session
     counters, detections, evidence links and observables in one
     transaction (`internal/store/analysis.go`), retrying up to
     `pipeline.persist_retry` times
   - only after that commit, records the event in the rule windows
   - links new detections to cases and, for new high-severity cases,
     creates a pending response request
   - publishes the stored result to live dashboard connections
4. If the write keeps failing, the event goes to
   `data/spool/failed-events.jsonl` with the reason, the failure counter
   goes up, the rule state is left untouched and nothing is sent to the
   dashboard. The spool file is not re-imported automatically.

One worker keeps the database order (`seq`) the same as the rule
evaluation order. It is enough for a lab; the queue counters show when it
is not.

## Live updates

`/api/ws` sends `hello` with the latest `seq`, then one `result` per
stored event. Each browser tab has its own buffer. If a tab falls behind,
the server sends `resync` and the tab fetches `/api/events?after_seq=N`
from the database, so a slow tab sees events late instead of never. The
same catch-up runs after a reconnect.

## Storage

Events, sessions and credentials are partitioned by month. Partitions
are created on demand for any timestamp, including replayed test data.
Events have a composite primary key `(id, timestamp)`, so every table that
points at an event stores both columns and uses a two-column foreign key.

Tables added by this project: `rules`, `detections`,
`detection_evidence`, `observable_evidence`, `cases`, `case_detections`,
`case_events`, `case_notes`, `case_history`, `response_actions`,
`action_history`, `scenario_runs`. `case_history` and `action_history`
reject UPDATE and DELETE with a trigger.

## Cases

A detection joins the most recent open case for the same sensor and
source address if that case had activity within
`cases.correlation_window` (30 minutes by default). Otherwise a new case
is opened. A shared address does not prove a shared actor, so analysts can
move detections to a new case or merge two cases; both are recorded in the
history.

## Response

`internal/response` implements one playbook, `restrict-lab-source`:

pending approval -> (approve) -> active -> expired or reversed
pending approval -> (reject) -> rejected
active -> failed, if verification shows a service still accepts the source

Verification asks the denylist directly and, where the host can send from
the source address (any 127.x address on Linux, aliased addresses on
macOS), opens a real TCP connection. The result is:

- **verified**: the connection was closed before any data *and* the
  connection guard counted a denylist refusal
- **failed**: the denylist does not hold the source, or the service
  answered the connection; the entry is removed
- **not confirmed**: anything else, including a service that refused or
  timed out (it may be stopped) and a connection closed for another
  reason, such as the connection limit

A failed connection is never proof: a stopped decoy would look the same
as a blocked one. Active restrictions are reloaded at startup; ones that
expired while the lab was stopped are marked expired.

## Shutdown

On Ctrl-C the listeners stop and open connections are closed, then queued
events are written (up to `pipeline.drain_timeout`), then the database
pool closes. Events still queued after the timeout go to the spool file.

## Masking

`internal/redact` masks secrets in everything the API returns and in
exports: password fields, Authorization and Cookie headers, form and
query parameters, URL credentials, Redis AUTH, SQL IDENTIFIED BY and
common command-line password flags. The database keeps the original
values, because they are the evidence. `?reveal=secrets` returns them and
is logged with the analyst name; case exports record in the case history
whether secrets were included.

## Completeness of exports

A case export reads every linked event, detection, observable and action
by paging until the end, and the JSON states `"complete": true` with the
counts. The Markdown report lists the first 500 events in its table and
says how many there are in total. The case page loads the timeline 500
events at a time with "Load more".
