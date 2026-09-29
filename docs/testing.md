# Testing

## Commands

| Command | Needs | Covers |
|---|---|---|
| `go test ./...` | nothing | 94 tests, listed below |
| `go test -race ./...` | nothing | the same, with the race detector |
| `HIVE_TEST_DSN=... go test ./internal/store/` | a migrated database | storage and case tests against PostgreSQL |
| `labtest` | the running lab | 11 scenarios over real network connections |
| `cd frontend && pnpm typecheck && pnpm lint` | Node.js | dashboard type and lint checks |
| `./scripts/ci-e2e.sh` | PostgreSQL, a built dashboard | starts a lab on a scratch database, runs every scenario, checks masking, request guards and shutdown |

`.github/workflows/ci.yml` runs all of these on GitHub's Ubuntu runners
(Go tests with the race detector, database tests, dashboard checks, then
the end-to-end script) and keeps `ci-out/` as an artifact. It uses the
runner's preinstalled PostgreSQL, so CI needs no Docker either.

Use a separate database for `HIVE_TEST_DSN` (for example `hive_test`). The
tests write cases and detections with made-up addresses in 198.51.100.0/24,
which would otherwise show up in your lab.

## What the unit tests cover

- **Rules** (`internal/detection`): 33 cases in
  `testdata/detections/cases.yaml`, at least one positive and one
  negative per rule, including events outside the window, mentions
  without execution, the wrong account and a different session. Also
  suppression, rule validation, and that unstored events do not count.
- **Shell parsing**: separators, quotes, `sudo -u`, redirects.
- **Pipeline** (`internal/event`): full queue drops are counted; closing
  drains queued events; a slow browser is marked for catch-up; a failed
  database write is spooled, not broadcast, and not counted by rules.
- **Config** (`internal/config`): defaults are valid and loopback; the
  example file loads; typos are rejected; all problems are reported at
  once; environment overrides the file and a bad value is an error;
  relative paths resolve from the config file; port clashes are found.
- **API guard** (`internal/api`): wrong Host header, foreign origin,
  form posts and cross-origin JSON posts are refused.
- **Connection guard** (`internal/netguard`): denied sources are closed
  before any data; the connection limit and idle timeout work.
- **Observables** (`internal/intel`): internal and public addresses, URL
  normalisation, client-set values, upload hashes, blocklist injection
  attempts, STIX escaping.
- **Response** (`internal/response`): approval verified through a real
  connection that the guard refuses; a stopped service reported as not
  confirmed rather than blocked (the regression test for a bug I
  introduced); a connection that is accepted marks the action failed and
  removes the entry; rejection and reversal need reasons; invalid state
  changes refused; expiry removes the entry; after a restart active
  restrictions come back and ones that ran out are expired; requests are
  made when a case reaches the severity threshold, not when it was
  already above it.
- **Masking** (`internal/redact`): passwords, Authorization and Cookie
  headers, form and query fields, URL credentials, Redis AUTH, SQL
  IDENTIFIED BY and command-line password flags are masked; ordinary text
  is left alone; the original event is not changed.
- **Cases**: closing needs a verdict and a reason; reopening rules.
- **Scenario runner**: source pool parsing.
- **HTTP**: scanner User-Agents, and that general HTTP clients are not
  scanners.

## Database tests

`internal/store/store_integration_test.go`: five logins create one
detection and the sixth is a linked repeat with the right evidence roles;
events in an old month get a partition; detections within the window
share a case and later ones open a new case; the database refuses to
close a case without a verdict; `case_history` rejects UPDATE and DELETE;
a second restriction request returns the open one; invalid state changes
are refused.

## Scenarios

`scenarios/*.yaml`, run by `cmd/labtest`. Each lists expected rules,
rules that must not fire and, where relevant, expected observables.

| Scenario | Kind | Expects |
|---|---|---|
| ssh-discovery-download | attack | HLAB-SSH-001, HLAB-SSH-002 |
| ssh-password-guessing | attack | HLAB-AUTH-001, HLAB-AUTH-002 (test-credentials) |
| ssh-guess-then-success | attack | HLAB-AUTH-003 (test-credentials) |
| http-sensitive-paths | attack | HLAB-HTTP-001, HLAB-HTTP-002 |
| http-ordinary-browsing | benign | no detections |
| service-sweep | attack | HLAB-NET-001 |
| redis-config-write | attack | HLAB-REDIS-001 |
| ftp-upload | attack | upload hash observable |
| ssh-admin-routine | benign | no detections |
| ssh-port-forward | attack | HLAB-SSH-003 |
| mysql-probe | benign | no detections |

Results on my machine (Ubuntu 24.04, PostgreSQL 16), 21 September 2026:
all 11 passed in `test-credentials` mode; in `accept-all` mode 9 passed
and the two password scenarios were skipped with the reason printed.

## What the end-to-end script checks

Beyond running all 11 scenarios against a real lab: passwords are masked
in the API by default and shown with `?reveal=secrets`; a foreign origin
is refused; a form post is refused; the dashboard is served; the lab
shuts down cleanly with no failed or dropped events.

## Manual checks I ran

These were done by hand against the running lab and are not automated.

- **Database outage.** Stopped PostgreSQL while the lab ran and sent an
  HTTP request. `/api/ready` returned 503, `/api/health` stayed 200, the
  event was written to `data/spool/failed-events.jsonl` with the reason.
  After restarting PostgreSQL, new events were stored and readiness
  returned 200. The spooled event is not re-imported.
- **Restart with an active restriction.** Approved a 10-minute
  restriction, restarted the lab; the restriction was reloaded and the
  source was still refused.
- **Expiry.** Approved a 4-second restriction; within one check interval
  it was marked expired and the source could connect again.
- **Response verification.** After approving a restriction for SSH, an
  SSH client from the restricted address was reset before the banner and
  a `connection.denied` event was recorded, while the same port from
  another address returned the banner, so the decoy was healthy. The same
  test for Redis was captured packet by packet in
  `evidence/pcaps/*-containment.*`.
- **Shutdown.** Ctrl-C stored the queued events and exited in 1 to 2
  seconds with 0 failed and 0 dropped.
- **Race detector on a live server.** Built with `-race`, ran all
  scenarios, no races reported.
- **Dashboard.** Screenshots of every page reviewed at 1440 px and 390 px
  wide; no console errors.

## Baseline

Before changing anything I ran the original code, with no Redis
server running, against PostgreSQL 16 on 20 September 2026 with one SSH
session (`uname -a`, `cat /etc/passwd`, `wget http://example.test/x.sh`,
`exit`), three HTTP requests and one FTP login.

- 16 events stored.
- 0 sessions stored: every insert failed the foreign key to `sensors`,
  because no sensor row is ever written.
- 0 credentials stored: "no partition of relation credentials found for
  row"; only event and session partitions were created.
- 16 "failed to stream event" errors from the Redis stream.
- 15 detections, all confidence 100, with the event type as the only
  evidence.
- Every successful SSH login recorded as T1021.004 (lateral movement);
  typing `exit` recorded as T1059.004.
- The API and all decoys bound to every interface.
- FTP upload data read and discarded.
- One goroutine left running per finished SSH session.

## Test data and databases

Use a different database for each purpose, or results mix:

| Database | Used by |
|---|---|
| `hive` (or your own name) | the lab you investigate in |
| `hive_test` | `HIVE_TEST_DSN` database tests |
| `hive_ci` | `scripts/ci-e2e.sh` |

I once ran the database tests against the lab database, and their
made-up cases appeared in the dashboard.

## Results of the recorded run

22 September 2026, development environment (Ubuntu 24.04 container,
PostgreSQL 16), SSH in test-credentials mode:

- `go test -race ./...`: 94 passed, 0 failed, 4 skipped (the database
  tests, which need `HIVE_TEST_DSN`)
- database tests: 4 passed
- `./scripts/ci-e2e.sh`: 11 of 11 scenarios passed, all 7 checks passed
- dashboard: type check, lint and build clean; pages reviewed as
  screenshots at 1400 px and 390 px wide with no console errors
- evidence from that run is in `evidence/`
