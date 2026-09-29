# Honeypot SOC Investigation Lab

A practice lab for security operations (SOC) work that runs on one computer.

It starts six fake services that look like real ones: SSH, a web server,
FTP, Windows file sharing (SMB), MySQL and Redis. Anything that connects to
them is recorded. Detection rules look at those records, group related
alerts into cases, and a web dashboard lets you investigate each case,
write down what you found, and decide what to do about it.

Everything stays on your machine. By default the fake services only accept
connections from the same computer, and a built-in test runner plays the
role of the attacker, so you can practise without exposing anything to the
internet.

This project is a heavily modified version of
[Hive Honeypot Network](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/honeypot-network)
by AngelaMos and CarterPerez-dev. What changed and why is listed in
[UPSTREAM.md](UPSTREAM.md).

## What you can do with it

- Watch the decoys record logins, typed commands, web requests, file
  uploads and database commands, with times in UTC and both ends of each
  connection.
- Read why each alert fired. Every detection names its rule and version,
  the events it counted, the threshold it crossed and the time window, for
  example: "3 distinct sensitive paths (/.env, /.git/config,
  /wp-config.php.bak) within 1 minute".
- Work a case from start to finish: follow the timeline, add notes, set a
  verdict (suspicious, benign, expected test activity, or not enough
  evidence) and close it with a written reason. Every change is kept in
  the case history.
- Approve or reject a response. The one built-in response blocks a source
  address from the fake services for a set time and lifts it when it
  expires or when you reverse it. It checks the block with a real
  connection and only reports "verified" when the lab records that it
  refused that connection, so a stopped service is never mistaken for a
  working block.
- Mark addresses, domains, URLs and file hashes as suspicious or confirmed,
  then export only the ones you picked as STIX 2.1 or as a blocklist.
- Run eleven test scenarios with one command and see which rules fired.
  Each scenario uses its own source address, and the runner refuses to
  start unless every address has been quiet long enough that nothing
  carries over from an earlier run.
- Read evidence without spreading it: passwords and other secrets are
  masked in the dashboard and in exports. Showing them takes a deliberate
  click, which is logged, and exports are recorded in the case history.

## What it is not

- It is not a production honeypot. It was built and tested on one machine
  with test traffic, not on the internet.
- The detection thresholds are my starting values for a lab. They are not
  industry standards and have not been measured against real attack data.
- The response only affects this program's fake services. It does not
  change the computer's firewall and does not close connections that are
  already open.
- The dashboard has no login. It must stay on 127.0.0.1, which is the
  default.
- The case history cannot be edited or deleted through the application or
  by normal SQL, but the database owner can still change it. It is a
  record, not tamper-proof evidence.
- Masking catches secrets in known fields and common command patterns. It
  is a guard against casual exposure, not a guarantee; treat the database
  and any packet captures as sensitive.

More in [docs/limitations.md](docs/limitations.md).

## Quick start

You need Go 1.25 or newer, Node.js 20 or newer with pnpm, and PostgreSQL
running locally (tested with version 16). No Docker.

```bash
./scripts/setup-local.sh     # creates the database, config.yaml, bin/hive; runs checks
./scripts/build-local.sh     # builds the dashboard
./bin/hive serve             # starts everything
```

On macOS, also give the scenarios their own addresses once per boot:

```bash
sudo ./scripts/mac-loopback-aliases.sh add
```

Open http://127.0.0.1:8000. In a second terminal, create some activity:

```bash
./bin/labtest
```

Each scenario prints PASS, FAIL or SKIP. New cases appear on the
Incidents page. The two password-guessing scenarios are skipped unless
`ssh.auth_mode` is `test-credentials`, because in the default mode every
password is accepted.

If something does not start, run `./bin/hive doctor`. It checks the
config, database, schema version, ports and folders, and says how to fix
each problem. Step-by-step setup for Linux and macOS is in
[docs/local-setup.md](docs/local-setup.md).

## How it works

```
 fake services (127.0.0.1)          one ordered worker                   dashboard (127.0.0.1:8000)
 SSH 2222  HTTP 8080  FTP 2121  ->  queue -> rules -> one database   ->  live updates, cases,
 SMB 4450  MySQL 3307 Redis 6380    transaction -> cases -> response     evidence, exports
                                          |
                                     PostgreSQL
```

An event is shown on the dashboard only after it, its detections and its
evidence links are saved together in one database transaction. If the
database is down, the event is written to a spool file with the reason
instead of being lost silently, and the readiness check reports the
problem. [docs/architecture.md](docs/architecture.md) has the details.

The ten rules are in [rules/default.yaml](rules/default.yaml). Each one
states why it matters, what could cause a false alarm, what to check
next, and which tests prove it fires and stays quiet.
[docs/detection-design.md](docs/detection-design.md) explains the choices.

## What I found in the original and fixed

Before changing anything I ran the original against a real database with
one SSH session, three web requests and one FTP login. The results are in
[docs/testing.md](docs/testing.md#baseline). The main problems were:

- No sessions and no credentials were saved (16 events stored, 0
  sessions, 0 credentials), because a required database row was never
  created and one table had no storage partition.
- Every detection had confidence 100, and every SSH login was labelled as
  lateral movement.
- Rules matched text anywhere in a command, so `echo curl` counted as a
  download.
- All services listened on every network interface, not just this
  computer.
- FTP uploads were read and then thrown away.
- Each SSH session left a background task running until the program
  stopped.
- The dashboard read event objects that the processing code was still
  changing, and slow browsers had events dropped with no record.

Later testing found one more: `curl`, `wget` and Python's HTTP library
were treated as attack scanners, so any scripted web request opened a
case.

I also introduced and fixed a bug of my own. My first version of the
response check treated any failed connection as proof that a source was
blocked, so a stopped decoy would have looked like successful
containment. It now only reports a block as verified when the connection
guard records that it refused the connection, and says "not confirmed"
when it cannot tell. `TestStoppedServiceIsUnverifiedNotSuccess` covers
it.

## Testing

```bash
go test ./...                    # 94 tests, including 33 rule cases
go test -race ./...              # same tests with the race detector
HIVE_TEST_DSN=postgres://hive:hive@127.0.0.1:5432/hive_test?sslmode=disable \
  go test ./internal/store/      # database tests; use a separate database
./bin/labtest                    # 11 scenarios against the running lab
./scripts/ci-e2e.sh              # starts a lab on a scratch database and checks it end to end
```

`.github/workflows/ci.yml` runs all of these on every push, using the
PostgreSQL that comes with GitHub's Ubuntu runners. There is no Docker in
the project or in CI.

What each test covers, and the results of the database outage, restart
and shutdown checks, are in [docs/testing.md](docs/testing.md).

## Worked examples and evidence

[docs/walkthrough.md](docs/walkthrough.md) goes from a clean start to a
closed, exported case in about 20 minutes, with screenshots.

`evidence/` holds one complete run: the scenario results, two packet
captures with packet-numbered annotations, complete case exports and a
STIX export. Three investigations written from that run are in
[docs/reports/](docs/reports/), with a template beside them.

That evidence was recorded in the environment where this version was
built, not on the author's own machine.

## Project layout

```
cmd/hive/            the server and its commands (serve, migrate, doctor, cleanup)
cmd/labtest/         scenario runner
internal/detection/  rule engine and shell command parser
internal/event/      queue, ordered processor, live updates
internal/store/      PostgreSQL access
internal/cases/      case grouping and validation
internal/response/   restrict-source playbook and denylist
internal/netguard/   connection limits and denylist checks for every decoy
internal/sshd ...    the six fake services
internal/api/        HTTP API and dashboard server
internal/redact/     masking of passwords and other secrets
migrations/          database schema (001 to 018)
rules/               detection rules
scenarios/           test scenarios for labtest
testdata/detections/ rule test cases
frontend/            React dashboard
docs/                design, setup, testing, walkthrough, reports
evidence/            captures, scenario results and case exports from one run
.github/workflows/   CI: tests, race detector, dashboard checks, end-to-end run
```

## Safety and legal

Only run the lab on computers and networks you own or are allowed to
test. The fake services record whatever is sent to them, including
passwords. If you change `network.honeypot_host` to an address other
machines can reach, read [docs/networking.md](docs/networking.md) first.

