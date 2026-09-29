# Limitations

Things this lab does not do, or does only partly. Most are deliberate
for a local lab; a few are gaps I know about.

## Scope

- Built and tested on one Linux machine with generated traffic. It has
  not run on the internet and I would not put it there as it is.
- One sensor per database. The data model has a sensor ID, but nothing
  was tested with more than one.
- The decoys are medium-interaction: the SSH shell answers common
  commands from a script, and `wget` or `curl` never download anything.
  An experienced attacker would notice quickly.

## Detection

- Thresholds are my lab starting values, not measured or standard.
- Rules only see one sensor's events and group by source address. NAT,
  shared hosts and address changes will merge or split activity wrongly;
  the manual split and merge exist for that.
- Rule state is in memory. After a restart, windows start empty, so a
  pattern that spans a restart may not fire.
- There is no detection for SMB or MySQL behaviour beyond connection
  counting.

## Pipeline

- One worker processes events. It kept up with the scenarios but was not
  load tested.
- Events dropped because the queue was full are counted and logged but
  their content is lost.
- Spooled events (from database failures) are kept in a file and not
  imported back automatically.

## Response

- The restriction only affects this program's decoys. It does not change
  the host firewall, isolate anything, or close open sessions. The TCP
  handshake still completes and the lab then closes the connection, so a
  port scan from a restricted address still sees the port as open. The
  containment capture in `evidence/pcaps/` shows this.
- Live verification needs to send from the restricted address: any 127.x
  address on Linux, aliased addresses on macOS
  (`scripts/mac-loopback-aliases.sh`). Where that is not possible, or
  where the decoy does not accept a connection at all, the action is
  marked "not confirmed" and stays in place. It is never reported as
  verified on the strength of a failed connection.
- Only one playbook exists, and it acts on a source address. There is
  nothing for blocking a user account, a URL or a file hash.

## Data and audit

- No login and no roles. The analyst name comes from the browser or the
  config and is not verified.
- Case and action history reject UPDATE and DELETE through a database
  trigger. The database owner can remove the trigger, so the history is
  append-only, not tamper-proof.
- Captured passwords and commands are stored in plain text, because they
  are the evidence. The API masks them by default and reveals them only on
  an explicit, logged request, but masking covers known fields and common
  command patterns; a secret typed in an unusual form can still appear.
  Session replays are stored and shown unmasked. Treat the database,
  replays and captures as sensitive.
- GeoIP is optional and approximate; internal addresses have no location.

## Dashboard

- Tested in Chromium only.
- The session list treats every HTTP request as its own session, as the
  original did.

## Evidence in this repository

The files in `evidence/` and the reports in `docs/reports/` come from a
run in the environment where this version was built, under the analyst name
`assistant-demo`. They show what the lab produces and how an investigation
is written up. To generate a fresh record, rerun the walkthrough in your own
environment.
