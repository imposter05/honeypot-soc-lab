# Investigation report: CASE-00003, SSH password guessing followed by a successful login

> **Provenance.** Worked example. The evidence comes from a real run of this lab on 22 September 2026 in the development environment used to build it (Ubuntu 24.04 container, PostgreSQL 16), started with the commands in [docs/walkthrough.md](../walkthrough.md). The analyst actions were made through the API under the name `assistant-demo`. To reproduce the investigation, rerun the walkthrough on your machine and write your own report; this one shows the expected shape and level of detail.

## Summary

Source 127.208.20.12 failed three SSH logins as `labuser` and then logged
in with the correct password, all within half a second, and ran one
command. HLAB-AUTH-003 fired correctly. I restricted SSH from the source,
confirmed the restriction with a live connection, then lifted it. Verdict:
expected test activity (labtest scenario `ssh-guess-then-success`).

## Scope

- Lab run ID: `20260922T114855Z-666cb1` ([results](../../evidence/scenario-runs/20260922T114855Z-666cb1.json))
- Case: CASE-00003 ([JSON](../../evidence/cases/CASE-00003.json), [report export](../../evidence/cases/CASE-00003.md))
- Time range: 2026-09-22 11:49:00.572Z to 11:49:49.225Z
- Source: 127.208.20.12, decoy 127.0.0.1:2222 (SSH)
- Captures: [`20260922T114853Z.pcap`](../../evidence/pcaps/20260922T114853Z.md), packets #223 to #348
- SSH auth mode: test-credentials (only `labuser` / `lab-password-1` is accepted)

## Timeline

| Time (UTC) | What happened | Event ID |
|---|---|---|
| 11:49:00.572 | login.failed, user labuser, source port 40929 | 01a0c8f2-a61c-7671-be90-c6988d48a4f0 |
| 11:49:00.726 | login.failed, user labuser, source port 40121 | 01a0c8f2-a6b6-7177-859a-7798def533c2 |
| 11:49:00.880 | login.failed, user labuser, source port 42687 | 01a0c8f2-a750-7b4b-a5c1-cef16221a3fd |
| 11:49:01.034 | login.success, user labuser, source port 58215 | 01a0c8f2-a7ea-70a5-b5a1-a5af42c9641d |
| 11:49:01.335 | command `id` in the new session | 01a0c8f2-a917-7322-a987-1131675b5bc7 |
| 11:49:48 | restriction approved; verification probe refused | (verification record, action 2) |
| 11:49:49.225 | manual SSH attempt from the source, closed by the denylist | 01a0c8f3-6429-76b3-ae45-75e8829a321d |
| 11:50:11 | restriction lifted | (action history) |

## Detections

- **HLAB-AUTH-003 v1, detection 5** (high, confidence high). Evidence:
  three failures as `contributing` and the success as `trigger`. Agree:
  the rule needs failures and a success for the same account from the same
  source, and all four events match.
- Not fired: HLAB-AUTH-002 (burst of failures) needs five failures; there
  were three. Correct.
- Not fired: HLAB-AUTH-001 (volume) needs five attempts; there were four.
  Correct.

## Evidence checked

- **Event data.** Each failure recorded `auth_mode: test-credentials`, so
  the failures were real wrong passwords, not an artefact of accept-all
  mode. The passwords are masked in the dashboard and in the exports.
- **Session.** The successful login opened session 01a0c8f2...; the only
  command was `id` (added to the case by hand as evidence that the
  account was used, not just authenticated).
- **Capture.** Packets #223 to #348 hold four TCP connections to 2222,
  one per login attempt, each with its own source port. SSH is encrypted
  after key exchange, so the capture confirms the connections and their
  timing, not the passwords.

## Observables

- 127.208.20.12: internal address, left as observed; not exportable by
  default.
- `SSH-2.0-hlab-labtest`: SSH client string, marked client-set because
  the client chooses it. Left as observed.

## Response

Approved restriction action 2 for SSH only, 15 minutes.

- Verification: **verified**. The guard recorded a denylist refusal for
  the probe connection.
- Manual check: an SSH client bound to 127.208.20.12 was reset before the
  banner (`connection.denied` at 11:49:49.225Z). The same port from
  127.208.20.99 returned `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`, so
  the service was healthy and the refusal came from the restriction.
- Lifted at 11:50:11 with the reason "Source confirmed as the labtest
  scenario; block tested and no longer needed".

The restriction only applies to new connections to this lab's decoys; it
is not a firewall rule.

## Verdict

Expected test activity. The source address and timing match
`ssh-guess-then-success` in run `20260922T114855Z-666cb1`, which passed.

## What I would change

- In the default accept-all mode this pattern cannot be detected, because
  no login ever fails. The dashboard says which mode applied, but a new
  analyst could still read "no AUTH-003" as "no guessing". Worth a banner
  on the Detections page when the lab runs in accept-all mode.
- The `exit` command from the same session was recorded but not linked
  to the case. Linking every event from a session that contains a
  detection would save a manual step.
