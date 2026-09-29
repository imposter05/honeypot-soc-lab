# Investigation report: CASE-00004, sensitive web paths requested with a scanner User-Agent

> **Provenance.** Worked example. The evidence comes from a real run of this lab on 22 September 2026 in the development environment used to build it (Ubuntu 24.04 container, PostgreSQL 16), started with the commands in [docs/walkthrough.md](../walkthrough.md). The analyst actions were made through the API under the name `assistant-demo`. To reproduce the investigation, rerun the walkthrough on your machine and write your own report; this one shows the expected shape and level of detail.

## Summary

Source 127.208.20.13 requested four configuration and admin paths from
the HTTP decoy in 0.3 s, each time claiming to be the Nikto scanner.
HLAB-HTTP-001 and HLAB-HTTP-002 fired. Only decoy content was returned.
No restriction was requested (medium severity is below the playbook
threshold) and I lowered the case to low. Verdict: expected test activity
(`http-sensitive-paths`). The investigation also showed a weakness in
how HTTP-001 reports repeats, described at the end.

## Scope

- Lab run ID: `20260922T114855Z-666cb1`
- Case: CASE-00004 ([JSON](../../evidence/cases/CASE-00004.json), [report export](../../evidence/cases/CASE-00004.md))
- Time range: 2026-09-22 11:49:03.047Z to 11:49:03.356Z
- Source: 127.208.20.13, decoy 127.0.0.1:8080
- Capture: [`20260922T114853Z.pcap`](../../evidence/pcaps/20260922T114853Z.md), packets #349 to #388; `GET /.git/config` is packet #362

## Timeline

| Time (UTC) | Request | Response | Event ID |
|---|---|---|---|
| 11:49:03.047 | GET /.env | 403 | 01a0c8f2-afc7-73e6-bf9c-316b4c3769f8 |
| 11:49:03.151 | GET /.git/config | 200 | 01a0c8f2-b02f-7245-935d-0bd4e9de83ae |
| 11:49:03.253 | GET /wp-config.php.bak | 403 | 01a0c8f2-b095-7cc8-a21e-d6b9f74cb3ac |
| 11:49:03.356 | GET /phpmyadmin/ | 200 | 01a0c8f2-b0fc-7aa7-b0e6-6c6d2673262c |

Each request also produced a `scan.detected` event with the same
timestamp.

## Detections

- **HLAB-HTTP-001 v1, detection 7** (medium, confidence medium). The
  third distinct path (/wp-config.php.bak) was the trigger, with /.env
  and /.git/config contributing. Agree.
- **HLAB-HTTP-002 v1, detection 6** (low, confidence low). Nikto
  User-Agent on the first request, then three repeats. Agree with the low
  confidence: the explanation says the header is a claim.

## Evidence checked

- **Response codes.** /.git/config and /phpmyadmin/ returned 200 with
  decoy pages. Nothing real was exposed.
- **Capture.** Packet #362 contains the `GET /.git/config` request with
  the header `User-Agent: Mozilla/5.00 (Nikto/2.1.6)`. HTTP is plain
  text, so Follow TCP Stream shows every request and response.
- **Rate.** Four requests in 0.3 s, one connection each, is automated.

## Observables

- `Mozilla/5.00 (Nikto/2.1.6)`: left as observed and flagged
  client-set. It says what the client claimed, not what it was.
- 127.208.20.13: internal, observed.

## Response

None. The case was medium severity, below `response.min_severity: high`,
so no request was created, and a restriction would not have changed
anything after the probing stopped. I lowered the severity to low because
only decoy content was returned.

## Verdict

Expected test activity; matches `http-sensitive-paths` in run `20260922T114855Z-666cb1`.

## What I would change

- The fourth path, /phpmyadmin/, was linked to detection 7 as a
  `repeat` because it arrived inside the suppression window. It is
  correct not to open a second detection, but the explanation still lists
  only three paths, so an analyst reading the explanation alone would miss
  the fourth. Repeats should add new distinct values to the detection's
  matched values.
