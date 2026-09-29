# Detection design

## What a rule must contain

Rules are YAML in `rules/default.yaml` (built into the binary) or in the
file named by `detection.rules_file`. Loading fails, with every problem
listed, unless each rule has:

- an ID like `HLAB-AUTH-001` and a version number
- a kind, which selects the Go code that evaluates it
- severity, confidence, and a sentence explaining the confidence
- a description and a rationale
- the event fields it needs
- known false positives (or "none known")
- what an analyst should check next
- a suppression period for repeats
- ATT&CK technique IDs that exist in the local catalogue (or none)
- names of at least one test where it must fire and one where it must not

`TestEveryRuleHasTests` fails if a named test is missing or expects the
wrong result.

## Confidence

Confidence is `low`, `medium` or `high` and describes how specific the
behaviour is. It is not a probability; nothing here was measured against
real traffic. The original project gave every detection 100.

## The rules

| ID | Fires when | Default threshold |
|---|---|---|
| HLAB-AUTH-001 | many logins from one source to one service | 5 in 5 min |
| HLAB-AUTH-002 | many rejected logins | 5 in 5 min (test-credentials mode) |
| HLAB-AUTH-003 | rejected logins, then a success, same account | 3 failures in 5 min |
| HLAB-HTTP-001 | several distinct sensitive paths requested | 3 in 1 min |
| HLAB-HTTP-002 | User-Agent matches a scanning tool | 1 (low confidence) |
| HLAB-NET-001 | several different decoys contacted | 3 in 1 min |
| HLAB-SSH-001 | several distinct discovery commands in one session | 3 in 10 min |
| HLAB-SSH-002 | download tool run with a URL or host/path | 1 |
| HLAB-SSH-003 | SSH port-forward requested | 1 |
| HLAB-REDIS-001 | CONFIG SET, SLAVEOF, REPLICAOF or MODULE sent | 1 |

Full wording, false positives and guidance are in the YAML and on the
Detections > Rules page.

## Choices and why

**Accept-all versus test-credentials.** By default the SSH decoy accepts
any password, as the original did. Then there are no failed logins, so
the failure rules can never fire. HLAB-AUTH-001 counts all attempts and
works in both modes; HLAB-AUTH-002 and 003 need `test-credentials`. Every
auth event records which mode applied, and the explanation says so.

**Parsing commands instead of searching text.** The original searched
command text for words like `curl` or `id`, so `echo curl` and any line
containing "ID" matched. `internal/detection/shellparse.go` splits a line
on `; && || | &`, honours quotes, strips `sudo` and `VAR=value`, drops
redirect targets and uses the command name. Tests in
`shellparse_test.go` and the `discovery-mentions-only` and
`transfer-echo-mentions-curl` cases cover this.

**Port forwarding is not lateral movement.** The original labelled every
SSH login as T1021.004 (lateral movement). A login to a decoy is not
movement between hosts. HLAB-SSH-003 fires only on a `direct-tcpip`
request, records the requested target, and says the request was refused.

**Event time, not clock time.** Windows use event timestamps, so
replayed test events behave like live ones.

**State changes only after storage.** `Evaluate` does not change rule
state. The processor calls `Apply` only after the transaction commits.
If the write fails, the event does not count toward later matches
(`TestUnappliedEventsAreNotCounted`,
`TestPersistFailureIsNotBroadcastOrCounted`).

**Repeats.** After a rule fires for a group (for example one source and
one service), further matches within `suppress_for` are linked to the
same detection with the role `repeat`, and `suppressed_count` goes up.
You see one detection with its repeat count instead of fifty alerts.

**Evidence roles.** Each detection links to events as `trigger` (the
event that crossed the threshold), `contributing` (earlier events in the
window, at most 50) or `repeat`.

**Scanner User-Agents.** The header is set by the client, so HLAB-HTTP-002
is low confidence and the explanation says the value is a claim. General
HTTP clients (curl, wget, python-requests, Go-http-client, libwww-perl)
are not treated as scanners.

## Changing a threshold

1. Copy `rules/default.yaml`, edit it and set `detection.rules_file`.
2. Raise the rule's `version`, so old detections keep pointing at the
   version that produced them.
3. Run `go test ./internal/detection/` and `labtest`.
