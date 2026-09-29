# Investigation report: CASE-NNNNN

Write this after closing the case. The "Export report" button on the case
page produces the facts section; the rest is yours.

## Summary

Two or three sentences: what happened, what you decided, and why.

## Scope

- Lab run ID (from labtest):
- Case number(s):
- Time range (UTC):
- Source address(es):
- Packet capture file (evidence/pcaps/):
- SSH auth mode during the run:

## Timeline

The key events in order, with times and event IDs. Paste from the export
and cut to what matters.

| Time (UTC) | Service | What happened | Event ID |
|---|---|---|---|

## Detections

For each detection: rule ID and version, what it counted, and whether you
agree with it. Say plainly if a detection was wrong or missing.

## Evidence checked

What you looked at beyond the alerts: session replay, raw event data,
the packet capture, observables. What each one showed.

## Observables

Values you marked suspicious, confirmed or benign, and why.

## Response

Whether you approved, rejected or reversed a restriction, the services
and expiry, and what the verification reported.

## Verdict

suspicious / benign / expected test activity / insufficient evidence,
and the reasoning.

## What I would change

Rule thresholds, missing detections, or anything that slowed the
investigation down.
