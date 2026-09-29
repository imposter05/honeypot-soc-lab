# Network test log

One row per test run, so reports can link a capture, a labtest run and
the cases it produced.

| Date (UTC) | labtest run ID | Capture | SSH auth mode | Result | Cases | Environment |
|---|---|---|---|---|---|---|
| 2026-09-22 11:48 | 20260922T114855Z-666cb1 | 20260922T114853Z.pcap | test-credentials | 11 of 11 passed | CASE-00001 to CASE-00007 | development container, Ubuntu 24.04 |
| 2026-09-22 11:50 | (manual containment test) | 20260922T115026Z-containment.pcap | test-credentials | restricted source closed, unrestricted source answered | CASE-00006 | development container, Ubuntu 24.04 |
