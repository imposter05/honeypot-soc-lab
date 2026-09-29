# Evidence

Output from one real run of the lab, used by the reports in
`docs/reports/`.

**Where it came from.** Recorded on 22 September 2026 in the development
environment used to build this version (Ubuntu 24.04 container,
PostgreSQL 16), following [docs/walkthrough.md](../docs/walkthrough.md).
It was not recorded on Hiten's own machine. Analyst actions in the case
files are under the name `assistant-demo`. Rerun the walkthrough to
produce your own set; keep this one as a reference or delete it.

| Path | What it is |
|---|---|
| `scenario-runs/20260922T114855Z-666cb1.json` | labtest results: 11 scenarios, expected and observed rules, source addresses |
| `pcaps/20260922T114853Z.pcap` | all scenario traffic, 608 packets |
| `pcaps/20260922T114853Z.md` | which address is which scenario, key packets |
| `pcaps/20260922T115026Z-containment.pcap` | a restricted and an unrestricted connection to Redis, 23 packets |
| `pcaps/20260922T115026Z-containment.md` | packet-by-packet reading of the containment test |
| `cases/CASE-0000N.json` | complete case exports (events, detections, evidence links, notes, history), passwords masked |
| `cases/CASE-0000N.md` | the same cases as readable reports |
| `cases/CASE-00001-observables.stix.json` | STIX 2.1 export of the two observables marked suspicious |
| `network-tests/README.md` | log of test runs |

The captures contain only the lab test passwords from
`config.example.yaml` and `scenarios/`. Captures from any other setup
may contain real passwords; check before publishing them.
