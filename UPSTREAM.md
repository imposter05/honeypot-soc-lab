# Upstream project and changes

This project is based on **Hive Honeypot Network** by AngelaMos and
CarterPerez-dev, published at
https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/honeypot-network
under the GNU Affero General Public License v3.0.

Modified by Hiten, September 2026. Files that came from the original keep
their "©AngelaMos | 2026" header; changed files add a "Modified by Hiten,
2026" line that says what changed. New files carry "Hiten | 2026".

## Kept from the original

- The six decoy services and their protocol behaviour.
- The MITRE ATT&CK technique catalogue (two techniques added).
- Database migrations 001 to 011, unchanged.
- The session replay recorder and player.
- The Go module path `github.com/CarterPerez-dev/hive`.

## Removed

- Docker Compose files, the nginx and Redis configuration, the Cloudflare
  tunnel file and `install.sh`. The lab runs natively with PostgreSQL.
- The Redis event stream.
- The detector in `internal/mitre/detector.go`, replaced by
  `internal/detection`.
- The `learn/` tutorial, which described the removed architecture.
- The world map and its third-party map tiles.
- README badges and the live demo link.

## Changed or added

- Configuration: strict YAML, separate addresses for the dashboard and the
  decoys (both 127.0.0.1 by default), readable validation errors.
- Event pipeline: bounded queue with counted drops, one ordered worker,
  one database transaction per event, spool file on database failure,
  live updates only after storage, catch-up after reconnect.
- Detection: ten rules with rationale, false positives, guidance and
  tests; windows on event time; suppression of repeats; shell command
  parsing.
- Cases, notes, verdicts, split and merge, append-only history.
- The restrict-lab-source response playbook with approval, verification,
  expiry and reversal.
- Observables with analyst status, internal-address and client-set flags;
  exports of selected items only.
- Connection limits, idle timeouts, a fixed FTP passive port range and
  capture of FTP uploads.
- `hive doctor`, `hive cleanup`, the `labtest` runner and scenarios.
- Masking of passwords and other secrets in the API, the dashboard and
  exports, with an explicit, logged way to see them.
- A CI workflow and an end-to-end script that runs the lab and its
  scenarios on a scratch database.
- A new dashboard.

Migrations 012 to 018 are new. They add columns and tables and do not
change or drop anything created by 001 to 011.
