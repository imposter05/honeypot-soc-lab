#!/usr/bin/env bash
# Hiten | 2026
# ci-e2e.sh
#
# End-to-end check used by CI and runnable locally:
#   1. builds bin/hive and bin/labtest
#   2. writes a config for a scratch database with SSH in
#      test-credentials mode (so every scenario can run)
#   3. migrates, starts the lab, waits until /api/ready says ready
#   4. runs all scenarios, then checks a few API behaviours
#   5. stops the lab and checks it shut down cleanly
#
# Needs a running PostgreSQL where DB_URL's user may create tables.
#   DB_URL=postgres://hive:hive@127.0.0.1:5432/hive_ci?sslmode=disable ./scripts/ci-e2e.sh
# Results go to ci-out/.

set -euo pipefail
cd "$(dirname "$0")/.."

DB_URL="${DB_URL:-postgres://hive:hive@127.0.0.1:5432/hive_ci?sslmode=disable}"
GO="${GO:-go}"
GOFLAGS_EXTRA="${GOFLAGS_EXTRA:-}"
OUT=ci-out
rm -rf "$OUT" && mkdir -p "$OUT"

$GO build $GOFLAGS_EXTRA -o bin/hive ./cmd/hive
$GO build $GOFLAGS_EXTRA -o bin/labtest ./cmd/labtest

# Paths in a config file are relative to its folder, so data lands in
# ci-out/data; migrations and the dashboard are one level up.
sed -e "s#dsn: postgres://.*#dsn: $DB_URL#" \
    -e 's/^  auth_mode: accept-all/  auth_mode: test-credentials/' \
    -e 's#^  migrations: migrations#  migrations: ../migrations#' \
    -e 's#^  frontend: frontend/dist#  frontend: ../frontend/dist#' \
    config.example.yaml > "$OUT/config.yaml"

H="./bin/hive -c $OUT/config.yaml"
$H migrate up
$H doctor || true

$H serve > "$OUT/serve.log" 2>&1 &
PID=$!
cleanup() { kill -INT "$PID" 2>/dev/null || true; }
trap cleanup EXIT

for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8000/api/ready > "$OUT/ready.json" 2>/dev/null; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8000/api/ready > "$OUT/ready.json" || { echo "lab never became ready"; cat "$OUT/serve.log"; exit 1; }

./bin/labtest -out "$OUT/lab-runs" | tee "$OUT/labtest.txt"

fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
API=http://127.0.0.1:8000/api
check "passwords masked by default" \
  "! curl -fsS '$API/events?type=login.success&limit=100' | grep -q 'lab-password-1'"
check "reveal=secrets shows them" \
  "curl -fsS '$API/events?type=login.success&limit=100&reveal=secrets' | grep -q 'lab-password-1'"
check "foreign origin refused" \
  "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Origin: http://evil.test' $API/incidents)\" = 403 ]"
check "form post refused" \
  "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -X POST -d a=b $API/incidents/1/notes)\" = 415 ]"
check "dashboard served" \
  "curl -fsS http://127.0.0.1:8000/ | grep -q 'Honeypot SOC Investigation Lab'"

kill -INT "$PID"
for i in $(seq 1 20); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
trap - EXIT
check "clean shutdown" "! kill -0 $PID 2>/dev/null && grep -q 'stopped' $OUT/serve.log"
# the console log is coloured; strip the codes before matching
sed 's/\x1b\[[0-9;]*m//g' "$OUT/serve.log" > "$OUT/serve.txt"
check "no failed or dropped events" "grep -E 'stopped .*dropped=0 failed=0' $OUT/serve.txt >/dev/null"
exit $fail
