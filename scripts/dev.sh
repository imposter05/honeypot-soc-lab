#!/usr/bin/env bash
# Hiten | 2026
# dev.sh
#
# Runs the Go server and the Vite dev server together. Open
# http://127.0.0.1:5173. Stop both with Ctrl-C.

set -euo pipefail
cd "$(dirname "$0")/.."

[ -f config.yaml ] || { echo "No config.yaml. Run ./scripts/setup-local.sh first." >&2; exit 1; }
[ -d frontend/node_modules ] || (cd frontend && pnpm install)

mkdir -p bin
go build -o bin/hive ./cmd/hive
./bin/hive doctor >/dev/null || { ./bin/hive doctor; exit 1; }

./bin/hive serve &
SERVER=$!
trap 'kill -INT $SERVER 2>/dev/null; wait $SERVER 2>/dev/null' EXIT INT TERM

(cd frontend && pnpm dev --host 127.0.0.1 --port 5173 --strictPort)
