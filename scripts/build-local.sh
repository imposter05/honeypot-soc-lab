#!/usr/bin/env bash
# Hiten | 2026
# build-local.sh
#
# Builds the dashboard into frontend/dist and the Go binaries into
# bin/. After this, `./bin/hive serve` serves everything from
# http://127.0.0.1:8000.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building dashboard"
(cd frontend && pnpm install --frozen-lockfile && pnpm build)

echo "Building bin/hive and bin/labtest"
mkdir -p bin
go build -trimpath -o bin/hive ./cmd/hive
go build -trimpath -o bin/labtest ./cmd/labtest

echo "Done. Start with: ./bin/hive serve"
