#!/usr/bin/env bash
# Hiten | 2026
# setup-local.sh
#
# One-time setup on Linux or macOS with PostgreSQL already installed:
#   1. checks for Go, Node.js, pnpm and psql
#   2. creates the "hive" role and database if they are missing
#   3. copies config.example.yaml to config.yaml if there is none
#   4. builds the hive binary and runs the migrations
#   5. runs `hive doctor`
#
# It does not install anything system-wide and does not use Docker.
# Override the database settings with DB_NAME, DB_USER, DB_PASS and
# PGADMIN (the command used to run admin SQL, default: psql as the
# postgres user).

set -euo pipefail
cd "$(dirname "$0")/.."

DB_NAME="${DB_NAME:-hive}"
DB_USER="${DB_USER:-hive}"
DB_PASS="${DB_PASS:-hive}"

say()  { printf '%s\n' "$*"; }
fail() { printf 'setup: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 not found. $2"
}

need go   "Install Go 1.25 or newer: https://go.dev/dl/"
need psql "Install the PostgreSQL client (and server) from your package manager."
need node "Install Node.js 20 or newer."
need pnpm "Install pnpm: npm install -g pnpm"

if [ -z "${PGADMIN:-}" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    PGADMIN="psql -d postgres"
  else
    PGADMIN="sudo -u postgres psql"
  fi
fi

say "Checking PostgreSQL role and database ($DB_USER / $DB_NAME)"
if ! $PGADMIN -tAc "SELECT 1" >/dev/null 2>&1; then
  fail "cannot run admin SQL with '$PGADMIN'. Is PostgreSQL running? Set PGADMIN to a working psql command."
fi
if [ "$($PGADMIN -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")" != "1" ]; then
  $PGADMIN -c "CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASS'"
  say "  created role $DB_USER"
fi
if [ "$($PGADMIN -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" != "1" ]; then
  $PGADMIN -c "CREATE DATABASE $DB_NAME OWNER $DB_USER"
  say "  created database $DB_NAME"
fi

if [ ! -f config.yaml ]; then
  cp config.example.yaml config.yaml
  sed -i.bak "s#postgres://hive:hive@127.0.0.1:5432/hive#postgres://$DB_USER:$DB_PASS@127.0.0.1:5432/$DB_NAME#" config.yaml
  rm -f config.yaml.bak
  say "Created config.yaml"
fi

say "Building bin/hive"
mkdir -p bin
go build -o bin/hive ./cmd/hive
go build -o bin/labtest ./cmd/labtest

say "Running migrations"
./bin/hive migrate up

say ""
./bin/hive doctor || true
say ""
say "Next: ./scripts/build-local.sh to build the dashboard, then ./bin/hive serve"
say "      or ./scripts/dev.sh for development with live reload of the dashboard."
