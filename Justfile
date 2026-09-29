# ©AngelaMos | 2026
# Modified by Hiten, 2026: Docker recipes removed; local workflow only.
# Justfile (optional; the scripts in scripts/ do the same without just)

set shell := ["bash", "-uc"]

default:
    @just --list --unsorted

setup:
    ./scripts/setup-local.sh

dev:
    ./scripts/dev.sh

build:
    ./scripts/build-local.sh

serve:
    ./bin/hive serve

doctor:
    go run ./cmd/hive doctor

migrate:
    go run ./cmd/hive migrate up

test:
    go test ./...

# needs a migrated database; see docs/testing.md
test-db dsn="postgres://hive:hive@127.0.0.1:5432/hive_test?sslmode=disable":
    HIVE_TEST_DSN="{{dsn}}" go test -count=1 ./internal/store/

race:
    go test -race ./...

lab *ARGS:
    go run ./cmd/labtest {{ARGS}}

lint:
    golangci-lint run --timeout=5m

frontend-check:
    cd frontend && pnpm typecheck && pnpm lint
