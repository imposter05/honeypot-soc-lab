# Local setup

Tested on Ubuntu 24.04 with Go 1.26, Node.js 20, pnpm 9 and PostgreSQL 16.
The scripts also handle macOS (Homebrew PostgreSQL), but I have not run
them there.

## 1. Install the tools

Ubuntu or Debian:

```bash
sudo apt install postgresql postgresql-client
# Go: https://go.dev/dl/   Node.js 20+: https://nodejs.org/
npm install -g pnpm
```

macOS:

```bash
brew install go node pnpm postgresql@16
brew services start postgresql@16
```

## 2. Run the setup script

```bash
./scripts/setup-local.sh
```

It creates the `hive` role and database (password `hive`) if they are
missing, copies `config.example.yaml` to `config.yaml`, builds `bin/hive`
and `bin/labtest`, runs the migrations and runs `hive doctor`.

Different names or a different admin command:

```bash
DB_NAME=soclab DB_USER=soclab DB_PASS='choose-one' ./scripts/setup-local.sh
PGADMIN="psql -h 127.0.0.1 -U postgres" ./scripts/setup-local.sh
```

## 3. Build the dashboard and start

```bash
./scripts/build-local.sh
./bin/hive serve
```

Open http://127.0.0.1:8000.

For dashboard development, `./scripts/dev.sh` runs the server and the
Vite dev server together; open http://127.0.0.1:5173.

## Useful commands

| Command | What it does |
|---|---|
| `hive doctor` | checks config, folders, rules, database, schema and ports |
| `hive migrate up` / `status` | applies or lists migrations |
| `hive cleanup --older-than 720h` | shows what would be removed; add `--apply` to remove it |
| `hive keygen` | creates the SSH host key |
| `labtest` | runs the scenarios in `scenarios/` against the running lab |
| `scripts/mac-loopback-aliases.sh add` | macOS: adds the loopback addresses labtest needs |
| `scripts/ci-e2e.sh` | starts a lab on a scratch database and checks it end to end |

## Configuration

All settings are in `config.yaml`, with comments in
`config.example.yaml`. Unknown keys are an error. Environment variables
override the file; `HIVE_DATABASE_URL` is the one most often needed.

To test the failed-login rules, set:

```yaml
ssh:
  auth_mode: test-credentials
```

Then only the pairs under `ssh.test_credentials` are accepted.

## Seeing masked values

Passwords and other secrets are masked in the dashboard and in exports.
"Show masked values" on an event, "Show passwords" on Settings and
"include passwords" on a case export ask the server for the real values;
each request is written to the server log with your analyst name, and case
exports are also written to the case history.

## Common problems

| Message | Fix |
|---|---|
| `connection refused` to 127.0.0.1:5432 | start PostgreSQL |
| `database is at migration N but this build needs 18` | `./bin/hive migrate up` |
| `127.0.0.1:2222 is already in use by another program` | stop that program or change `ssh.port` |
| Dashboard shows "Dashboard not built" | `./scripts/build-local.sh` |
| labtest cannot find isolated source addresses (macOS) | `sudo ./scripts/mac-loopback-aliases.sh add` |
| labtest says addresses were used recently | wait the stated time, or add more aliases with `--count` |
