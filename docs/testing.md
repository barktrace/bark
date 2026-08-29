# Testing

## Fast checks

Run the unit, integration, race, frontend, and static-analysis checks before a
release:

```sh
go test ./...
go test -race ./...
go vet ./...
npm ci --prefix ui
npm run build --prefix ui
```

The CLI integration uses a real `sentry-cli` binary and covers releases,
commits, deploys, source maps, debug files, pre-production builds, snapshots,
issues, events, logs, repositories, monitors, and code mappings:

```sh
SENTRY_CLI_BIN=/path/to/sentry-cli \
  go test -count=1 -run TestSentryCLIWorkflow -v ./internal/httpapi
```

CI downloads checksum-pinned `sentry-cli` 3.7.0 and runs this test. Setting
`SENTRY_CLI_BIN` makes the same integration available locally.

The standalone PDB parser has opt-in fixture checks for compiler-produced
Microsoft PDB 7 files. They verify public/procedure symbols, CodeView C13 source
locations, nested inline sites, and inline line-program file changes:

```sh
BARKTRACE_PDB_FIXTURE=/path/to/application.pdb \
  go test -count=1 -run TestRealPDBFixture -v ./internal/symbolicate

BARKTRACE_PDB_INLINE_FIXTURE=/path/to/nested-inline.pdb \
BARKTRACE_PDB_INLINE_FILES_FIXTURE=/path/to/inline-file-changes.pdb \
  go test -count=1 -run 'TestRealPDBInline' -v ./internal/symbolicate
```

A compiler-produced ProGuard/R8 mapping can exercise bounded inline-chain
discovery, including a representative repeated-range group:

```sh
BARKTRACE_PROGUARD_FIXTURE=/path/to/mapping.txt \
  go test -count=1 -run TestRealProguardFixture -v ./internal/symbolicate
```

The minidump parser can also be checked against a real dump and an optional
matching Breakpad symbol file containing `STACK CFI` or Windows `STACK WIN`
records:

```sh
BARKTRACE_MINIDUMP_FIXTURE=/path/to/crash.dmp \
BARKTRACE_MINIDUMP_SYMBOL_FIXTURE=/path/to/module.sym \
  go test -count=1 -run TestRealMinidumpFixture -v ./internal/symbolicate
```

An ELF or Mach-O executable can exercise its real `.eh_frame` table:

```sh
BARKTRACE_DWARF_CFI_FIXTURE=/path/to/executable \
  go test -count=1 -run TestRealDwarfCFIFixture -v ./internal/symbolicate
```

Expression-based CFA and register rules have a separate real-object gate:

```sh
BARKTRACE_DWARF_EXPRESSION_FIXTURE=/path/to/executable \
BARKTRACE_DWARF_EXPRESSION_ARCH=x86_64 \
  go test -count=1 -run TestRealDwarfExpressionFixture -v ./internal/symbolicate
```

A thin or universal Mach-O executable can exercise its real compact-unwind
table. Set the architecture when selecting a slice from a universal binary:

```sh
BARKTRACE_COMPACT_UNWIND_FIXTURE=/path/to/executable \
BARKTRACE_COMPACT_UNWIND_ARCH=arm64 \
  go test -count=1 -run TestRealMachOCompactUnwindFixture -v ./internal/symbolicate
```

The replicated SQLite integration test downloads a checksum-verified, pinned
libSQL server and proves concurrent Barktrace replicas can migrate and share
metadata:

```sh
./scripts/test-libsql.sh
```

## Browser end-to-end test

The browser test builds the production image and launches a disposable OIDC
provider. A real Chromium browser signs in, proves automatic account creation,
creates a project, sends a Sentry event, opens the resulting issue and telemetry
views, uploads and applies a distribution-specific indexed source map by debug
ID, verifies Sentry-compatible organization/project/key/issue/event detail,
issue activity and comment lifecycle, event attachment download, and user-feedback listing
routes, runs a Discover query, creates a saved dashboard widget, renders an
interactive rrweb replay, verifies Sentry-compatible replay search, issue
correlation, decoded segments, click classification, automatic Replay issues,
viewer history, durable batch deletion, and dashboard/MCP filters, analyzes a sampled
profile, exercises team ownership and assignment plus MCP triage, quota,
retention, alert, uptime, and cron operations, and signs out.

```sh
npm ci --prefix tests/e2e
./scripts/test-e2e.sh
```

Set `BARKTRACE_E2E_DATABASE_URL` to run the same production-image workflow
against PostgreSQL instead of local SQLite.

The default browser image is `mcr.microsoft.com/playwright:v1.56.1-noble`.
Override `BARKTRACE_E2E_BROWSER_IMAGE` to use another image containing Chromium.
The harness uses host networking and ports `18080` and `19090`, overridable with
`BARKTRACE_E2E_APP_PORT` and `BARKTRACE_E2E_OIDC_PORT`; it currently targets
Linux development machines and GitHub-hosted Linux runners.

## Sentry Relay compatibility

Run the opt-in compatibility check against the pinned stock Sentry Relay
26.8.0 image with:

```sh
./scripts/test-relay.sh
```

This starts Relay in managed mode, exercises its real registration and project
configuration clients, sends an envelope through Relay, and verifies that the
event reaches Barktrace. It uses host ports `18180`, `18182`, and `19190` and
requires Docker, `curl`, and `sqlite3`.

## Sustained ingestion and memory gate

The load gate exercises error, transaction, and structured-log envelopes through
the real HTTP ingestion handler, durable blob queue, SQLite database, grouping,
and release linking. Defaults are one minute, eight senders, at least 25 accepted
requests/second, p95 below two seconds, no more than 0.1% failures, a fully
drained queue, exact accepted/stored parity, and peak RSS below 128 MiB.

```sh
./scripts/test-load.sh
```

For a longer pre-release soak:

```sh
BARKTRACE_LOAD_DURATION=15m \
BARKTRACE_LOAD_CONCURRENCY=16 \
BARKTRACE_LOAD_MIN_RPS=25 \
./scripts/test-load.sh
```

All thresholds can be changed through the `BARKTRACE_LOAD_*` variables used in
the script. The command prints a JSON report suitable for retaining as a CI
artifact and exits non-zero if any gate fails.
