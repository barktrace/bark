# Architecture

## Runtime

One Go process owns HTTP, OIDC, ingestion, queries, migrations, and static file
serving. Astro is build-time only. Its static output is copied into the Go
package and embedded in the binary, so Node is absent from the final image.

The public route layout is:

- `/ui/*` — Astro dashboard
- `/auth/*` — OIDC and session endpoints
- `/api/0/*` — Sentry-compatible management endpoints
- `/api/{project_id}/envelope/` — SDK envelopes
- `/api/{project_id}/store/` — legacy SDK events
- `/api/{project_id}/logs/` — lightweight structured log ingestion
- `/mcp` — optional authenticated Streamable HTTP MCP endpoint
- `/organizations`, `/projects`, `/issues`, `/releases`, `/performance`, `/logs`, `/uptime/*` — native JSON API
- `/healthz` and `/readyz` — probes

## Memory policy

- Standard-library `net/http`; no reflection-heavy web framework.
- SQLite WAL mode with a single open connection by default.
- Streaming envelope parsing with hard per-item and request limits.
- Raw event JSON is not duplicated after normalization.
- Bounded queues only; ingestion remains synchronous until a durable queue is
  introduced.
- Static assets are embedded and served directly without a Node process.

The target is an idle RSS below 40 MiB and a default container memory limit of
128 MiB. Profiling and replay processing will use disk-backed work queues rather
than retaining payloads in memory.

The current stripped Linux binary is about 8.7 MiB. A live probe with OIDC
discovery, SQLite WAL, health checks, and the embedded dashboard loaded measured
13.3 MiB idle RSS. `GOMEMLIMIT` defaults to 96 MiB in the image.

## Tenancy and identity

Users are global identities. Organizations own projects and releases through
memberships. OIDC issuer/subject is immutable; verified email is used only once
for safe account linking. The first user in the default organization becomes
owner, while later auto-provisioned users become members.

## Release linkage

An event carrying `release` upserts an organization release and links it to the
receiving project. Events store the resolved release ID. Issues retain their
first and latest release IDs, allowing regression and suspect-commit modules to
be added without changing ingestion identity.

## Observability processors

Transactions and log items are normalized synchronously into compact indexed
tables. Uptime checks run in the same Go process with bounded response reads and
sequential scheduling. Public HTTP/HTTPS targets are allowed by default;
loopback, link-local, and private IPs are rejected before creation and again at
connection time to reduce SSRF and DNS-rebinding risk.

## Compatibility boundary

The implemented surface includes errors, deterministic grouping, transactions,
structured logs, uptime, organizations, projects, releases, and core
envelope/store ingestion. Other unsupported envelope categories are written to
`ingestion_outcomes`, so clients do not retry indefinitely. Durable processing
for full trace waterfalls, sessions, check-ins, attachments, profiles, replays,
metrics, alert notifications, source maps, symbolication, commit metadata, quotas, and retention is
planned as separate bounded modules. This boundary is explicit because claiming
complete Sentry parity before those processors exist would make SDK delivery
look successful while silently discarding data.
