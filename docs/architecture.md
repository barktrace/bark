# Architecture

## Runtime

One Go process owns HTTP, OIDC, ingestion, queries, migrations, and static file
serving. Astro is build-time only. Its static output is copied into the Go
package and embedded in the binary, so Node is absent from the final image.

The public route layout is:

- `/ui/*` — Astro dashboard
- `/auth/*` — OIDC and session endpoints
- `/api/0/*` — Sentry-compatible management endpoints
- `/api/0/relays/*` — managed Relay registration and project configuration
- `/api/{project_id}/envelope/` — SDK envelopes
- `/api/{project_id}/store/` — legacy SDK events
- `/api/{project_id}/logs/` — lightweight structured log ingestion
- `/mcp` — authenticated, organization-scoped Streamable HTTP MCP endpoint
- `/organizations`, `/projects`, `/issues`, `/releases`, `/discover`, `/dashboards`, `/performance`, `/logs`, `/uptime/*`, `/cron/*`, `/replays`, `/profiles`, `/metrics`, and `/artifacts` — native JSON API
- `/healthz` and `/readyz` — probes

## Memory policy

- Standard-library `net/http`; no reflection-heavy web framework.
- SQLite WAL mode with a single open connection by default; PostgreSQL and
  remote libSQL are available when an external metadata plane is required.
- Streaming envelope parsing with hard per-item and request limits.
- Raw event JSON is not duplicated after normalization.
- Payloads are persisted before processing and consumed through leased,
  retryable jobs with a bounded worker loop.
- Static assets are embedded and served directly without a Node process.

The target is an idle RSS below 40 MiB and a default container memory limit of
128 MiB. Replay and profile payloads remain in blob storage; on-demand analysis
uses strict compressed/decompressed input and output-cardinality bounds rather
than retaining an unbounded session or profile in memory.

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

Transactions, logs, check-ins, replays, profiles, metrics, feedback, and
attachments are normalized into compact indexed tables or content-addressed
blobs. Background ingestion, uptime, alert delivery, cron evaluation, and
retention work uses database leases or atomic job leases so multiple processes
do not duplicate scheduled work. Public HTTP/HTTPS targets are allowed by default;
loopback, link-local, and private IPs are rejected before creation and again at
connection time to reduce SSRF and DNS-rebinding risk.

Discover compiles a deliberately bounded field/filter grammar into parameterized
SQLite queries. Dataset names, fields, aggregates, and ordering are selected
from static allowlists. Queries are limited to 20 fields, 20 search terms, 100
rows, and 90 days. Saved dashboard widgets retain only the query definition and
execute through the same organization- and project-scoped engine.

## Compatibility boundary

The implemented surface includes errors and triage, transactions and spans,
sessions and release health, structured logs, uptime and cron monitoring,
replays, profiles, metrics, feedback, attachments, source maps and native debug
files, releases/commits/deploys, alerts, quotas, audit logs, durable ingestion,
and the common self-hosted `sentry-cli` workflows. S3-compatible storage can be
used for blobs shared by several processes. Multi-node deployments connect each
Barktrace replica to the same replicated libSQL database and S3 bucket. Database
leases ensure only one replica performs each scheduled worker task, while HTTP
ingestion and queries remain active on every replica.
