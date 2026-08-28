# Barktrace

![Barktrace — Follow every failure](docs/assets/barktrace-social.svg)

> Follow every failure.

Barktrace is a memory-conscious, organization-aware observability server. A
single Go process serves the Sentry-compatible API at `/` and an embedded Astro
dashboard at `/ui`.

The current foundation includes:

- SQLite with WAL mode and one bounded connection;
- generic OpenID Connect login with PKCE, state, nonce, verified-email account
  linking, and automatic organization provisioning;
- organization memberships and project-scoped access;
- Sentry envelope and store ingestion;
- deterministic issue grouping and release-to-event/issue linkage;
- transaction ingestion with latency percentiles and endpoint summaries;
- structured log ingestion, filtering, and trace/release correlation;
- scheduled HTTP uptime monitors with check and incident history;
- an authenticated Streamable HTTP MCP server for issue investigation;
- one final Docker image containing the API and compiled Astro dashboard.

The dashboard lists projects, grouped issues, event counts, and the first and
latest release associated with each issue. Clicking a project switches its
issue and release activity without running a separate frontend service.

## Run locally

```sh
cp .env.example .env
set -a; . ./.env; set +a
go run ./cmd/barktrace
```

Open `http://localhost:8080/ui/`. The API health endpoint is `/healthz`.

Detailed guides:

- [Configuration](docs/configuration.md)
- [Docker, Dokploy, backup, and upgrades](docs/deployment.md)
- [MCP server and client setup](docs/mcp.md)
- [Sentry SDK compatibility](docs/sentry-compatibility.md)
- [Performance, logs, and uptime](docs/observability.md)
- [Brand identity and assets](docs/brand.md)
- [Architecture and compatibility boundary](docs/architecture.md)

## Pocket ID

Create an OIDC client in Pocket ID with this callback URL:

```text
https://errors.example.com/auth/oidc/callback
```

Set `OIDC_ISSUER_URL` to the Pocket ID issuer, copy its client ID and secret,
and set both `BARKTRACE_PUBLIC_URL` and `OIDC_REDIRECT_URL` to the externally
reachable HTTPS URL. Login is OIDC-only. A new verified identity automatically
creates a user and joins the default organization; the first member is its
owner.

## Docker and Dokploy

Published multi-architecture images are available from GitHub Container
Registry:

```sh
docker pull ghcr.io/barktrace/bark:latest
```

Every push to `main` publishes `latest`, `main`, and `sha-<commit>` tags.
Version tags such as `v1.2.3` additionally publish `1.2.3` and `1.2`.

The image needs one persistent mount at `/data` and listens on port `8080`.
For Dokploy, deploy this repository with its Dockerfile, attach a persistent
volume to `/data`, configure an HTTP health check on `/readyz`, and add the
variables from `.env.example`. No PostgreSQL or second container is required.

An importable production parameter template is available at
`deploy/dokploy.env.example`. Keep one replica: SQLite does not support several
Barktrace containers sharing the same volume.

The default runtime budget is `128 MiB`, with Go's soft memory limit set to
`96 MiB`. A local production-binary probe measured roughly `13.3 MiB` idle RSS.
Back up the SQLite database with SQLite's online backup mechanism rather than
copying the live WAL file by itself.

## Production-readiness boundary

The current version is functional and deployable as a small, single-node error
tracker: error ingestion, grouping, organizations, projects, OIDC account
creation, releases, the dashboard, probes, migrations, and backup procedures
are present. It is not complete Sentry parity.

Span waterfall detail, sessions, check-ins, attachments, profiles, replays,
metrics, alert notifications, source maps/symbolication, commit metadata,
quotas, retention controls, member administration, high availability, and
per-tenant MCP credentials remain to be implemented. Unsupported envelope items are
acknowledged and recorded as ingestion outcomes so SDKs do not retry forever.
