# Deployment

## Published image

The `main` branch is published for AMD64 and ARM64 as
`ghcr.io/barktrace/bark:latest`. A version tag such as `v1.2.3` publishes
`1.2.3` and `1.2` image tags. Pull requests build the image without publishing
it.

```sh
docker pull ghcr.io/barktrace/bark:latest
```

Barktrace ships as one image. The final image contains the Go server, embedded
dashboard, SQLite support, and a built-in healthcheck; Node is used only by the
build stage.

## Requirements

- one application replica when using the default local SQLite database, or a
  replicated libSQL database plus S3 blob storage for multiple replicas;
- one persistent volume mounted at `/data`;
- TCP port `8080` behind an HTTPS reverse proxy;
- an OpenID Connect provider;
- a proxy request-body limit of at least 20 MiB for Sentry envelopes.

SQLite is intentionally the only database engine. Do not scale several
application replicas over one filesystem database. Vertical scaling with local
SQLite is the simplest topology; multi-node deployments use a shared replicated
libSQL service for metadata and S3-compatible object storage for payloads.

## Docker Compose

Copy the example configuration and replace all example domains and secrets:

```sh
cp deploy/dokploy.env.example .env
docker compose config
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

The included `compose.yml` publishes port `8080`, creates the `barktrace_data`
volume, and applies a 128 MiB memory limit. Terminate TLS at the reverse proxy
and route the public hostname to port `8080`.

## Dokploy

1. Create a Compose application from this repository and select
   `compose.yml`, or create a Dockerfile application using `Dockerfile`.
2. Configure the domain (for example `errors.example.com`) with HTTPS and route
   it to container port `8080`.
3. Attach persistent storage to `/data`. Keep exactly one replica unless the
   remote-libSQL and S3 multi-node topology below is configured.
4. Import the variables in `deploy/dokploy.env.example` into the Environment
   panel. Enter OIDC and MCP values as secrets rather than committing them.
5. Use `GET /readyz` as the health check. A successful response is HTTP 200.
6. Set the proxy upload/body limit to at least 20 MiB, then deploy.

For Pocket ID, create an OIDC client and register this exact callback:

```text
https://errors.example.com/auth/oidc/callback
```

Set `OIDC_ISSUER_URL` to Pocket ID's issuer URL. The issuer must be reachable
from the container during startup because Barktrace performs OIDC discovery
before opening its HTTP listener.

After deployment, verify both probes and sign in once:

```sh
curl --fail https://errors.example.com/healthz
curl --fail https://errors.example.com/readyz
```

The first verified OIDC user is automatically created and becomes owner of the
default organization. Create a project in `/ui`, then copy its displayed DSN
into a compatible Sentry SDK. See the [Sentry compatibility matrix](sentry-compatibility.md)
for tested examples and unsupported data categories.

## Upgrades

1. Create a database backup.
2. Pull or build the new image.
3. Replace the single running container without changing its `/data` volume.
4. Check `/readyz`, sign in, and send a test event.

Database migrations are embedded in the binary and run transactionally during
startup. Roll back the image and restore the pre-upgrade database if a release
cannot start; older binaries may not understand a newer schema.

## Backup and restore

The database is `/data/barktrace.db`. Because WAL mode is enabled, never copy only
that file while the service is running.

For an online backup, run SQLite's backup API from a host or maintenance
container that can access the volume:

```sh
mkdir -p backups
sqlite3 /path/to/barktrace.db ".backup 'backups/barktrace-$(date +%Y%m%d-%H%M%S).db'"
sqlite3 backups/barktrace-YYYYMMDD-HHMMSS.db "PRAGMA integrity_check;"
```

Dokploy volume snapshots are also suitable when they are crash-consistent. The
simplest portable alternative is to stop Barktrace, copy the entire `/data`
directory (including `-wal` and `-shm` files if present), and restart it.

To restore a local SQLite deployment, stop Barktrace, preserve the current volume, put the backed-up
`barktrace.db` in `/data`, remove stale `barktrace.db-wal` and `barktrace.db-shm`
files, ensure UID/GID `65532` can write the directory, and start the one replica.
Confirm `/readyz` before accepting traffic.

## Multi-node deployment

For API redundancy without PostgreSQL, provision a replicated libSQL service
(self-hosted or managed) and an S3-compatible bucket. Configure every Barktrace
replica with the same values:

```env
BARKTRACE_DATABASE_URL=libsql://barktrace.example.turso.io
BARKTRACE_DATABASE_AUTH_TOKEN=replace-with-database-token
BARKTRACE_BLOB_BACKEND=s3
BARKTRACE_S3_ENDPOINT=https://s3.example.com
BARKTRACE_S3_REGION=eu-west-1
BARKTRACE_S3_BUCKET=barktrace
BARKTRACE_S3_ACCESS_KEY_ID=replace-me
BARKTRACE_S3_SECRET_ACCESS_KEY=replace-me
BARKTRACE_S3_PREFIX=production
```

Each replica still needs a small writable `/data` mount for bounded temporary
files, but the local `barktrace.db` is not used when `BARKTRACE_DATABASE_URL` is
set. Route traffic through a health-checking load balancer. Migrations are
serialized with a database lease, and scheduled workers already use leases, so
replicas can start and serve concurrently. Availability and backup guarantees
for metadata are those of the chosen libSQL service; configure its replication
and point-in-time recovery separately.

## Operational limits

This release is a deployable single-node or remote-libSQL multi-node
observability service, not complete Sentry parity. It includes durable ingestion, symbolication artifacts,
check-ins, feedback, attachments, replays, profiles, metrics, release metadata,
SMTP/webhook/Slack delivery, RBAC, audit logs, quotas, and scoped MCP access.

For high-durability payload storage, set `BARKTRACE_BLOB_BACKEND=s3` and provide
the S3 variables documented in [configuration.md](configuration.md). Background
workers coordinate through database leases. Never run multiple replicas against
independent local SQLite databases or place one SQLite file on an unsafe network
filesystem; use the remote-libSQL topology above for active-active API service.
