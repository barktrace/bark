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

- one application replica;
- one persistent volume mounted at `/data`;
- TCP port `8080` behind an HTTPS reverse proxy;
- an OpenID Connect provider;
- a proxy request-body limit of at least 20 MiB for Sentry envelopes.

SQLite is intentionally the only database. Do not scale the application to
multiple replicas sharing the volume. Vertical scaling and a fast local or
block-storage volume are the supported topology; network filesystems with
unreliable SQLite locking are not.

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
3. Attach persistent storage to `/data`. Keep exactly one replica.
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

To restore, stop Barktrace, preserve the current volume, put the backed-up
`barktrace.db` in `/data`, remove stale `barktrace.db-wal` and `barktrace.db-shm`
files, ensure UID/GID `65532` can write the directory, and start the one replica.
Confirm `/readyz` before accepting traffic.

## Operational limits

This release is a deployable error-tracking MVP, not complete Sentry parity.
Error events, grouping, projects, organizations, OIDC users, releases, the
dashboard, and core Sentry envelope/store ingestion work. Performance tracing,
logs, uptime, alerts, replays, metrics, symbolication/source maps, commit
metadata, quotas, retention controls, invitation/member administration, and
high-availability storage are not implemented yet.
