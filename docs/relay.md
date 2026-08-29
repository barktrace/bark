# Sentry Relay

Barktrace accepts a managed [Sentry Relay](https://develop.sentry.dev/server/relay/)
as an optional ingestion proxy. Barktrace itself remains a single-container
deployment; add Relay only when you need its buffering, filtering, or edge
ingestion behavior.

## Supported protocol

Barktrace implements Relay's Ed25519 registration handshake and these upstream
routes:

- `POST /api/0/relays/register/challenge/`
- `POST /api/0/relays/register/response/`
- `POST /api/0/relays/projectconfigs/?version=3`
- `POST /api/0/relays/publickeys/`
- `GET /api/0/relays/live/`

Relay credentials and the registration HMAC secret are persisted in the same
SQLite or libSQL metadata database as projects. Registration requests and all
subsequent configuration requests are signed and have bounded body, batch, and
signature-age limits. A Relay ID cannot later be rebound to another public key.

## Configuration

Generate Relay's `config.yml` and `credentials.json` once:

```sh
docker run --rm -it \
  -v "$PWD/relay:/work" \
  -w /work \
  getsentry/relay:latest config init
```

Set the generated `config.yml` to managed mode and point it at Barktrace:

```yaml
relay:
  mode: managed
  upstream: https://errors-internal.example.com/
  host: 0.0.0.0
  port: 3000
processing:
  enabled: false
```

Start Relay with its configuration directory mounted persistently:

```sh
docker run --detach --name barktrace-relay \
  --restart unless-stopped \
  -p 3000:3000 \
  -v "$PWD/relay/.relay:/work" \
  getsentry/relay:latest -c /work run
```

Route public Sentry ingestion paths such as `/api/{project_id}/envelope/` and
`/api/{project_id}/store/` to Relay. Route `/ui/`, `/auth/`, `/mcp`, health
checks, and management APIs directly to Barktrace. Relay's configured upstream
must be able to reach Barktrace directly.

Keep `credentials.json` private and persistent. Barktrace allows a new Relay to
self-register after proving possession of its generated private key. Registered
Relays are trusted as internal deployment components and can retrieve the
minimal project configuration required to validate and forward envelopes.

## Verification

After Relay starts, its log should contain `relay successfully registered with
upstream`. Its public liveness route should respond with HTTP 200:

```sh
curl --fail https://errors.example.com/api/0/relays/live/
```

Send an SDK event through the public Relay address and confirm it appears in
Barktrace. Relay fetches configuration by the public key embedded in the DSN;
no project keys need to be copied into Relay's configuration.
