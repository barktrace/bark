# Configuration

Barktrace is configured entirely with environment variables. SSO is mandatory;
the process validates its OIDC configuration and exits before listening if a
required value is absent or unsafe.

## Application

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `BARKTRACE_PUBLIC_URL` | production | `http://localhost:8080` | Externally visible origin. Production values must use HTTPS and must not contain a path. It is also used to construct project DSNs. |
| `BARKTRACE_ADDR` | no | `:8080` | HTTP listen address inside the container. |
| `BARKTRACE_HEALTHCHECK_URL` | no | `http://127.0.0.1:8080/readyz` | URL used only by the binary's `healthcheck` subcommand. Set it if changing the container listen port. |
| `BARKTRACE_DATA_DIR` | no | `./data` (`/data` in the image) | Directory containing `barktrace.db` and its WAL files. Persist the whole directory. |
| `BARKTRACE_DATABASE_URL` | no | empty | PostgreSQL or remote SQLite-compatible libSQL URL. Leave empty for local SQLite. Use a shared database together with S3 blobs for multiple replicas. |
| `BARKTRACE_DATABASE_AUTH_TOKEN` | with authenticated libSQL | empty | Authentication token for the remote metadata database. It is deliberately separate from the URL to avoid leaking it in logs. |
| `BARKTRACE_DEFAULT_ORG_NAME` | no | `Default` | Display name of the organization created during first login. |
| `BARKTRACE_DEFAULT_ORG_SLUG` | no | `default` | URL-safe slug of the default organization. Keep it stable after first deployment. |
| `BARKTRACE_AUTO_PROVISION` | no | `true` | Creates a user from a new verified OIDC identity. When false, only identities linked to existing users can sign in. |
| `BARKTRACE_SESSION_LIFETIME_HOURS` | no | `720` | Browser-session lifetime in hours. |
| `BARKTRACE_RATE_LIMIT_PER_MINUTE` | no | `1000` | Maximum ingestion requests per project in a fixed one-minute window. A rejected request returns HTTP 429 and Sentry retry headers. |
| `GOMEMLIMIT` | no | `96MiB` in the image | Go soft memory limit. Keep it below the container memory limit. |
| `BARKTRACE_MCP_TOKEN` | no | empty | Optional legacy instance-wide MCP credential. It must contain at least 32 characters; organization-scoped credentials can instead be created in the UI. |
| `BARKTRACE_UPTIME_ALLOW_PRIVATE_TARGETS` | no | `false` | Allows uptime monitors to contact loopback and private-network IPs. Keep disabled unless Barktrace is intentionally monitoring trusted internal services. |
| `BARKTRACE_BLOB_BACKEND` | no | `local` | Blob backend: `local` or `s3`. Use `s3` whenever several Barktrace replicas share PostgreSQL or remote libSQL metadata. |

`BARKTRACE_DATABASE_URL` accepts `postgres://`, `postgresql://`, `libsql://`,
`https://`, or `wss://` URLs. PostgreSQL URLs may contain standard credentials
and connection options such as `sslmode`. Plain HTTP/WebSocket libSQL URLs are
accepted only on loopback for development; credentials and query parameters are
rejected for libSQL, whose token must be passed separately.

## Email alerts

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `SMTP_HOST` | for email alerts | empty | SMTP server hostname. |
| `SMTP_PORT` | no | `587` | SMTP server port. |
| `SMTP_USERNAME` | no | empty | SMTP authentication username. |
| `SMTP_PASSWORD` | no | empty | SMTP authentication password. |
| `SMTP_FROM` | with `SMTP_HOST` | empty | Envelope sender and `From` address. |
| `SMTP_TLS_MODE` | no | `starttls` | `starttls`, implicit `tls`, or `none`. |

## S3-compatible blob storage

| Variable | Required with `s3` | Default | Description |
| --- | --- | --- | --- |
| `BARKTRACE_S3_ENDPOINT` | yes | empty | S3-compatible endpoint URL. HTTPS is required unless insecure HTTP is explicitly enabled. |
| `BARKTRACE_S3_REGION` | no | `us-east-1` | SigV4 region. |
| `BARKTRACE_S3_BUCKET` | yes | empty | Existing bucket used for payload objects. |
| `BARKTRACE_S3_ACCESS_KEY_ID` | yes | empty | S3 access key. |
| `BARKTRACE_S3_SECRET_ACCESS_KEY` | yes | empty | S3 secret key. |
| `BARKTRACE_S3_SESSION_TOKEN` | no | empty | Temporary-credential session token. |
| `BARKTRACE_S3_PREFIX` | no | empty | Optional key prefix. |
| `BARKTRACE_S3_ALLOW_HTTP` | no | `false` | Permit plaintext non-loopback endpoints; intended only for isolated development networks. |

## OpenID Connect

| Variable | Required | Example | Description |
| --- | --- | --- | --- |
| `OIDC_ISSUER_URL` | yes | `https://id.example.com` | Exact issuer URL advertised by the provider. HTTPS is required except on loopback. |
| `OIDC_CLIENT_ID` | yes | `barktrace` | OIDC client ID. |
| `OIDC_CLIENT_SECRET` | yes | secret | OIDC client secret. Store it as a secret in the deployment platform. |
| `OIDC_REDIRECT_URL` | yes | `https://errors.example.com/auth/oidc/callback` | Callback registered with the provider. It must match exactly. |
| `OIDC_PROVIDER_NAME` | no | `Pocket ID` | Label shown on the login button; defaults to `SSO`. |
| `OIDC_SCOPES` | no | `openid email profile` | Space-separated scopes. `openid` and an email claim are required in practice. |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | no | `true` | Reject identities whose `email_verified` claim is not true. Disabling this weakens safe account linking. |

The login flow uses authorization code, PKCE, state, and nonce. Users are keyed
by issuer and subject. A verified email is used only when initially linking an
identity. With automatic provisioning enabled, the first user becomes owner of
the default organization and subsequent users become members.

## Local development example

Use a loopback issuer or a development OIDC provider and register
`http://localhost:8080/auth/oidc/callback`:

```sh
cp .env.example .env
set -a
. ./.env
set +a
go run ./cmd/barktrace
```

Open `http://localhost:8080/ui/`. The service deliberately does not provide a
password-login fallback.
