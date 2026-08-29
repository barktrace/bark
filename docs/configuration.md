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
| `BARKTRACE_DEFAULT_ORG_NAME` | no | `Default` | Display name of the organization created during first login. |
| `BARKTRACE_DEFAULT_ORG_SLUG` | no | `default` | URL-safe slug of the default organization. Keep it stable after first deployment. |
| `BARKTRACE_AUTO_PROVISION` | no | `true` | Creates a user from a new verified OIDC identity. When false, only identities linked to existing users can sign in. |
| `BARKTRACE_SESSION_LIFETIME_HOURS` | no | `720` | Browser-session lifetime in hours. |
| `BARKTRACE_RATE_LIMIT_PER_MINUTE` | no | `1000` | Maximum ingestion requests per project in a fixed one-minute window. A rejected request returns HTTP 429 and Sentry retry headers. |
| `GOMEMLIMIT` | no | `96MiB` in the image | Go soft memory limit. Keep it below the container memory limit. |
| `BARKTRACE_MCP_TOKEN` | no | empty | Enables `/mcp` when set. It must contain at least 32 characters. |
| `BARKTRACE_UPTIME_ALLOW_PRIVATE_TARGETS` | no | `false` | Allows uptime monitors to contact loopback and private-network IPs. Keep disabled unless Barktrace is intentionally monitoring trusted internal services. |

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
