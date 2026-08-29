# Sentry compatibility

Barktrace accepts standard Sentry DSNs and the event-ingestion protocol used by
current Sentry SDKs. Project DSNs use a numeric Sentry project ID while the
native API retains an internal UUID.

## Tested SDK setup

Python (`sentry-sdk` 2.21.0):

```python
import sentry_sdk

sentry_sdk.init(
    dsn="https://PUBLIC_KEY@errors.example.com/1",
    release="billing-api@1.4.0",
    environment="production",
)
```

Go (`sentry-go` 0.43.0):

```go
if err := sentry.Init(sentry.ClientOptions{
    Dsn:         "https://PUBLIC_KEY@errors.example.com/1",
    Release:     "billing-api@1.4.0",
    Environment: "production",
}); err != nil {
    log.Fatal(err)
}
defer sentry.Flush(2 * time.Second)
```

The DSN shown in the project setup page should always be copied verbatim.

## Supported ingestion surface

| Capability | Status |
| --- | --- |
| Envelope endpoint `/api/{project_id}/envelope/` | Supported |
| Legacy store endpoint `/api/{project_id}/store/` | Supported |
| DSN query authentication and `X-Sentry-Auth` | Supported |
| Identity, gzip, deflate, Brotli, and Zstandard request bodies | Supported |
| Error and security event storage | Supported |
| Message and exception grouping | Supported |
| Python exception interface (`exception.values`) | Supported |
| Go SDK exception-array interface | Supported |
| Release and environment fields | Supported |
| Duplicate event-ID handling | Supported |
| Browser SDK CORS preflight | Supported |
| Transaction envelopes and trace identifiers | Supported |
| Inline and standalone span normalization | Supported |
| Session envelopes and release health | Supported |
| Sentry structured log envelope items | Supported |
| Project ingestion rate-limit headers | Supported |
| Unknown envelope item acknowledgement/outcome recording | Supported |

The compatibility checks currently exercise real `sentry-sdk` 2.21.0 and
`sentry-go` 0.43.0 clients against the production Docker image.

## Not yet Sentry-compatible

Barktrace is compatible with Sentry SDK error delivery, not with the complete
Sentry product or HTTP API. The following need dedicated implementations:

- check-ins, profiles, replays, metrics, and attachments;
- source-map ingestion, native debug files, and symbolication;
- user feedback and client-report processing;
- Sentry-compatible alert-management APIs and quota categories (native webhook/Slack rules, project rate limits, and retention controls are available);
- commit/deploy metadata and suspect commits;
- the broader `/api/0` project, team, member, and issue API;
- complete endpoint coverage expected by `sentry-cli` (native Bearer API tokens and release creation are available);
- Relay protocol support and multi-node/high-availability ingestion.

Unsupported envelope item types receive a successful response and
are recorded in `ingestion_outcomes` with `processor pending`. This prevents SDK
retry storms, but the unsupported payload itself is not retained. Transactions
and log items are retained; replay and profiling payloads are not.
