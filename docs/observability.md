# Performance, logs, and uptime

All three processors use the same project and organization access boundary as
errors. Their dashboard views are available at `/ui/performance/`, `/ui/logs/`,
and `/ui/uptime/`.

## Performance

Barktrace stores Sentry envelope items whose type is `transaction`. Configure a
Sentry SDK with tracing enabled and use the normal project DSN. The dashboard
shows throughput, failures, average, p50 and p95 latency, and slow transaction
groups for 1 hour, 24 hour, 7 day, or 30 day windows.

Transaction releases are linked to the same organization and project release
records used by error events. Trace ID, root span ID, operation, status,
environment, duration, span count, and the original payload are retained.

## Structured logs

Sentry envelope items with type `log` or `logs` are accepted. Barktrace also
offers a small batch endpoint for agents and applications that do not use a
Sentry SDK:

```sh
curl -X POST \
  'https://errors.example.com/api/1/logs/?sentry_key=PUBLIC_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"timestamp":"2026-08-28T18:00:00Z","level":"info","body":"deployment completed","environment":"production","release":"api@2.4.0","trace_id":"0123456789abcdef"}]}'
```

The endpoint accepts one object, an array, or an object containing `items`.
Each item requires `body` or `message`; batches are capped at 1,000 entries and
5 MiB. Attributes are stored as JSON and can carry `sentry.release`,
`sentry.environment`, `sentry.trace_id`, and `sentry.span_id`.

## Uptime

Organization owners and administrators can create GET or HEAD monitors from the
dashboard. Intervals range from 30 seconds to 24 hours and timeouts from 1 to 30
seconds. Checks follow at most five redirects, read at most 64 KiB, and regard
HTTP 200–399 as healthy by default. A failed check opens one incident; the next
successful check resolves it.

Private, loopback, link-local, multicast, and unspecified targets are blocked
both during monitor creation and at connection time. This protects the service
from common SSRF and DNS-rebinding paths. To monitor trusted intranet services,
set `BARKTRACE_UPTIME_ALLOW_PRIVATE_TARGETS=true` and restrict who has
organization administrator access.

The single-process scheduler checks due monitors in small sequential batches,
which keeps memory and outbound concurrency bounded for SQLite deployments.
