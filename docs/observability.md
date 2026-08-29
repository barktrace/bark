# Performance, release health, logs, and uptime

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
Inline transaction spans and standalone `span`/`spans` envelope items are
normalized. Select a transaction group in the dashboard to inspect its latest
sample and span waterfall.

## Sessions and release health

Sentry `session` envelope items are upserted by project and session ID. Release
rows show session count, distinct users, and crash-free session and user
percentages. Configure `release` in the SDK and enable its session tracking to
populate these values.

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

## Session replay

Sentry `replay_event` and `replay_recording` envelope items are linked by replay
and segment ID. Select a segment under **Telemetry → Replays** to watch the
session in the official rrweb player and inspect its visited URLs, error and
trace correlation, event-category counts, and ordered navigation, interaction,
console, lifecycle, and DOM-mutation timeline. Form input changes are counted,
but their captured text is deliberately excluded from analysis results. The
player reflects the recording received from the SDK, so configure the SDK's
masking and blocking options before collecting sessions that may contain
sensitive content.

Analysis accepts uncompressed, gzip, zlib, Zstandard, and Brotli payloads. It reads
at most 16 MiB of stored compressed data per segment, expands at most 24 MiB,
scans at most 100,000 recording events, and returns at most 2,000 timeline
entries. The UI renders at most 500 timeline entries at once.

Interactive playback combines up to 100 segments from the selected session and
returns at most 20,000 rrweb events or 8 MiB of serialized events. A recording
must contain a full rrweb snapshot. Playback never starts automatically. The
native endpoints are:

- `GET /replays/{internal_segment_id}/analysis`
- `GET /replays/{internal_segment_id}/playback`

## Profiling

Transaction and continuous-profile envelope payloads are retained with their
profile, profiler, chunk, and transaction identifiers. Select a profile under
**Telemetry → Profiles** to inspect sampled threads, hottest frames, and a
bounded flamegraph. The native endpoint is
`GET /profiles/{internal_profile_id}/analysis`.

Profile analysis accepts at most 50,000 frames, 100,000 stacks, 200,000 samples,
5,000 flamegraph nodes, and 128 frames per sampled stack. The UI shows the top
50 hotspots and bounds its flamegraph rendering to 350 frames and 12 levels so
large profiles do not monopolize browser or server memory.

## Metrics

Sentry metric envelope items are normalized into project-scoped points with
name, type, unit, timestamp, value, and tags. **Telemetry → Metrics** shows
bounded count, minimum, average, and maximum summaries; the same dataset is
available through Discover and MCP.

## Source maps and native debug files

JavaScript events are rewritten with uploaded Source Map v3 artifacts. Barktrace
supports regular and indexed source maps, nullable embedded sources, canonical
URL-style `sourceRoot` values such as `webpack:///`, release and distribution
selection, and modern debug IDs from artifact bundles. Original generated frame
fields are retained with an `original_` prefix when a frame is rewritten.

Native frames can use uploaded ELF, Mach-O/dSYM, or Breakpad debug files selected
by image debug ID. ELF and thin or universal Mach-O artifacts resolve function
symbols and DWARF source files, lines, and columns, including runtime image-base
rebasing. DWARF loading is skipped when its uncompressed sections exceed 32 MiB
so a debug artifact cannot consume the container's whole memory budget.
Breakpad files resolve bounded `FUNC` records before falling back to the nearest
`PUBLIC` symbol and add `FILE` and source-line information when present.
Inline-frame expansion, CFI stack unwinding, PDB/PE, and ProGuard mapping are not
currently implemented.

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

New-issue, regression, and uptime-down alert rules can deliver JSON to HTTPS
webhooks or Slack incoming webhooks. Deliveries are retried up to three times
and their status is visible under Organization settings.
