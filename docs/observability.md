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

The Sentry-compatible organization endpoint returns totals and aligned time
series, with optional project, release, and environment filters:

```sh
curl --get 'https://errors.example.com/api/0/organizations/acme/sessions/' \
  -H 'Cookie: barktrace_session=...' \
  --data-urlencode 'statsPeriod=24h' \
  --data-urlencode 'interval=1h' \
  --data-urlencode 'field=sum(session)' \
  --data-urlencode 'field=count_unique(user)' \
  --data-urlencode 'field=crash_free_rate(session)' \
  --data-urlencode 'groupBy=release' \
  --data-urlencode 'groupBy=environment'
```

Supported fields are `sum(session)`, `count_unique(user)`,
`avg(session.duration)`, `crash_free_rate(session)`, and
`crash_free_rate(user)`. Results can group by `project`, `release`,
`environment`, and `session.status`; explicit RFC3339 `start`/`end` ranges are
also accepted. Queries are limited to 90 days and 1,000 time buckets.

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

## Cron monitoring

Sentry SDK check-ins and `monitor_config` payloads create or update cron
monitors automatically. Sentry-compatible management clients can list and
create monitors at `/api/0/organizations/{organization}/monitors/`, manage a
monitor by ID or slug at the corresponding `/{monitor}/` path, and read its
check-in history from `/{monitor}/checkins/`. Monitor mutations require project
administrator access and are written to the organization audit log.

## Session replay

Sentry `replay_event` and `replay_recording` envelope items are linked by replay
and segment ID. Replay error IDs are indexed against retained events and issues.
**Telemetry → Replays** can search by URL, user or replay ID and filter by
environment, release, and error presence. Select a segment to watch the
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

- `GET /replays?project_id={project_uuid}&q={text}&environment={environment}&release={release}&user_id={user}&has_error=true&issue_id={issue}`
- `GET /replays/{internal_segment_id}/analysis`
- `GET /replays/{internal_segment_id}/playback`

Sentry-compatible clients can use:

- `GET /api/0/organizations/{organization}/replays/`
- `GET /api/0/organizations/{organization}/replays/{replay_id}/`
- `GET /api/0/organizations/{organization}/replay-count/?data_source=events`
- `GET /api/0/organizations/{organization}/replay-selectors/`
- `DELETE /api/0/projects/{organization}/{project}/replays/{replay_id}/`
- `GET /api/0/projects/{organization}/{project}/replays/{replay_id}/clicks/`
- `GET /api/0/projects/{organization}/{project}/replays/{replay_id}/recording-segments/`
- `GET /api/0/projects/{organization}/{project}/replays/{replay_id}/recording-segments/{segment_id}/`
- `GET /api/0/projects/{organization}/{project}/replays/{replay_id}/viewed-by/`
- `POST /api/0/projects/{organization}/{project}/replays/jobs/delete/`
- `GET /api/0/projects/{organization}/{project}/replays/jobs/delete/{job_id}/`

The organization list accepts Sentry project, environment, release, time-range,
free-text, `has:error`, and `issue:{id}` filters. Deleting a session requires
project administrator access, removes all segments and correlations, records an
audit event, and queues unreferenced backing objects for durable deletion.
Batch deletion jobs are persisted, processed in bounded batches under a
multi-node lease, and resume after restart. Click targets are resolved from
rrweb snapshots and mutations; three same-node clicks within one second are
classified as rage clicks, while clicks followed by seven seconds without a DOM
mutation or navigation are classified as dead clicks. Form values are never
stored in the selector index. Each interaction type and selector forms a
deduplicated Replay issue. A Replay segment contributes one synthetic issue
event containing its selector, count, environment, release, URL, and Replay ID;
reingestion is idempotent, resolved groups reopen as regressions, and normal
issue alerts, assignment, snoozing, and resolution workflows apply. Removing a
Replay also removes its synthetic events and repairs or removes affected groups.

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

Native frames can use uploaded ELF, Mach-O/dSYM, PE/COFF, Microsoft PDB, or
Breakpad debug files selected by image debug ID. ELF, thin or universal Mach-O,
and PE/COFF artifacts resolve function symbols and DWARF source files, lines,
and columns, including runtime image-base rebasing. DWARF loading is skipped
when its uncompressed sections exceed 32 MiB so a debug artifact cannot consume
the container's whole memory budget. Standalone PDB 7 files resolve bounded
CodeView public and procedure symbols, C13 source files, lines, and columns, and
nested `S_INLINESITE` call frames through IPI function identities and inlinee
line programs, with section/RVA rebasing. Breakpad files resolve bounded `FUNC`
records before falling back to the nearest `PUBLIC` symbol, add `FILE` and
source-line information, and expand up to 512 nested `INLINE`/`INLINE_ORIGIN`
call frames.
ELF, Mach-O/dSYM, and DWARF-enabled PE files likewise expand bounded
`DW_TAG_inlined_subroutine` chains with call-site locations. Stack unwinding for
uploaded minidumps uses matching Breakpad `STACK CFI` records, Windows x86
`STACK WIN` program/FPO metadata, bounded ELF or Mach-O `.eh_frame` tables, and
x86/x86-64/ARM64 Mach-O compact-unwind records, with architecture-aware universal
binary selection and a frame-pointer fallback. The DWARF interpreter covers the
common CFA, register, offset, value-offset, advance, and saved-state
instructions for x86, x86-64, and ARM64. Minidump parsing unwinds up to 256
threads and 2,048 total event frames, retains the original dump as an event
attachment, and limits each walk to 256 frames. Bounded DWARF CFA, register
location, and register-value expressions cover common arithmetic, branching,
register-relative, dereference, and direct-value operations. Mach-O compact
unwind supports frame-based and immediate/indirect frameless x86 and x86-64
encodings, plus ARM64 frame-based and frameless encodings.

Java and Android frames can use ProGuard/R8 mapping files selected by the
event's ProGuard UUID. Barktrace restores class, method, source filename, and
line values while retaining their obfuscated values under `original_` fields.
Consecutive R8 mappings with the same obfuscated range expand into their
bounded inline call chain, including methods owned by another class and
class-specific source-file metadata. Event frames remain in Sentry's
oldest-to-newest order, and each mapping lookup emits at most 512 frames.
Mapping parsing is limited to 20 MiB and one million entries. Native uploads use
`artifact_type=proguard`; compatible clients can also post multipart mapping
files to `/api/0/projects/{organization}/{project}/files/proguard/`.

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

Sentry-compatible clients can manage the same rules through
`GET`/`POST /api/0/projects/{organization}/{project}/rules/` and
`GET`/`PUT`/`DELETE /api/0/projects/{organization}/{project}/rules/{id}/`.
First-seen, regression, user-feedback, uptime, cron, and metric conditions are
mapped to Barktrace triggers. Environment and level filters are supported.
Each rule currently has one email, HTTPS webhook, or Slack action; both match
modes must be `all`.
