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
| Cron/check-in envelope items | Supported |
| Attachments and user reports | Supported |
| Replay event/recording payloads | Storage, retrieval, metadata, bounded statistics, event timeline, and interactive rrweb playback |
| Profile and metric payloads | Storage, summaries, sampled-profile hotspots, threads, and flamegraph |
| Source maps and release files | Source Map v3, including indexed maps, canonical URL source roots, release/distribution precedence, embedded source context, and debug-ID artifact bundles |
| ELF, Mach-O/dSYM, PE/COFF, Microsoft PDB, and Breakpad debug files | ELF, thin/universal Mach-O, and PE/COFF function symbols with bounded DWARF source locations and inline chains; standalone PDB 7 CodeView public/procedure symbols, C13 source locations, and nested inline sites; and Breakpad `FUNC`/`PUBLIC` symbols with `FILE`/line and nested `INLINE` records, selected by debug ID |
| ProGuard and R8 mappings | Debug-ID-selected Java class, method, filename, and line remapping with bounded inline-call expansion, including the Sentry multipart upload route |
| Native minidumps | Raw or multipart `/api/{project_id}/minidump/` ingestion, event metadata and attachments, bounded multi-thread x86/x86-64/ARM64 contexts, Breakpad `STACK CFI`, Windows x86 `STACK WIN`, ELF/Mach-O `.eh_frame`, x86/x86-64/ARM64 Mach-O compact unwind, universal-binary architecture selection, frame-pointer fallback, and debug-ID symbolication |
| Release commits and deploys | Supported |
| Artifact bundle/chunk upload protocol | Supported for common `sentry-cli` workflows |
| Pre-production APK/AAB/IPA build upload and installable APK/IPA download | Supported |
| Snapshot image upload, latest-base lookup, and ZIP download | Supported |
| Durable queue, retry, and dead-letter handling | Supported |
| Organization events/Discover endpoint | Errors, transactions, spans, logs, metrics, bounded filters and aggregates |
| Organization and project detail endpoints | Supported, including project DSN-key discovery |
| Organization members and teams | Listing, team CRUD, team membership, project links, and project responses |
| Issue and event detail endpoints | Supported, including latest/group events, status, priority, user/team assignment, bookmark, snooze, public sharing, and permanent discard updates |
| Managed Sentry Relay | Registration, Ed25519 request authentication, v3 project configs, public-key lookup, and liveness |

The compatibility checks currently exercise real `sentry-sdk` 2.21.0 and
`sentry-go` 0.43.0 clients against the production Docker image. CI also
exercises real, checksum-pinned `sentry-cli` 3.7.0 release, source-map, debug-file, build,
snapshot, issue, event, log, deploy, repository, monitor, and code-mapping
workflows.

## Not yet Sentry-compatible

Barktrace implements the current `sentry-cli` network surface and common SDK
workflows, not the complete Sentry SaaS product or every private HTTP endpoint.
The bounded Discover subset supports selected fields, equality/negation/wildcard
filters, free-text search, project/environment/release/level/status filters,
ordering, and `count`, `count_unique`, `sum`, `avg`, `min`, `max`, and percentile
aggregates. It does not implement every SnQL function or Sentry query operator.
Every Sentry profile format and comparison workflow and the full integration
marketplace remain outside the current compatibility boundary. Native ELF
symbolication resolves function symbols and DWARF source files, lines, and
columns when the artifact contains at most 32 MiB of uncompressed DWARF data.
Mach-O objects extracted from dSYM bundles receive the same bounded symbol and
DWARF lookup, including runtime load-address rebasing, universal-binary
architecture selection, and bounded `DW_TAG_inlined_subroutine` expansion.
Native minidumps use bounded Breakpad `STACK CFI`, Windows x86 `STACK WIN`
program/FPO metadata, common ELF/Mach-O `.eh_frame` CFA rules, x86, x86-64, and
ARM64 Mach-O compact-unwind tables, or frame pointers to unwind up to 256 captured
threads and 2,048 total event frames. Universal Mach-O artifacts select their
unwind slice from the minidump architecture. Bounded DWARF CFA, register
location, and register-value expressions cover the common stack-machine
operations. PE/COFF images resolve embedded symbols and DWARF source locations. Standalone Microsoft
PDB 7 files resolve bounded public and procedure symbols, C13 source locations,
and nested `S_INLINESITE` records through IPI and inlinee-line metadata.
ProGuard/R8 mappings restore classes, methods, source files, source lines, and
bounded inline call chains, including cross-class inline methods. Breakpad
symbolication resolves bounded function ranges, source lines, nested inline
records, and `STACK CFI` records. Replay playback supports standard rrweb
recordings and bounded session-wide segment assembly;
Sentry-specific replay search, issue detection, and retention controls are not
yet complete. Relay support covers the managed forwarding path, not every Relay
processing-mode service or private Sentry endpoint. Unknown envelope categories
receive a successful response and an ingestion outcome so clients do not retry
forever.
