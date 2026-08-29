#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$repo_dir"

exec go run ./tests/loadtest \
  -duration "${BARKTRACE_LOAD_DURATION:-1m}" \
  -concurrency "${BARKTRACE_LOAD_CONCURRENCY:-8}" \
  -min-rps "${BARKTRACE_LOAD_MIN_RPS:-25}" \
  -max-p95 "${BARKTRACE_LOAD_MAX_P95:-2s}" \
  -max-error-rate "${BARKTRACE_LOAD_MAX_ERROR_RATE:-0.001}" \
  -max-rss-mib "${BARKTRACE_LOAD_MAX_RSS_MIB:-128}"
