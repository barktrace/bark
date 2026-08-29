#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
run_dir=$(mktemp -d)
server_pid=

cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" >/dev/null 2>&1 || true; fi
  rm -rf "$run_dir"
}
trap cleanup EXIT INT TERM

version=${LIBSQL_TEST_VERSION:-0.24.32}
case "$(uname -m)" in
  x86_64) archive="libsql-server-x86_64-unknown-linux-gnu.tar.xz" ;;
  aarch64|arm64) archive="libsql-server-aarch64-unknown-linux-gnu.tar.xz" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
base_url="https://github.com/tursodatabase/libsql/releases/download/libsql-server-v${version}"
# BARKTRACE_CURL_FLAGS is useful for supplying a corporate CA bundle locally.
# CI and normal environments leave it empty and retain standard TLS validation.
curl ${BARKTRACE_CURL_FLAGS:-} --fail --location --silent --show-error "$base_url/$archive" --output "$run_dir/$archive"
curl ${BARKTRACE_CURL_FLAGS:-} --fail --location --silent --show-error "$base_url/$archive.sha256" --output "$run_dir/$archive.sha256"
(cd "$run_dir" && sha256sum --check "$archive.sha256")
tar -xJf "$run_dir/$archive" -C "$run_dir"
sqld="$run_dir/${archive%.tar.xz}/sqld"

"$sqld" --db-path "$run_dir/data.sqld" --http-listen-addr 127.0.0.1:18082 --no-welcome >"$run_dir/sqld.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 80); do
  if curl --silent --fail http://127.0.0.1:18082/health >/dev/null 2>&1; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then cat "$run_dir/sqld.log"; exit 1; fi
  sleep 0.25
done

cd "$repo_dir"
BARKTRACE_TEST_LIBSQL_URL=http://127.0.0.1:18082 \
  go test -run TestRemoteLibSQLSupportsConcurrentReplicas -count=1 -v ./internal/store
