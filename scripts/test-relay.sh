#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
run_dir=$(mktemp -d)
relay_image=${BARKTRACE_RELAY_TEST_IMAGE:-getsentry/relay:26.8.0}
relay_container="barktrace-relay-test-$$"
oidc_pid=
barktrace_pid=

cleanup() {
  docker rm -f "$relay_container" >/dev/null 2>&1 || true
  if [ -n "$barktrace_pid" ]; then kill "$barktrace_pid" >/dev/null 2>&1 || true; fi
  if [ -n "$oidc_pid" ]; then kill "$oidc_pid" >/dev/null 2>&1 || true; fi
  rm -rf "$run_dir"
}
trap cleanup EXIT INT TERM

cd "$repo_dir"
mkdir -p "$run_dir/data" "$run_dir/relay"
go build -o "$run_dir/oidctest" ./tests/oidctest
go build -o "$run_dir/barktrace" ./cmd/barktrace

OIDC_TEST_ADDR=127.0.0.1:19190 \
OIDC_TEST_ISSUER=http://127.0.0.1:19190 \
OIDC_TEST_REDIRECT_URL=http://127.0.0.1:18180/auth/oidc/callback \
  "$run_dir/oidctest" >"$run_dir/oidc.log" 2>&1 &
oidc_pid=$!

for _ in $(seq 1 40); do
  if curl --silent --fail http://127.0.0.1:19190/healthz >/dev/null; then break; fi
  sleep 0.25
done

BARKTRACE_ADDR=127.0.0.1:18180 \
BARKTRACE_DATA_DIR="$run_dir/data" \
BARKTRACE_PUBLIC_URL=http://127.0.0.1:18180 \
BARKTRACE_DEFAULT_ORG_SLUG=relay-test \
OIDC_ISSUER_URL=http://127.0.0.1:19190 \
OIDC_CLIENT_ID=barktrace-e2e \
OIDC_CLIENT_SECRET=barktrace-e2e-secret \
OIDC_REDIRECT_URL=http://127.0.0.1:18180/auth/oidc/callback \
  "$run_dir/barktrace" >"$run_dir/barktrace.log" 2>&1 &
barktrace_pid=$!

for _ in $(seq 1 80); do
  if curl --silent --fail http://127.0.0.1:18180/readyz >/dev/null; then break; fi
  sleep 0.25
done
curl --silent --fail http://127.0.0.1:18180/readyz >/dev/null || { cat "$run_dir/barktrace.log"; exit 1; }

sqlite3 "$run_dir/data/barktrace.db" "
  PRAGMA foreign_keys=ON;
  INSERT INTO organizations(id, slug, name) VALUES('relay-org', 'relay-org', 'Relay Org');
  INSERT INTO projects(id, sentry_id, organization_id, slug, name, platform, public_key)
  VALUES('relay-project', '42', 'relay-org', 'relay-app', 'Relay App', 'javascript', '0123456789abcdef0123456789abcdef');
"

docker run --rm "$relay_image" credentials generate --stdout >"$run_dir/relay/credentials.json"
cat >"$run_dir/relay/config.yml" <<'EOF'
relay:
  mode: managed
  upstream: http://127.0.0.1:18180/
  host: 127.0.0.1
  port: 18182
processing:
  enabled: false
EOF
chmod 0777 "$run_dir/relay"
chmod 0666 "$run_dir/relay/config.yml" "$run_dir/relay/credentials.json"

docker run --detach --rm --name "$relay_container" --network host \
  --volume "$run_dir/relay:/work" \
  "$relay_image" -c /work run >/dev/null

for _ in $(seq 1 80); do
  if curl --silent --fail http://127.0.0.1:18182/api/0/relays/live/ >/dev/null; then break; fi
  sleep 0.25
done
curl --silent --fail http://127.0.0.1:18182/api/0/relays/live/ >/dev/null || { docker logs "$relay_container"; exit 1; }

curl --silent --fail -X POST \
  'http://127.0.0.1:18182/api/42/envelope/?sentry_key=0123456789abcdef0123456789abcdef&sentry_version=7' \
  -H 'Content-Type: application/x-sentry-envelope' \
  --data-binary '{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","dsn":"http://0123456789abcdef0123456789abcdef@127.0.0.1:18182/42"}
{"type":"event","content_type":"application/json"}
{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","level":"error","message":"through real Relay","platform":"javascript"}
' >/dev/null

for _ in $(seq 1 50); do
  count=$(sqlite3 "$run_dir/data/barktrace.db" "SELECT COUNT(*) FROM events WHERE event_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';")
  if [ "$count" = "1" ]; then
    echo "Relay registration, project configuration, and envelope forwarding passed"
    exit 0
  fi
  sleep 0.2
done

docker logs "$relay_container"
cat "$run_dir/barktrace.log"
echo "Relay did not forward the test envelope" >&2
exit 1
