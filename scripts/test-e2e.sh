#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
run_dir=$(mktemp -d)
provider_pid=
container_name="barktrace-e2e-$$"
app_port=${BARKTRACE_E2E_APP_PORT:-18080}
oidc_port=${BARKTRACE_E2E_OIDC_PORT:-19090}
app_url="http://127.0.0.1:$app_port"
oidc_url="http://127.0.0.1:$oidc_port"
mcp_token=barktrace-e2e-mcp-token-0000000000000000

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  if [ -n "$provider_pid" ]; then kill "$provider_pid" >/dev/null 2>&1 || true; fi
  docker run --rm --volume "$run_dir/data:/data" --entrypoint /bin/sh barktrace:e2e -c 'rm -rf /data/*' >/dev/null 2>&1 || true
  rm -rf "$run_dir"
}
trap cleanup EXIT INT TERM

cd "$repo_dir"
mkdir -p "$run_dir/data"
chmod 0777 "$run_dir/data"

go build -o "$run_dir/oidctest" ./tests/oidctest
OIDC_TEST_ADDR="127.0.0.1:$oidc_port" OIDC_TEST_ISSUER="$oidc_url" OIDC_TEST_REDIRECT_URL="$app_url/auth/oidc/callback" "$run_dir/oidctest" >"$run_dir/oidc.log" 2>&1 &
provider_pid=$!

for _ in $(seq 1 40); do
  if curl --silent --fail "$oidc_url/healthz" >/dev/null; then break; fi
  sleep 0.25
done
curl --silent --fail "$oidc_url/healthz" >/dev/null || { cat "$run_dir/oidc.log"; exit 1; }

docker build --tag barktrace:e2e ${BARKTRACE_DOCKER_BUILD_ARGS:-} .
docker run --detach --name "$container_name" --network host \
  --volume "$run_dir/data:/data" \
  --env BARKTRACE_ADDR="127.0.0.1:$app_port" \
  --env BARKTRACE_PUBLIC_URL="$app_url" \
  --env BARKTRACE_DEFAULT_ORG_NAME='E2E Organization' \
  --env BARKTRACE_DEFAULT_ORG_SLUG=e2e \
  --env BARKTRACE_DATABASE_URL="${BARKTRACE_E2E_DATABASE_URL:-}" \
  --env BARKTRACE_MCP_TOKEN="$mcp_token" \
  --env OIDC_ISSUER_URL="$oidc_url" \
  --env OIDC_CLIENT_ID=barktrace-e2e \
  --env OIDC_CLIENT_SECRET=barktrace-e2e-secret \
  --env OIDC_REDIRECT_URL="$app_url/auth/oidc/callback" \
  --env OIDC_PROVIDER_NAME='Test SSO' \
  barktrace:e2e >/dev/null

for _ in $(seq 1 80); do
  if curl --silent --fail "$app_url/readyz" >/dev/null; then break; fi
  sleep 0.25
done
curl --silent --fail "$app_url/readyz" >/dev/null || { docker logs "$container_name"; exit 1; }

browser_image=${BARKTRACE_E2E_BROWSER_IMAGE:-mcr.microsoft.com/playwright:v1.56.1-noble}
if ! docker run --rm --network host \
  --env BARKTRACE_E2E_URL="$app_url" \
  --env BARKTRACE_E2E_MCP_TOKEN="$mcp_token" \
  --volume "$repo_dir:/workspace:ro" \
  --workdir /workspace/tests/e2e \
  --entrypoint node \
  "$browser_image" browser.mjs; then
  docker logs "$container_name"
  exit 1
fi
