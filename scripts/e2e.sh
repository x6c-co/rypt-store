#!/usr/bin/env bash
# Runs the Playwright specs against a fresh rypt-store instance: builds the
# binary with the SPA, starts rqlited and the server on free ports, reads
# the setup token from the server log, runs `npm run e2e`, and cleans up.
#
# Needs: `make tools` (rqlited in .tools/) or rqlited on PATH, Node, and
# `npx playwright install chromium`.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

rqlited="${RYPT_STORE_TEST_RQLITED:-$(ls "$root"/.tools/rqlite/*/rqlited 2>/dev/null | tail -1 || true)}"
rqlited="${rqlited:-$(command -v rqlited || true)}"
if [[ -z "$rqlited" ]]; then
  echo "rqlited not found: run 'make tools'" >&2
  exit 1
fi

if [[ "${SKIP_BUILD:-}" != 1 ]]; then
  (cd "$root/web" && npm ci --no-audit --no-fund && npm run build)
  (cd "$root" && CGO_ENABLED=0 go build -o "$work/rypt-store" ./cmd/rypt-store)
  bin="$work/rypt-store"
else
  bin="${RYPT_STORE_BIN:?set RYPT_STORE_BIN with SKIP_BUILD=1}"
fi

rq_http=$(free_port); rq_raft=$(free_port); https=$(free_port)
"$rqlited" -http-addr "127.0.0.1:$rq_http" -raft-addr "127.0.0.1:$rq_raft" "$work/rqlite" >"$work/rqlite.log" 2>&1 &
pids+=($!)

RYPT_STORE_DATA_DIR="$work/data" \
RYPT_STORE_DATABASE_URL="http://127.0.0.1:$rq_http" \
RYPT_STORE_SERVER_HTTPS_LISTEN="127.0.0.1:$https" \
RYPT_STORE_SERVER_HTTP_LISTEN="" \
RYPT_STORE_METRICS_LISTEN="" \
  "$bin" server >"$work/server.log" 2>&1 &
pids+=($!)

token=""
for _ in $(seq 1 150); do
  token="$(grep -A2 'Setup token' "$work/server.log" 2>/dev/null | tail -1 | tr -d ' ' || true)"
  if [[ -n "$token" ]] && curl -skf "https://localhost:$https/healthz" >/dev/null; then break; fi
  sleep 0.2
done
if [[ -z "$token" ]]; then
  echo "server did not start:" >&2
  cat "$work/server.log" >&2
  exit 1
fi

cd "$root/web"
rm -rf e2e/.state
status=0
RYPT_STORE_E2E_URL="https://localhost:$https" RYPT_STORE_E2E_SETUP_TOKEN="$token" npx playwright test || status=$?
if grep -q '"level":"ERROR"' "$work/server.log"; then
  echo "server logged errors:" >&2
  grep '"level":"ERROR"' "$work/server.log" >&2
  status=1
fi
exit $status
