#!/usr/bin/env bash
# One command for the UAA suite: start the stand in Docker, run the tests
# against it, and stop it again — the same locally and in CI.
#
# Whoever starts the stand stops it: a stand that was already running (from
# `npm run uaa:up`) is left running. UAA_KEEP=1 keeps one this script started.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"
PORT="${UAA_PORT:-8080}"

already_running=false
if [ -n "$(docker compose ps -q --status running 2>/dev/null)" ]; then
  already_running=true
fi

stop() {
  status=$?
  # On failure, print UAA's log before anything removes the container — after
  # `down` there is nothing left to read, locally or in CI.
  if [ "$status" -ne 0 ]; then
    echo "--- UAA log (last 200 lines) ---" >&2
    docker compose -f "$HERE/compose.yaml" logs --no-color --tail 200 >&2 || true
  fi
  if [ "$already_running" = false ] && [ "${UAA_KEEP:-0}" != 1 ]; then
    "$HERE/down.sh" >/dev/null 2>&1 || echo "could not stop the UAA stand" >&2
  fi
  exit "$status"
}
trap stop EXIT

UAA_PORT="$PORT" "$HERE/up.sh"
cd "$ROOT"
UAA_URL="http://localhost:$PORT/uaa" \
  npm test -- src/__tests__/integration/uaaSaml2Bearer.test.ts "$@"
