#!/usr/bin/env bash
# One command for the provider stand suites: start UAA and Keycloak in Docker,
# run the tests against them, and stop them again — the same locally and in CI.
#
# Whoever starts the stand stops it: a stand that was already running (from
# `npm run stand:up`) is left running. STAND_KEEP=1 keeps one this script
# started.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"

already_running=false
if [ -n "$(docker compose ps -q --status running 2>/dev/null)" ]; then
  already_running=true
fi

stop() {
  status=$?
  # On failure, print the servers' logs before anything removes the
  # containers — after `down` there is nothing left to read, locally or in CI.
  if [ "$status" -ne 0 ]; then
    echo "--- stand logs (last 200 lines per service) ---" >&2
    docker compose -f "$HERE/compose.yaml" logs --no-color --tail 200 >&2 || true
  fi
  if [ "$already_running" = false ] && [ "${STAND_KEEP:-0}" != 1 ]; then
    "$HERE/down.sh" >/dev/null 2>&1 || echo "could not stop the stand" >&2
  fi
  exit "$status"
}
trap stop EXIT

UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" "$HERE/up.sh"
cd "$ROOT"
UAA_URL="http://localhost:$PORT/uaa" \
  KEYCLOAK_URL="http://localhost:$KC_PORT/realms/test" \
  npm test -- src/__tests__/integration/stand "$@"
