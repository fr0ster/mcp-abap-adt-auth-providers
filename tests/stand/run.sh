#!/usr/bin/env bash
# One command for the provider stand suites: start UAA and Keycloak in Docker,
# run the tests against them, and stop them again — the same locally and in CI.
#
# Whoever starts a server stops it, per service: one that was already running
# (from `npm run stand:up`, or started by hand) is left running, and only the
# ones this script started are removed. STAND_KEEP=1 keeps those too.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"

SERVICES=(uaa keycloak)
started=()
for service in "${SERVICES[@]}"; do
  if [ -z "$(docker compose ps -q --status running "$service" 2>/dev/null)" ]; then
    started+=("$service")
  fi
done

# A server that is already running is not ours to change. `docker compose up`
# would recreate it if the requested port differs from the one it is published
# on, so refuse instead — before anything is started or trapped.
declare -A WANTED=([uaa]="127.0.0.1:$PORT" [keycloak]="127.0.0.1:$KC_PORT")
for service in "${SERVICES[@]}"; do
  if [[ " ${started[*]} " != *" $service "* ]]; then
    actual="$(docker compose port "$service" 8080 2>/dev/null || true)"
    if [ "$actual" != "${WANTED[$service]}" ]; then
      echo "$service is already running on $actual, not ${WANTED[$service]};" \
        "stop it (npm run stand:down) or run with its port" >&2
      exit 1
    fi
  fi
done

stop() {
  status=$?
  # On failure, print the servers' logs before anything removes the
  # containers — after `down` there is nothing left to read, locally or in CI.
  if [ "$status" -ne 0 ]; then
    echo "--- stand logs (last 200 lines per service) ---" >&2
    docker compose -f "$HERE/compose.yaml" logs --no-color --tail 200 >&2 || true
  fi
  if [ "${#started[@]}" -gt 0 ] && [ "${STAND_KEEP:-0}" != 1 ]; then
    if [ "${#started[@]}" -eq "${#SERVICES[@]}" ]; then
      "$HERE/down.sh" >/dev/null 2>&1 || echo "could not stop the stand" >&2
    else
      docker compose -f "$HERE/compose.yaml" rm --stop --force "${started[@]}" \
        >/dev/null 2>&1 || echo "could not stop: ${started[*]}" >&2
    fi
  fi
  exit "$status"
}
trap stop EXIT

UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" "$HERE/up.sh"
cd "$ROOT"
UAA_URL="http://localhost:$PORT/uaa" \
  KEYCLOAK_URL="http://localhost:$KC_PORT/realms/test" \
  npm test -- src/__tests__/integration/stand "$@"
