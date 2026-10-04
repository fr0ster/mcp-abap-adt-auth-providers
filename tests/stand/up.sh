#!/usr/bin/env bash
# Starts the provider test stand — UAA and Keycloak — and waits until both
# answer. Their configuration is committed under tests/stand/, so a fresh clone
# needs nothing but Docker.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"
KC_HTTPS_PORT="${KEYCLOAK_HTTPS_PORT:-8444}"
CA="$(pwd)/keycloak/tls/ca.crt"

UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" KEYCLOAK_HTTPS_PORT="$KC_HTTPS_PORT" \
  docker compose up -d

wait_for() { # name url
  for _ in $(seq 1 90); do
    if [ "$(curl -s --cacert "$CA" -o /dev/null -w '%{http_code}' "$2")" = 200 ]; then
      echo "$1 is up: $2"
      return 0
    fi
    sleep 2
  done
  echo "$1 did not come up; see: docker compose -f tests/stand/compose.yaml logs" >&2
  return 1
}
wait_for UAA "http://localhost:$PORT/uaa/healthz"
wait_for Keycloak "http://localhost:$KC_PORT/realms/test/.well-known/openid-configuration"
wait_for "Keycloak HTTPS" "https://localhost:$KC_HTTPS_PORT/realms/test/.well-known/openid-configuration"

# What the suites need from this stand, for a run by hand
# (`npm run test:stand` sets them itself).
cat <<ENV
UAA_URL=http://localhost:$PORT/uaa
KEYCLOAK_URL=http://localhost:$KC_PORT/realms/test
KEYCLOAK_HTTPS_URL=https://localhost:$KC_HTTPS_PORT/realms/test
NODE_EXTRA_CA_CERTS=$CA
ENV
