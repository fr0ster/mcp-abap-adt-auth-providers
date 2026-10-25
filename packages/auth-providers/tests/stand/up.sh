#!/usr/bin/env bash
# Starts the provider test stand — UAA, Keycloak and the Kerberos stand (a KDC
# and a Negotiate-only service, built from kerberos/) — and waits until each
# answers. Their configuration is committed under tests/stand/, so a fresh
# clone needs nothing but Docker.
#
# STAND_SERVICES names the services to start (default: all four); run.sh
# passes only the ones it starts, so a server already running is neither
# rebuilt nor recreated (--no-deps: a dependency is in the list exactly when
# it is not running). Only the services started are waited for.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"
KC_HTTPS_PORT="${KEYCLOAK_HTTPS_PORT:-8444}"
CA="$(pwd)/keycloak/tls/ca.crt"

SERVICES="${STAND_SERVICES-uaa keycloak kdc negotiate}"
starts() { case " $SERVICES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

if [ -n "$SERVICES" ]; then
  # Word splitting is intended: $SERVICES is a list of service names.
  # shellcheck disable=SC2086
  UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" KEYCLOAK_HTTPS_PORT="$KC_HTTPS_PORT" \
    docker compose up -d --build --no-deps $SERVICES
fi

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
if starts uaa; then
  wait_for UAA "http://localhost:$PORT/uaa/healthz"
fi
if starts keycloak; then
  wait_for Keycloak "http://localhost:$KC_PORT/realms/test/.well-known/openid-configuration"
  wait_for "Keycloak HTTPS" "https://localhost:$KC_HTTPS_PORT/realms/test/.well-known/openid-configuration"
fi

# The Kerberos stand publishes no port: its healthchecks say when the KDC has
# written the keytabs and the service answers.
wait_healthy() { # container
  for _ in $(seq 1 90); do
    if [ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = healthy ]; then
      echo "$1 is up"
      return 0
    fi
    sleep 2
  done
  echo "$1 did not come up; see: docker compose -f tests/stand/compose.yaml logs" >&2
  return 1
}
if starts kdc; then wait_healthy auth-providers-kdc; fi
if starts negotiate; then wait_healthy auth-providers-negotiate; fi

# What the host suites need from this stand, for a run by hand
# (`npm run test:stand` sets them itself). The SPNego suite runs inside the
# stand through `npm run test:stand` only: it needs the tracked files run.sh
# exports.
cat <<ENV
UAA_URL=http://localhost:$PORT/uaa
KEYCLOAK_URL=http://localhost:$KC_PORT/realms/test
KEYCLOAK_HTTPS_URL=https://localhost:$KC_HTTPS_PORT/realms/test
NODE_EXTRA_CA_CERTS=$CA
ENV
