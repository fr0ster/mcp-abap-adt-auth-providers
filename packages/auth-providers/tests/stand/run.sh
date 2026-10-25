#!/usr/bin/env bash
# One command for the provider stand suites: start UAA, Keycloak and the
# Kerberos stand in Docker, run the tests against them, and stop them again —
# the same locally and in CI. The host suites run first; then the SPNego suite
# runs inside the stand (the spnego-client container, see compose.yaml), and
# the run fails if either fails. STAND_SPNEGO=0 leaves the Kerberos stand out
# (CI runs it on one Node version only).
#
# The SPNego container never sees the working tree: this script exports the
# files git tracks of the two packages (and the root .gitignore their build
# reads) into a temporary directory, refuses it if any path in it is one git
# ignores, mounts it read-only, and removes it at exit. So an ignored secret —
# tests/test-config.yaml, tests/xsuaa/.local/, an .env — never reaches a
# container that runs registry code with network access.
#
# Whoever starts a server stops it, per service: one that was already running
# (from `npm run stand:up`, or started by hand) is left running, and only the
# ones this script started are removed. STAND_KEEP=1 keeps those too.
#
# Written for Bash 3.2, the /bin/bash macOS still ships: no associative arrays,
# and no arrays at all — an empty one is "unbound" under `set -u` there.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"
KC_HTTPS_PORT="${KEYCLOAK_HTTPS_PORT:-8444}"
SPNEGO="${STAND_SPNEGO:-1}"
if [ "$SPNEGO" = 1 ]; then
  SERVICES="uaa keycloak kdc negotiate"
else
  SERVICES="uaa keycloak"
fi
SPNEGO_SOURCE=""

wanted_address() { # service
  case "$1" in
    uaa) echo "127.0.0.1:$PORT" ;;
    keycloak) echo "127.0.0.1:$KC_PORT" ;;
  esac
}

# Space-separated names of the services this run starts, and so owns.
started=""
for service in $SERVICES; do
  if [ -z "$(docker compose ps -q --status running "$service" 2>/dev/null)" ]; then
    started="$started $service"
  fi
done
started="${started# }"

# A server that is already running is not ours to change. `docker compose up`
# would recreate it if the requested port differs from the one it is published
# on, so refuse instead — before anything is started or trapped.
for service in $SERVICES; do
  case " $started " in
    *" $service "*) ;;
    *)
      # The Kerberos stand publishes no port: nothing to compare.
      case "$service" in kdc | negotiate) continue ;; esac
      actual="$(docker compose port "$service" 8080 2>/dev/null || true)"
      wanted="$(wanted_address "$service")"
      if [ "$actual" != "$wanted" ]; then
        echo "$service is already running on $actual, not $wanted;" \
          "stop it (npm run stand:down) or run with its port" >&2
        exit 1
      fi
      if [ "$service" = keycloak ]; then
        actual="$(docker compose port keycloak 8443 2>/dev/null || true)"
        if [ "$actual" != "127.0.0.1:$KC_HTTPS_PORT" ]; then
          echo "keycloak is already running with HTTPS on ${actual:-no port}," \
            "not 127.0.0.1:$KC_HTTPS_PORT; stop it (npm run stand:down)" \
            "or run with its port" >&2
          exit 1
        fi
      fi
      ;;
  esac
done

stop() {
  status=$?
  if [ -n "$SPNEGO_SOURCE" ]; then rm -rf "$SPNEGO_SOURCE"; fi
  # On failure, print the servers' logs before anything removes the
  # containers — after `down` there is nothing left to read, locally or in CI.
  if [ "$status" -ne 0 ]; then
    echo "--- stand logs (last 200 lines per service) ---" >&2
    docker compose -f "$HERE/compose.yaml" logs --no-color --tail 200 >&2 || true
  fi
  if [ -n "$started" ] && [ "${STAND_KEEP:-0}" != 1 ]; then
    # down.sh (compose down --volumes) removes all four servers and the
    # Kerberos volume: only when this run started all four. With
    # STAND_SPNEGO=0, or any server already running, only the started ones go,
    # so a hand-started kdc/negotiate and their volume survive.
    if [ "$started" = "uaa keycloak kdc negotiate" ]; then
      "$HERE/down.sh" >/dev/null 2>&1 || echo "could not stop the stand" >&2
    else
      # Word splitting is intended: $started is a list of service names.
      # shellcheck disable=SC2086
      docker compose -f "$HERE/compose.yaml" rm --stop --force $started \
        >/dev/null 2>&1 || echo "could not stop: $started" >&2
      # The Kerberos stand's volume and network, once neither of its servers
      # is left: both were this run's.
      case " $started " in
        *" kdc "*" negotiate "*)
          docker volume rm auth-providers-keytabs >/dev/null 2>&1 || true
          docker network rm stand_kerberos >/dev/null 2>&1 || true
          ;;
      esac
    fi
  fi
  exit "$status"
}
trap stop EXIT

# Only the services this run starts are built and started: a running one is
# left as it is.
UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" KEYCLOAK_HTTPS_PORT="$KC_HTTPS_PORT" \
  STAND_SERVICES="$started" "$HERE/up.sh"
cd "$ROOT"
# NODE_EXTRA_CA_CERTS: the suites trust Keycloak's HTTPS through the stand's
# own CA, as a consumer trusts a private CA — no provider takes a `ca`.
host_status=0
UAA_URL="http://localhost:$PORT/uaa" \
  KEYCLOAK_URL="http://localhost:$KC_PORT/realms/test" \
  KEYCLOAK_HTTPS_URL="https://localhost:$KC_HTTPS_PORT/realms/test" \
  NODE_EXTRA_CA_CERTS="$HERE/keycloak/tls/ca.crt" \
  npm test -- src/__tests__/integration/stand "$@" || host_status=$?

# The SPNego suite, inside the stand's network: the container copies the
# packages from the read-only repository, installs and builds them there, and
# exits with the suite's code (kerberos/client/run-suite.sh).
spnego_status=0
if [ "$SPNEGO" = 1 ]; then
  REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
  SPNEGO_SOURCE="$(mktemp -d)"
  # Tracked files only, as they are in the working tree (a deleted one is
  # skipped); nothing untracked, nothing ignored.
  git -C "$REPO" ls-files -z -- .gitignore packages/auth-providers \
    packages/auth-spnego-gssapi |
    while IFS= read -r -d '' path; do
      if [ -e "$REPO/$path" ]; then printf '%s\0' "$path"; fi
    done |
    tar -C "$REPO" --null -T - -cf - | tar -C "$SPNEGO_SOURCE" -xf -
  # The check: no path of the export is one git ignores.
  ignored="$(cd "$SPNEGO_SOURCE" && find . -print | sed -e 's|^\./||' -e '/^\.$/d' |
    git -C "$REPO" check-ignore --no-index --stdin || true)"
  if [ -n "$ignored" ]; then
    echo "refusing the SPNego export: it holds paths git ignores:" >&2
    echo "$ignored" >&2
    exit 1
  fi
  SPNEGO_SOURCE="$SPNEGO_SOURCE" docker compose -f "$HERE/compose.yaml" \
    run --rm --build --no-deps spnego-client || spnego_status=$?
fi

if [ "$host_status" -ne 0 ] || [ "$spnego_status" -ne 0 ]; then
  echo "stand suites failed: host $host_status, SPNego $spnego_status" >&2
  exit 1
fi
