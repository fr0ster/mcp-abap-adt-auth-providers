#!/usr/bin/env bash
# Deletes what setup.sh recorded in .local/owned — nothing else — in reverse
# order, crossing each off as it goes. On the first failure it stops with a
# non-zero status and keeps .local/ (the keys and the record), so running it
# again finishes the job. Only when nothing is left does it remove .local/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target

if [ ! -s "$LEDGER" ]; then
  echo "Nothing recorded as owned; nothing to delete."
  rm -rf "$LOCAL"
  exit 0
fi

fail() {
  echo "teardown stopped: $1 — $LOCAL is kept; run tests/xsuaa/teardown.sh again" >&2
  exit 1
}

delete_instance() { # name
  if owns "instance $1"; then
    if service_exists "$1"; then
      cf delete-service-key "$1" "$KEY" -f --wait >/dev/null 2>&1 || true
      cf delete-service "$1" -f --wait >/dev/null || fail "could not delete $1"
    fi
    disown "instance $1"
    echo "$1: deleted"
  fi
}

delete_instance "$INSTANCE"
if owns "trust $ORIGIN"; then
  node "$HERE/trust.mjs" delete "$LOCAL" "$ORIGIN" || fail "could not delete trust $ORIGIN"
  disown "trust $ORIGIN"
fi
delete_instance "$API_INSTANCE"

if [ -s "$LEDGER" ]; then
  fail "still recorded as owned: $(tr '\n' ' ' < "$LEDGER")"
fi
rm -rf "$LOCAL"
