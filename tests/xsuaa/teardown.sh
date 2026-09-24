#!/usr/bin/env bash
# Deletes what setup.sh recorded in .local/owned — nothing else — in reverse
# order, crossing each off as it goes. A resource is deleted only if its
# current ID still matches the record; one whose name now belongs to another
# resource is left alone and crossed off, since ours is already gone.
# On the first failure it stops with a non-zero status and keeps .local/ (the
# keys and the record), so running it again finishes the job. Only when
# nothing is left does it remove .local/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target
guard_ledger

if [ -z "$(ledger_entries)" ]; then
  echo "Nothing recorded as owned; nothing to delete."
  rm -rf "$LOCAL"
  exit 0
fi

fail() {
  echo "teardown stopped: $1 — $LOCAL is kept; run tests/xsuaa/teardown.sh again" >&2
  exit 1
}

delete_instance() { # name
  recorded="$(recorded_id instance "$1")"
  [ -n "$recorded" ] || return 0
  current="$(instance_guid "$1")"
  if [ -z "$current" ]; then
    echo "$1: already gone"
  elif [ "$current" != "$recorded" ]; then
    echo "$1: now $current, not ours ($recorded) — left alone" >&2
  else
    cf delete-service-key "$1" "$KEY" -f --wait >/dev/null 2>&1 || true
    cf delete-service "$1" -f --wait >/dev/null || fail "could not delete $1"
    echo "$1: deleted ($recorded)"
  fi
  disown instance "$1"
}

delete_instance "$INSTANCE"
recorded_trust="$(recorded_id trust "$ORIGIN")"
if [ -n "$recorded_trust" ]; then
  node "$HERE/trust.mjs" delete "$LOCAL" "$ORIGIN" "$recorded_trust" \
    || fail "could not delete trust $ORIGIN"
  disown trust "$ORIGIN"
fi
delete_instance "$API_INSTANCE"

if [ -n "$(ledger_entries)" ]; then
  fail "still recorded as owned: $(ledger_entries | tr '\n' ' ')"
fi
rm -rf "$LOCAL"
