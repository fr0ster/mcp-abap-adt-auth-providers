#!/usr/bin/env bash
# One command for the live XSUAA checks: set up, run the suite, tear down —
# also when a test fails. The exit status is non-zero if the tests or the
# teardown failed: a run that leaves resources behind is not a success.
# XSUAA_KEEP=1 keeps the environment for another run. Not part of CI.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/lib.sh"
guard_target

finish() {
  status=$?
  if [ "${XSUAA_KEEP:-0}" != 1 ]; then
    if ! "$HERE/teardown.sh"; then
      echo "teardown failed — resources may remain; run tests/xsuaa/teardown.sh" >&2
      [ "$status" -ne 0 ] || status=1
    fi
  fi
  exit "$status"
}
trap finish EXIT

"$HERE/setup.sh"
cd "$ROOT"
XSUAA_LOCAL="$LOCAL" npm test -- src/__tests__/integration/xsuaa "$@"
