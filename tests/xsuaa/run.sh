#!/usr/bin/env bash
# One command for the live XSUAA checks: set up, run the suite, tear down —
# also when a test fails, keeping its exit code. XSUAA_KEEP=1 keeps the
# environment for another run. Not part of CI: it needs a real subaccount.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/lib.sh"
guard_target

finish() {
  status=$?
  if [ "${XSUAA_KEEP:-0}" != 1 ]; then
    "$HERE/teardown.sh" || echo "teardown failed — run tests/xsuaa/teardown.sh" >&2
  fi
  exit "$status"
}
trap finish EXIT

"$HERE/setup.sh"
cd "$ROOT"
XSUAA_LOCAL="$LOCAL" npm test -- src/__tests__/integration/xsuaa "$@"
