#!/usr/bin/env bash
# Removes everything setup.sh created, in reverse order, and the local key
# material. Safe to run when some of it is already gone.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target

if [ -f "$LOCAL/api-key.json" ]; then
  node "$HERE/trust.mjs" delete "$LOCAL" "$ORIGIN" || echo "trust: could not delete" >&2
fi
for instance in "$API_INSTANCE" "$INSTANCE"; do
  if service_exists "$instance"; then
    cf delete-service-key "$instance" "$KEY" -f --wait >/dev/null 2>&1 || true
    cf delete-service "$instance" -f --wait >/dev/null
    echo "$instance: deleted"
  fi
done
rm -rf "$LOCAL"
