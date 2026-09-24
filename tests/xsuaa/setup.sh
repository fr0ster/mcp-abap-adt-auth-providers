#!/usr/bin/env bash
# Creates the XSUAA test environment in the targeted space and subaccount:
#   - an xsuaa/application instance whose client may use saml2-bearer,
#     refresh_token and password, with a service key;
#   - an xsuaa/apiaccess instance with a key, used only to manage trust;
#   - a SAML trust to a test identity provider whose key is generated here,
#     locally, and never leaves tests/xsuaa/.local/ (gitignored).
# Everything it creates is recorded, with its ID, in .local/owned. A resource
# with one of these names whose ID is not recorded there is someone else's:
# it refuses. Re-running reuses only what it owns. Undo with teardown.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target
guard_ledger

refuse_foreign() { # description
  echo "Refusing: $1 exists but is not recorded as ours in $LEDGER." \
    "Remove or rename it, or run elsewhere." >&2
  exit 2
}

# Check every instance name before creating anything, so a collision leaves
# nothing half-built behind.
for instance in "$INSTANCE" "$API_INSTANCE"; do
  guid="$(instance_guid "$instance")" || exit 3
  if [ -n "$guid" ] && [ "$guid" != "$(recorded_id instance "$instance")" ]; then
    refuse_foreign "service instance $instance ($guid)"
  fi
done

start_ledger
if [ ! -f "$LOCAL/idp.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=$ORIGIN" -keyout "$LOCAL/idp.key" -out "$LOCAL/idp.crt" 2>/dev/null
  chmod 600 "$LOCAL/idp.key"
fi

ensure_instance() { # name plan [params-file]
  guid="$(instance_guid "$1")" || exit 3
  if [ -n "$guid" ]; then
    [ "$guid" = "$(recorded_id instance "$1")" ] || refuse_foreign "service instance $1 ($guid)"
    echo "$1: reused (owned, $guid)"
  else
    if [ -n "${3:-}" ]; then
      cf create-service xsuaa "$2" "$1" -c "$3" --wait >/dev/null
    else
      cf create-service xsuaa "$2" "$1" --wait >/dev/null
    fi
    guid="$(instance_guid "$1")" || exit 3
    [ -n "$guid" ] || { echo "$1: created, but cf reports it absent" >&2; exit 1; }
    own instance "$1" "$guid"
    echo "$1: created ($guid)"
  fi
  if ! cf service-key "$1" "$KEY" >/dev/null 2>&1; then
    cf create-service-key "$1" "$KEY" --wait >/dev/null
  fi
}

ensure_instance "$API_INSTANCE" apiaccess
save_key "$API_INSTANCE" "$LOCAL/api-key.json"

# The trust needs the apiaccess key to be checked at all, hence this order.
trust_id="$(node "$HERE/trust.mjs" id "$LOCAL" "$ORIGIN")"
if [ -n "$trust_id" ]; then
  [ "$trust_id" = "$(recorded_id trust "$ORIGIN")" ] || refuse_foreign "trust $ORIGIN ($trust_id)"
  node "$HERE/trust.mjs" refresh "$LOCAL" "$ORIGIN" "$trust_id"
else
  trust_id="$(node "$HERE/trust.mjs" create "$LOCAL" "$ORIGIN")"
  own trust "$ORIGIN" "$trust_id"
  echo "trust $ORIGIN: created ($trust_id)"
fi

ensure_instance "$INSTANCE" application "$HERE/xs-security.json"
save_key "$INSTANCE" "$LOCAL/bearer-key.json"
