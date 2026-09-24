#!/usr/bin/env bash
# Creates the XSUAA test environment in the targeted space and subaccount:
#   - an xsuaa/application instance whose client may use saml2-bearer,
#     refresh_token and password, with a service key;
#   - an xsuaa/apiaccess instance with a key, used only to manage trust;
#   - a SAML trust to a test identity provider whose key is generated here,
#     locally, and never leaves tests/xsuaa/.local/ (gitignored).
# Everything it creates is recorded in .local/owned. Anything with one of
# these names that is not recorded there is someone else's: it refuses.
# Re-running reuses only what it owns. Undo with teardown.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target
mkdir -p "$LOCAL"
chmod 700 "$LOCAL"

refuse_foreign() { # description
  echo "Refusing: $1 already exists and was not created by these scripts" \
    "(not in $LEDGER). Remove or rename it, or run elsewhere." >&2
  exit 2
}

ensure_instance() { # name plan [params-file]
  if service_exists "$1"; then
    owns "instance $1" || refuse_foreign "service instance $1"
    echo "$1: reused (owned)"
  else
    if [ -n "${3:-}" ]; then
      cf create-service xsuaa "$2" "$1" -c "$3" --wait >/dev/null
    else
      cf create-service xsuaa "$2" "$1" --wait >/dev/null
    fi
    own "instance $1"
    echo "$1: created"
  fi
  if ! cf service-key "$1" "$KEY" >/dev/null 2>&1; then
    cf create-service-key "$1" "$KEY" --wait >/dev/null
  fi
}

# Check every name before creating anything, so a collision leaves nothing
# half-built behind.
for instance in "$INSTANCE" "$API_INSTANCE"; do
  if service_exists "$instance" && ! owns "instance $instance"; then
    refuse_foreign "service instance $instance"
  fi
done

if [ ! -f "$LOCAL/idp.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=$ORIGIN" -keyout "$LOCAL/idp.key" -out "$LOCAL/idp.crt" 2>/dev/null
  chmod 600 "$LOCAL/idp.key"
fi

ensure_instance "$API_INSTANCE" apiaccess
save_key "$API_INSTANCE" "$LOCAL/api-key.json"

# The trust needs the apiaccess key to be checked at all, hence this order.
if node "$HERE/trust.mjs" exists "$LOCAL" "$ORIGIN"; then
  owns "trust $ORIGIN" || refuse_foreign "trust $ORIGIN"
  node "$HERE/trust.mjs" refresh "$LOCAL" "$ORIGIN"
else
  node "$HERE/trust.mjs" create "$LOCAL" "$ORIGIN"
  own "trust $ORIGIN"
fi

ensure_instance "$INSTANCE" application "$HERE/xs-security.json"
save_key "$INSTANCE" "$LOCAL/bearer-key.json"
