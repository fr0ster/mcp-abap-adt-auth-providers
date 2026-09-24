#!/usr/bin/env bash
# Creates the XSUAA test environment in the targeted subaccount:
#   - an xsuaa/application instance whose client may use saml2-bearer,
#     refresh_token and password, with a service key;
#   - an xsuaa/apiaccess instance with a key, used only to manage trust;
#   - a SAML trust to a test identity provider whose key is generated here,
#     locally, and never leaves tests/xsuaa/.local/ (gitignored).
# Idempotent: what already exists is reused. Undo with teardown.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
guard_target
mkdir -p "$LOCAL"
chmod 700 "$LOCAL"

if [ ! -f "$LOCAL/idp.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=$ORIGIN" -keyout "$LOCAL/idp.key" -out "$LOCAL/idp.crt" 2>/dev/null
  chmod 600 "$LOCAL/idp.key"
fi

ensure_instance() { # name plan [params-file]
  if service_exists "$1"; then
    echo "$1: exists"
  elif [ -n "${3:-}" ]; then
    cf create-service xsuaa "$2" "$1" -c "$3" --wait >/dev/null
    echo "$1: created"
  else
    cf create-service xsuaa "$2" "$1" --wait >/dev/null
    echo "$1: created"
  fi
  if ! cf service-key "$1" "$KEY" >/dev/null 2>&1; then
    cf create-service-key "$1" "$KEY" --wait >/dev/null
  fi
}

ensure_instance "$INSTANCE" application "$HERE/xs-security.json"
save_key "$INSTANCE" "$LOCAL/bearer-key.json"
ensure_instance "$API_INSTANCE" apiaccess
save_key "$API_INSTANCE" "$LOCAL/api-key.json"

node "$HERE/trust.mjs" create "$LOCAL" "$ORIGIN"
