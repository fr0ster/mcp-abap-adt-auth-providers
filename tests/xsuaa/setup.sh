#!/usr/bin/env bash
# Creates the XSUAA test environment in the targeted space and subaccount:
#   - an xsuaa/application instance whose client may use saml2-bearer,
#     refresh_token, password and client_credentials, and authenticate with a
#     secret or a client certificate (credential-types binding-secret, x509),
#     with two service keys: `key`, holding a secret, and `x509-key`, holding
#     a certificate and its private key. The x509 key is created afresh on
#     every run — XSUAA's certificate is valid for about seven days;
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
# On an instance of ours, an x509 key we did not record is someone else's.
guid="$(instance_guid "$INSTANCE")" || exit 3
if [ -n "$guid" ]; then
  key="$(key_guid "$guid" "$X509_KEY")" || exit 3
  if [ -n "$key" ] && [ "$key" != "$(recorded_id key "$X509_KEY")" ]; then
    refuse_foreign "service key $X509_KEY of $INSTANCE ($key)"
  fi
fi

start_ledger
# Key and certificate are made as a pair, under temporary names, and moved in
# only when both exist: a failed openssl must not leave a key without its
# certificate, which every later run would take as done.
if [ ! -f "$LOCAL/idp.key" ] || [ ! -f "$LOCAL/idp.crt" ]; then
  rm -f "$LOCAL/idp.key.new" "$LOCAL/idp.crt.new"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=$ORIGIN" -keyout "$LOCAL/idp.key.new" -out "$LOCAL/idp.crt.new" \
    2>"$LOCAL/openssl.err" || {
      cat "$LOCAL/openssl.err" >&2
      rm -f "$LOCAL/idp.key.new" "$LOCAL/idp.crt.new" "$LOCAL/openssl.err"
      exit 1
    }
  chmod 600 "$LOCAL/idp.key.new"
  mv "$LOCAL/idp.key.new" "$LOCAL/idp.key"
  mv "$LOCAL/idp.crt.new" "$LOCAL/idp.crt"
  rm -f "$LOCAL/openssl.err"
fi

ensure_instance() { # name plan [params-file [key-params]]
  guid="$(instance_guid "$1")" || exit 3
  if [ -n "$guid" ]; then
    [ "$guid" = "$(recorded_id instance "$1")" ] || refuse_foreign "service instance $1 ($guid)"
    # An instance kept from an earlier run (XSUAA_KEEP=1) gets today's
    # parameters: credential types and grant types may have been added since.
    if [ -n "${3:-}" ]; then
      cf update-service "$1" -c "$3" --wait >/dev/null
    fi
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
    if [ -n "${4:-}" ]; then
      cf create-service-key "$1" "$KEY" -c "$4" --wait >/dev/null
    else
      cf create-service-key "$1" "$KEY" --wait >/dev/null
    fi
  fi
}

ensure_instance "$API_INSTANCE" apiaccess
save_key "$API_INSTANCE" "$KEY" "$LOCAL/api-key.json"

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

# `key` names its credential type: with two allowed, it must hold a secret
# whatever XSUAA takes as the default.
ensure_instance "$INSTANCE" application "$HERE/xs-security.json" \
  '{"credential-type":"binding-secret"}'
save_key "$INSTANCE" "$KEY" "$LOCAL/bearer-key.json"

# The x509 key: deleted if we own one (its certificate may be near expiry),
# then created afresh and recorded. Its file holds a private key; it is
# written only by save_key, readable by its owner only, and never printed.
instance="$(recorded_id instance "$INSTANCE")"
key="$(key_guid "$instance" "$X509_KEY")" || exit 3
if [ -n "$key" ]; then
  [ "$key" = "$(recorded_id key "$X509_KEY")" ] || refuse_foreign "service key $X509_KEY of $INSTANCE ($key)"
  cf delete-service-key "$INSTANCE" "$X509_KEY" -f --wait >/dev/null
  disown key "$X509_KEY"
  echo "$X509_KEY: deleted ($key), to be created afresh"
fi
rm -f "$LOCAL/x509-key.json"
cf create-service-key "$INSTANCE" "$X509_KEY" -c '{"credential-type":"x509"}' --wait >/dev/null
key="$(key_guid "$instance" "$X509_KEY")" || exit 3
[ -n "$key" ] || { echo "$X509_KEY: created, but cf reports it absent" >&2; exit 1; }
own key "$X509_KEY" "$key"
echo "$X509_KEY: created ($key)"
save_key "$INSTANCE" "$X509_KEY" "$LOCAL/x509-key.json"
