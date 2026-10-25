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
# On an instance of ours, a key with one of our names that we did not record
# is someone else's.
for pair in "$INSTANCE/$KEY" "$INSTANCE/$X509_KEY" "$API_INSTANCE/$KEY"; do
  guid="$(instance_guid "${pair%%/*}")" || exit 3
  if [ -n "$guid" ]; then
    key="$(key_guid "$guid" "${pair#*/}")" || exit 3
    if [ -n "$key" ] && [ "$key" != "$(recorded_id key "$pair")" ]; then
      refuse_foreign "service key $pair ($key)"
    fi
  fi
done

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

# Sets REUSED=1 when the instance was ours already, 0 when created here.
ensure_instance() { # name plan [params-file]
  guid="$(instance_guid "$1")" || exit 3
  if [ -n "$guid" ]; then
    [ "$guid" = "$(recorded_id instance "$1")" ] || refuse_foreign "service instance $1 ($guid)"
    # An instance kept from an earlier run (XSUAA_KEEP=1) gets today's
    # parameters: credential types and grant types may have been added since.
    if [ -n "${3:-}" ]; then
      quietly cf update-service "$1" -c "$3" --wait || {
        echo "$1: could not update it with $3" >&2
        exit 1
      }
    fi
    REUSED=1
    echo "$1: reused (owned, $guid)"
  else
    if [ -n "${3:-}" ]; then
      quietly cf create-service xsuaa "$2" "$1" -c "$3" --wait
    else
      quietly cf create-service xsuaa "$2" "$1" --wait
    fi
    guid="$(instance_guid "$1")" || exit 3
    [ -n "$guid" ] || { echo "$1: created, but cf reports it absent" >&2; exit 1; }
    own instance "$1" "$guid"
    REUSED=0
    echo "$1: created ($guid)"
  fi
}

# Makes sure the instance's key exists and is recorded as ours. With
# fresh=1 an owned key is deleted and created again. A key is recorded right
# after it is created — and also when cf reports the create failed, if the
# key is there anyway: it was absent a moment ago, on an instance of ours, so
# it is the one this run asked for. Unrecorded, it would block every later run.
ensure_key() { # instance key fresh [key-params]
  instance="$(recorded_id instance "$1")"
  [ -n "$instance" ] || { echo "$1: not recorded as ours; no key made" >&2; exit 1; }
  key="$(key_guid "$instance" "$2")" || exit 3
  if [ -n "$key" ]; then
    [ "$key" = "$(recorded_id key "$1/$2")" ] || refuse_foreign "service key $1/$2 ($key)"
    if [ "$3" != 1 ]; then
      echo "$1/$2: reused (owned, $key)"
      return 0
    fi
    quietly cf delete-service-key "$1" "$2" -f --wait || {
      echo "$1/$2: could not delete it to create it afresh" >&2
      exit 1
    }
    disown key "$1/$2"
    echo "$1/$2: deleted ($key), to be created afresh"
  fi
  created=1
  if [ -n "${4:-}" ]; then
    quietly cf create-service-key "$1" "$2" -c "$4" --wait || created=0
  else
    quietly cf create-service-key "$1" "$2" --wait || created=0
  fi
  key="$(key_guid "$instance" "$2")" || {
    echo "$1/$2: could not tell whether it was created, so it is not recorded." \
      "If cf service-keys $1 lists it, remove it: cf delete-service-key $1 $2 -f" >&2
    exit 3
  }
  if [ -n "$key" ]; then
    own key "$1/$2" "$key"
    echo "$1/$2: created ($key)"
  fi
  [ "$created" = 1 ] || { echo "$1/$2: could not create it" >&2; exit 1; }
  [ -n "$key" ] || { echo "$1/$2: created, but cf reports it absent" >&2; exit 1; }
}

ensure_instance "$API_INSTANCE" apiaccess
ensure_key "$API_INSTANCE" "$KEY" 0
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

ensure_instance "$INSTANCE" application "$HERE/xs-security.json"
# `key` names its credential type: with two allowed, it must hold a secret
# whatever XSUAA takes as the default. A reused instance was just updated, so
# its `key` is made again under today's credential types.
ensure_key "$INSTANCE" "$KEY" "$REUSED" '{"credential-type":"binding-secret"}'
save_key "$INSTANCE" "$KEY" "$LOCAL/bearer-key.json"

# The x509 key is made afresh on every run: its certificate lives about seven
# days. Its file holds a private key; it is written only by save_key,
# readable by its owner only, and never printed.
rm -f "$LOCAL/x509-key.json"
ensure_key "$INSTANCE" "$X509_KEY" 1 '{"credential-type":"x509"}'
save_key "$INSTANCE" "$X509_KEY" "$LOCAL/x509-key.json"
