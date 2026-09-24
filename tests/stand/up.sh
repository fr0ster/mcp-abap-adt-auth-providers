#!/usr/bin/env bash
# Starts the provider test stand — UAA and Keycloak: renders UAA's config and
# keys on first run, starts both containers, and waits until both answer.
# Needs docker and openssl.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${UAA_PORT:-8080}"
KC_PORT="${KEYCLOAK_PORT:-8081}"
GEN=.generated

if [ ! -f "$GEN/config/uaa.yml" ] || [ "$(cat "$GEN/port" 2>/dev/null)" != "$PORT" ]; then
  mkdir -p "$GEN/config" "$GEN/secrets"
  [ -f "$GEN/idp.key" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=test-idp" -keyout "$GEN/idp.key" -out "$GEN/idp.crt" 2>/dev/null
  [ -f "$GEN/sp.key" ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=uaa-sp" -keyout "$GEN/sp.key" -out "$GEN/sp.crt" 2>/dev/null
  [ -f "$GEN/jwt.key" ] || openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 -out "$GEN/jwt.key" 2>/dev/null
  PORT="$PORT" GEN="$GEN" node - <<'NODE'
const fs = require('node:fs');
const { GEN, PORT } = process.env;
const indent = (file, n) =>
  fs.readFileSync(`${GEN}/${file}`, 'utf8').trim().split('\n')
    .map((l) => ' '.repeat(n) + l).join('\n');
const cert = fs.readFileSync(`${GEN}/idp.crt`, 'utf8').trim().split('\n').slice(1, -1).join('');
const metadata =
  '<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test-idp">' +
  '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
  '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>' +
  `<ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
  '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>' +
  '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://test-idp.invalid/sso"/>' +
  '</md:IDPSSODescriptor></md:EntityDescriptor>';
const yml = fs.readFileSync('uaa/uaa.yml.template', 'utf8')
  .replace('@@PORT@@', PORT)
  .replace('@@JWT_KEY@@', indent('jwt.key', 12))
  .replace('@@SP_KEY@@', indent('sp.key', 10))
  .replace('@@SP_CERT@@', indent('sp.crt', 10))
  .replace('@@IDP_METADATA@@', metadata);
fs.writeFileSync(`${GEN}/config/uaa.yml`, yml);
fs.writeFileSync(`${GEN}/port`, PORT);
NODE
  chmod -R a+rX "$GEN/config" "$GEN/secrets"
fi

UAA_PORT="$PORT" KEYCLOAK_PORT="$KC_PORT" docker compose up -d

wait_for() { # name url
  for _ in $(seq 1 90); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$2")" = 200 ]; then
      echo "$1 is up: $2"
      return 0
    fi
    sleep 2
  done
  echo "$1 did not come up; see: docker compose -f tests/stand/compose.yaml logs" >&2
  return 1
}
wait_for UAA "http://localhost:$PORT/uaa/healthz"
wait_for Keycloak "http://localhost:$KC_PORT/realms/test/.well-known/openid-configuration"
