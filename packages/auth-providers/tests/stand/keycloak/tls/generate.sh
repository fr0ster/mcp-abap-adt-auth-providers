#!/usr/bin/env bash
# Regenerates every TLS fixture of the provider stand in this directory: a
# throwaway CA, Keycloak's server certificate, the client certificates
# client-a and client-b, and the private_key_jwt signing pair. See README.md.
#
# The CA's key is used here and deleted: the committed fixtures need only the
# CA certificate, and a new set is always generated whole. After running it,
# update the copies of the signing key's public half in
# ../realm-test.json (client "jwt") and ../../uaa/config/uaa.yml (client
# "jwt_client"), and Keycloak's client "mtls" if a subject changes.
set -euo pipefail
cd "$(dirname "$0")"
DAYS=3650
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
  -subj "/O=stand/CN=stand test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$WORK/ca.key" -out ca.crt

issue() { # name subject extensions
  openssl req -newkey rsa:2048 -nodes -subj "$2" \
    -keyout "$1.key" -out "$WORK/$1.csr"
  printf '%s\n' "$3" >"$WORK/$1.ext"
  openssl x509 -req -in "$WORK/$1.csr" -CA ca.crt -CAkey "$WORK/ca.key" \
    -CAcreateserial -CAserial "$WORK/ca.srl" -days "$DAYS" \
    -extfile "$WORK/$1.ext" -out "$1.crt"
}

issue server "/O=stand/CN=localhost" \
  "subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE"
issue client-a "/O=stand/CN=client-a" \
  "extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE"
issue client-b "/O=stand/CN=client-b" \
  "extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE"

# The private_key_jwt signing pair: a key, and a self-signed certificate that
# carries its public half to Keycloak (jwt.credential.certificate).
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
  -subj "/O=stand/CN=jwt-client" -keyout jwt.key -out jwt.crt

# Keycloak reads the key files as its own container user.
chmod 644 ./*.key ./*.crt
