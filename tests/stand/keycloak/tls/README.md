# Stand TLS fixtures — TEST FIXTURES

Every certificate and key here exists only for the local provider stand. They
are committed on purpose, like the rest of `tests/stand/`, so a fresh clone and
CI need nothing but Docker. Nothing outside the stand trusts them: the CA is
trusted only by Keycloak's HTTPS listener in `../../compose.yaml` and by the
stand suites, through `NODE_EXTRA_CA_CERTS` set in `../../run.sh`. Do not reuse
them, and never add the CA to a system trust store.

| File | What it is | Used by |
|---|---|---|
| `ca.crt` | the throwaway CA (its key was deleted after signing) | Keycloak's truststore (`KC_TRUSTSTORE_PATHS`); the suites' `NODE_EXTRA_CA_CERTS` |
| `server.crt`, `server.key` | Keycloak's HTTPS certificate: `localhost`, `127.0.0.1` | `KC_HTTPS_CERTIFICATE_FILE` / `_KEY_FILE` |
| `client-a.crt`, `client-a.key` | `CN=client-a,O=stand`, clientAuth | the realm's `mtls` client (its subject DN) and the user `client-a` of the X.509 logon |
| `client-b.crt`, `client-b.key` | `CN=client-b,O=stand`, clientAuth — mapped to nothing | the refused cases |
| `jwt.key`, `jwt.crt` | the `private_key_jwt` signing pair; the certificate only carries the public key | the realm's `jwt` client (`jwt.credential.certificate`); UAA's `jwt_client` (`jwks`) |

## How they were made

`./generate.sh` regenerates the whole set (RSA 2048, valid 10 years) with
`openssl`, and deletes the CA's key. It changes every certificate, so after a
run update the copies of the signing key's public half in
`../realm-test.json` (client `jwt`, `jwt.credential.certificate`: the base64 of
`jwt.crt`) and `../../uaa/config/uaa.yml` (client `jwt_client`, `jwks`).

The key files are mode 644 so Keycloak's container user can read them —
acceptable only because they protect nothing. `.gitignore` keeps key and
certificate-bundle files out of the repository and names each of these as an
exception.
