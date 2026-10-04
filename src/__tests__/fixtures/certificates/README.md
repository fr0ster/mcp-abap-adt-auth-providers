Throwaway test material for the certificate provider tests: a self-signed client
certificate (`client.crt` / `client.key`), the same pair as `client.pfx` with the
passphrase `test-passphrase`, the same key encrypted (`client-encrypted.key`, PKCS#8, same passphrase), and an unrelated key (`other.key`) for the
"key does not match the certificate" case. Trusted by nothing; never use it
anywhere else.

`other.crt` is a self-signed certificate for `other.key` (a stand-in non-leaf
certificate, not an issuer of `client.crt`, used only to make a PEM chain and the chain PFX); `client-chain.pfx` holds the client key and
certificate with `other.crt` as an extra certificate (passphrase
`test-passphrase`, current encryption: PBES2/AES-256-CBC). Made with:

    openssl req -new -x509 -key other.key -subj "/CN=other-test" -days 36500 -out other.crt
    openssl pkcs12 -export -inkey client.key -in client.crt -certfile other.crt \
      -passout pass:test-passphrase -out client-chain.pfx

`expired.crt` is a self-signed certificate for `client.key` that expired on
2021-01-01 (valid 2020-01-01 to 2021-01-01), for the "the client certificate has
expired" refusal. Made with (OpenSSL 3.4 or later, for `-not_before`/`-not_after`):

    openssl req -x509 -key client.key -subj "/CN=expired-test" \
      -not_before 20200101000000Z -not_after 20210101000000Z -out expired.crt
