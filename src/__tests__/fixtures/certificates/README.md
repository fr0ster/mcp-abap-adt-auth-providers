Throwaway test material for the certificate provider tests: a self-signed client
certificate (`client.crt` / `client.key`), the same pair as `client.pfx` with the
passphrase `test-passphrase`, the same key encrypted (`client-encrypted.key`, PKCS#8, same passphrase), and an unrelated key (`other.key`) for the
"key does not match the certificate" case. Trusted by nothing; never use it
anywhere else.

`other.crt` is a self-signed certificate for `other.key` (a second, unrelated
certificate, for chains); `client-chain.pfx` holds the client key and
certificate with `other.crt` as an extra certificate (passphrase
`test-passphrase`, current encryption: PBES2/AES-256-CBC). Made with:

    openssl req -new -x509 -key other.key -subj "/CN=other-test" -days 36500 -out other.crt
    openssl pkcs12 -export -inkey client.key -in client.crt -certfile other.crt \
      -passout pass:test-passphrase -out client-chain.pfx
