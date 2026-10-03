Throwaway test material for the certificate provider tests: a self-signed client
certificate (`client.crt` / `client.key`), the same pair as `client.pfx` with the
passphrase `test-passphrase`, and an unrelated key (`other.key`) for the
"key does not match the certificate" case. Trusted by nothing; never use it
anywhere else.
