# Client certificates — goal and path

**Status:** agreed direction, before the spec. The spec and then the plan come
next; this file fixes what they are for.

## Goal

A consumer of `@mcp-abap-adt/auth-providers` can authenticate **with a client
certificate instead of a secret** wherever SAP or an identity provider accepts
one, through the same providers and the same `IAuthProvider` contract — and
every claim about it is proven on a stand, not assumed.

Two places a certificate is used, and this work covers both to the depth that
can be measured:

- **B — the token endpoint (the main part).** Today every token request
  (`clientCredentialsAuth`, `browserAuth`, `tokenRefresher`, `oidcToken`,
  `passcodeAuth`, `saml2TokenExchange`) authenticates the *client* with
  `clientId` + `clientSecret`. An XSUAA service key with
  `credential-type: x509` has no secret at all: it carries `certificate`, `key`
  and `certurl`, and the token request must go over mTLS to `certurl`.
  Keycloak accepts the same (`client-x509`), and UAA accepts `private_key_jwt`
  instead. A token provider must be able to authenticate its client either way.
- **A — the logon to the ABAP system.** `CertificateAuthProvider` presents a
  client certificate in the TLS handshake of each logon. Proven here to the TLS
  level and to an X.509 user mapping in Keycloak; **not** against an ABAP
  system's `CERTRULE`, because none is available to test.

**Success:** an XSUAA x509 service key, a Keycloak `client-x509` client and a
UAA `private_key_jwt` client each yield a token through this package's
providers, with no secret configured, in tests that run against the stand (UAA,
Keycloak) or the BTP trial (XSUAA, not in CI); and a certificate logon is
refused or accepted at the TLS level exactly as configured.

## What was measured (spike, 2026-10-04)

- Keycloak 26.7 in Docker: mTLS client authentication works
  (`clientAuthenticatorType: client-x509`, subject DN in RFC 2253 order), and
  the token is bound to the certificate (`cnf.x5t#S256`). X.509 *user* login
  works through the direct-grant X.509 authenticator — the analogue of
  `CERTRULE`.
- nginx with `ssl_verify_client on`: `CertificateAuthProvider.fromFiles`
  through `@mcp-abap-adt/connection` gets 200, PEM and PFX.
- CF UAA v79.7 (the stand's image): no `tls_client_auth`; `private_key_jwt`
  works (`jwks` on the client, assertion `aud` = the token endpoint).
- XSUAA on the BTP trial: `credential-types: ["x509", "binding-secret"]`, a key
  created with `credential-type: x509` → `certificate`, `key`, `certurl`;
  `client_credentials` over mTLS at `certurl` → 200. That token is refused by
  ADT (401): no user, and the client is not trusted by the ABAP system's
  `xsappname` — out of reach on a trial.
- Two defects found and fixed separately: a bad PFX passphrase now refused in
  `prepare()` (auth-providers 5.2.3); the server certificate verified by
  default (`@mcp-abap-adt/connection` 11.0.0).

## Holds throughout

1. **The `IAuthProvider` rules stand unchanged** (`CLAUDE.md`, rules 1–7): no
   exception crosses the contract; a refusal carries fixed words only — never a
   key, a passphrase, a certificate's content or an error's message.
2. **How the client authenticates is a strategy, composed by the consumer.**
   A secret, a certificate, a signed JWT — each is a collaborator passed in;
   no provider builds one of its own, no provider guesses from what fields
   happen to be present (rule 7).
3. **The secret path keeps working as it does today.** A consumer that passes
   `clientSecret` sees no change in what is sent.
4. **The server certificate is always verified** on every token request,
   whatever the client presents; trusting a private CA is an explicit `ca`.
5. **No key material reaches a log line**, as no token does today.
6. **Every supported combination is proven on the stand or the trial.** What
   cannot be measured (ABAP `CERTRULE`, an x509 token accepted by ADT) is
   written down as unproven, not claimed.
7. **Dependencies only from the registry**, contracts only from the contract
   packages this package already uses.

## Out of scope

- An ABAP system's `CERTRULE` / `STRUSTSSO2` configuration, and ADT accepting
  an x509-obtained token — no system to prove it on.
- `mcp-abap-adt` and the other consumers: each adopts this in its own change,
  for the systems it serves.
- Issuing, rotating or storing certificates; loading a service key
  (`@mcp-abap-adt/auth-broker` / `auth-stores`).

## Open, for the spec

1. **The client-authentication contract.** One interface every token request
   goes through (secret in the body or basic header, mTLS certificate,
   `private_key_jwt`) — and whether it belongs in this package or in
   `@mcp-abap-adt/interfaces-auth` / `interfaces-auth-sap`.
2. **The endpoint.** XSUAA x509 sends to `certurl`, not `url`: who decides the
   token URL — the configuration, or the client-authentication strategy.
3. **Which providers take it.** All token providers, or those whose grant has
   a client to authenticate on the server side (`client_credentials`,
   authorization code, refresh, SAML bearer, token exchange, passcode).
4. **Certificate-bound tokens** (`cnf.x5t#S256`): a refresh must go over the
   same mTLS client, or the bound token is refused.
5. **Version.** Additive (5.3.0) if the secret stays the default shape;
   a major if the configuration must change.
6. **The Keycloak stand:** HTTPS with client-auth `request`, a test CA and
   client certificates as committed fixtures trusted by nothing but the stand.

## Path

1. This goal → spec → plan, each reviewed in this PR.
2. Implementation in this PR; stand suites (Keycloak mTLS, UAA
   `private_key_jwt`) in `npm run test:stand`; XSUAA x509 in
   `npm run test:xsuaa` (trial, not in CI).
3. If a contract package must change, that change is released first, in its
   own repository, and this PR builds against the published version.
4. External review, merge, release; then each consumer decides in its own
   change whether to use it.
