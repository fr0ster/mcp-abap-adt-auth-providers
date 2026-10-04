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

- **B — the token endpoint (the main part).** Today a token request
  (`clientCredentialsAuth`, `browserAuth`, `tokenRefresher`, `oidcToken`,
  `passcodeAuth`, `saml2TokenExchange`) authenticates the *client* with
  `clientId` + `clientSecret` — or, for the OIDC providers, whose
  `clientSecret` is optional, not at all: a public client sends only
  `client_id` (`oidcToken`'s `buildAuthHeaders`). An XSUAA service key with
  `credential-type: x509` has no secret at all: it carries `certificate`, `key`
  and `certurl`, and the token request must go over mTLS to `certurl`.
  Keycloak accepts the same (`client-x509`), and UAA accepts `private_key_jwt`
  instead. A token provider must be able to authenticate its client either way.
- **B, at the resource — a certificate-bound token.** A token issued over mTLS
  may be bound to the certificate (`cnf.x5t#S256`, RFC 8705 §3): the resource
  server then accepts it only over a TLS connection that presents the same
  certificate. Today `BaseTokenProvider.establish()` presents nothing and
  `authorize()` adds only `Authorization: Bearer`, so a bound token would be
  refused at the resource. Obtaining the token is not enough: the provider
  must also present the certificate on the resource connection.
- **A — the logon to the ABAP system.** `CertificateAuthProvider` presents a
  client certificate in the TLS handshake of each logon. Proven here to the TLS
  level and to an X.509 user mapping in Keycloak; **not** against an ABAP
  system's `CERTRULE`, because none is available to test.

**Success:** an XSUAA x509 service key, a Keycloak `client-x509` client and a
UAA `private_key_jwt` client each yield a token through this package's
providers, with no secret configured; a certificate-bound token is accepted by
a resource that enforces the binding when the provider presents its
certificate, and refused when the certificate is absent or another one — in tests that run against the stand (UAA,
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
3. **What works today keeps working.** A consumer that passes `clientSecret`
   sees no change in what is sent, and a public OIDC client — no
   `clientSecret`, no client authentication — stays a supported composition,
   not an error and not a new mandatory collaborator.
4. **The server certificate is always verified** on every token request,
   whatever the client presents; trusting a private CA is an explicit `ca`.
5. **No key material reaches a log line**, as no token does today.
6. **A bound token travels with its certificate.** A provider that obtains a
   certificate-bound token presents that certificate on every connection the
   token is used on — the resource logon (`establish()` → the logon target's
   TLS material) and every refresh — or the token is not offered at all.
7. **Every supported combination is proven on the stand or the trial.** What
   cannot be measured (ABAP `CERTRULE`, an x509 token accepted by ADT) is
   written down as unproven, not claimed.
8. **Dependencies only from the registry**, contracts only from the contract
   packages this package already uses.

## Out of scope

- An ABAP system's `CERTRULE` / `STRUSTSSO2` configuration, and ADT accepting
  an x509-obtained token — no system to prove it on.
- `mcp-abap-adt` and the other consumers: each adopts this in its own change,
  for the systems it serves.
- Issuing, rotating or storing certificates; loading a service key
  (`@mcp-abap-adt/auth-broker` / `auth-stores`).

## Decided (2026-10-04, before the spec)

1. **The client-authentication contract** is a strategy, `IClientAuthentication`
   (working name), in `@mcp-abap-adt/interfaces-auth` beside
   `IAuthorizationStrategy` — a consumer may write its own (a JWT signed by an
   HSM key), and the broker composes it. It shapes a token request: form
   parameters, headers, TLS material, and the endpoint. This package ships
   four: none (a public client), secret (Basic header or body), certificate
   (mTLS) and `private_key_jwt`.
2. **The endpoint is the strategy's.** A token request goes where the
   strategy says: XSUAA x509 → `certurl`; OIDC → `mtls_endpoint_aliases` from
   discovery when published. The authorization page stays where the
   configuration says.
3. **Every provider that sends a token request** takes an optional
   `clientAuthentication`. Without it the provider does exactly what it does
   today: the secret when given, else a public client. `Saml2PureProvider`
   sends no token request and is not touched.
4. **A bound token is presented by its own provider.** A token provider with
   the certificate strategy presents the same material in `establish()`
   through `logon.tlsMaterial()` — no separate `CertificateAuthProvider` to
   compose, so the consumer cannot pair two different certificates. When the
   logon target refuses TLS material (RFC) and the token is bound
   (`cnf.x5t#S256`), the provider answers Oops; an unbound token goes on.
5. **Version:** auth-providers 5.3.0 (an optional parameter is added);
   `interfaces-auth` a minor (a type is added), released first.
6. **The Keycloak stand:** HTTPS with client-auth `request`; a test CA, a
   server certificate and client certificates as committed fixtures trusted
   by nothing but the stand. The resource that enforces the binding is
   Keycloak's own userinfo endpoint — a third party checks it, not our code;
   measured first, and only if it does not enforce the binding, a minimal
   resource on the stand instead.

## Path

1. This goal → spec → plan, each reviewed in this PR.
2. Implementation in this PR; stand suites (Keycloak mTLS and a bound token
   at a resource enforcing the binding, UAA `private_key_jwt`) in `npm run test:stand`; XSUAA x509 in
   `npm run test:xsuaa` (trial, not in CI).
3. `interfaces-auth` gains `IClientAuthentication` in its own PR and release
   first; this PR builds against the published version, never a link.
4. External review, merge, release; then each consumer decides in its own
   change whether to use it.
