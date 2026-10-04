# Client certificates — design

**Answers:** `docs/superpowers/2026-10-04-client-certificates-goal.md` — its
"Holds throughout" binds every section below; its "Decided" list is not
reopened here.

**Status:** for review. The plan follows only after this is approved.

## 1. The contract — `@mcp-abap-adt/interfaces-auth` (minor)

Types only, released from the interfaces repository before this package
builds against it (goal, Path 3).

```ts
/** What a token request is, before the client is authenticated. */
export interface ITokenRequestDraft {
  /** The token endpoint the provider's configuration names. */
  readonly endpoint: string;
  /** The mTLS alias of that endpoint, when the server published one (RFC 8705 §5). */
  readonly mtlsEndpoint?: string;
  readonly clientId: string;
  /** `client_credentials`, `authorization_code`, `refresh_token`, … — or `device_authorization`. */
  readonly grantType: string;
}

/** How this client authenticates one token request. */
export interface ITokenRequestAuthentication {
  /** Where the request goes instead of `draft.endpoint` (XSUAA `certurl`, an mTLS alias). */
  readonly endpoint?: string;
  /** Form parameters added to the body (`client_id`, `client_secret`, `client_assertion`, …). */
  readonly parameters?: Readonly<Record<string, string>>;
  /** Headers added to the request (`Authorization: Basic …`). */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * How a token provider's client authenticates to the authorization server.
 * Called once per request to the server — the first token, every refresh,
 * the device authorization — never cached by the caller.
 */
export interface IClientAuthentication {
  authenticate(draft: ITokenRequestDraft): Promise<ITokenRequestAuthentication>;
  /**
   * The TLS client material this client presents, when it presents one: in
   * the token request's handshake, and on the resource logon of a token bound
   * to it. Absent for a client that presents none.
   */
  tlsMaterial?(): Promise<ICertificateMaterial>;
}
```

- A return value, not a target: the request is assembled by this package
  alone, and a value is what a test asserts on.
- `ICertificateMaterial` is the existing type; nothing about it changes.
- The draft carries no secret and no previous response, so a strategy cannot
  depend on one.

## 2. The strategies this package ships

All in `src/clientAuthentication/`, exported from the package index. Each is
a factory returning `IClientAuthentication`; none reads the environment, a
file or a service key by itself (rule 7).

| Factory | Sends | `tlsMaterial()` |
|---|---|---|
| `noClientAuthentication()` | `client_id` in the body | — |
| `clientSecretBasic(secret)` | `Authorization: Basic base64(id:secret)` | — |
| `clientSecretPost(secret)` | `client_id`, `client_secret` in the body | — |
| `tlsClientCertificate({ material, endpoint? })` | `client_id` in the body; the request goes to `endpoint`, else `draft.mtlsEndpoint`, else `draft.endpoint` | the material |
| `privateKeyJwt({ key, algorithm, keyId?, audience? })` | `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion` | — |

- **`tlsClientCertificate`** — `material` is an `ICertificateMaterial` or a
  `() => Promise<ICertificateMaterial>` (a loader the consumer owns, e.g. a
  `FileCertificateMaterialLoader` bound to its config). The material is
  checked once, on first use, exactly as `CertificateAuthProvider.prepare()`
  checks it since 5.2.3 — incomplete, then `createSecureContext` — and refused
  in the same fixed words. The check is one shared function, not a copy.
- **`privateKeyJwt`** — signs with `node:crypto`, no new dependency.
  `algorithm` is `RS256` or `ES256`. Claims: `iss` = `sub` = client id,
  `aud` = `audience` else the endpoint the request goes to, `jti` random
  (UUID), `iat` now, `exp` = `iat` + 60 s. `kid` header when `keyId` is given.
  A key that is not a private key of that algorithm is refused on first use in
  fixed words. Measured: UAA v79.7 accepts `aud` = its token endpoint.
- A consumer with an HSM writes its own `IClientAuthentication`; nothing in
  this package assumes one of the five.

## 3. How a provider uses it

Every provider that sends a request to an authorization server takes an
optional `clientAuthentication?: IClientAuthentication` in its configuration:
`ClientCredentialsProvider`, `AuthorizationCodeProvider`,
`UaaPasscodeProvider`, `Saml2BearerProvider`, `OidcBrowserProvider`,
`OidcDeviceFlowProvider`, `OidcPasswordProvider`,
`OidcTokenExchangeProvider`. `Saml2PureProvider` is not touched.

**With it,** every request that provider sends to the server — first token,
refresh, device authorization, device poll, token exchange — is built as:

1. the grant's own parameters (`grant_type`, `code`, `refresh_token`, …);
2. `authenticate(draft)`: its parameters and headers added; its `endpoint`, if
   any, replaces the URL;
3. when `tlsMaterial` exists, the request goes through an `https.Agent`
   built from that material — server verification left as Node does it
   (`rejectUnauthorized` never set; a private CA is
   `NODE_EXTRA_CA_CERTS`, the explicit, process-wide way Node offers).

A constructor given both a strategy and a `clientSecret` is a
`ValidationError` naming `clientSecret` — two ways of authenticating one
client is a mistake, not a preference. Where `clientSecret` is required today
(`ClientCredentialsProvider`, `AuthorizationCodeProvider`), a strategy
satisfies that requirement instead.

**Without it,** each request is sent exactly as today (goal, Holds 3). Today's
shapes differ by site and are kept as they are:

| Site | Today, with a secret | Today, without |
|---|---|---|
| `clientCredentialsAuth` | `client_id` + `client_secret` in the body | (secret required) |
| `tokenRefresher` (UAA refresh) | Basic | (secret required) |
| `browserAuth.exchangeCodeForToken` | Basic | (secret required) |
| `passcodeAuth` | Basic `id:secret` | Basic `id:` (empty secret) |
| `saml2TokenExchange` (exchange, refresh) | `client_id` in body + Basic | `client_id` in body |
| `oidcToken` (code, refresh, poll, password, exchange) | `client_id` in body + Basic | `client_id` in body |
| `oidcToken.initiateDeviceAuthorization` | `client_id` in body, no Basic | same |

These are pinned **before** any site changes: one test per row records the
request a site sends (URL, body, headers) and asserts it unchanged. Internally
each site keeps a private adapter producing that same shape; it is not one of
the public strategies and is not constructed when a strategy is given.

**OIDC discovery** reads `mtls_endpoint_aliases.token_endpoint` and
`…device_authorization_endpoint` into the draft's `mtlsEndpoint`; nothing
else about discovery changes. Measured: Keycloak 26.7 publishes them.

## 4. A bound token at the resource

**One certificate per provider, pinned.** A provider calls
`strategy.tlsMaterial()` **once** — before its first request to the server or
its first logon, whichever comes first — checks the material (§2), computes
the SHA-256 thumbprint of its leaf certificate (`x5t#S256`, base64url, over
the DER), and keeps both for its lifetime. Every later token request, refresh
and resource logon uses that pinned material; `tlsMaterial()` is never called
again. A certificate that rotates means a new provider instance — the
consumer (or the broker) constructs it, as for any other credential change.
This holds whatever the strategy is, the consumer's own included, so a
strategy that would answer A, then B cannot split a token from its logon
(RFC 8705 §3). `tlsClientCertificate` also reads its material once, but the
guarantee is the provider's, not the strategy's.

Measured 2026-10-04: the thumbprint of the leaf certificate equals the
`cnf.x5t#S256` Keycloak 26.7 put in the token; from a PFX it is read through a
`TLSSocket` over the material's secure context and equals the PEM one.

**The binding check, in every branch.** Before the provider presents or sends
a token — `establish()` and `authorize()` — it reads the token's binding:
`cnf["x5t#S256"]` from a JWT payload; an opaque token, or a JWT without
`cnf`, is unbound. This covers a token the provider obtained and a token it
was seeded with (`accessToken` in the configuration, or one restored by a
store).

| Token | Pinned material | `establish(logon)` | `authorize(request)` |
|---|---|---|---|
| unbound | none | nothing presented, Ok | Bearer, Ok |
| unbound | yes | `logon.tlsMaterial(pinned)`: Ok → Ok; Oops → Ok (the Bearer carries it) | Bearer, Ok |
| bound | equal thumbprint | `logon.tlsMaterial(pinned)`: Ok → Ok; Oops (RFC) → that Oops (rule 4) | Bearer, Ok |
| bound | none, or another thumbprint | Oops, nothing presented | Oops, no header written |

The refusal for the last row is fixed words: `'the token is bound to a
client certificate this provider does not present'`, hint `'configure the
certificate the token was issued for, or obtain a new token'`. No thumbprint
appears in it. A renewal in `rejected()` goes through the same strategy and
the same pinned material, so a refreshed token is bound to the same
certificate — and the check above runs on it like on any other.

`authorize()` otherwise stays as it is: it adds the Bearer header.

## 5. Refusals and logs

- A strategy that throws is caught by the existing `safely` boundary of the
  provider method that called it. New fixed refusals, chosen by class:
  - material unusable or incomplete — the existing
    `'the client certificate could not be used'` /
    `'the client certificate is incomplete'` (same wording, same function);
  - signing key unusable — `'the client signing key could not be used'`,
    hint `'check the private key and that it matches the algorithm'`.
  The error classes go on the `instanceof` allowlist in `refusal.ts`; no
  message, key, passphrase or certificate content reaches a refusal (rule 2).
- `describeOAuthErrorBody` gets `client_assertion` and `client_secret` from
  the authentication added to its redaction list; a JWT-shaped value is
  already redacted. No key material is ever passed to a logger
  (`noTokensInLogs.test.ts` extended to the new strategies).

## 6. The certificate logon (goal, part A)

`CertificateAuthProvider` is unchanged. Its stand proof: Keycloak's direct
grant with the X.509 authenticator maps the presented certificate's CN to a
user (the `CERTRULE` analogue). The test takes the material
`CertificateAuthProvider.establish()` hands a recording logon target and
presents it on a Node `https` request — accepted for a mapped certificate,
refused for an unmapped one and for none. ABAP `CERTRULE` stays unproven and
`docs/btp-setup.md` says so.

## 7. The stand

- **Keycloak** keeps its HTTP port and gains HTTPS
  (`KEYCLOAK_HTTPS_PORT`, default 8444, loopback only) with
  `KC_HTTPS_CLIENT_AUTH=request` and `KC_TRUSTSTORE_PATHS`.
- **Fixtures** in `tests/stand/keycloak/tls/`: a test CA, a server certificate
  for `localhost`/`127.0.0.1`, client certificates `client-a` (mapped) and
  `client-b` (not mapped), a signing key pair for `private_key_jwt`. Trusted by
  nothing but the stand; committed, with a README saying so and how they were
  made; `.gitignore` names each key file as an exception.
- **Realm `test`** gains: `mtls` (`client-x509`, subject DN of `client-a`,
  bound tokens on, direct grant on for a refresh token), `jwt`
  (`client-jwt`, the committed public key), and the X.509 direct-grant flow for
  part A.
- **UAA** gains a `private_key_jwt` client with the committed public key as
  `jwks`.
- `run.sh` exports `NODE_EXTRA_CA_CERTS` to the stand CA for the suites.

**Measured 2026-10-04 on Keycloak 26.7.4** (a probe container, not the stand
yet): a `client-x509` client with bound tokens gets a token carrying
`cnf.x5t#S256`; userinfo answers 200 with the same certificate, 401 with none,
401 with another; the token endpoint answers 401 to another certificate and
to none.

## 8. Tests

| Where | What it proves |
|---|---|
| unit, per site | without a strategy the request is byte-for-byte today's (§3 table) |
| unit, per strategy | what each sends; `tlsClientCertificate` endpoint order; `privateKeyJwt` claims and signature verify with the public key; unusable material/key → the fixed refusal, nothing secret in it |
| unit, providers | a strategy reaches every request of each provider, refresh included; `clientSecret` + strategy is a `ValidationError` |
| unit, `establish()` / `authorize()` | every row of §4's table, a seeded bound `accessToken` without a strategy and with a different certificate included; a strategy answering A then B is called once and the provider keeps presenting A |
| stand, Keycloak | `ClientCredentialsProvider` + `tlsClientCertificate` → bound token; userinfo with the material from `establish()` → 200, none → 401, `client-b` → 401; token request with `client-b` → refused; `OidcPasswordProvider` + mTLS → refresh stays bound; `privateKeyJwt` → token |
| stand, UAA | `ClientCredentialsProvider` + `privateKeyJwt` → token |
| stand, part A | §6 |
| trial, XSUAA (`test:xsuaa`, not CI) | an x509 key (`setup.sh` creates the instance with `credential-types: ["x509"]` and the key with `credential-type: x509`) → `ClientCredentialsProvider` + `tlsClientCertificate({ endpoint: certurl })` → token, no secret anywhere |

Every new rule gets the load-bearing check: break it, watch its own test go
red, revert.

## 9. Documentation

README (a "Client authentication" section: the five strategies, composing a
bound token, the XSUAA x509 recipe as fields mapped by the consumer),
`docs/btp-setup.md` (x509 per provider, tagged Measured/SAP/Inference
honestly; ADT accepting such a token stays Inference), `CLAUDE.md` (the new
directory, rule 7's list of collaborators), `CHANGELOG.md` 5.3.0.

## 10. Not in this change

Service-key parsing (the broker maps `certificate`/`key`/`certurl`); a
per-provider `ca` option; `tls_client_auth` on UAA (it has none);
`mcp-abap-adt` and other consumers.
