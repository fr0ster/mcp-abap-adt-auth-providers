# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@mcp-abap-adt/auth-providers` — a TypeScript npm package providing every implementation of `IAuthProvider` (from `@mcp-abap-adt/interfaces-auth`) for SAP ABAP ADT: the credential a process delegates to, and the token providers behind it. Any provider from this package can be handed to the process with no check of what it is; each answers all four moments of the contract:

```ts
prepare(): Promise<AuthOutcome>;                          // once per connect
establish(logon: ILogonTarget): Promise<AuthOutcome>;      // every logon
authorize(request: IRequestTarget): Promise<AuthOutcome>;  // every request attempt
rejected(rejection: IAuthRejection): Promise<AuthOutcome>; // the system said no
```

`AuthOutcome` is `{ ok: true }` or `{ ok: false, refusal: { reason, hint? } }`.

**Non-token credentials** — one way in, nothing to refresh:
- **`BasicAuthProvider`** — a user and a password: a header over HTTP, logon parameters over RFC
- **`CertificateAuthProvider`** — a client certificate presented in the TLS handshake of each logon
- **`SamlAuthProvider`** — a SAML session negotiated elsewhere, handed over as cookies
- **`TokenAuthProvider`** — a token from outside this package: `.fixed(token)` or `.from(refresher)`
- **`SncLogonProvider`** — passwordless RFC logon through an installed SNC product (Secure Login Client); see `docs/passwordless-sso.md`

**Token providers** — `BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider`, so each is both an `IAuthProvider` and the stateful token contract the broker's `getTokens()` / `refreshTokens()` still use, with no wrapper:
- **`ClientCredentialsProvider`** — `client_credentials`, no user interaction
- **`AuthorizationCodeProvider`** — UAA authorization code, interactive
- **`OidcBrowserProvider`** — OIDC authorization code with PKCE, interactive
- **`OidcDeviceFlowProvider`**, **`OidcPasswordProvider`**, **`OidcTokenExchangeProvider`**
- **`Saml2BearerProvider`** — SAML assertion exchanged for an OAuth2 token
- **`Saml2PureProvider`** — SAML assertion exchanged for session cookies (its `applyToken` override writes cookies, not a header)
- **`UaaPasscodeProvider`** — UAA/XSUAA one-time passcode from `/passcode` (`cf login --sso`), headless

`docs/btp-setup.md` maps each token provider to what it needs on the SAP side (XSUAA client, trust, user, ABAP mapping) and whether ADT accepts its token; every claim is tagged SAP, Community, Measured, Inference or Pending (a check written but not yet run against the real system). Keep the tags honest when changing it; flip a Pending to Measured, with the date, only after the run.
`docs/passwordless-sso.md` covers passwordless logon: SNC over RFC — `SncLogonProvider`, built and measured against a live system — and the HTTP alternatives (X.509 client certificates, SPNego, IAS), still undecided.

Both SAML providers validate the assertion first, through an `IAssertionValidator` (see "SAML assertion validation").

Every token provider that sends a request to an authorization server — all but `Saml2PureProvider` — takes an optional `clientAuthentication: IClientAuthentication`: how its *client* authenticates every request it sends (first token, refresh, device authorization and poll, token exchange). See "Client authentication".

### Rules every provider follows

1. **No exception crosses the contract.** Each of the four methods catches everything its body throws — its own work, a collaborator, and a target (`header`, `cookies`, `logonParameters`, `tlsMaterial` may throw) — and answers Oops. Every method body runs inside one `safely(…)` boundary (`src/auth/refusal.ts`).
2. **A refusal carries no secret — so it never carries an error's message.** It is built only from fixed wording chosen per error class, plus metadata only when its value is on an allowlist this package owns: config field names (`KNOWN_CONFIG_FIELDS`), an `AssertionValidationError`'s `check` (`AssertionCheck` values only), a fixed set of system error codes, a fixed set of RFC SDK keys (SNC), or a class label decided by `instanceof` against this package's own constructors — else "unknown error". No `message`, `cause` or body of any error reaches a refusal, and a `name` property is never read.
3. **Nothing to add is Ok.** A provider with nothing for a moment writes to no target and answers Ok.
4. **A target's Oops is the provider's to judge.** A provider with no other way in (SNC, certificate) returns the target's Oops as its own; one that has another (a password is also a header) goes on.
5. **`rejected()` blames the credential only when it was refused.** A `401` or `RFC_LOGON_FAILURE` is the credential; a `403`, a redirect, a `5xx`, any other status or RFC key gets the neutral words of `readRejection` (`src/auth/rejection.ts`) and no renewal; a rejection with neither is `unknown` — a renewer renews once, a fixed credential answers neutrally. SNC explains a GSS code in the error before any of that.
6. **`rejected()` decides alone; retrying is the consumer's.** One renewal is at most one refresh, then — only if the refresh is refused or there is no refresh token — one login through the strategy the consumer gave the provider. No step runs twice. A provider never answers Ok without having changed what it presents: a renewal that yields the same credential is Oops "the renewal returned the credential that was refused".
7. **No implicit defaults — the consumer composes.** A constructor takes every collaborator explicitly (the interactive strategy, the client-authentication strategy, the device-code presenter, the SAML validator and replay store, the SNC locator and probes); no provider builds one of its own when none is given. Static factories (`inBrowser`, `fromTerminal`, `toConsole`, `fromFiles`, `forSecureLoginClient`) assemble a named, common recipe — the consumer, or the broker, still creates the instance from a constructor or a factory.
8. **A bound token travels with its certificate.** A token provider pins its strategy's TLS material once — `tlsMaterial()` read before its first request or logon, checked, its leaf's `x5t#S256` computed, a copy kept for the provider's lifetime (the logon target gets a copy of it each time); a rotated certificate is a new provider. Its leaf's `notAfter` is checked at pin time and before every token request and logon that presents it — "the client certificate has expired", nothing sent, a renewal refused whole. Before presenting a token, `establish()` and `authorize()` read its binding (`readBinding`, `src/auth/tokenBinding.ts`): **bound** (a JWT with `cnf`) is presented only with the pinned certificate of that thumbprint, else Oops "the token is bound to a client certificate this provider does not present" and nothing written; **unbound** (a JWT without `cnf`) goes as a Bearer; **unknown** (anything else, an opaque token above all) is treated as bound when a certificate is pinned and goes as a Bearer when none is. `establish()` decides on the token held and obtains nothing — none, expired or being renewed is unknown. **A held token bound to another thumbprint than the pinned one** (or with an unreadable `cnf`) is unusable, like an expired one: `getTokens()` / `authorize()` renew it once (rule 6's order) and check the new token — still bound elsewhere is Oops "the new token is bound to …" in `authorize()` and remembered with the refusal its renewal produced (`remembered: { token, refusal }`: not renewed again — `getTokens()` returns it, `authorize()` answers that refusal — until the token changes, `prepare()`, or `rejected()` for that token held, whose renewal's refusal then replaces it; a superseded refused token gets Ok without a renewal, rule 6); a renewal that throws while such a token is held is remembered the same way with its own refusal (`renew()` decides, so getTokens, prepare and rejected alike), e.g. "the client certificate has expired" stays visible, with no token request and no login. An expired token bound to the pinned one (or unbound) is never remembered: each attempt renews it, as before; `establish()` reads it as unknown. With nothing pinned a bound token is refused in `establish()` / `authorize()`, and `getTokens()` returns it. Only `establish()` / `authorize()` present the certificate; a consumer of `getTokens()` / `refreshTokens()` must present it itself.

### New directories

- `src/credentials/` — `BasicAuthProvider`, `CertificateAuthProvider`, `FileCertificateMaterialLoader`, `SamlAuthProvider`, `TokenAuthProvider`
- `src/deviceCode/` — `IDeviceCodePresenter`, `DeviceCodePrompt`, `consoleDeviceCodePresenter`: how `OidcDeviceFlowProvider` shows the user where to go and what to enter, injected like a strategy instead of writing to the logger itself
- `src/snc/` — `SncLogonProvider` and its collaborators: `DefaultSncLibraryLocator`, `SecureLoginClientProbe`, `nodeSncSystem` (the machine seam — env, file heads, registry, behind one injectable interface), the PE/Mach-O/ELF architecture reader, the refusal mapping (`sncRefusal`). A product probe only names the product behind the library, for the `rejected()` hint — it checks nothing, because the SNC library starts the Secure Login Client on demand (measured), so `prepare()` is Ok with the client not running. An unusable library is refused naming each candidate's source, path and fixed reason
- `src/auth/refusal.ts` — `OK`, `oops`, `refusalFrom`, `safely` — the one place a thrown value becomes a refusal (rules 1 and 2), and the allowlists
- `src/auth/rejection.ts` — `readRejection`, `refuseFor`, `unknownRefusal` — what a rejection says about the credential (rule 5)
- `src/clientAuthentication/` — the five shipped `IClientAuthentication` factories: `noClientAuthentication`, `clientSecretBasic` (required `encoding: 'raw' | 'form'`, no default — XSUAA accepts only raw, UAA and Keycloak need form for reserved characters; raw refuses a client id with `:`, `BasicClientIdError`) / `clientSecretPost` (`clientSecret.ts`), `tlsClientCertificate` (material or a loader, read and checked once; a failed load is retried), `privateKeyJwt` (RS256 / ES256 through `node:crypto`, 60 s assertion, `aud` = `audience`, else the draft's `tokenEndpoint` — every draft this package builds carries the plain token endpoint, the device initiation's included, never the mTLS alias — else the request's endpoint). None reads the environment, a file or a service key

## Build Commands

```bash
npm run build        # Full clean build (rm dist + tsc)
npm run build:fast   # Fast incremental build
npm run test:check   # TypeScript type checking only
npm run lint:check   # Biome, read-only
npm run lint         # Biome with --write
npm test             # Run all tests (uses --experimental-vm-modules)
```

To run a single test file, or one case:

```bash
npm test -- src/__tests__/auth/callbackServer.test.ts
npm test -- src/__tests__/auth/callbackServer.test.ts -t "name of the case"
```

Never invoke `npx jest` directly — the npm script supplies `--experimental-vm-modules`, without which the suite fails to load.

Debug logging: `DEBUG_AUTH_PROVIDERS=true` or `DEBUG_BROWSER_AUTH=true`.

## Architecture

### Core design principles

**Interface-only communication.** All interaction with external dependencies happens through contract packages: `@mcp-abap-adt/interfaces-auth` (token providers, `IAuthProvider`, strategies, `IClientAuthentication`, `ICertificateMaterial`, callback server, assertion validator and replay store, error codes), `@mcp-abap-adt/interfaces-auth-sap` (XSUAA configuration, `ICertificateMaterialLoader`) and `@mcp-abap-adt/interfaces-utils` (`ILogger`). Depend on the contract package whose contracts are used, nothing wider — never `interfaces-adt`, which carries ADT contracts this package does not use. The package does not know about concrete implementation classes from other packages. A logger is `ILogger`, never a local abstraction. This file does not track version numbers — they lag behind: see `package.json` for the versions in use, and `CHANGELOG.md` for when and why they changed.

**Everything pluggable is a strategy.** Anything a consumer might reasonably want to do differently is expressed as a strategy behind an interface. The package ships the parts and named factories; the consumer composes. This is why an authorization library does not own a socket, a browser or stdin — a consumer may legitimately own them instead.

**No token the provider holds reaches a log line**, and no key material either. `BaseTokenProvider.formatToken` is the one way a token appears in a log, and it yields only `<redacted, N chars>`, never a character of the secret (`noTokensInLogs.test.ts`, which also covers the client-authentication strategies). A token endpoint's error body contributes only `error` and `error_description`, through `describeOAuthErrorBody`. It redacts every secret the request sent and anything JWT-shaped (`oauthErrorBodies.test.ts`). A new opaque token that a server invents cannot be recognised there; that limit is documented, not hidden.

**Nothing writes to `process.stdout`.** Under an MCP or LSP stdio transport, stdout carries protocol traffic, and a stray line corrupts it. Prompts go to the `ILogger` when there is one and to `process.stderr` when there is not — see `src/auth/announce.ts`. A prompt that vanishes without a logger is also a bug: a user who cannot see a device code cannot finish the flow.

### Package responsibilities

This package ONLY:
- implements `IAuthProvider` — every credential a process delegates to — and, for the token providers, `IRefreshableTokenProvider` beside it
- builds authorization URLs and exchanges codes, assertions and refresh tokens for tokens
- ships strategies, validators and named static factories for conducting an interactive authorization or assembling a common recipe
- validates SAML assertions, with two shipped validators and an in-memory replay store, all replaceable
- resolves the SNC library for a passwordless RFC logon (`SncLogonProvider`), producing logon parameters only

This package does NOT:
- store tokens (`@mcp-abap-adt/auth-stores`)
- orchestrate authentication (`@mcp-abap-adt/auth-broker`)
- load service keys or manage sessions
- decide how a user reaches an authorization URL, or where the redirect is received — the consumer may replace both
- fetch identity provider metadata — certificates and entity IDs come from configuration
- open a connection or speak RFC/HTTP itself — `SncLogonProvider` depends on neither `@mcp-abap-adt/sap-rfc-lite` nor `@mcp-abap-adt/connection`

### Module structure

```
src/
├── index.ts                  # public surface: providers, credentials, strategies, callback factories, validators, errors
├── credentials/               # every non-token IAuthProvider
│   ├── BasicAuthProvider.ts
│   ├── CertificateAuthProvider.ts
│   ├── FileCertificateMaterialLoader.ts  # PEM pair or PFX from files
│   ├── SamlAuthProvider.ts
│   └── TokenAuthProvider.ts   # .fixed(token) / .from(refresher)
├── snc/                       # SncLogonProvider — passwordless RFC logon
│   ├── SncLogonProvider.ts
│   ├── DefaultSncLibraryLocator.ts   # explicit sncLib, or SNC_LIB_64/SNC_LIB/registry/app-bundle in order
│   ├── SecureLoginClientProbe.ts     # names the Secure Login Client when the library is inside its install path; checks nothing
│   ├── SncSystem.ts           # the machine seam: env, file heads, registry (reg.exe by absolute path, 5 s timeout) — nodeSncSystem()
│   ├── libraryArchitectures.ts  # PE / Mach-O (thin + FAT/FAT_64) / ELF header reader
│   └── sncRefusal.ts          # the three GSS error shapes, and an unusable library, → a fixed refusal
├── deviceCode/
│   └── DeviceCodePresenter.ts  # IDeviceCodePresenter, DeviceCodePrompt, consoleDeviceCodePresenter
├── providers/                 # one file per grant type, all extending BaseTokenProvider
├── strategies/
│   ├── BrowserCallbackStrategy.ts  # class + browser/oidc/saml constructors
│   ├── manualStrategies.ts         # paste a code, paste a SAMLResponse, paste a passcode — timeoutMs, dispose()
│   ├── codeStrategies.ts           # external (needs the URL) and static (does not)
│   └── asOidcResult.ts             # string payload → OidcCallbackResult
├── auth/
│   ├── refusal.ts             # OK, oops, refusalFrom, safely — where every thrown value becomes a refusal
│   ├── rejection.ts           # readRejection: is this rejection the credential's?
│   ├── callbackServer.ts     # runCallbackScope: one owner, one release point
│   ├── announce.ts           # logger-or-stderr, never stdout
│   ├── browserAuth.ts        # UAA URL building, code exchange, browser launch
│   ├── oidcBrowserAuth.ts    # OIDC callback factory
│   ├── saml2Auth.ts          # SAML callback factory, AuthnRequest building
│   ├── samlBearerAssertion.ts  # SAMLResponse → one base64url Assertion (RFC 7522)
│   ├── tokenRequest.ts       # prepareTokenRequest / sendTokenRequest: the one strategy path; errors without the request
│   ├── certificateMaterial.ts  # assertCertificateMaterial / checkCertificateMaterial (shared with CertificateAuthProvider), certificateThumbprint
│   ├── tokenBinding.ts       # readBinding: bound / unbound / unknown
│   ├── oauthErrorBody.ts     # describeOAuthErrorBody, oauthErrorFields: redaction longest first, JWT-shaped values; a registered OAuth `error` code kept verbatim
│   └── …                     # oidcToken, oidcDiscovery (mtlsAlias), oidcPkce, passcodeAuth, …
├── validation/
│   ├── assertionValidator.ts   # createSignedResponseValidator / createSignedAssertionValidator: the check table
│   ├── signedNode.ts           # verify every signature, resolve the element each covers
│   ├── documentIds.ts          # duplicate-ID refusal, required IDs
│   ├── xsdDateTime.ts          # strict xsd:dateTime parsing
│   └── inMemoryReplayStore.ts  # createInMemoryReplayStore, the process-wide defaultReplayStore
├── clientAuthentication/      # IClientAuthentication factories — the consumer composes one into a token provider
│   ├── index.ts
│   ├── noClientAuthentication.ts  # client_id in the body: a public client
│   ├── clientSecret.ts            # clientSecretBasic (encoding raw | form), clientSecretPost
│   ├── tlsClientCertificate.ts    # tls_client_auth: endpoint, else the mTLS alias, else the draft's; tlsMaterial()
│   └── privateKeyJwt.ts           # a signed client assertion; ClientAuthenticationError for an unusable key
├── sso/                      # SsoProviderFactory
└── errors/
    ├── TokenProviderErrors.ts
    ├── AssertionValidationError.ts  # carries `check: AssertionCheck`
    ├── CertificateMaterialError.ts  # carries `incomplete`, `expired`; CERTIFICATE_INCOMPLETE / CERTIFICATE_UNUSABLE / CERTIFICATE_EXPIRED words
    └── ClientAuthenticationError.ts # ClientAuthenticationError (signing key), ClientAuthenticationResultError (a result that cannot be sent), BasicClientIdError (raw Basic, an id with ':')
```

### How an interactive login works

A provider owns what it can compute: the authorization URL and the token exchange. Everything between them belongs to an `IAuthorizationStrategy`:

1. the provider hands the strategy an `AuthorizationRequest` carrying `buildAuthorizationUrl(redirectUri)`;
2. the strategy decides where the redirect will be received, then asks for the URL — that ordering is what makes an ephemeral port possible, since the URL cannot be assembled before the socket is bound;
3. the strategy returns an `AuthorizationOutcome` carrying the payload **and** the redirect URI that actually took part, because the token exchange must send the same one.

Ship-default strategies: `browserCallbackStrategy`, `oidcCallbackStrategy`, `samlCallbackStrategy`, `manualPasteStrategy`, `manualSamlResponseStrategy`, `externalCodeStrategy`, `staticCodeStrategy`.

**Lifecycle: whoever constructs, disposes.** A consumer-supplied strategy is never disposed by a provider — the point of a long-lived receiver is to outlive one login. A default the provider constructed itself is disposed from a `finally`, and a `dispose` failure is logged rather than allowed to replace the error that made the login fail. `dispose()` disables a strategy permanently, which is why providers construct a fresh default per login.

### Client authentication

`IClientAuthentication.authenticate(draft)` — the draft carries the endpoint, the server's mTLS alias (`mtlsAlias`, from discovery of an endpoint not given in configuration), the client id and the grant type, never a secret or a previous response — returns `{ endpoint?, parameters?, headers? }`; `tlsMaterial?()` the certificate it presents.

- **One path with a strategy, today's request without one.** Every site that sends to an authorization server (client credentials, UAA refresh, code exchange, passcode, SAML exchange and refresh, every OIDC request, device initiation included) takes an optional `TokenRequestAuth`. With it, `prepareTokenRequest` (`src/auth/tokenRequest.ts`) builds the grant's own parameters plus the strategy's, checks the result before anything is sent — strings only, no line break in a header, nothing replacing the site's own parameters or headers, an absolute `https:` endpoint (`http:` only when the configured one is `http:` and there is no material), else `ClientAuthenticationResultError` — sends through an `https.Agent` built from exactly the four material fields (`rejectUnauthorized` never set; a private CA is `NODE_EXTRA_CA_CERTS`; no `ca` option), with `maxRedirects: 0`. Without it, each site's private adapter sends exactly the pre-strategy request, also with `maxRedirects: 0`; `tokenRequestShapes.test.ts` pins every site's shape, and `tokenRequestRedirect.test.ts` proves on real sockets that no site, on either path, follows a 307. OIDC discovery is the one request that follows redirects: a GET for public metadata, no secret.
- **Errors carry no request, on both paths.** `sendTokenRequest` rethrows a failure as a new `AxiosError` (`instanceof` and `axios.isAxiosError` hold) built without `config`, `request`, `cause` or `response.config` (agent with key/PFX/passphrase, form body, `Authorization`) — so its `toJSON()` serialises no config — keeping `message`, `code`, `status` and a response of `status`, `statusText`, empty `headers` and the body reduced to `error` / `error_description` / `error_uri` (`oauthErrorFields`). A test that automocks axios keeps its real `AxiosError` (`jest.createMockFromModule` plus `jest.requireActual(…).AxiosError`), or the rethrown error is an empty mock. Redaction covers the site's own secrets (`grantSecrets`: refresh token, code, verifier, assertion, passcode, password, device code, subject/actor token; and the configured `clientSecret`, which each site passes beside `grantSecrets(…)`) and the strategy's (`client_secret`, `client_assertion`, a Basic credential — its base64, its secret as sent and that secret form-decoded, so `clientSecretBasic`'s original and encoded secret alike), longest first; a custom strategy's secret in another parameter or header is not recognised — a documented limit. A TLS failure on the allowlist (`tlsFailureCode`) passes unwrapped and is refused naming its code, in words fixed per kind: untrusted server certificate → `NODE_EXTRA_CA_CERTS`; `CERT_HAS_EXPIRED` and `ERR_TLS_CERT_ALTNAME_INVALID` their own; a server's alert refusing the client certificate (both OpenSSL spellings, `SSL/TLS_ALERT_…` and `SSLV3_ALERT_…`) → "the server refused the client certificate".
- **`clientSecret` beside a strategy is a `ValidationError`** naming `clientSecret`, decided in the `BaseTokenProvider` constructor on presence (`!== undefined`), so `''` counts. Where `clientSecret` was required (`ClientCredentialsProvider`, `AuthorizationCodeProvider`), a strategy satisfies it.
- **Pinning** (`BaseTokenProvider.pin`): once per lifetime, concurrent first needs share one attempt, a failed read pins nothing and the next moment reads again; `renew()` pins before anything is sent, so unusable material refuses the renewal whole. The material is copied (Buffers too) so a strategy changing its object later changes nothing.
- **What a strategy or loader throws** goes through `refusalFrom`: `CertificateMaterialError` and `ClientAuthenticationError` / `ClientAuthenticationResultError` / `BasicClientIdError` get their fixed words; any other error (a loader's `ENOENT`) is "`<auth type>` token request failed (unknown error, CODE)" (`getAuthType()`) — by design (rule 2).
- **The opaque-token limit.** A provider learns a binding only from the token; it does not introspect. An opaque token bound to a certificate needs the certificate strategy configured, or it goes as a plain Bearer and is refused `401` by the resource.

### SAML assertion validation

A SAML provider validates the payload before anything else uses it — `Saml2BearerProvider` before the token exchange, `Saml2PureProvider` before `cookieProvider`, whose `expiresAt` comes from the result. The validator is built in the constructor: without `assertionValidator`, missing `idpCertificates` or `idpEntityId` is a `ValidationError` there — and so is a missing `idpEntityId` beside a shipped validator supplied as `assertionValidator`, recognised by a module-private, non-enumerable symbol both factories set. A custom validator needs no `idpEntityId`.

- **Two validators, chosen by identifier, not by option.** `createSignedResponseValidator` requires the `Response` signed and runs all twelve checks — `Saml2PureProvider`'s default. `createSignedAssertionValidator` requires the `Assertion` signed, accepts a bare one, and does not read `Status`, `Response/Issuer` or `Destination` — `Saml2BearerProvider`'s default, since the token endpoint gets the Assertion alone.
- **Everything is read from the signed element.** Every signature must verify and envelope its target; every SAML 2.0 `Assertion`/`EncryptedAssertion` and every SAML 1.x `Assertion` must be the signed one or inside it — and never inside a `ds:Signature`, whose subtree an enveloped signature leaves unsigned; IDs must be unique. The assertion-only validator reads the bare root `Assertion` or the Response's direct-child one, never merely the first covered. Every required field is refused when absent; of the fields the validators read, only `NotBefore` (Conditions and bearer confirmation), `Response/Issuer` and `NameID` may be missing (`nameId` is `undefined` when the `Subject` carries none or more than one). A `<!DOCTYPE` is refused before parsing; XML is parsed with `parseStrictXml` (`src/auth/strictXml.ts`), which throws on every parser fault and never writes to the console; `KeyInfo` certificates are never used; SHA-1 is accepted (xml-crypto defaults).
- **The request ID is minted, declared (`authnRequestId`) or declared absent (`idpInitiated: true`)** — never inferred. Neither is a `ValidationError` raised after the strategy returns; `idpInitiated` with a declared ID is one raised at construction (`validateSamlConfig`); `idpInitiated` without `authorizationUrl` makes `buildAuthorizationUrl` throw before any URL exists. UAA and XSUAA refuse `InResponseTo` on the saml2-bearer grant, so bearer against them needs `idpInitiated`.
- **Shipped validators fail closed without `expectedIssuer`.** Providers always pass `idpEntityId`.
- **Every refusal names its rule.** No two rules under one `check` share a message, and every test asserts the fragment only its rule produces. An element that must appear exactly once distinguishes absent from more than one (`requireOne`). `bearerConfirmation` is existential and lists each candidate's first failed sub-rule in a fixed order (`readConfirmation`), capped at five (`describeRefusals`). Every document value in a message goes through `quoteUntrusted`, xml-crypto's own `loadSignature` messages and `toBearerAssertion`'s parser message included. The Response's direct-child `Assertion` is counted before placement; once placement pins the signed element to the one required, no further identity check can fire, so there is none — the wrapping attacks are refused by count or placement, each with a test through `validate()`. Nothing is exported for tests. The README's "Refusal messages" table lists every message the shipped validators produce; change it with the code.
- **Replay store is process-wide** (`defaultReplayStore`), keyed `{issuer, assertionId}`, retained to min(`Conditions/@NotOnOrAfter`, the latest bearer `NotOnOrAfter` that answers the request and names the ACS, one not yet open included) + `clockSkewMs` — not `expiresAt`, which takes the earliest. `clockSkewMs` defaults to 0.

### Callback server

`runCallbackScope` owns the socket for the duration of one scope. It is released on the first terminal outcome — the body returning or throwing, an explicit failure, the timeout, or an abort — and the factory settles only once the port is actually free, so a settled promise always means the socket is gone.

- `port: 0` binds an ephemeral port; `handle.port` and `handle.redirectUri` report what the OS gave. Not usable where the redirect is registered with the identity provider, as a SAML ACS always is.
- The default port is **61001** — above Linux's `ip_local_port_range` (32768–60999) and clear of the 3001/3333 range application servers use. The default login timeout is 30 s.
- A `/callback` carrying neither a payload nor an explicit error is answered `400`, counted, and **ignored** — the login keeps waiting, bounded by the timeout, whose message reports how many such requests arrived. An explicit `error=` from the provider still ends the login at once.

## Testing

**Unit tests** mock axios or the module boundary. **Integration tests** need `tests/test-config.yaml` (copy `tests/test-config.yaml.template`) and skip without it. **A default run opens no browser:** the browser-login cases in `AuthorizationCodeProvider.test.ts` and `browserAuth.integration.test.ts` run only with `interactive_login: true` in the config or `MCP_ABAP_ADT_INTERACTIVE=1`. The no-browser cases take tokens from a session file, and the first rule that applies wins: `MCP_ABAP_ADT_SESSION_FILE`, then `session_path` (any path), then `<destination_dir>/sessions/<destination>.env`, where `destination_dir` defaults to `~/.config/mcp-abap-adt` on Unix and `Documents/mcp-abap-adt` on Windows (`resolveSessionFile`). They copy it to a temporary directory and never write the original. The build uses `tsconfig.build.json`, which leaves `src/__tests__` out of `dist`; `test:check` still type-checks it. `src/__tests__/integration/samlValidation.test.ts` needs nothing: it runs both assertion validators end to end through `Saml2PureProvider` against `@mcp-abap-adt/auth-mocks`, inside `npm test`. It starts one mock IdP per `signWhat` in `beforeAll` — each start generates an RSA key — and a test picks its variant with `standFor`, which calls `setVariant`; every test gets its own replay store.

**The provider stand** (`tests/stand/`; `npm run test:stand` starts it, runs the suites and stops it, and CI runs the same as its own job) runs Cloud Foundry UAA and Keycloak in Docker: real token endpoints for every provider but `Saml2PureProvider`'s cookie half. UAA carries a SAML identity provider whose key the tests sign with; Keycloak imports the `test` realm from `tests/stand/keycloak/realm-test.json`, and is also the SAML identity provider for both SAML providers: the Keycloak→UAA suite registers Keycloak in UAA and sets Keycloak's IdP-initiated SSO at run time. `keycloakSaml.test.ts` trusts only the certificates under `KeyDescriptor use="signing"` in Keycloak's metadata (`signingCertificates`). UAA's saml2-bearer grant refuses any assertion carrying `InResponseTo`, so only an IdP-initiated assertion gets through — an SP-initiated one never will, whatever the provider does. Both servers' configuration, and the test IdP's key, are committed fixtures — not secrets, trusted by nothing but the local stand — so a clone needs only Docker. The UAA suite takes the issuer from UAA's discovery and the bearer Recipient from its SAML metadata, never from `UAA_URL`, which is what keeps `UAA_PORT` working with a committed configuration. `src/__tests__/integration/stand/formLogin.ts` plays the user on each server's login and consent pages. It needs no SAP system, so it is the place to prove anything about a provider's wire contract. The suites run only when `UAA_URL` / `KEYCLOAK_URL` / `KEYCLOAK_HTTPS_URL` are set; `test:stand` sets all three. A server already running — from `npm run stand:up` or started by hand — is left running; `run.sh` removes only the servers it started itself, per service.

Keycloak also serves HTTPS on loopback (`KEYCLOAK_HTTPS_PORT`, default 8444; `KEYCLOAK_HTTPS_URL`) with `KC_HTTPS_CLIENT_AUTH=request` — a request with no certificate or another one reaches Keycloak and is refused by the rule under test, not by the handshake — and `KC_TRUSTSTORE_PATHS` the stand CA. The TLS fixtures live in `tests/stand/keycloak/tls/` (CA whose key was deleted, server certificate, `client-a` mapped, `client-b` mapped to nothing, the `jwt` signing pair), regenerated by `generate.sh`, after which the public half's copies in `realm-test.json` and `uaa.yml` must be updated; `.gitignore` names each key file as an exception. `run.sh` exports `NODE_EXTRA_CA_CERTS` to that CA for the suites — no provider is given a `ca`; `up.sh` prints the variables for a run by hand. Clients: Keycloak `mtls` (`client-x509`, subject DN of `client-a`, bound tokens, direct grant), `jwt` (`private_key_jwt`, the committed public key), `x509-login` (the X.509 direct-grant user logon, the `CERTRULE` analogue); UAA `jwt_client` (`jwks`; UAA has no `tls_client_auth`, and its assertion `aud` is its issuer from discovery). Suite: `src/__tests__/integration/stand/clientCertificates.test.ts`. `clientSecretBasic`'s encodings are measured in `clientSecretBasic.test.ts` against UAA `basic_reserved` / `basic:colon` and Keycloak `basic-reserved` / `basic:colon` (secret `se+cr%25et/x`): form gets a token, raw a `401`. A stand started before Keycloak had an HTTPS port must be stopped once (`npm run stand:down`): `run.sh` refuses a running Keycloak whose HTTPS port is not the one asked for.

**Live XSUAA checks** (`tests/xsuaa/`, `npm run test:xsuaa`, not in CI) create an XSUAA instance, an `apiaccess` instance and a SAML trust in a real BTP subaccount, run `src/__tests__/integration/xsuaa/`, and remove everything — also on failure. The scripts refuse unless `cf target` matches `XSUAA_CF_API`, `XSUAA_CF_ORG` and `XSUAA_CF_SPACE` exactly — a developer's `cf` may point at a production org — and touch only what `setup.sh` recorded in `.local/owned` — bound to that API/org/space and to each resource's GUID or id, re-checked before every reuse, refresh or delete; a name held by any other resource is refused or left alone. A failed teardown stops, keeps `.local/`, and the run exits non-zero. The test IdP's key is generated per run into the gitignored `tests/xsuaa/.local/` — unlike the stand's fixtures, this key is trusted by a real subaccount, so it must never be committed. The application instance has `credential-types: ["binding-secret", "x509"]` (and `client_credentials` among its grants); its `key` is created with `{"credential-type":"binding-secret"}` (remade when a kept instance is updated), and `x509-key` with `{"credential-type":"x509"}` is deleted and created afresh every run (its certificate lives about seven days), saved owner-only to `.local/x509-key.json` and never printed; `src/__tests__/integration/xsuaa/x509.test.ts` maps its `certificate`/`key`/`certurl` as a consumer would. Ledger records: `target <api>|<org>|<space>`, `instance <name> <guid>`, `key <instance>/<key> <guid>`, `trust <origin> <id>`; keys are looked up by GUID through `cf curl /v3/service_credential_bindings` (`key_guid`), and teardown deletes keys before their instance. `btp create security/trust` only trusts IAS tenants; a custom SAML IdP goes through the `apiaccess` plan's `/sap/rest/identity-providers` (SAP Community calls the plan deprecated; SAP Help still documents it).

Two conventions worth knowing, each of which has cost a debugging round:

- **Attach a rejection expectation before triggering it.** `const rejected = expect(p).rejects.toThrow(…)` first, then deliver the request, then `await rejected`. Awaiting the trigger first leaves the promise unhandled at the moment it rejects, and Jest reports an unhandled rejection instead of a passing assertion.
- **Assert on the port, not on a log line.** Anything claiming a socket was released binds it to prove it. Log output proves nothing — code paths have claimed a port was freed without calling `close()`.

When a test is meant to protect a rule, prove it is load-bearing: break the rule deliberately, watch the test go red, revert. Tests have passed here while the rule they existed to protect could be deleted outright.

## Error classes

All extend `TokenProviderError`, with codes from `@mcp-abap-adt/interfaces-auth`:
`ValidationError` (carries `missingFields[]`), `RefreshError` (carries `cause?`), `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`, `AssertionValidationError` (carries `check: AssertionCheck`, code `ASSERTION_VALIDATION_ERROR`), `CertificateMaterialError` (carries `incomplete` and `expired`, code `CERTIFICATE_MATERIAL_ERROR`), `ClientAuthenticationError` (a `privateKeyJwt` key that cannot be used), `ClientAuthenticationResultError` (a strategy result that cannot be sent) and `BasicClientIdError` (raw `clientSecretBasic` with a client id containing `:`), all three code `CLIENT_AUTHENTICATION_ERROR`. The last four have fixed messages, carry nothing of the material, key or result, and are on `refusal.ts`'s `instanceof` allowlist with their own fixed words.

## Plans and specs

Everything under `docs/superpowers/` — specs, plans, goals, todo lists, any other working document — is kept in the tree only while active: not yet implemented and not cancelled. Once fully implemented OR cancelled, delete the file, at the latest before the release that ships the work. History lives in git; the directory holds only work in progress. What a deleted document still owes the future (next steps in other repositories, say) goes into the PR description first.
