# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- A `bearerConfirmation` refusal naming several candidates joins them with
  ` | ` instead of `; `, and ends ` | and N more`. The count reason
  `carries N SubjectConfirmationData; exactly one is allowed` contains `; `
  itself, so the old separator read ambiguously. `check` and every reason's
  wording are unchanged.

### Removed

- `mcp.json`, an XSUAA service key with a client secret, committed to the
  repository on 2025-12-23 with the since-removed `bin/` CLIs. It was never in
  the npm package. It stays in the git history, so that binding should be
  rotated or deleted. `.gitignore` now keeps `mcp.json` and
  `*service-key*.json` out.

## [4.1.2] - 2026-09-26

### Security

- **No token the provider holds reaches a log line.** Every provider logged tokens through
  `BaseTokenProvider.formatToken`. That function returned a token of 50
  characters or fewer whole, and a longer one's first and last 25 characters.
  UAA and XSUAA refresh tokens are opaque and about 34 characters, so they were
  logged in full, at `info`, by `AuthorizationCodeProvider` on creation, on
  refresh (old and new) and by `BaseTokenProvider` on every token update. Access
  tokens leaked 50 characters. A log line now carries only
  `<redacted, N chars>`. Anyone who shipped logs from an earlier version at
  `info` or `debug` should treat the refresh tokens in them as exposed, and
  revoke them.
- **No token endpoint's error body reaches a log line or an error message
  whole.** The SAML exchange and SAML refresh logged the whole error body, and
  `refreshJwtToken` and `getTokenWithClientCredentials` serialised it into the
  thrown `Error`'s message, which `BaseTokenProvider` then logged. Only the
  body's `error` and `error_description` are kept now, each quoted and capped:
  `error` at 64 characters, and `error_description` at 512, so a server's
  diagnosis survives. Both are redacted first. Every secret the request itself
  sent (refresh token, assertion, client secret), however short, whether it
  comes back as sent or form- or percent-encoded, and anything shaped like a JWT
  becomes `<redacted>`. A server that echoes one of those, in the body or in
  its description, no longer leaks it. **Limit:** an opaque token the request
  did not send cannot be told from an ordinary identifier, so if a server writes
  a new one into `error_description` it passes through, capped at 512
  characters. Scrubbing every long string would also erase the IDs that make a
  refusal diagnosable.

## [4.1.1] - 2026-09-26

### Changed

- The `signedNode` refusal for an assertion inside a `ds:Signature` now reads
  "…inside a ds:Signature, which is never accepted". The 4.1.0 wording, "where
  no signature covers it", was untrue when a signed Response also covers that
  signature. `check` and the fragment `inside a ds:Signature` are unchanged.

### Fixed

- The tarball no longer ships `dist/__tests__/…`. Test helpers and stand
  fixtures were built into `dist` and published with 4.0.0 and 4.1.0. The build
  now uses `tsconfig.build.json`, which leaves `src/__tests__` out, and the
  tarball drops from 140 to 128 files. Nothing a consumer imports changes.

### Development

- `@mcp-abap-adt/auth-stores` devDependency `^1.2.1`, which depends on
  `@mcp-abap-adt/interfaces-auth` `^2.0.1`. The development tree now holds a
  single `interfaces-auth` 2.0.1 instead of a second, nested 1.2.0. Nothing
  published changes.
- The live authorization tests take tokens from any session file:
  `MCP_ABAP_ADT_SESSION_FILE`, or `session_path` in `tests/test-config.yaml`,
  or the stores' folder `<destination_dir>/sessions/<destination>.env`. The
  folder defaults to `~/.config/mcp-abap-adt` on Unix and
  `Documents/mcp-abap-adt` on Windows. Browser logins run only with
  `interactive_login: true` or `MCP_ABAP_ADT_INTERACTIVE=1`, so a default
  `npm test` never waits for one.

## [4.1.0] - 2026-09-26

Three refusals get stricter; no export, configuration field or error class
changes. The README's *Upgrading from 4.0 to 4.1* lists what now fails.

### Changed

- **Every refusal names its rule.** No two rules under one `check` share a
  message. An element that must appear exactly once says which way it failed
  — absent, or more than one — for the Response's direct-child `Assertion`,
  each signature's `ds:Reference`, `Status`, `StatusCode`, the assertion's
  `Issuer`, `Conditions`, `Subject` and each bearer candidate's
  `SubjectConfirmationData`. An empty `Issuer`, a `StatusCode` without a
  `Value`, an `AudienceRestriction` naming no audience, and an absent versus
  an invalid `Conditions/@NotOnOrAfter` each get their own message. The
  signed-node refusal names the element the validator requires
  (`samlp:Response` or `saml:Assertion`). `check` is unchanged for every
  refusal, and every document 4.0.0 refused is still refused; code matching
  on message text must match on `check`. The README lists every message
  the shipped validators produce.
- **`bearerConfirmation` says why every candidate failed.** Still
  existential: one confirmation passing every sub-rule is enough, and every
  candidate is evaluated. A refusal lists each candidate in document order
  with the first sub-rule it failed, in a fixed order, at most five, then
  `and N more`. A `Subject` absent or repeated, and a `Subject` holding no
  `SubjectConfirmation`, have messages of their own.
- **Every document value a message interpolates is quoted and cut**
  (`quoteUntrusted`: JSON-quoted, 64 characters at most), including the
  post-signature `Status` code, issuer and `Destination`, the `Conditions`
  dates, xml-crypto's own messages about a malformed `Signature`, which embed
  the offending element, and the parser message in `Saml2BearerProvider`'s
  bearer conversion.

### Fixed

- A SAML 1.x `Assertion` (`urn:oasis:names:tc:SAML:1.0:assertion`) outside
  the signed assertion is refused at `signedNode`, as a SAML 2.0 one already
  was. Before, one in `Extensions` passed either validator.
- An `Assertion` or `EncryptedAssertion` (SAML 2.0) or a SAML 1.x `Assertion`
  inside a `ds:Signature` is refused at `signedNode`. An enveloped signature
  leaves its own subtree out of the digest, so an element in `ds:Object`
  there is unsigned however deep inside the signed assertion it sits; before,
  such an element inside the signed assertion's own `ds:Signature` passed
  either validator, `Saml2BearerProvider`'s default included.
- `idpInitiated: true` with `authnRequestId` is refused when the provider is
  constructed — a `ValidationError` with `missingFields: ['idpInitiated']` —
  not after `authorize()` returns, so before the user has been through the
  browser. A `Saml2BearerProvider` seeded with a `refreshToken` did work in 4.0
  until that token lapsed, since a refresh never reaches the strategy; it now
  fails at construction.
- A malformed `Signature` whose `loadSignature` throws something other than
  an `Error` is refused at `signature` quoting what was thrown. Before, the
  refusal carried an empty message, and a thrown `null` or `undefined`
  escaped as a `TypeError` instead of an `AssertionValidationError`.

### Removed

- The `bin` commands `auth-authorization-code` and `auth-client-credentials`
  (the `bin` field, and `bin` in `files`), and the devDependency `tsx`. They
  never ran from an npm install: they were `.ts` files with a `tsx` shebang,
  importing `src/`, which is not published. Not a breaking change for that
  reason.

### Documentation

- `ValidatedAssertion.nameId` is `undefined` when the `Subject` carries no
  `NameID` or more than one. `NameID` is surfaced, never refused.

### Development

- `@mcp-abap-adt/interfaces-auth` `^2.0.1`, whose
  `IAssertionReplayStore.recordIfUnseen` JSDoc now describes the retention this
  package implements: until the last instant a validator would still accept
  the assertion, not its expiry.
- `@mcp-abap-adt/auth-stores` stays a devDependency: three test suites import
  `AbapServiceKeyStore` from it.
- The end-to-end SAML suite (`samlValidation.test.ts`) runs about 6× faster,
  about 41 s down to about 7 s: it starts one mock identity provider per
  signed element in `beforeAll` and switches variants, instead of one per
  test, each generating an RSA key. Every test still gets its own replay
  store.
- The Keycloak suite trusts only the certificates under `KeyDescriptor
  use="signing"` in Keycloak's metadata.

## [4.0.0] - 2026-09-25

### Breaking

- **Both SAML providers validate the assertion before trusting it** (#19).
  Until now the only check was that the payload was a non-empty string, and
  `Saml2PureProvider` took its session lifetime from a regular expression over
  the unverified XML. `Saml2BearerProvider` now validates before the token
  exchange, `Saml2PureProvider` before `cookieProvider`, through twelve checks:
  document shape, unique IDs, signature, that the signed node is the node read,
  `Status`, assertion ID, issuer, `Conditions`, `NotBefore`, `NotOnOrAfter`,
  audience, one bearer subject confirmation (request ID, recipient, window) and
  `Destination`, then replay. The README's *SAML assertion validation* lists
  them with what refuses each.

  **The configuration is required.** Supply `idpCertificates` (PEM or bare
  base64 DER, a list for key rotation) and `idpEntityId`, or an
  `assertionValidator` of your own; without them the provider's constructor
  throws a `ValidationError` naming what is missing. A shipped validator
  supplied as `assertionValidator` still needs `idpEntityId`, and its absence
  fails at construction too; only a custom validator does without.
  `spEntityId` becomes the `Audience` the assertion must name.

  **Request IDs.** `InResponseTo` must answer the AuthnRequest the package
  minted, or `authnRequestId` when the package did not build the request — a
  pre-built `authorizationUrl`, or a strategy that returns a payload without
  calling `buildAuthorizationUrl`. `idpInitiated: true` declares that no request
  was sent, so the assertion must carry no `InResponseTo`; it gives up the
  login-CSRF defence of a request ID, and is never inferred.
  `Saml2BearerProvider` against UAA or XSUAA needs it, since both refuse an
  assertion carrying `InResponseTo`. Having neither an ID nor the declaration,
  or combining the declaration with an ID, raises a `ValidationError`. With
  `idpInitiated` and no `authorizationUrl`, a strategy that calls
  `buildAuthorizationUrl` is refused inside the builder, before any URL is
  produced — so before a browser opens.

  **Status, by validator.** Under `createSignedResponseValidator` —
  `Saml2PureProvider`'s default — an identity provider returning a
  non-`Success` status is now refused, where it was accepted before.
  `Saml2BearerProvider`'s default, `createSignedAssertionValidator`, does not
  read `Status`, so a bearer consumer sees no change there: a declining identity
  provider mints no signed assertion, and the login fails for want of one.

  **Migrating:** see *Migrating from 3.x to 4.0* in the README — add the trust
  configuration, check `spEntityId`, and for `Saml2BearerProvider` against UAA
  or XSUAA add `idpInitiated: true` with a strategy that never calls
  `buildAuthorizationUrl`.
- **`parseSamlNotOnOrAfter` is removed.** `Saml2PureProvider`'s `expiresAt` is
  now the validated assertion's expiry — the earlier of `Conditions/@NotOnOrAfter`
  and the accepted bearer confirmation's — read from the verified document.
- **`buildSamlAuthorizationUrl` returns `{ url, requestId? }`**, since the
  minted ID must survive to validation, and **`getSamlAssertion` returns
  `Promise<SamlAssertionResult>`** (payload, request ID, ACS) instead of
  `Promise<string>`. None of these, nor `parseSamlNotOnOrAfter`, was exported
  from the package root; only a deep import of `dist/auth/saml2Auth` or
  `dist/providers/saml2Utils` is affected.
- **`@mcp-abap-adt/interfaces-auth` `^2.0.0`** (was `^1.2.0`), where
  `AssertionContext.expectedInResponseTo` is optional — a breaking change for
  implementers of `IAssertionValidator`, which must refuse an assertion
  carrying `InResponseTo` when it is absent.

### Added

- **`createSignedResponseValidator`** and **`createSignedAssertionValidator`**,
  sharing `ShippedValidatorOptions` (`idpCertificates`, `clockSkewMs`,
  `replayStore`). The first requires the signature to cover the `Response` and
  performs all twelve checks; the second accepts a signature over the
  `Assertion` — bare, or inside a Response — and does not read `Status`,
  `Response/Issuer` or `Destination` at all. `Saml2PureProvider` defaults to the
  first, `Saml2BearerProvider` to the second; `assertionValidator` replaces
  either.
- **Replay detection**: `defaultReplayStore`, a process-wide in-memory store
  shared by every default validator, keyed by `{issuer, assertionId}` and
  retained until the earlier of `Conditions/@NotOnOrAfter` and the latest
  `NotOnOrAfter` of a bearer confirmation that answers the request and names
  the ACS, plus `clockSkewMs` — as long as the assertion could still be
  accepted, which can outlast `expiresAt`; `createInMemoryReplayStore()` for
  an isolated one; `assertionReplayStore` on the providers for a shared store
  across processes.
- **`clockSkewMs`**, default `0`.
- Any XML parse fault — including one `@xmldom/xmldom` would otherwise repair,
  such as an undeclared entity — is a refusal at `document`, and the parser
  never writes to the console; the bearer conversion (`toBearerAssertion`)
  parses the same way.
- The validators refuse a payload carrying a `<!DOCTYPE` declaration, never
  take a signing certificate from the document's own `KeyInfo`, and accept
  RSA-SHA1 signatures and SHA-1 digests, as `xml-crypto` does by default; a
  consumer wanting to refuse SHA-1 wraps a shipped validator in its own.
- **`AssertionValidationError`**, with `check: AssertionCheck` naming the check
  that refused the assertion, and code `ASSERTION_VALIDATION_ERROR`.
- `xml-crypto` becomes a runtime dependency, for signature verification.

### Development

- Both validators run end to end in `npm test`, through `Saml2PureProvider`
  and a real callback, against responses from `@mcp-abap-adt/auth-mocks` (the
  devDependency and its range are unchanged). Every corruption variant is refused at the
  check it targets, except `statusFailure` and `wrongDestination`, which the
  assertion-only validator accepts — both halves asserted.
- The provider stand's SAML suites run every login through the provider's
  validation, including Keycloak's real responses, signed at both levels; the
  live XSUAA suite does the same with its per-run identity provider, and now
  refuses the `InResponseTo` case itself, before XSUAA sees it.
- `@mcp-abap-adt/interfaces-auth-sap` `^1.0.1`.

## [3.0.0] - 2026-09-24

### Added

- **`UaaPasscodeProvider`** and **`manualPasscodeStrategy`** — the one-time
  passcode `cf login --sso` uses, for UAA and XSUAA. The user fetches a
  Temporary Authentication Code from `<uaaUrl>/passcode` in any browser,
  logging in however the identity zone asks, and the provider exchanges it
  through the password grant and refreshes afterwards — a headless SSO login
  that XSUAA supports, unlike the device authorization grant. A rejected code
  reports UAA's reason (`Invalid passcode`). Tested on the UAA stand.

### Breaking

- **Node.js 22 or 24** — `engines: "^22 || ^24"` (was `>=18.2.0`). The
  supported versions now follow SAP BTP, Cloud Foundry, whose Node.js buildpack
  offers exactly 22 and 24: Node 18 reached its end of life on 30 April 2025
  and Node 20 on 30 April 2026, and SAP has removed 20 from Cloud Foundry. The
  odd releases between them are excluded too — 23 reached end of life on 1 June
  2025 and 25 on 1 June 2026 — and so is 26 until SAP offers it. CI tests on 22
  and 24 instead of 18.

  **Migrating:** run on Node 22 or 24. Nothing in the API changed.
- **`DeviceFlowProvider` is removed**, with `DeviceFlowProviderConfig` and the
  `auth-device-flow` command. It sent the device authorization grant to
  `${uaaUrl}/oauth/device_authorization`, a path no server we could find
  serves: Cloud Foundry UAA has no device grant, XSUAA answers that path with a
  redirect to its login page and advertises no `device_authorization_endpoint`,
  and servers that do implement RFC 8628 — Keycloak, Spring Authorization
  Server, Ory Hydra, Zitadel, Dex — publish it elsewhere. Its live tests had
  long been skipped.

  **Migrating:** for a server that implements RFC 8628, use
  `OidcDeviceFlowProvider` — it finds the endpoints through discovery
  (`issuerUrl`) or takes them explicitly, and is tested against Keycloak. For a
  headless login to UAA or XSUAA, use `UaaPasscodeProvider`: the user fetches
  a one-time code from `<uaaUrl>/passcode` in any browser, as with
  `cf login --sso`.

### Fixed

- **`Saml2BearerProvider` sends what RFC 7522 accepts** (#37). It forwarded
  the strategy's payload as is — after an interactive login, the whole
  `SAMLResponse` in standard base64 — where §2.1 takes one Assertion,
  base64url-encoded. Cloud Foundry UAA answers 401 to a Response in either
  encoding, so the provider could not get a token through any interactive
  strategy. It now takes the Assertion out of a Response (copying onto it
  every namespace declaration it inherited, including one used only inside an
  `xsi:type` value, and keeping its signature) and sends it
  base64url-encoded; a bare Assertion in either encoding is re-encoded. A
  Response with no Assertion, several, or only an `EncryptedAssertion` is
  refused before anything is sent. `@xmldom/xmldom` becomes a dependency.

### Development

- **Every provider but two is tested against a real authorization server** in
  Docker: Cloud Foundry UAA — the server XSUAA is built from — and Keycloak.
  `npm run test:stand` starts both, runs the suites and stops them, and CI runs
  the same as its own job on Node 22 and 24.
  - UAA: `Saml2BearerProvider` (confirming end to end what #23 was about: a
    refresh token is issued with the saml2-bearer token when the client may
    hold one, and spent without running the authorization strategy),
    `ClientCredentialsProvider`, `AuthorizationCodeProvider` with refresh.
  - Keycloak: `OidcPasswordProvider` with refresh, `OidcBrowserProvider` with
    S256 PKCE, `OidcDeviceFlowProvider`, `OidcTokenExchangeProvider`
    (RFC 8693).
  - Keycloak as the SAML identity provider: `Saml2BearerProvider` end to end
    into UAA, with no assertion built by the tests, and the identity-provider
    half of `Saml2PureProvider`. This showed that UAA's bearer grant refuses
    the answer to an SP-initiated login for its `InResponseTo`, and accepts an
    IdP-initiated one; the README says so under `Saml2BearerProvider`.
  - Interactive logins go through each server's own login and consent pages,
    submitted over HTTP by a test helper.
  - Not covered: `DeviceFlowProvider`, whose `/oauth/device_authorization`
    neither server serves, and `Saml2PureProvider`'s cookie exchange, which is
    the consumer's `cookieProvider`.

- **Live checks against a real XSUAA** — `npm run test:xsuaa`, not in CI —
  create an XSUAA instance and a SAML trust in a BTP subaccount, run, and
  remove them. On a trial subaccount: `Saml2BearerProvider` gets a token and a
  refresh token from an IdP-initiated assertion, converts a whole
  `SAMLResponse`, refreshes without its strategy, and is refused an assertion
  carrying `InResponseTo`, exactly as by UAA; `UaaPasscodeProvider` works,
  including — checked by hand — with an ABAP environment's own service key,
  whose token opens ADT.
  `@mcp-abap-adt/auth-mocks` becomes a devDependency, for signing assertions.
  The stand itself is not published.

## [2.2.2] - 2026-09-24

### Dependencies

- The lockfile is refreshed within the declared ranges (#33), replacing
  thirteen Dependabot bumps. `npm audit` on the development tree goes from 15
  findings (1 critical, 8 high) to none. No dependency range in `package.json`
  changed, and the lockfile is not part of the published package, so an
  installation of 2.2.2 resolves exactly what one of 2.2.1 already could.

## [2.2.1] - 2026-09-24

### Fixed

- **`Saml2BearerProvider` spends its refresh token** (#23). `performRefresh()`
  used to run a full interactive login on both of its branches, so a session
  holding a valid refresh token still went through the IdP and a browser — and
  a headless consumer got `BROWSER_AUTH_REQUIRED` from `auth-broker`. It now
  sends a `refresh_token` grant to the same token endpoint and with the same
  client credentials as the assertion exchange, keeps the refresh token it spent
  when the response carries no new one, and falls back to a full login when the
  grant is refused.

## [2.2.0] - 2026-09-24

### Dependencies

- **`@mcp-abap-adt/interfaces` is replaced by the contract packages this
  package actually uses.** The facade is deleted upstream; 51.0.0 is its last
  version. The contracts now come from:
  - `@mcp-abap-adt/interfaces-auth` `^1.2.0` — `ITokenProvider`, `ITokenResult`,
    `IAuthorizationStrategy`, the callback server types, `AUTH_TYPE_*` and
    `TOKEN_PROVIDER_ERROR_CODES`;
  - `@mcp-abap-adt/interfaces-auth-sap` `^1.0.0` — `IAuthorizationConfig`;
  - `@mcp-abap-adt/interfaces-utils` `^1.1.0` — `ILogger`.

  No export of this package changed. A consumer that imports these types itself
  should import them from the same packages, not from the facade.
- `@mcp-abap-adt/logger` (dev) `^0.4.0`, which is on `interfaces-utils` as well.

## [2.1.0] - 2026-09-03

### Licence

- **This package is now `LGPL-3.0-only`.** It was MIT up to and including 2.0.0, and
  those versions stay MIT — a licence change is not retroactive, and anyone
  already using 2.0.0 under MIT keeps that grant for 2.0.0.

  The library licence of the GNU family, chosen for what it does *not* ask:
  linking it into your own program — importing it, as every consumer of an npm
  package does — does not put your program under the LGPL. What it asks is that
  changes to this library stay free and that your users can substitute their own
  build of it.

  Both texts ship in the package: `LICENSE` is the LGPL, `COPYING` is the GPL it
  is written on top of. The LGPL is a set of additional permissions over the GPL,
  so it cannot be read without both.

  Copyright © 2025–2026 Oleksii Kyslytsia.


## [2.0.0] - 2026-07-31

Callback reception leaves the providers. How an interactive login is conducted —
reaching the authorization URL, receiving what comes back, the port, the timeout
— is now an `IAuthorizationStrategy` the consumer may replace wholesale; the
provider keeps only what it can compute, the URL and the token exchange. (#11)

### Breaking

- **`browser` and `redirectPort` are removed from every provider config**, along
  with `redirectUri`, `authorizationCode` and `authorizationCodeProvider`
  (OIDC) and `assertionFlow`, `assertionProvider` and `manualInput` (SAML).
  All are replaced by a single `authorization` strategy. See the migration
  table in the README.
- **The default callback port is now 61001, was 3001** — for the UAA flow and
  for SAML alike, the latter because `resolveAcsUrl` (which defaulted the ACS to
  `http://localhost:3001/callback`) is gone and the ACS now comes from the
  strategy. If you relied on the default and registered
  `http://localhost:3001/callback` with your identity provider, the **IdP**
  rejects the redirect and the error you see comes from it, not from this
  package. Pass `port: 3001` explicitly to keep the old behaviour.
- **`acsUrl` is required when `authorizationUrl` is set** on `Saml2BearerProvider`
  and `Saml2PureProvider`, and is rejected at construction. The ACS inside a
  pre-built, deflated `SAMLRequest` cannot be read, so it cannot be checked
  against what the strategy binds; 1.x accepted the combination and quietly used
  a default ACS that was usually not where the IdP posted.
- **The terminal-paste channel is gone from the browser callback strategy.** In
  1.x a `none` / `headless` login could also be completed by pasting the code on
  stdin, and that worked without the consumer choosing anything; it is the
  channel headless and SSH users reached for most. `browserCallbackStrategy`
  reads no stdin at all — under an MCP or LSP stdio transport that stream
  carries the protocol, so an authorization library must not consume it. The
  capability moved to `manualPasteStrategy({ redirectUri, read })`, which is now
  an explicit choice; the paste form served on `/` remains the other fallback
  for a browser on a different machine.
- **Device flow prompts no longer go to stdout.** `DeviceFlowProviderConfig`
  accepts `logger?: ILogger`; the verification URI and user code go to that
  logger, or to stderr when none is supplied. `OidcDeviceFlowProvider` likewise.
  Anything capturing stdout to read the device code must now read stderr or
  supply a logger. stdout carries protocol traffic under an MCP or LSP stdio
  transport.
- `Saml2AssertionConfig` and `Saml2AssertionFlow` are removed from the types, and
  `src/auth/manualInput.ts` is gone; `manualPasteStrategy` and
  `manualSamlResponseStrategy` replace them.
- Requires `@mcp-abap-adt/interfaces` `^11.6.0` (was `^11.4.0`).

### Added

- `IAuthorizationStrategy` support in all four interactive providers
  (`AuthorizationCodeProvider`, `OidcBrowserProvider`, `Saml2BearerProvider`,
  `Saml2PureProvider`), with shipped strategies: `browserCallbackStrategy`,
  `oidcCallbackStrategy`, `samlCallbackStrategy`, `manualPasteStrategy`,
  `manualSamlResponseStrategy`, `externalCodeStrategy`, `staticCodeStrategy`,
  and the `asOidcResult` adapter. `BrowserCallbackStrategy`,
  `DEFAULT_CALLBACK_PORT` and `DEFAULT_LOGIN_TIMEOUT_MS` are exported too.
- `asOidcResult` bridges the code-producing strategies, which yield a `string`,
  to `OidcBrowserProvider`, which takes `IAuthorizationStrategy<OidcCallbackResult>`.
  It delegates `dispose`, so wrapping costs nothing in lifecycle terms.
- The three `CallbackServerFactory` implementations are exported —
  `withBrowserCallbackServer`, `withOidcCallbackServer`, `withSamlCallbackServer`
  — so a consumer can reuse the transport while replacing everything around it,
  or inject its own into a shipped strategy via `callbackServer`.
- Ephemeral callback ports (`port: 0`), where the identity provider accepts a
  loopback redirect on any port. The bound port is reported back, so the token
  exchange can send the redirect URI that actually received the callback.
- `OidcBrowserProvider` discovers lazily: a strategy that already holds a code
  no longer drags in a discovery request, nor the `issuerUrl` requirement.

### Fixed

- A `/callback` carrying neither a code nor an error no longer ends the login;
  it is answered, counted, and reported in the timeout message.
- The OIDC callback route now distinguishes an IdP refusal from a stray
  request — it previously had no `error=` branch at all.
- The SAML callback route no longer shows a success page before checking
  whether an assertion arrived; a request with no assertion is answered 400.
- Manual input prompts go to stderr; they went to stdout, which corrupts an
  MCP/LSP stdio transport.
- The token exchange sends the redirect URI that actually received the
  callback, rather than one rebuilt from an assumed port.
- The PKCE challenge is pinned to the verifier that reaches the exchange.
- A strategy disposed while its port probe was still awaiting used to report
  everything released and then bind a socket behind it.
- The remote paste hint named `http://localhost:<port>/` — an address that
  cannot work for the one reader it addresses, someone whose browser is on
  another machine. It now names `http://<this-host>:<port>/`, keeping the real
  port and leaving the host to the reader, as the 1.x wording did.

### Docs

- `README.md` documents strategies throughout, adds *Choosing an authorization
  strategy* and *Migrating from 1.x to 2.0*, and corrects two claims that were
  already wrong in 1.x: the default `browser` mode is `'none'`, not `'system'`,
  and `extractCode` is internal, not exported.
- `docs/REFACTORING_PROPOSAL.md` is deleted; the `ITokenProvider` refactor it
  proposed shipped in 1.0.0.

## [1.2.0] - 2026-07-28

### Fixed
- **A callback server could hold its port after the login it was opened for had ended.** Three flows, three shapes of one defect: `browserAuth` leaked the socket when a callback carried neither `code` nor `error` — measured still bound at +5 s, +20 s, +35 s and +45 s, i.e. for the life of the process — while `oidcBrowserAuth` and `saml2Auth` had no timeout at all, so an abandoned login never settled and never released anything. (#11)
- **A rejected login could report a port that was not yet free.** Five exit paths closed the socket asynchronously *after* the promise had settled, leaving a window in which "already in use" was untrue.
- **`AuthorizationCodeProvider` raced `startBrowserAuth` against a second 30-second timer** of its own, so which fired was down to scheduling; when the outer one won it rejected while the socket was still bound. That timer was never cleared, keeping a login that succeeded in a second armed for the remaining 29.
- **A hung browser launcher could delay the timeout and the release.** The launch is no longer awaited on the critical path.

### Changed
- All three flows now run inside a factory scope implementing `CallbackServerFactory` from `@mcp-abap-adt/interfaces`. The port is released when the scope ends — by success, error, timeout, cancellation, or a body that throws — instead of when a promise happens to settle, and the scope settles only once the socket is free. `timeoutMs` is mandatory and an `AbortSignal` is honoured before, during and after the bind.
- Shutdown is bounded: stop accepting, wait up to 500 ms for `close`, then force. A timeout can no longer hang on its own cleanup.
- Requires `@mcp-abap-adt/interfaces` `^11.4.0` (was `^2.3.0`).
- **`engines.node` is now `>=18.2.0`** (was `>=18.0.0`), for `server.closeAllConnections()`.
- `browserAuth.ts` is 395 lines, down from 790: the HTTP server, six separate close sites, two timers and the process-signal handlers are gone from it.

### Removed
- **The callback server no longer installs `SIGTERM` / `SIGINT` / `SIGHUP` / `exit` handlers.** A terminating process releases its listening sockets to the OS regardless — measured at 0-1 ms after the process disappears — and these were part of the cleanup tangle being removed. A client that kills the process mid-login still gets its port back.
- **The manual paste channel no longer retries a bad code.** It used to re-render the form when the exchange failed; the code is now exchanged after the scope closes, so a wrong or expired paste ends the attempt. That retry loop was the only reason the socket outlived the code.

### Notes
- Public API is unchanged: `AuthorizationCodeProviderConfig` keeps `browser` and `redirectPort`, still defaulting to 3001.
- The three factories stay internal. Exposing them so a consumer can supply its own callback receiver is issue #11 and is not part of this release.
- A callback carrying neither `code` nor `error` still ends the login with an error. Only the leaked socket was fixed, not the termination.

## [1.1.0] - 2026-06-02

### Added
- `extractCode(input)` helper: pulls an OAuth2 authorization code out of a bare
  code, a `code=...` string, or a full redirected URL.
- Manual paste authentication for `none`/`headless` browser modes, so login can
  complete when the automatic `localhost` callback can't reach the process
  (browser on another machine / container / SSH). Three racing channels, first
  one wins:
  - the existing automatic `GET /callback?code=...` redirect;
  - an HTML paste form on the same callback server (`GET /` + `GET /submit`);
  - stdin paste, only when `process.stdin.isTTY` (never consumed under stdio
    RPC transports).

### Fixed
- `none`/`headless` mode now prints the authorization URL even when no logger is
  supplied. The prompt previously rode on `log?.info(...)` and was silently
  dropped without a logger; it now falls back to `stderr` (never stdout, to keep
  stdio RPC transports uncorrupted).

## [1.0.5] - 2026-02-12

### Fixed
- Log SAML bearer token exchange HTTP errors with response details for troubleshooting.

## [1.0.4] - 2026-02-11

### Changed
- Remove Cloud Foundry passcode provider and related docs/tests.

### Fixed
- Always send Basic auth header for OIDC password grant, even with empty client secret.


## [1.0.3] - 2026-02-11

### Fixed
- Always send Basic auth header for OIDC password grant, even with empty client secret.


## [1.0.2] - 2026-02-11

### Added
- OIDC providers now support explicit endpoints (`authorizationEndpoint`, `tokenEndpoint`, `deviceAuthorizationEndpoint`) without discovery.
- OIDC browser flow supports manual authorization code input via `authorizationCode` / `authorizationCodeProvider`.
- OIDC browser flow supports custom `redirectUri` (required for manual code / OOB flows).

### Changed
- OIDC provider configs accept optional `issuerUrl` when explicit endpoints are provided.
- Dependency updates: `axios` ^1.13.5, `@biomejs/biome` ^2.3.14, `@mcp-abap-adt/auth-stores` ^1.0.1, `@types/node` ^25.2.3, `pino` ^10.3.1.

## [1.0.0] - 2026-02-10

### Added
- SSO providers for OIDC and SAML2, plus `SsoProviderFactory` for DI-friendly creation.
- OIDC flows: browser (PKCE), device flow, password grant, token exchange.
- SAML2 flows: browser/manual/assertion input, bearer exchange, and pure SAML (cookie-based) output.
- `BaseTokenProvider` now supports `tokenType` and `expiresAt` from `ITokenResult`.

## [1.0.1] - 2026-02-10

### Added
- GitHub Actions CI workflow (build + test on push/PR).

## [0.2.10] - 2025-12-25

### Changed
- **Logging Improvements**: Enhanced logging for better debugging and readability
  - **Date Formatting**: Expiration dates now displayed in readable format (`YYYY-MM-DD HH:MM:SS UTC`) instead of ISO format (`2025-12-25T11:08:15.000Z`)
  - **Token Formatting**: Tokens are logged in truncated format (start...end) for security and readability
  - **Browser Information**: Added logging of browser type and authorization URL before starting browser authentication
  - **Token Lifecycle**: Improved logging of token acquisition, validation, and refresh operations with formatted dates
  - **Structured Logging**: Replaced `console.log/info/warn/error` with `DefaultLogger` from `@mcp-abap-adt/logger` in test helpers
    - Proper formatting with icons and level prefixes (ℹ️, 🐛, ⚠️, ❌)
    - Respects `LOG_LEVEL` or `AUTH_LOG_LEVEL` environment variable
    - Consistent logging format across all packages
  - **Environment Variable Names**: Added short names for debug flags (backward compatible)
    - `DEBUG_PROVIDER=true` (short) or `DEBUG_AUTH_PROVIDERS=true` (long)
    - Both names are supported for backward compatibility

### Added
- **Browser Auth Timeout**: Added 30-second timeout for browser-based authentication
  - Prevents provider from blocking consumer indefinitely when user doesn't complete authentication
  - Timeout error is thrown if authentication is not completed within 30 seconds
  - Helps prevent hanging in automated tests and CI/CD environments
- **Logger Package Dependency**: Added `@mcp-abap-adt/logger` to devDependencies
  - Required for `DefaultLogger` and `getLogLevel()` utilities in test helpers
  - Added `pino` and `pino-pretty` to devDependencies to support PinoLogger initialization

### Fixed
- **Test Hanging Issues**: Fixed Jest tests hanging after completion
  - Added `forceExit: true` to Jest configuration to force exit after tests complete
  - Improved cleanup of HTTP server and timers to prevent open handles
  - Added protection against double execution of server close handlers
  - Proper cleanup of `finishTimeoutId` timer in all scenarios (success, error, timeout)
  - Server now resolves promise only after fully closing to ensure Jest can exit cleanly

## [0.2.9] - 2025-12-25

### Changed
- **Logging Improvements**: Enhanced logging for better debugging and readability
  - **Date Formatting**: Expiration dates now displayed in readable format (`YYYY-MM-DD HH:MM:SS UTC`) instead of ISO format (`2025-12-25T11:08:15.000Z`)
  - **Token Formatting**: Tokens are logged in truncated format (start...end) for security and readability
  - **Browser Information**: Added logging of browser type and authorization URL before starting browser authentication
  - **Token Lifecycle**: Improved logging of token acquisition, validation, and refresh operations with formatted dates

### Added
- **Browser Auth Timeout**: Added 30-second timeout for browser-based authentication
  - Prevents provider from blocking consumer indefinitely when user doesn't complete authentication
  - Timeout error is thrown if authentication is not completed within 30 seconds
  - Helps prevent hanging in automated tests and CI/CD environments

### Fixed
- **Test Hanging Issues**: Fixed Jest tests hanging after completion
  - Added `forceExit: true` to Jest configuration to force exit after tests complete
  - Improved cleanup of HTTP server and timers to prevent open handles
  - Added protection against double execution of server close handlers
  - Proper cleanup of `finishTimeoutId` timer in all scenarios (success, error, timeout)
  - Server now resolves promise only after fully closing to ensure Jest can exit cleanly

## [0.2.8] - 2025-12-24

### Changed
- **Integration Tests**: Replaced mock-based unit tests with comprehensive integration tests using real YAML configuration
  - Tests now use `test-config.yaml` for loading real service keys and session files
  - Simplified test configuration structure: only `destination` and optional `destination_dir` (removed `abap`/`xsuaa` sections)
  - Default paths: `~/.config/mcp-abap-adt` (Unix) or `%USERPROFILE%\Documents\mcp-abap-adt` (Windows)
- **Logging**: Migrated from `console.log` to structured logging using `@mcp-abap-adt/logger`
  - All providers and browser auth functions now use `ILogger` interface
  - Consistent structured logging with log levels (debug, info, warn, error)
  - Better debugging with token validation details and execution flow

### Added
- **Test Scenarios**: Comprehensive integration test coverage for token lifecycle
  - Scenario 1 & 2: Token lifecycle - login via browser and reuse token from previous scenario
  - Scenario 3: Expired session + expired refresh token - provider should re-authenticate via browser
  - Token validation: Explicit validation of token expiration in all scenarios
- **Test Configuration**: Simplified `test-config.yaml.template` with detailed comments
  - Only requires `destination` name (service key and session files are auto-resolved)
  - Optional `destination_dir` (commented out by default, can be uncommented for custom paths)
  - Clear documentation of test scenarios and file formats

### Fixed
- **Test Hanging Issues**: Fixed tests hanging due to browser and port conflicts
  - Changed `browser: 'none'` to `browser: 'system'` for interactive authentication
  - Each test scenario uses unique ports (3101, 3102, 3103) to avoid conflicts
  - Improved server cleanup: `resolve(tokens)` called immediately after token exchange, server closes asynchronously
  - Added delays after browser-based tests to allow ports to free up
- **Token Validation**: Added explicit token validation in all test scenarios
  - Tests verify that returned tokens are valid and not expired
  - Uses JWT `exp` claim validation with 60-second buffer (matching `BaseTokenProvider`)

## [0.2.7] - 2025-12-24

### Changed
- **AuthorizationCodeProvider**: configured via constructor; `getTokens()` has no parameters
- **ClientCredentialsProvider**: configured via constructor; `getTokens()` has no parameters
- **BaseTokenProvider**: `getTokens()` signature matches the stateful interface (no parameters)

### Fixed
- **Tests**: updated jest dependencies and typings for `@jest/globals`

## [0.2.6] - 2025-12-24

### Changed
- **AuthorizationCodeProvider**: implements the new stateful `ITokenProvider.getTokens(authConfig, options)` flow
- **ClientCredentialsProvider**: implements the new stateful `ITokenProvider.getTokens(authConfig, options)` flow
- **BaseTokenProvider**: updated to accept `authConfig` and `options` parameters

### Removed
- **BtpTokenProvider**: removed in favor of `AuthorizationCodeProvider`
- **XsuaaTokenProvider**: removed in favor of `AuthorizationCodeProvider` and `ClientCredentialsProvider`

## [0.2.5] - 2025-12-22

### Changed
- **Migrated to Biome**: Replaced ESLint/Prettier with Biome for linting and formatting
  - Added `@biomejs/biome` as dev dependency (^2.3.10)
  - Added `biome.json` configuration file with recommended rules
  - Added npm scripts: `lint`, `lint:check`, `format`
  - Updated `build` script to include Biome check before TypeScript compilation
  - All code now follows Biome formatting and linting rules

### Fixed
- **Type Safety Improvements**: Replaced `any` types with proper types for better type safety
  - All catch blocks: Changed from `any` to `unknown` with proper type guards
  - Promise resolve/reject handlers: Added proper types instead of `any`
  - Error handling: Improved error message extraction with proper type checking
  - `RefreshError` constructor: Fixed type compatibility when passing error causes
- **Code Quality**: Improved code style
  - Replaced optional chaining where appropriate
  - Fixed assignment in expression (moved to separate statement)
  - Added Biome override for test files to allow non-null assertions in tests

## [0.2.4] - 2025-12-21

### Changed
- **Local JWT Validation**: Both `BtpTokenProvider.validateToken()` and `XsuaaTokenProvider.validateToken()` now validate JWT locally by checking `exp` claim instead of making HTTP requests
  - No HTTP calls to SAP server for validation
  - Prevents unnecessary browser authentication when server is unreachable (ECONNREFUSED, timeout)
  - 60-second buffer before expiration to account for clock skew
  - HTTP validation (401/403) is handled by retry mechanism in `makeAdtRequest` wrapper
  - Consistent validation behavior across all token providers

### Fixed
- **Browser Auth on Network Error**: Fixed issue where network errors during token validation would trigger browser authentication
  - Previously, network errors could return `false` → triggered refresh → opened browser
  - Now, validation is purely local - network issues are handled at request time

## [0.2.3] - 2025-12-21

### Added
- **Headless Browser Mode**: Added `browser: 'headless'` option for SSH and remote sessions
  - Logs authentication URL and waits for manual callback
  - Server keeps running until user completes authentication in their browser
  - Ideal for environments without display (SSH, Docker, CI/CD)
  - Differs from `'none'` which immediately rejects (for automated tests)
- **Cross-Platform Browser Support**: Improved browser opening reliability across all platforms
  - **Linux**: Added `DISPLAY=:0` fallback when `DISPLAY` and `WAYLAND_DISPLAY` environment variables are not set
    - Helps when running from terminals that don't set DISPLAY automatically
    - Logs when fallback is used for debugging
  - **Linux**: Added alternative browser executable names for better compatibility
    - Chrome: `google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser`
    - Edge: `microsoft-edge`, `microsoft-edge-stable`
    - Firefox: `firefox`, `firefox-esr`
  - **Windows**: Added `SIGBREAK` signal handler for cleanup (Ctrl+Break)
    - Ensures proper port cleanup on Windows-specific termination signals

### Fixed
- **Windows Browser Opening**: Fixed fallback browser commands for Windows
  - Changed from `start chrome` to `cmd /c start "" "chrome"` syntax
  - Fixed system default browser opening with proper empty title parameter
  - Prevents "command not found" errors when using fallback mechanism

### Changed
- **Dependency Update**: Updated `@mcp-abap-adt/interfaces` to `^0.2.4` for headless browser mode support
- **Test Coverage**: Added unit tests for browser modes (`none` and `headless`)
  - Tests verify `none` mode rejects immediately with URL in error message
  - Tests verify `headless` mode logs URL and waits for callback

## [0.2.2] - 2025-12-20

### Fixed
- **Process Termination Cleanup**: OAuth callback server now properly cleans up when process is terminated
  - Added `process.on('exit', 'SIGTERM', 'SIGINT', 'SIGHUP')` handlers to ensure server closes on process termination
  - This fixes port leaks when MCP clients (like Cline) kill the stdio server before authentication completes
  - Cleanup handlers are automatically removed after authentication completes to prevent memory leaks
  - Ports are now properly freed even when process is forcefully terminated

## [0.2.1] - 2025-01-XX

### Added
- **Automatic Port Selection**: Browser auth server now automatically finds an available port if the requested port is in use
  - When `startBrowserAuth()` is called with a port, it checks if the port is available
  - If the port is busy, it automatically tries the next ports (up to 10 attempts)
  - This prevents `EADDRINUSE` errors when multiple stdio servers run simultaneously
  - Port selection happens before server startup, ensuring no conflicts

### Fixed
- **Server Port Cleanup**: Improved server shutdown to ensure ports are properly freed after authentication completes
  - Added `keepAliveTimeout = 0` and `headersTimeout = 0` to prevent connections from staying open
  - Added `closeAllConnections()` calls before `server.close()` to ensure all connections are closed
  - Server now waits for HTTP response to finish before closing to prevent connection leaks
  - Added proper error handling for browser open failures to ensure server is closed
  - Server now properly closes in all error scenarios (timeout, browser open failure, callback errors)
  - This prevents ports from remaining occupied after authentication completes or server shutdown

### Changed
- **Port Selection Logic**: `startBrowserAuth()` now uses `findAvailablePort()` to automatically select a free port
  - Default behavior: tries requested port first, then tries next ports if busy
  - Port range: tries up to 10 consecutive ports starting from the requested port
  - Logs when a different port is used (for debugging)

## [0.2.0] - 2025-12-19

### Added
- **Typed Error Classes**: Added specialized error classes for better error handling and debugging
  - `TokenProviderError` - Base class for all token provider errors with error code
  - `ValidationError` - Thrown when authConfig validation fails (includes `missingFields: string[]` array)
  - `RefreshError` - Thrown when token refresh operation fails (includes `cause?: Error` with original error)
  - `SessionDataError` - Thrown when session data is invalid or incomplete (includes `missingFields` array)
  - `ServiceKeyError` - Thrown when service key data is invalid or incomplete (includes `missingFields` array)
  - `BrowserAuthError` - Thrown when browser authentication fails or is cancelled (includes `cause` error)
  - All error codes use constants from `@mcp-abap-adt/interfaces` package (`TOKEN_PROVIDER_ERROR_CODES`)
  - Errors are exported from package root for easy import

### Changed
- **Enhanced Validation Error Messages**: Validation errors now list specific missing field names instead of generic messages
  - Example: `XSUAA refreshTokenFromSession: authConfig missing required fields: uaaUrl, uaaClientId`
  - `ValidationError` includes `missingFields: string[]` property for programmatic access to missing fields
  - Each missing field is checked individually and added to the list
- **Improved Error Handling in Refresh Methods**: All refresh operations now wrap errors with typed error classes
  - `refreshTokenFromSession` throws `RefreshError` when client_credentials or browser auth fails
  - `refreshTokenFromServiceKey` throws `RefreshError` when browser authentication fails
  - Original error is preserved in `RefreshError.cause` property for debugging
  - Error messages include provider type (XSUAA/BTP) and operation name for clarity
- **Dependency Update**: Updated `@mcp-abap-adt/interfaces` to `^0.2.2` for `TOKEN_PROVIDER_ERROR_CODES` constants
- **Test Coverage**: Added tests for error handling edge cases
  - Tests verify `RefreshError` is thrown when authentication fails
  - Tests verify `ValidationError` includes correct missing field names
  - Tests verify error messages contain expected substrings

## [0.1.5] - 2025-12-13

### Changed
- Dependency bump: `@mcp-abap-adt/interfaces` to `^0.1.16` to align with latest interfaces release

## [0.1.4] - 2025-12-08

### Added
- **Integration Tests for browserAuth**: Added real integration test that uses actual service keys and OAuth flow
  - Test verifies token retrieval with real credentials from service keys
  - Shows all authentication stages with logging when `DEBUG_AUTH_PROVIDERS=true` is set
  - Tests both access token and refresh token retrieval
- **Test Logger Helper**: Added `createTestLogger` helper for tests with environment variable control
  - Supports log levels (debug, info, warn, error) via `LOG_LEVEL` environment variable
  - Only outputs logs when `DEBUG_AUTH_PROVIDERS=true` or `DEBUG_BROWSER_AUTH=true` is set
  - Provides clean, controlled logging for test scenarios

### Changed
- **Improved Logging in browserAuth**: Made logging more concise and informative
  - All log messages are now single-line strings without verbose objects
  - Logs show key information: what we send, what we receive, token lengths
  - Example: `Tokens received: accessToken(2263 chars), refreshToken(34 chars)`
  - Logging only works when logger is provided (no default console output)
- **exchangeCodeForToken Function**: Exported for testing purposes
  - Function is marked as `@internal` but exported to enable unit testing
  - Allows testing token exchange logic without full browser auth flow

### Fixed
- **Test Error Logging**: Fixed error test to use mock logger without console output
  - Error test no longer pollutes console with error messages
  - Still verifies that error logging occurs via spy

## [0.1.3] - 2025-12-07

### Added
- **Configurable Browser Auth Port**: Added optional `browserAuthPort` parameter to `BtpTokenProvider` constructor
  - Allows configuring the OAuth callback server port (default: 3001)
  - Prevents port conflicts when proxy server runs on the same port
  - Port is passed through to `startBrowserAuth` and `exchangeCodeForToken` functions
  - Enables proxy to configure browser auth port via CLI parameter or YAML config

### Changed
- **BtpTokenProvider Constructor**: Now accepts optional `browserAuthPort?: number` parameter
  - Defaults to 3001 if not specified (maintains backward compatibility)
- **startBrowserAuth Function**: Added optional `port: number = 3001` parameter
  - Port is used for OAuth callback server and redirect URI
- **exchangeCodeForToken Function**: Added optional `port: number = 3001` parameter
  - Port is used in redirect URI when exchanging authorization code for tokens
- **Implementation Isolation**: Internal authentication functions are no longer exported from package
  - `startBrowserAuth`, `refreshJwtToken`, and `getTokenWithClientCredentials` are now internal functions
  - Providers use private method wrappers to call these functions
  - Constructor parameters (like `browserAuthPort`) are passed through private methods to internal functions
  - This ensures proper encapsulation and prevents direct usage of internal implementation details
- **Test Improvements**: Unit tests now use provider methods instead of direct internal function imports
  - Tests use `jest.spyOn` to mock private provider methods instead of mocking internal functions
  - Tests now properly test the public API of providers, ensuring better isolation
  - This aligns with encapsulation principles and makes tests more maintainable

## [0.1.2] - 2025-12-05

### Changed
- **Dependency Injection**: Moved `@mcp-abap-adt/auth-stores` and `@mcp-abap-adt/logger` from `dependencies` to `devDependencies`
  - These packages are only used in tests, not in production code
  - Logger is injected via `ITokenProviderOptions.logger?: ILogger` interface in production code
  - Auth stores are not used in production code (consumers inject their own store implementations)

### Removed
- **Unused Dependencies**: Removed `@mcp-abap-adt/connection` dependency (not used in production code)

## [0.1.1] - 2025-12-04

### Added
- **Interfaces Package Integration**: Migrated to use `@mcp-abap-adt/interfaces` package for all interface definitions
  - All interfaces now imported from shared package
  - Dependency on `@mcp-abap-adt/interfaces@^0.1.1` added
  - Updated `@mcp-abap-adt/connection` dependency to `^0.1.14`
  - Updated `@mcp-abap-adt/auth-stores` dependency to `^0.1.3`

### Changed
- **Interface Renaming**: Interfaces renamed to follow `I` prefix convention:
  - `TokenProviderResult` → `ITokenProviderResult` (type alias for backward compatibility)
  - `TokenProviderOptions` → `ITokenProviderOptions` (type alias for backward compatibility)
  - Old names still work via type aliases for backward compatibility
- **Logger Interface**: Updated to use `ILogger` from `@mcp-abap-adt/interfaces` instead of `Logger` from `@mcp-abap-adt/logger`
  - `browserAuth.ts` now uses `ILogger` interface with basic methods (info, error, warn, debug)
  - Browser-specific logging methods (browserUrl, browserOpening) now use basic `info` and `debug` methods

### Fixed
- **BtpTokenProvider Integration Tests**: Fixed to use ABAP destination and `AbapServiceKeyStore` instead of XSUAA
  - BTP and ABAP use the same authentication flow and service key format
  - Tests now correctly use `getAbapDestination` and `hasRealConfig(config, 'abap')`
  - Tests now use `AbapServiceKeyStore` instead of `BtpServiceKeyStore` for loading service keys

## [0.1.0] - 2025-12-04

### Added
- Initial release
- **XsuaaTokenProvider** - Uses `client_credentials` grant type (no browser required)
- **BtpTokenProvider** - Uses browser-based OAuth2 or refresh token flow
- Browser authentication flow with OAuth2 callback server
- Client credentials authentication
- Token refresh functionality
- Token validation (`validateToken` method)
- **Integration Tests**:
  - Integration tests for all providers using real files from `test-config.yaml`
  - Test configuration helpers (`configHelpers.ts`) matching auth-broker format
  - YAML-based test configuration (`tests/test-config.yaml.template`)
  - Tests for service key to session conversion
  - Tests for token validation
  - BTP tests use `AbapServiceKeyStore` (same format as ABAP) and `BtpSessionStore` (without `sapUrl`)
  - ABAP tests use `AbapServiceKeyStore` and `AbapSessionStore` (with `sapUrl`)
  - Both BTP and ABAP tests use `abap.destination` from config (same authentication flow)

### Fixed
- **Integration Tests**: Corrected BTP and ABAP test separation
  - BTP tests correctly handle base BTP sessions (no `sapUrl` required)
  - ABAP tests correctly handle ABAP sessions (with `sapUrl` from service key)
- **Token Validation**: BTP tests now handle cases where `serviceUrl` may not be available (base BTP)
- **Session Storage**: BTP tests no longer attempt to save `serviceUrl` to `BtpSessionStore` (which doesn't accept `sapUrl`)

### Changed
- **Documentation**: Updated README to clarify BTP vs ABAP differences and correct store usage
  - Added explicit examples showing BTP and ABAP as separate entities
  - Clarified that BTP uses `BtpServiceKeyStore`/`BtpSessionStore` (without `sapUrl`)
  - Clarified that ABAP uses `AbapServiceKeyStore`/`AbapSessionStore` (with `sapUrl`)
  - Updated integration test configuration examples

### Dependencies
- `@mcp-abap-adt/auth-broker` ^0.1.6 - Interface definitions
- `@mcp-abap-adt/auth-stores` ^0.1.2 - Store implementations
- `@mcp-abap-adt/connection` ^0.1.13 - Connection utilities
- `@mcp-abap-adt/logger` ^0.1.0 - Logging utilities
