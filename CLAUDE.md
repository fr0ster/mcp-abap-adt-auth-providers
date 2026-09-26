# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@mcp-abap-adt/auth-providers` — a TypeScript npm package providing authentication token providers for SAP ABAP ADT via Model Context Protocol (MCP). Each provider implements `ITokenProvider` for one grant type or protocol:

- **`ClientCredentialsProvider`** — `client_credentials`, no user interaction
- **`AuthorizationCodeProvider`** — UAA authorization code, interactive
- **`OidcBrowserProvider`** — OIDC authorization code with PKCE, interactive
- **`OidcDeviceFlowProvider`**, **`OidcPasswordProvider`**, **`OidcTokenExchangeProvider`**
- **`Saml2BearerProvider`** — SAML assertion exchanged for an OAuth2 token
- **`Saml2PureProvider`** — SAML assertion exchanged for session cookies
- **`UaaPasscodeProvider`** — UAA/XSUAA one-time passcode from `/passcode` (`cf login --sso`), headless

`docs/btp-setup.md` maps each provider to what it needs on the SAP side (XSUAA client, trust, user, ABAP mapping) and whether ADT accepts its token; every claim is tagged SAP, Community, Measured or Inference. Keep the tags honest when changing it.

All extend `BaseTokenProvider`, which owns the token lifecycle (cache, expiry, refresh-then-login fallback). Both SAML providers validate the assertion first, through an `IAssertionValidator` (see "SAML assertion validation").

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

**Interface-only communication.** All interaction with external dependencies happens through contract packages: `@mcp-abap-adt/interfaces-auth` ^2.0.1 (token providers, strategies, callback server, assertion validator and replay store, error codes), `@mcp-abap-adt/interfaces-auth-sap` (XSUAA configuration) and `@mcp-abap-adt/interfaces-utils` (`ILogger`). Depend on the contract package whose contracts are used, nothing wider — never `interfaces-adt`, which carries ADT contracts this package does not use. The package does not know about concrete implementation classes from other packages. A logger is `ILogger`, never a local abstraction.

**Everything pluggable is a strategy.** Anything a consumer might reasonably want to do differently is expressed as a strategy behind an interface. The package ships a working default so nobody is forced to write one, and the consumer can always replace it. This is why an authorization library does not own a socket, a browser or stdin — a consumer may legitimately own them instead.

**No token the provider holds reaches a log line.** `BaseTokenProvider.formatToken` is the one way a token appears in a log, and it yields only `<redacted, N chars>`, never a character of the secret (`noTokensInLogs.test.ts`). A token endpoint's error body contributes only `error` and `error_description`, through `describeOAuthErrorBody`. It redacts every secret the request sent and anything JWT-shaped (`oauthErrorBodies.test.ts`). A new opaque token that a server invents cannot be recognised there; that limit is documented, not hidden.

**Nothing writes to `process.stdout`.** Under an MCP or LSP stdio transport, stdout carries protocol traffic, and a stray line corrupts it. Prompts go to the `ILogger` when there is one and to `process.stderr` when there is not — see `src/auth/announce.ts`. A prompt that vanishes without a logger is also a bug: a user who cannot see a device code cannot finish the flow.

### Package responsibilities

This package ONLY:
- implements `ITokenProvider`
- builds authorization URLs and exchanges codes, assertions and refresh tokens for tokens
- ships default strategies for conducting an interactive authorization
- validates SAML assertions, with two shipped validators and an in-memory replay store, all replaceable

This package does NOT:
- store tokens (`@mcp-abap-adt/auth-stores`)
- orchestrate authentication (`@mcp-abap-adt/auth-broker`)
- load service keys or manage sessions
- decide how a user reaches an authorization URL, or where the redirect is received — the consumer may replace both
- fetch identity provider metadata — certificates and entity IDs come from configuration

### Module structure

```
src/
├── index.ts                  # public surface: providers, strategies, callback factories, validators, errors
├── providers/                # one file per grant type, all extending BaseTokenProvider
├── strategies/
│   ├── BrowserCallbackStrategy.ts  # class + browser/oidc/saml constructors
│   ├── manualStrategies.ts         # paste a code, paste a SAMLResponse
│   ├── codeStrategies.ts           # external (needs the URL) and static (does not)
│   └── asOidcResult.ts             # string payload → OidcCallbackResult
├── auth/
│   ├── callbackServer.ts     # runCallbackScope: one owner, one release point
│   ├── announce.ts           # logger-or-stderr, never stdout
│   ├── browserAuth.ts        # UAA URL building, code exchange, browser launch
│   ├── oidcBrowserAuth.ts    # OIDC callback factory
│   ├── saml2Auth.ts          # SAML callback factory, AuthnRequest building
│   ├── samlBearerAssertion.ts  # SAMLResponse → one base64url Assertion (RFC 7522)
│   └── …                     # oidcToken, oidcDiscovery, oidcPkce, passcodeAuth, …
├── validation/
│   ├── assertionValidator.ts   # createSignedResponseValidator / createSignedAssertionValidator: the check table
│   ├── signedNode.ts           # verify every signature, resolve the element each covers
│   ├── documentIds.ts          # duplicate-ID refusal, required IDs
│   ├── xsdDateTime.ts          # strict xsd:dateTime parsing
│   └── inMemoryReplayStore.ts  # createInMemoryReplayStore, the process-wide defaultReplayStore
├── sso/                      # SsoProviderFactory
└── errors/
    ├── TokenProviderErrors.ts
    └── AssertionValidationError.ts  # carries `check: AssertionCheck`
```

### How an interactive login works

A provider owns what it can compute: the authorization URL and the token exchange. Everything between them belongs to an `IAuthorizationStrategy`:

1. the provider hands the strategy an `AuthorizationRequest` carrying `buildAuthorizationUrl(redirectUri)`;
2. the strategy decides where the redirect will be received, then asks for the URL — that ordering is what makes an ephemeral port possible, since the URL cannot be assembled before the socket is bound;
3. the strategy returns an `AuthorizationOutcome` carrying the payload **and** the redirect URI that actually took part, because the token exchange must send the same one.

Ship-default strategies: `browserCallbackStrategy`, `oidcCallbackStrategy`, `samlCallbackStrategy`, `manualPasteStrategy`, `manualSamlResponseStrategy`, `externalCodeStrategy`, `staticCodeStrategy`.

**Lifecycle: whoever constructs, disposes.** A consumer-supplied strategy is never disposed by a provider — the point of a long-lived receiver is to outlive one login. A default the provider constructed itself is disposed from a `finally`, and a `dispose` failure is logged rather than allowed to replace the error that made the login fail. `dispose()` disables a strategy permanently, which is why providers construct a fresh default per login.

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

**The provider stand** (`tests/stand/`; `npm run test:stand` starts it, runs the suites and stops it, and CI runs the same as its own job) runs Cloud Foundry UAA and Keycloak in Docker: real token endpoints for every provider but `Saml2PureProvider`'s cookie half. UAA carries a SAML identity provider whose key the tests sign with; Keycloak imports the `test` realm from `tests/stand/keycloak/realm-test.json`, and is also the SAML identity provider for both SAML providers: the Keycloak→UAA suite registers Keycloak in UAA and sets Keycloak's IdP-initiated SSO at run time. `keycloakSaml.test.ts` trusts only the certificates under `KeyDescriptor use="signing"` in Keycloak's metadata (`signingCertificates`). UAA's saml2-bearer grant refuses any assertion carrying `InResponseTo`, so only an IdP-initiated assertion gets through — an SP-initiated one never will, whatever the provider does. Both servers' configuration, and the test IdP's key, are committed fixtures — not secrets, trusted by nothing but the local stand — so a clone needs only Docker. The UAA suite takes the issuer from UAA's discovery and the bearer Recipient from its SAML metadata, never from `UAA_URL`, which is what keeps `UAA_PORT` working with a committed configuration. `src/__tests__/integration/stand/formLogin.ts` plays the user on each server's login and consent pages. It needs no SAP system, so it is the place to prove anything about a provider's wire contract. The suites run only when `UAA_URL` / `KEYCLOAK_URL` are set; `test:stand` sets both. A server already running — from `npm run stand:up` or started by hand — is left running; `run.sh` removes only the servers it started itself, per service.

**Live XSUAA checks** (`tests/xsuaa/`, `npm run test:xsuaa`, not in CI) create an XSUAA instance, an `apiaccess` instance and a SAML trust in a real BTP subaccount, run `src/__tests__/integration/xsuaa/`, and remove everything — also on failure. The scripts refuse unless `cf target` matches `XSUAA_CF_API`, `XSUAA_CF_ORG` and `XSUAA_CF_SPACE` exactly — a developer's `cf` may point at a production org — and touch only what `setup.sh` recorded in `.local/owned` — bound to that API/org/space and to each resource's GUID or id, re-checked before every reuse, refresh or delete; a name held by any other resource is refused or left alone. A failed teardown stops, keeps `.local/`, and the run exits non-zero. The test IdP's key is generated per run into the gitignored `tests/xsuaa/.local/` — unlike the stand's fixtures, this key is trusted by a real subaccount, so it must never be committed. `btp create security/trust` only trusts IAS tenants; a custom SAML IdP goes through the `apiaccess` plan's `/sap/rest/identity-providers` (SAP Community calls the plan deprecated; SAP Help still documents it).

Two conventions worth knowing, each of which has cost a debugging round:

- **Attach a rejection expectation before triggering it.** `const rejected = expect(p).rejects.toThrow(…)` first, then deliver the request, then `await rejected`. Awaiting the trigger first leaves the promise unhandled at the moment it rejects, and Jest reports an unhandled rejection instead of a passing assertion.
- **Assert on the port, not on a log line.** Anything claiming a socket was released binds it to prove it. Log output proves nothing — code paths have claimed a port was freed without calling `close()`.

When a test is meant to protect a rule, prove it is load-bearing: break the rule deliberately, watch the test go red, revert. Tests have passed here while the rule they existed to protect could be deleted outright.

## Error classes

All extend `TokenProviderError`, with codes from `@mcp-abap-adt/interfaces-auth`:
`ValidationError` (carries `missingFields[]`), `RefreshError` (carries `cause?`), `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`, and `AssertionValidationError` (carries `check: AssertionCheck`, code `ASSERTION_VALIDATION_ERROR`).

## Plans and specs

Plans under `docs/superpowers/plans/` and specs under `docs/superpowers/specs/` are kept in the tree only while active — not yet implemented and not cancelled. Once fully implemented OR cancelled, delete the file. History lives in git; these directories hold only work in progress.
