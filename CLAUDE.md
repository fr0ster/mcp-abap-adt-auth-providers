# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@mcp-abap-adt/auth-providers` — a TypeScript npm package providing authentication token providers for SAP ABAP ADT via Model Context Protocol (MCP). Each provider implements `ITokenProvider` for one grant type or protocol:

- **`ClientCredentialsProvider`** — `client_credentials`, no user interaction
- **`AuthorizationCodeProvider`** — UAA authorization code, interactive
- **`DeviceFlowProvider`** — UAA device flow, interactive but headless
- **`OidcBrowserProvider`** — OIDC authorization code with PKCE, interactive
- **`OidcDeviceFlowProvider`**, **`OidcPasswordProvider`**, **`OidcTokenExchangeProvider`**
- **`Saml2BearerProvider`** — SAML assertion exchanged for an OAuth2 token
- **`Saml2PureProvider`** — SAML assertion exchanged for session cookies

All extend `BaseTokenProvider`, which owns the token lifecycle (cache, expiry, refresh-then-login fallback).

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

**Interface-only communication.** All interaction with external dependencies happens through interfaces from `@mcp-abap-adt/interfaces`. The package does not know about concrete implementation classes from other packages. A logger is `ILogger`, never a local abstraction.

**Everything pluggable is a strategy.** Anything a consumer might reasonably want to do differently is expressed as a strategy behind an interface. The package ships a working default so nobody is forced to write one, and the consumer can always replace it. This is why an authorization library does not own a socket, a browser or stdin — a consumer may legitimately own them instead.

**Nothing writes to `process.stdout`.** Under an MCP or LSP stdio transport, stdout carries protocol traffic, and a stray line corrupts it. Prompts go to the `ILogger` when there is one and to `process.stderr` when there is not — see `src/auth/announce.ts`. A prompt that vanishes without a logger is also a bug: a user who cannot see a device code cannot finish the flow.

### Package responsibilities

This package ONLY:
- implements `ITokenProvider`
- builds authorization URLs and exchanges codes, assertions and refresh tokens for tokens
- ships default strategies for conducting an interactive authorization

This package does NOT:
- store tokens (`@mcp-abap-adt/auth-stores`)
- orchestrate authentication (`@mcp-abap-adt/auth-broker`)
- load service keys or manage sessions
- decide how a user reaches an authorization URL, or where the redirect is received — the consumer may replace both

### Module structure

```
src/
├── index.ts                  # public surface: providers, strategies, callback factories, errors
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
│   └── …                     # oidcToken, oidcDiscovery, oidcPkce, deviceFlowAuth, …
├── sso/                      # SsoProviderFactory
└── errors/TokenProviderErrors.ts
```

### How an interactive login works

A provider owns what it can compute: the authorization URL and the token exchange. Everything between them belongs to an `IAuthorizationStrategy`:

1. the provider hands the strategy an `AuthorizationRequest` carrying `buildAuthorizationUrl(redirectUri)`;
2. the strategy decides where the redirect will be received, then asks for the URL — that ordering is what makes an ephemeral port possible, since the URL cannot be assembled before the socket is bound;
3. the strategy returns an `AuthorizationOutcome` carrying the payload **and** the redirect URI that actually took part, because the token exchange must send the same one.

Ship-default strategies: `browserCallbackStrategy`, `oidcCallbackStrategy`, `samlCallbackStrategy`, `manualPasteStrategy`, `manualSamlResponseStrategy`, `externalCodeStrategy`, `staticCodeStrategy`.

**Lifecycle: whoever constructs, disposes.** A consumer-supplied strategy is never disposed by a provider — the point of a long-lived receiver is to outlive one login. A default the provider constructed itself is disposed from a `finally`, and a `dispose` failure is logged rather than allowed to replace the error that made the login fail. `dispose()` disables a strategy permanently, which is why providers construct a fresh default per login.

### Callback server

`runCallbackScope` owns the socket for the duration of one scope. It is released on the first terminal outcome — the body returning or throwing, an explicit failure, the timeout, or an abort — and the factory settles only once the port is actually free, so a settled promise always means the socket is gone.

- `port: 0` binds an ephemeral port; `handle.port` and `handle.redirectUri` report what the OS gave. Not usable where the redirect is registered with the identity provider, as a SAML ACS always is.
- The default port is **61001** — above Linux's `ip_local_port_range` (32768–60999) and clear of the 3001/3333 range application servers use. The default login timeout is 30 s.
- A `/callback` carrying neither a payload nor an explicit error is answered `400`, counted, and **ignored** — the login keeps waiting, bounded by the timeout, whose message reports how many such requests arrived. An explicit `error=` from the provider still ends the login at once.

## Testing

**Unit tests** mock axios or the module boundary. **Integration tests** need `tests/test-config.yaml` (copy `tests/test-config.yaml.template`) and skip without it.

Two conventions worth knowing, each of which has cost a debugging round:

- **Attach a rejection expectation before triggering it.** `const rejected = expect(p).rejects.toThrow(…)` first, then deliver the request, then `await rejected`. Awaiting the trigger first leaves the promise unhandled at the moment it rejects, and Jest reports an unhandled rejection instead of a passing assertion.
- **Assert on the port, not on a log line.** Anything claiming a socket was released binds it to prove it. Log output proves nothing — code paths have claimed a port was freed without calling `close()`.

When a test is meant to protect a rule, prove it is load-bearing: break the rule deliberately, watch the test go red, revert. Tests have passed here while the rule they existed to protect could be deleted outright.

## Error classes

All extend `TokenProviderError`, with codes from `@mcp-abap-adt/interfaces`:
`ValidationError` (carries `missingFields[]`), `RefreshError` (carries `cause?`), `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`.

## Plans and specs

Plans under `docs/superpowers/plans/` and specs under `docs/superpowers/specs/` are kept in the tree only while active — not yet implemented and not cancelled. Once fully implemented OR cancelled, delete the file. History lives in git; these directories hold only work in progress.
