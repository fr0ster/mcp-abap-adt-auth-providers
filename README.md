# @mcp-abap-adt/auth-providers
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

Every implementation of `IAuthProvider` for SAP ABAP ADT: the credential a
process delegates to, and the token providers behind it.

Token providers, the Basic/Certificate/SAML/Token credentials and passwordless
SNC logon are each an `IAuthProvider` the process takes as it is — whether it
is handed over directly to a connection, or through
`@mcp-abap-adt/auth-broker` for the stateful token API
(`getTokens()`/`refreshTokens()`).

## Migrating to 5.0.0 — a migration, not an update

5.0.0 is not an incremental release. Every provider here now implements
`IAuthProvider` (`@mcp-abap-adt/interfaces-auth` 3.0.0) and can be handed to
the process with no wrapper and no check of what it is — which is what a
consumer **migrates** to, building its providers from this package and
handing them to a `@mcp-abap-adt/connection` **10.0.0** process, rather than
updating in place; 9.x speaks the old, narrower `IAuthProvider`.

- **Credentials come from here, not from `@mcp-abap-adt/connection`.**
  `BasicAuthProvider`, `CertificateAuthProvider`, `SamlAuthProvider`,
  `TokenAuthProvider` and `FileCertificateMaterialLoader` moved into this
  package (`src/credentials/`); `connection` 10.0.0 removes its own copies.
  Import them from `@mcp-abap-adt/auth-providers` instead.
- **A token provider is handed to the process as it is.**
  `BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider`, so
  every token provider — `AuthorizationCodeProvider`, `ClientCredentialsProvider`,
  `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`,
  `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `Saml2PureProvider`,
  `UaaPasscodeProvider` — **is** an `IAuthProvider`, with no `TokenAuthProvider`
  wrapper around it. The broker's token API (`getTokens()` / `refreshTokens()`)
  is unchanged.
- **A store that persisted after `getTokens()` passes `onTokens` instead.**
  Every token provider's config takes an optional
  `onTokens?: (result: ITokenResult) => Promise<void>`, called after every
  *new* token — a login or a refresh, never a cache hit — and awaited before
  the provider answers. It is best effort: a failing `onTokens` is logged (in
  fixed words only, since it holds the tokens) and does not fail the
  authentication.
- **Nothing is defaulted any more.** A provider that used to build its own
  strategy, SAML validator, replay store or device-code output now takes it
  explicitly in its constructor — or the consumer calls the named factory:
  `AuthorizationCodeProvider.inBrowser`, `OidcBrowserProvider.inBrowser`,
  `Saml2PureProvider.inBrowser`, `Saml2BearerProvider.inBrowser`,
  `UaaPasscodeProvider.fromTerminal`, `OidcDeviceFlowProvider.toConsole`,
  `CertificateAuthProvider.fromFiles`, `SncLogonProvider.forSecureLoginClient`.
  Omitting `authorization` (or, for the SAML providers, `assertionValidator`)
  no longer compiles.
- **SAML trust configuration moved.** `idpCertificates`, `clockSkewMs` and
  `assertionReplayStore` are no longer fields of `Saml2BearerProviderConfig` /
  `Saml2PureProviderConfig`; both now take `assertionValidator:
  IAssertionValidator` directly (still required, together with `idpEntityId`
  for a shipped validator). Build one yourself with
  `createSignedResponseValidator` / `createSignedAssertionValidator`, or call
  `Saml2PureProvider.inBrowser(config, trust)` /
  `Saml2BearerProvider.inBrowser(config, trust)` with a `SamlTrust`
  (`{ idpCertificates, clockSkewMs?, replayStore? }`) — the recipe builds the
  shipped validator and defaults `replayStore` to `defaultReplayStore`.
- **`ShippedValidatorOptions.replayStore` is required.** A direct call to
  `createSignedResponseValidator` / `createSignedAssertionValidator` must now
  pass one — `defaultReplayStore`, or your own.
- **Manual strategies take `timeoutMs` and can be disposed.**
  `manualPasteStrategy`, `manualSamlResponseStrategy` and
  `manualPasscodeStrategy` accept `timeoutMs?: number`; on expiry, or when
  `dispose()` is called, the pending read is abandoned with a
  `BrowserAuthError` and the terminal `readline` it opened is closed —
  `dispose()` ends every concurrent `authorize()`, and resolves once all
  have settled. `read`
  is now `(prompt: string, signal: AbortSignal) => Promise<string>` — the
  signal aborts on timeout or dispose, and a custom `read` that ignores it
  still loses the race.
- **Needs `@mcp-abap-adt/connection` 10.0.0.**

## Passwordless RFC logon (SNC)

`SncLogonProvider` logs an on-premise system on over `RfcTransport` with no
password, through an installed SNC product — typically the SAP Secure Login
Client, holding a certificate from SAP Secure Login Service or Kerberos.
Measured 2026-09-29 against an on-premise system (Windows, Secure Login
Client 3.0.3): the SNC logon, discovery, reads and LOCK/UNLOCK all succeeded
over `RfcTransport`, each RFC conversation its own SNC logon at roughly
1–1.5 s. See [docs/passwordless-sso.md](docs/passwordless-sso.md) for the
HTTP alternatives, which remain undecided.

**Prerequisites:** the SNC product is installed and can log on to the profile
used for SAP applications (it need not be running beforehand — see the probe
rule below); the ABAP system accepts SNC for RFC and maps the
certificate's SNC name to a user; and, for the `RfcTransport` wire itself, the
machine has the SAP NW RFC SDK and `@mcp-abap-adt/sap-rfc-lite` installed.
This package itself depends on neither — it produces logon parameters and
loads nothing.

The usual choice:

```typescript
import { SncLogonProvider } from '@mcp-abap-adt/auth-providers';

const provider = SncLogonProvider.forSecureLoginClient({
  partnerName: 'p:CN=<system SNC name>', // the ABAP system's SNC name
});
```

`forSecureLoginClient` assembles `nodeSncSystem()` (the machine seam),
`DefaultSncLibraryLocator(system, sncLib)` and `[SecureLoginClientProbe(system)]`
— "this machine, library discovery, the Secure Login Client probe". `qop`
defaults to `'9'` (maximum, one of `'1' | '2' | '3' | '8' | '9'`), and
`myName` is sent only when set.

The explicit assembly, for a different SNC product, or a locator/probe of
your own (no implicit defaults — a constructor takes every collaborator):

```typescript
import {
  SncLogonProvider,
  DefaultSncLibraryLocator,
  SecureLoginClientProbe,
  nodeSncSystem,
} from '@mcp-abap-adt/auth-providers';

const system = nodeSncSystem();
const provider = new SncLogonProvider({
  partnerName: 'p:CN=<system SNC name>',
  locator: new DefaultSncLibraryLocator(system /*, sncLib */),
  probes: [new SecureLoginClientProbe(system)], // [] to name no product
});
```

**Discovery order and skip rule.** With no explicit `sncLib`,
`DefaultSncLibraryLocator` tries, in order: the environment variable
`SNC_LIB_64` (on a 64-bit process), `SNC_LIB`, the Windows registry
`HKLM\Software\SAP\SecureLogin\InstallPath64` (`InstallPath32` on a 32-bit
process) plus `lib\sapcrypto.dll`, then the macOS bundle `/Applications/Secure
Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib`. An unusable
candidate — missing, not a recognised library, or built for the wrong
architecture — is **skipped**, its reason kept, rather than failing the whole
search; empty or whitespace environment variables count as unset. Nothing
usable → `prepare()` is Oops listing every candidate tried, each as its source,
its path and its reason, e.g. "no usable SNC library was found: SNC_LIB
`<path>` (wrong architecture); registry `<path>` (missing)" — the source is one
of `SNC_LIB_64`, `SNC_LIB`, `registry`, `macOS bundle`, and the reason one of
`missing`, `not a library`, `wrong architecture`; no error message is ever
part of it, and it needs no logger. An **explicit** `sncLib` is the only
candidate: unusable, and the Oops names that one — "no usable SNC library was
found: sncLib `<path>` (missing)" — with no fallback to automatic discovery.
The hint is always "set sncLib to the SNC (GSS) library of your SNC product".
Architecture comes from the
file header — PE `Machine`; Mach-O thin and universal (`FAT_MAGIC` /
`FAT_MAGIC_64`); ELF `e_machine` — because the trap this guards against is
measured, not theoretical: the Secure Login Client installer sets the
machine-wide `SNC_LIB` to its x86 library, and a 64-bit Node process needs the
x64 one the registry points at.

**The probe rule — the product is named, not checked.** A probe
(`ISncProductProbe { product; appliesTo(libraryPath) }`) only says which
product is behind the library, so that `rejected()` can say what to do.
`SecureLoginClientProbe` applies to a library inside the Secure Login
Client's own installation (the registry's install paths on Windows, matched
case-insensitively; the app bundle on macOS); any other SNC library
(`gsskrb5.dll`, another vendor's) has no product named. `prepare()` only
resolves the library and notes which probe applies — nothing about the
product is checked before logon, not that it runs, not that a profile is
logged on. `prepare()` is therefore Ok with the client not running. Measured
2026-09-29 (Windows, Secure Login Client 3.0.3): with the client exited, the
RFC open through its `sapcrypto.dll` **started the client**, which logged on —
silently through the identity provider's SSO, or through its logon window. A
"not running" refusal would have stopped logons that succeed. What follows
for a consumer: **an RFC open can wait on the client's logon window** until
the user answers it. Only the shipped `SecureLoginClientProbe` (recognised by
class) yields the Secure Login Client hint; a probe of your own names its
product in the log, never in a refusal.

**The two explained failures**, from `rejected()` — the RFC SDK reports both
as a generic communication error, so the cause is found by searching the GSS
error text (never returned; only fixed wording and an allowlisted key go out):

- **`A2200019`** — reason "the SNC library has no credential to present
  (A2200019)"; hint "log on in the Secure Login Client, to the profile used
  for SAP applications" when the Secure Login Client probe applied, otherwise
  "make sure the SNC product behind `<library>` is logged on". Measured
  2026-09-29: with the client logged out, closing its logon window failed the
  RFC open with `GSS-API(min): A2200019:Operation aborted by user or
  application`, and `rejected()` answered with this reason.
- **`SNCERR_INIT`** (or "gssapi library invalid/missing") — reason "the RFC
  SDK could not initialise `<library>` as its SNC library (SNCERR_INIT)", no
  hint — usually the architecture mismatch above, if a mismatched library
  somehow reached this point.
- anything else — reason "SNC logon refused", plus the SDK's error key in
  parentheses when it is on the RFC-key allowlist (`RFC_LOGON_FAILURE`,
  `RFC_COMMUNICATION_FAILURE`, …) — never the underlying message or object.

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Overview

Every provider here is an `IAuthProvider` (`@mcp-abap-adt/interfaces-auth`
3.1.0) — `prepare()`, `establish()`, `authorize()`, `rejected()`, each answering
an `AuthOutcome` and never throwing — handed to the process as it is:

```typescript
import { AuthorizationCodeProvider } from '@mcp-abap-adt/auth-providers';

const provider = AuthorizationCodeProvider.inBrowser({
  uaaUrl: 'https://...',
  clientId: '...',
  clientSecret: '...',
});
// A connection 10.0.0 process calls prepare() on connect, authorize() per
// request, and rejected() on a 401: one renewal — a refresh, else one login.
```

### What `rejected()` answers

A provider blames its credential — and a token provider renews — only when the
rejection says the credential was refused: status `401`, or the RFC SDK's
`RFC_LOGON_FAILURE`. Anything else is answered with a neutral refusal that
names only the status or the SDK key, and nothing is renewed:

<!-- generated:refusal-table rejected -->
| The rejection | Kind | Basic, certificate, SAML cookies, fixed token | Token providers, `TokenAuthProvider.from` |
|---|---|---|---|
| `401`, `RFC_LOGON_FAILURE` | `credential-refused` | their own refusal: Basic "the user or password was refused"; certificate "the client certificate was refused"; SAML cookies "the SAML session was refused or has expired"; fixed token "the token was refused" | one renewal; Ok only if the credential changed |
| `403` | `system-refused` `not-authorized` | "the credential was accepted, but the user is not authorized (403)" — "check the user's authorizations in the system" | the same, no renewal |
| `3xx`, e.g. `302` | `system-refused` `redirected` | "the system redirected instead of accepting the credential (302)" — "the service may require another logon procedure (single sign-on, an identity provider)" | the same, no renewal |
| `5xx`, e.g. `503` | `system-refused` `system-failed` | "the system failed (503), not the credential" — "try again later" | the same, no renewal |
| any other status, e.g. `404` | `system-refused` `other-status` | "the system answered 404, which is not a credential refusal" | the same, no renewal |
| another RFC key, e.g. `RFC_COMMUNICATION_FAILURE` | `system-refused` `rfc-failure` | at a logon "the RFC logon failed (RFC_COMMUNICATION_FAILURE), not as a credential refusal"; at a request "the RFC call failed (RFC_COMMUNICATION_FAILURE), not as a credential refusal" | the same, no renewal |
| neither a status nor a known key | `system-refused` `unknown` | at a logon "the logon failed (unknown error)"; at a request "the request was refused (unknown error)" | one renewal — the rejection cannot tell |
<!-- /generated:refusal-table rejected -->

`SncLogonProvider` explains a GSS code in the error first (`A2200019`,
`SNCERR_INIT`) — the SDK reports SNC logon failures as a communication
failure — and otherwise answers the same way.

The token providers also implement `IRefreshableTokenProvider` —
`ITokenProvider` plus `refreshTokens()` — for the broker's token API:

- **ClientCredentialsProvider** — `client_credentials`, no user interaction
- **AuthorizationCodeProvider** — UAA/XSUAA authorization code, through a browser
- **UaaPasscodeProvider** — UAA/XSUAA one-time passcode from `/passcode`, the
  login `cf login --sso` uses: SSO without a browser on this machine
- **OidcBrowserProvider** — OIDC authorization code with PKCE
- **OidcDeviceFlowProvider** — OAuth 2.0 device authorization grant (RFC 8628)
- **OidcPasswordProvider**, **OidcTokenExchangeProvider** — password grant and
  token exchange (RFC 8693)
- **Saml2BearerProvider** — a SAML assertion exchanged for an OAuth2 token
  (RFC 7522)
- **Saml2PureProvider** — a SAML assertion exchanged for session cookies

Providers are configured via constructor; `getTokens()` takes no parameters and handles refresh/login internally. `refreshTokens()` obtains a new token even while the cached one looks valid — what a caller holding a 401 needs.

A token is only half of it: whether ADT accepts it depends on the XSUAA client,
the trust and the user configured on the SAP side. What each provider needs
there, and which are usable for ADT at all, is in
[docs/btp-setup.md](docs/btp-setup.md).
Logging on without a password — SAP GUI's SNC single sign-on and its HTTP
equivalents, X.509 client certificates and SPNego — is in
[docs/passwordless-sso.md](docs/passwordless-sso.md).

Since 2.0.0 an interactive login is conducted by an **authorization strategy**
(`IAuthorizationStrategy` from `@mcp-abap-adt/interfaces-auth`) passed as
`authorization`. The provider owns what it can compute — the authorization URL
and the token exchange; everything between them (reaching the URL, receiving
what comes back, the port, how long to wait) belongs to the strategy, which a
consumer may replace wholesale. See
[Choosing an authorization strategy](#choosing-an-authorization-strategy).

Since 5.3.0 a token provider's **client** may authenticate with a client
certificate or a signed assertion instead of a secret — a strategy passed as
`clientAuthentication` — and a token bound to that certificate is presented
only together with it. See [Client authentication](#client-authentication).

Since 4.0.0 both SAML providers **validate the assertion before trusting it** —
its signature, issuer, audience, recipient, time window, the request it answers,
and whether it has been seen before — and must therefore be told which identity
provider to trust. This is a breaking change: a 3.x SAML configuration fails at
construction. See [SAML assertion validation](#saml-assertion-validation).

If you are on an earlier version, see
[Upgrading from 4.0 to 4.1](#upgrading-from-40-to-41),
[Migrating from 3.x to 4.0](#migrating-from-3x-to-40),
[Migrating from 2.x to 3.0](#migrating-from-2x-to-30) and
[Migrating from 1.x to 2.0](#migrating-from-1x-to-20).

## Responsibilities and Design Principles

### Core Development Principle

**Interface-Only Communication**: This package follows a fundamental development principle: **all interactions with external dependencies happen ONLY through interfaces**. The code knows **NOTHING beyond what is defined in the interfaces**.

This means:
- Does not know about concrete implementation classes from other packages
- Does not know about internal data structures or methods not defined in interfaces
- Does not make assumptions about implementation behavior beyond interface contracts
- Does not access properties or methods not explicitly defined in interfaces

This principle ensures:
- **Loose coupling**: Providers are decoupled from concrete implementations in other packages
- **Flexibility**: New implementations can be added without modifying providers
- **Testability**: Easy to mock dependencies for testing
- **Maintainability**: Changes to implementations don't affect providers

### Package Responsibilities

This package is responsible for:

1. **Implementing token provider interface**: Provides concrete implementations of `ITokenProvider` interface defined in `@mcp-abap-adt/interfaces-auth`
2. **Token acquisition**: Handles OAuth2 flows (browser-based, refresh token, client credentials) to obtain JWT tokens
3. **Token validation**: Validates JWT locally by checking exp claim (no HTTP requests)
4. **OAuth2 flows**: Manages browser-based OAuth2 authorization code flow and refresh token flow
5. **SAML assertion validation**: Verifies a SAML assertion — signature, issuer, audience, recipient, time window, request ID, replay — before either SAML provider uses it

#### What This Package Does

- **Implements ITokenProvider**: Provides concrete implementations (`AuthorizationCodeProvider`, `ClientCredentialsProvider`)
- **Handles OAuth2 flows**: Browser-based OAuth2, refresh token, and client credentials grant types
- **Obtains tokens**: Makes HTTP requests to UAA endpoints to obtain JWT tokens
- **Validates tokens**: Validates JWT locally by checking exp claim (no HTTP requests)
- **Returns tokens**: Returns `ITokenResult` with `authorizationToken` and optional `refreshToken`
- **Validates SAML assertions**: Ships two validators (`createSignedResponseValidator`, `createSignedAssertionValidator`) and an in-memory replay store (`defaultReplayStore`); each SAML provider takes its validator as `assertionValidator` — built by the `inBrowser(config, trust)` factory, or supplied by the consumer, who may also supply its own `IAssertionValidator` or `IAssertionReplayStore`

#### What This Package Does NOT Do

- **Does NOT store tokens**: Token storage is handled by `@mcp-abap-adt/auth-stores`
- **Does NOT orchestrate authentication**: Token lifecycle management is handled by `@mcp-abap-adt/auth-broker`
- **Does NOT know about service keys**: Service key loading is handled by stores
- **Does NOT manage sessions**: Session management is handled by stores
- **Does NOT return `serviceUrl` if unknown**: Providers may not return `serviceUrl` because they only handle token acquisition, not connection configuration
- **Does NOT fetch identity provider metadata**: The certificates and entity ID a SAML assertion is checked against come from configuration; reading them from a file or a metadata URL is the consumer's job

### External Dependencies

This package interacts with external packages **ONLY through interfaces**:

- **`@mcp-abap-adt/auth-broker`**: Uses interfaces (`ITokenProvider`, `IAuthorizationConfig`) - does not know about `AuthBroker` implementation
- **`@mcp-abap-adt/logger`**: Uses `Logger` interface for logging - does not know about concrete logger implementation
- **`@mcp-abap-adt/connection`**: Uses connection utilities for token validation - interacts through well-defined functions
- **No direct dependencies on stores**: All interactions with stores happen through interfaces passed by consumers

## Usage

### Basic Usage

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  AuthorizationCodeProvider,
  ClientCredentialsProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

// User token via authorization_code (browser flow)
const authCodeBroker = new AuthBroker({
  tokenProvider: new AuthorizationCodeProvider({
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    authorization: browserCallbackStrategy({ browser: 'system' }),
  }),
});

// Service token via client_credentials (no browser)
const clientCredsBroker = new AuthBroker({
  tokenProvider: new ClientCredentialsProvider({
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
  }),
}, 'none');
```

### Choosing an authorization strategy

`authorization` decides how an interactive login is conducted. Omit it and the
provider builds the callback strategy for its own flow, on the default port —
which is convenient, and is also the only case where the default port applies
without you having chosen it. Every shipped strategy is a plain function
returning `IAuthorizationStrategy`, so a consumer can pass its own instead.

| Strategy | For | What it does |
|---|---|---|
| `browserCallbackStrategy(opts)` | `AuthorizationCodeProvider` | Binds a local callback server, opens the URL, waits for `?code=` |
| `oidcCallbackStrategy(opts)` | `OidcBrowserProvider` | The same, yielding `{ code, state }` |
| `samlCallbackStrategy(opts)` | `Saml2BearerProvider`, `Saml2PureProvider` | The same, receiving a posted `SAMLResponse` |
| `manualPasteStrategy({ redirectUri, read })` | code flows | Shows the URL, reads the pasted code (stdin by default) |
| `manualSamlResponseStrategy({ redirectUri, read })` | SAML flows | Shows the URL, reads the pasted `SAMLResponse` |
| `externalCodeStrategy({ redirectUri, provide })` | either | Hands the assembled URL to your function, takes back the payload |
| `staticCodeStrategy({ redirectUri, payload })` | either | You already hold the payload; the URL is never built |
| your own | any | Implement `IAuthorizationStrategy<TResult>` and pass it |

Options common to the three callback strategies:

| Option | Default | Meaning |
|---|---|---|
| `port` | `61001` (`DEFAULT_CALLBACK_PORT`) | Port to bind. `0` binds an ephemeral one — usable only where the identity provider accepts a loopback redirect on any port, never where a fixed redirect URI is registered |
| `browser` | `'none'` | `'none'` / `'headless'` print the URL; `'system'`, `'auto'`, `'chrome'`, `'edge'`, `'firefox'` open it |
| `callbackServer` | the one this package ships | Your own `CallbackServerFactory`, to reuse a server you already run |
| `openUrl` | the built-in launcher | Receives `(url, browser, redirectUri)` |
| `remoteHint` | the paste hint, only for the shipped UAA transport | Extra guidance printed in `'none'` / `'headless'` mode |
| `signal` | — | `AbortSignal` cancelling the login — the only bound there is (since 6.0.0 no login times out on its own): pass `AbortSignal.timeout(ms)` for a deadline |

Note the `browser` default: **`'none'`, so nothing is opened unless you ask for
it.** The URL is always shown, even with no logger — it falls back to `stderr`,
never stdout, so an MCP/LSP stdio transport is not corrupted. (1.x behaved the
same way; the 1.x README claiming `system` was the default was wrong.)

The three `CallbackServerFactory` implementations are exported too —
`withBrowserCallbackServer`, `withOidcCallbackServer`, `withSamlCallbackServer`
— so a consumer can keep the transport and replace everything around it, or the
reverse.

For the three shipped flows, passing `callbackServer` to a ready constructor is
the way to substitute a transport. The `BrowserCallbackStrategy` class behind
them is exported as well, for the case the constructors cannot express: a
receiver whose payload is none of the three shapes those flows deliver. Its
options are the same, except `callbackServer` is required — there is no default
transport to fall back on when the payload type is your own.

```typescript
import { BrowserCallbackStrategy } from '@mcp-abap-adt/auth-providers';

const strategy = new BrowserCallbackStrategy<MyPayload>({
  callbackServer: withMyOwnCallbackServer, // CallbackServerFactory<MyPayload>
  port: 61001,
  signal: AbortSignal.timeout(300_000), // your bound, if you want one
});
```

#### Bringing your own

```typescript
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';

const fromOurPortal: IAuthorizationStrategy<string> = {
  async authorize(request) {
    const redirectUri = 'https://portal.internal/oauth/callback';
    const url = await request.buildAuthorizationUrl(redirectUri);
    // The redirect URI you return is the one sent to the token endpoint.
    return { payload: await ourPortal.login(url), redirectUri };
  },
  async dispose() { await ourPortal.close(); },
};
```

`dispose` is optional, and whoever constructs a strategy disposes of it: a
strategy you pass in is yours to dispose, one the provider defaulted to is
disposed by the provider.

#### Manual paste over a callback server

With `browserCallbackStrategy` (the UAA transport), login can complete through
either of **two** channels — whichever finishes first wins:

1. **Automatic callback** — `GET /callback?code=...` on the bound redirect URI.
   Works when the browser is on the same machine as the process.
2. **Paste form** — open `http://<this-host>:<port>/` and paste the code (or the
   whole redirected URL). Works when the browser is on a *different* machine,
   since the callback server listens on all interfaces. In `'none'` /
   `'headless'` mode the strategy prints this address for you — with the real
   port and the host left for you to fill in, because the process cannot know
   which of its addresses you can reach.

**The terminal-paste channel is gone.** In 1.x a third channel read the code
from stdin when `process.stdin.isTTY`; `browserCallbackStrategy` has no such
reader, and this is deliberate rather than an oversight — under an MCP or LSP
stdio transport stdin carries the protocol, and an authorization library has no
business consuming it. Reading a pasted code is now a strategy of its own:

```typescript
import {
  AuthorizationCodeProvider,
  manualPasteStrategy,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  uaaUrl, clientId, clientSecret,
  // Binds no socket at all: prints the URL, then reads one line.
  // Defaults to stdin when it is a TTY — pass `read` to source it anywhere else.
  authorization: manualPasteStrategy({
    redirectUri: 'http://localhost:61001/callback',
  }),
});
```

`manualPasteStrategy` reads from stdin only when `process.stdin.isTTY`, and
throws a clear error otherwise rather than consuming a protocol stream. Supply
`read` to take the value from somewhere else entirely — a TUI prompt, an HTTP
request, a file:

```typescript
authorization: manualPasteStrategy({
  redirectUri: 'http://localhost:61001/callback',
  read: async (prompt) => askInOurUi(prompt),
})
```

The `redirectUri` you give it must be the one the identity provider will
redirect to; it is also the one sent to the token endpoint. It defaults to
`http://localhost:61001/callback`.

Both the paste form and `manualPasteStrategy` accept a bare code, `code=...`,
or a full redirected URL — whichever you paste, the code is extracted from it.

> The `extractCode(input)` helper behind that leniency is internal; it is not
> part of the package's exports, contrary to what the 1.1.0–1.2.0 README said.

### Client authentication

How the *client* proves itself to the authorization server — a secret, a
client certificate, a signed assertion — is a strategy too:
`IClientAuthentication` from `@mcp-abap-adt/interfaces-auth` (3.1.0), passed as
`clientAuthentication`. Eight token providers take it:
`ClientCredentialsProvider`, `AuthorizationCodeProvider`, `UaaPasscodeProvider`,
`Saml2BearerProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`,
`OidcPasswordProvider` and `OidcTokenExchangeProvider`. With one, every request
the provider sends to the server — the first token, every refresh, the device
authorization and each device poll, the token exchange — is authenticated by
it. `Saml2PureProvider` sends no token request and takes none.

**Without it nothing changes.** A provider given `clientSecret` sends exactly
the request it sent before 5.3.0, and an OIDC provider with neither stays a
public client that sends only `client_id`.

#### The five strategies

| Factory | What each request carries | Presents a certificate |
|---|---|---|
| `noClientAuthentication()` | `client_id` in the body | no |
| `clientSecretBasic(secret, { encoding: 'raw' \| 'form' })` | `Authorization: Basic base64(clientId:secret)`, each component written as `encoding` says — see [`clientSecretBasic`'s `encoding`](#clientsecretbasics-encoding) | no |
| `clientSecretPost(secret)` | `client_id` and `client_secret` in the body | no |
| `tlsClientCertificate({ material, endpoint? })` | `client_id` in the body, over a TLS connection presenting the certificate; sent to `endpoint`, else the server's mTLS alias of the endpoint, else the configured endpoint | yes |
| `privateKeyJwt({ key, algorithm, keyId?, audience? })` | `client_id`, `client_assertion_type` (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) and `client_assertion`: a JWT signed with `key` | no |

- **`tlsClientCertificate`** takes `material` as an `ICertificateMaterial`
  (`cert` + `key`, or `pfx`, with an optional `passphrase`) or as a loader
  `() => Promise<ICertificateMaterial>` you own. It is read and checked on
  first use, as `CertificateAuthProvider.prepare()` checks its material:
  material with neither a PFX nor both a certificate and its key is refused as
  *the client certificate is incomplete*; material a TLS context cannot be
  built from (a wrong passphrase, a key that is not the certificate's) as *the
  client certificate could not be used*; a certificate past its `notAfter` as
  *the client certificate has expired*. A failed load is not kept — the next
  request loads again.
- **`endpoint` replaces the URL of every request** the provider sends through
  `tlsClientCertificate`, not only the token request. With
  `OidcDeviceFlowProvider` that includes the device authorization, which would
  then go to the token endpoint you named. For the device flow, leave
  `endpoint` out and let discovery's `mtls_endpoint_aliases` route each
  request to its own mTLS alias (give `issuerUrl`, not the endpoints, so there
  is a discovery document to read them from).
- **`privateKeyJwt`** signs with `node:crypto`; `algorithm` is `RS256` (an RSA
  key) or `ES256` (a P-256 key). `key` is PEM text, PEM bytes or a
  `KeyObject`. Claims: `iss` = `sub` = the client id, `aud` = `audience`, else
  the draft's `tokenEndpoint` (the token endpoint, also for the device
  authorization), else the endpoint the request goes to, a random `jti`, `iat` now, `exp` 60 seconds
  later; a `kid` header when `keyId` is given. A key that is not a private key
  of that algorithm is refused on first use as *the client signing key could
  not be used*, and nothing of the key is in the refusal.
- **Your own.** Anything implementing `IClientAuthentication` — a JWT signed
  by an HSM, say. `authenticate(draft)` gets the endpoint, the server's mTLS
  alias when there is one, the client id and the grant type (no secret, no
  previous response) and returns `{ endpoint?, parameters?, headers? }`;
  `tlsMaterial?()` returns the certificate it presents, if any. What it returns
  is checked before anything is sent: only string values; no header with a
  line break; no parameter or header replacing one of the request's own
  (`grant_type`, `Content-Type`, …); an endpoint that is an absolute `https:`
  URL — `http:` only when the configured endpoint is itself `http:` and no
  certificate is presented. Anything else is a
  `ClientAuthenticationResultError`, refused as *the client authentication
  returned a request that cannot be sent*. Only `client_secret`,
  `client_assertion` and a Basic credential are known to be secrets and
  redacted from what the server said — which, since 5.4.2, the package
  writes nowhere: not on a thrown error, not in a log line; the redaction
  stays as defence in depth. Every secret is redacted as sent, encoded —
  each character, unreserved ones included, as itself or percent-escaped in
  either case, a space also as `+` — and form-decoded (the whole value: `&`
  and `=` are part of it, a malformed `%` stays), and any base64 in the body
  (either alphabet, any padding, escaped or not, broken by spaces, tabs or
  line breaks) that decodes to text holding a secret is redacted too (since
  5.4.2). Limits: an escape escaped again
  (`%252F`) and an echo truncated inside a secret are not recognised, and a
  secret of one or two characters is redacted wherever it appears, unrelated
  words included — so with either `encoding`, and for a `clientSecret` sent without a
  strategy, neither the original, the encoded secret nor what a decoding
  server read survives its echo. Without a strategy, the Basic header a
  provider builds from `clientId` and `clientSecret` is redacted the same way
  — its base64 credential and its secret (since 5.4.2; earlier versions left
  an echoed base64 credential, from which `id:secret` decodes). A secret your
  strategy puts in any other parameter or header is not recognised as one.

```typescript
import { readFile } from 'node:fs/promises';
import {
  ClientCredentialsProvider,
  OidcPasswordProvider,
  privateKeyJwt,
  tlsClientCertificate,
} from '@mcp-abap-adt/auth-providers';

// A client certificate: the token request goes over mTLS, no secret anywhere.
const service = new ClientCredentialsProvider({
  uaaUrl: 'https://<idp>',
  clientId: 'my-client',
  clientAuthentication: tlsClientCertificate({
    material: async () => ({
      cert: await readFile('/etc/my-app/client.crt'),
      key: await readFile('/etc/my-app/client.key'),
    }),
    endpoint: 'https://<idp>/oauth/token',
  }),
});

// A signed client assertion instead of a secret.
const user = new OidcPasswordProvider({
  issuerUrl: 'https://<keycloak>/realms/<realm>',
  clientId: 'my-client',
  username: 'user',
  password: 'secret',
  clientAuthentication: privateKeyJwt({
    key: await readFile('/etc/my-app/signing.key'),
    algorithm: 'RS256',
  }),
});
```

#### Rules a provider keeps

- **`clientSecret` and a strategy together are a `ValidationError`** naming
  `clientSecret`, thrown by the constructor: two ways of authenticating one
  client is a mistake, not a preference. The check is for presence, not value
  — `clientSecret: ''` beside a strategy is refused too, so a consumer mapping
  a service key without a secret must leave `clientSecret` out rather than set
  it empty. Where `clientSecret` was required (`ClientCredentialsProvider`,
  `AuthorizationCodeProvider`), a strategy satisfies the requirement instead.
- **One certificate per provider, pinned.** The provider calls the strategy's
  `tlsMaterial()` once — before its first request to the server or its first
  logon, whichever comes first — checks the material, computes the
  `x5t#S256` thumbprint of its leaf certificate, and keeps a copy of both for
  its lifetime. Every later token request, refresh and logon uses that copy;
  after a successful read `tlsMaterial()` is never called again (a failed read
  pins nothing and refuses the moment that needed it). This holds whatever
  the strategy, your own included. **A certificate that rotates means a new
  provider instance** — the consumer, or the broker, constructs it, as for any
  other change of credential. A token that new provider holds bound to the old
  certificate is renewed, not refused (see below).
- **An expired client certificate is refused before it is sent.** The leaf's
  `notAfter` is checked when the material is pinned and again before every
  token request and logon that presents it: *the client certificate has
  expired*, with nothing sent — and a renewal refused that way keeps its
  refresh token. `CertificateAuthProvider` checks the same in `prepare()` and
  before each logon.
- **No token request follows a redirect**, with a strategy or without — the
  first token, a refresh, the device authorization and its poll, a token
  exchange. A `307`/`308` would re-send the client secret, the refresh token,
  the code, the passcode, the password or the assertion, and present the
  certificate, to wherever it points; a `3xx` fails the request instead.
  Configure the URL the server answers on, not one that redirects to it. OIDC
  discovery, a GET for public metadata that sends no secret, follows redirects
  as before.
- **The server's certificate is always verified, as Node verifies it.**
  `rejectUnauthorized` is never set and there is no `ca` option. A server
  behind a private CA is trusted the way Node offers, explicitly and
  process-wide: `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`, read when Node starts,
  which adds to Node's store rather than replacing it. A TLS failure is refused
  naming its code, with fixed words per kind:

  | Code | Reason (*… failed: …*) | Hint |
  |---|---|---|
  | `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `SELF_SIGNED_CERT_IN_CHAIN`, `DEPTH_ZERO_SELF_SIGNED_CERT`, `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | the server's certificate is not trusted (`<code>`) | if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS |
  | `CERT_HAS_EXPIRED` | the server's certificate has expired (`<code>`) | the server must renew its certificate; check also this machine's clock |
  | `ERR_TLS_CERT_ALTNAME_INVALID` | the host name is not in the server's certificate (`<code>`) | use the host name the server's certificate is issued for |
  | `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`, `ERR_SSL_TLSV1_ALERT_UNKNOWN_CA`, and `ERR_SSL_SSL/TLS_ALERT_…` / `ERR_SSL_SSLV3_ALERT_…` for `BAD_CERTIFICATE`, `CERTIFICATE_UNKNOWN`, `CERTIFICATE_EXPIRED`, `CERTIFICATE_REVOKED`, `UNSUPPORTED_CERTIFICATE` | the server refused the client certificate (`<code>`) | check that the server trusts the certificate's issuer and that the certificate is valid and not revoked |

  The last row is the alert a server sends when it refuses the client
  certificate in the handshake. Current OpenSSL — 3.5, bundled with Node 22
  and 24, and 3.6, both measured — spells the SSLv3-era alerts
  `SSL/TLS_ALERT_…`; older releases spelled them `SSLV3_ALERT_…`, so both are
  listed. Measured 2026-10-04 against `openssl s_server -Verify`:
  no certificate → `…CERTIFICATE_REQUIRED`, an issuer the server does not
  trust → `…UNKNOWN_CA`, an expired certificate →
  `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED`. Any other code is
  *unknown error*.
- **mTLS aliases (RFC 8705 §5).** An OIDC provider that discovers an endpoint
  hands the strategy the server's `mtls_endpoint_aliases` entry for it
  (`token_endpoint`, `device_authorization_endpoint`); `tlsClientCertificate`
  sends there unless it was given `endpoint`. An endpoint given in the
  configuration comes with no alias.
- **A loader that fails with its own error** — a missing file, say — is
  refused as *`<auth type>` token request failed (unknown error, ENOENT)*,
  where `<auth type>` is the provider's `getAuthType()`. The refusal names the
  error's code when it is on the package's allowlist, never its message.
  That is by design (rule 2 of the contract); a loader that wants its own words
  refused throws one of this package's classes.
- **Thrown errors carry no request.** A failed token request rethrows without
  the request it sent — no form body, no `Authorization` header, no TLS agent
  with a key or a passphrase — on both paths, strategy or not. It is still an
  `AxiosError` (`instanceof AxiosError` and `axios.isAxiosError()` hold), but
  a new one built without `config`, `request` or `cause`, so its `toJSON()`
  serialises no config: it keeps `code` and `status`, a rebuilt message
  (`Request failed with status code N`, or `the token request failed (<code>)`
  when no response came), and a `response` of `status`, an empty `statusText`
  (the reason phrase is the server's free text), empty `headers` and the
  server's body reduced to `error` when it is a registered OAuth code
  (`err.response.data.error` still reads `invalid_grant`), and to `{}`
  otherwise. Since 5.4.2 the server's `error_description` and `error_uri` go
  nowhere — no thrown error, no log line: a hostile server can echo any
  secret of the request in them. A failed request is noted in one `debug`
  line through the provider's logger with the same safe facts (`<site>: the
  token endpoint refused the request`, `{ status, error? }`).

#### `clientSecretBasic`'s `encoding`

Servers disagree on how the id and secret inside a Basic credential are
written, so `encoding` is required and has no default — the provider does not
guess:

- `'raw'` — `base64(clientId + ':' + secret)`, as given.
- `'form'` — each of the two first `application/x-www-form-urlencoded`
  (RFC 6749 §2.3.1; a space becomes `+`), then joined and base64'd.

Measured 2026-10-04, each row with the grant named:

| Server | Grant | `raw` | `form` | Source |
|---|---|---|---|---|
| SAP XSUAA (trial) | `client_credentials` | accepted — an id holding `!` and `\|`, a secret holding `$`, `=` and `_` (two keys) | refused (`401`) for that id and secret, as was each component `encodeURIComponent`'d | Measured (trial, 2026-10-04, by hand; not in `test:xsuaa`) |
| Cloud Foundry UAA (v79.7) | `client_credentials` (`ClientCredentialsProvider`) | refused (`401`) for the secret `se+cr%25et/x` | accepted for that secret, and for the id `basic:colon` | Measured (provider stand, `clientSecretBasic.test.ts`) |
| Keycloak (26.7) | `password` (`OidcPasswordProvider`) | refused (`401`) for the secret `se+cr%25et/x` | accepted for that secret, and for the id `basic:colon` | Measured (provider stand, `clientSecretBasic.test.ts`) |

What makes the stand's raw secret fail is its `+` and `%`, which UAA and
Keycloak form-decode (RFC 6749 §2.3.1) into another secret; its `/` is left as
it is by form-decoding. A client id or secret holding a space, or an id
holding `+` or `%`, is not measured: that UAA and Keycloak refuse it raw is
Inference from the same rule. So is how `'form'` fares where the server
percent-decodes per RFC 3986 instead — it would read a space's `+` as a `+`.

For the measured ids and secrets: use `'raw'` for XSUAA and `'form'` for UAA
and Keycloak. An id and secret holding none of the characters form encoding
changes (letters, digits, `*`, `-`, `.`, `_`) are the same in both encodings.
Where neither fits, `clientSecretPost` sends both in the body. With `'raw'`, a client id
containing `:` cannot be carried at all (RFC 7617 splits at the first colon):
each request is refused before anything is sent, *the client id contains ':',
which raw Basic cannot carry*, hint *use encoding: 'form' or
clientSecretPost*. A missing or other `encoding` is a `ValidationError` naming
`encoding`, thrown by `clientSecretBasic` itself. A `401` is reported as the
server's `401`: nothing is inferred from the secret's characters.

#### `privateKeyJwt`'s `audience`

By default the assertion's `aud` is the authorization server's token endpoint
— the draft's `tokenEndpoint`, which every request this package builds
carries, the device authorization included (since 5.3.0); a custom site's
draft without one falls back to the endpoint the request goes to. `audience`
overrides both for every request of the provider. Measured 2026-10-04 on the
provider stand:

- **Cloud Foundry UAA** (v79.7) accepts its issuer, `…/uaa/oauth/token` —
  which is also its token endpoint. Set `audience` to the issuer from its
  discovery when the URL you reach UAA by may differ from the one it calls
  itself.
- **Keycloak** (26.7) accepts the token endpoint (measured with the password
  grant and the whole device flow), but **not the device authorization
  endpoint**: an assertion whose `aud` is that endpoint is refused
  *"invalid_client": "Invalid token audience"*. `OidcDeviceFlowProvider` on
  Keycloak therefore needs no `audience`: the default names the token endpoint
  for the device authorization too. (The issuer,
  `https://<keycloak>/realms/<realm>`, set as `audience` was also measured to
  carry the whole device flow, on 2026-10-04 before this default; the stand
  no longer runs that case.)

#### A certificate-bound token, and its certificate

A token obtained over mTLS may be bound to the certificate (RFC 8705 §3,
`cnf.x5t#S256`): the resource then accepts it only on a connection presenting
that same certificate. So before a token provider presents a token —
`establish()` and `authorize()` — it reads what the token says about its
binding, in one of three states:

- **bound** — a JWT whose payload carries `cnf`; its `x5t#S256` is compared
  with the pinned certificate's thumbprint. A `cnf` that names no
  `x5t#S256` (another kind of binding, an empty one) is bound to a certificate
  the provider cannot match.
- **unbound** — a JWT whose payload carries no `cnf`.
- **unknown** — anything else, an opaque token above all: its binding, if
  any, lives on the server (introspection, RFC 8705 §3.2), and the token
  cannot say.

This applies to every token the provider holds: obtained, refreshed, seeded as
`accessToken`, or restored by a store. `establish(logon)` obtains nothing: it
decides on the token held, and no token, an expired one or one being renewed
counts as unknown — the token presented will be the one `authorize()` obtains
through the same strategy and pinned certificate, and `authorize()` checks
that one.

**After a rotation.** A held token bound to *another* certificate than the
pinned one — restored from a store after the certificate was rotated, say —
or whose `cnf` names no readable thumbprint, is unusable to this provider, and
it treats it like an expired token: `getTokens()` and `authorize()` renew it
once through the strategy and the pinned certificate — the refresh token when
there is one, else (or when the refresh is refused) one login, no step twice —
and the binding check then runs on the new token. Only when the new token is
still bound elsewhere is it refused by `authorize()`, as *the new token is
bound to a client certificate this provider does not present* — and
remembered: later attempts do not renew it again, so a server that keeps
binding to another certificate costs no token request (and no login) per
request. `getTokens()` returns the remembered token; `authorize()` refuses it.
A renewal that *fails* — the refresh and the login refused, the client
certificate expired, the server unreachable — is remembered the same way, with
its own refusal: later attempts answer those same words (*the client
certificate has expired*, say), with no token request and no login (after a
refused refresh every renewal is a login, interactive for a browser or device
strategy), until the token changes. The words are always those of the latest
renewal. Only a token held *bound elsewhere* is remembered: an expired token
whose renewal fails is renewed again on the next attempt, as before. The next `prepare()` renews once more. `rejected()` renews once more when the
refused token is the one held; a refused token that was already superseded is
answered Ok without a renewal (rule 6, as before). `getTokens()` pins the
certificate to compare thumbprints, so with a bound token held it may throw a
`CertificateMaterialError` when the material is unusable or expired. `establish()` reads such a held
token as unknown and presents the pinned certificate. With **no** certificate
pinned there is nothing to renew it for: `getTokens()` returns the token, and
`establish()` / `authorize()` refuse it.

| Token | Certificate pinned | `establish(logon)` | `authorize(request)` |
|---|---|---|---|
| unbound | none | presents nothing, Ok | Bearer, Ok |
| unbound | yes | presents it; Ok even when the logon takes no TLS material (the Bearer carries the token) — a logon target that throws is Oops | Bearer, Ok |
| bound to the pinned one | yes | presents it; a logon that takes no TLS material (RFC) is that logon's Oops | Bearer, Ok |
| bound to another, or `cnf` without a readable thumbprint | yes | read as **unknown**: presents the pinned one (a logon that takes no TLS material is that logon's Oops) | renewed once through the pinned one, the new token checked: Bearer, Ok — or, bound elsewhere again, Oops, no header written |
| bound | none | Oops, nothing presented | Oops, no header written |
| unknown | yes | **treated as bound**: presents it, and a logon that takes no TLS material is that logon's Oops | Bearer, Ok |
| unknown | none | presents nothing, Ok | Bearer, Ok |

The refusals are fixed words, with no thumbprint in them: a bound token and no
certificate pinned is *the token is bound to a client certificate this provider
does not present*, hint *give the provider a clientAuthentication that presents
the certificate the token was issued for*; a renewal still bound elsewhere is
*the new token is bound to a client certificate this provider does not
present*, hint *the authorization server bound the new token to another
certificate: check the certificate registered for this client*. A renewal in
`rejected()` goes through the same strategy and the same pinned certificate,
so a refreshed token is bound to the same certificate, and is checked like any
other.

> **The token API does not present the certificate.** Only the `IAuthProvider`
> methods — `establish()` and `authorize()` — present the pinned certificate
> and check a token's binding. `getTokens()` and `refreshTokens()` (the
> `IRefreshableTokenProvider` side, which the broker's token API uses) return
> the token itself, which may be bound to the certificate: a consumer that
> takes the token from there and sends it on its own connection must present
> the same certificate itself, or the resource refuses it — or use
> `establish()` / `authorize()` instead. `getTokens()` does renew a token bound
> to another certificate than the pinned one (above); it never checks the
> token it returns against a connection it does not own.

> **The opaque-token limit.** A provider learns a binding only from the token
> itself; it does not introspect. An **opaque** token bound to a certificate
> therefore needs the certificate strategy configured on the provider that
> presents it — the certificate is then pinned and the unknown token travels
> with it. Without the strategy the provider has no certificate to present and
> no way to know the token is bound: it sends a plain Bearer, the resource
> answers `401`, and `rejected()` treats that as any refused credential.

#### XSUAA with an x509 service key

An XSUAA instance whose `xs-security.json` allows the `x509` credential type
(`"oauth2-configuration": { "credential-types": ["binding-secret", "x509"] }`)
issues, for a key created with `{"credential-type": "x509"}`, a key that holds
`certificate` (a PEM chain), `key` (its private key) and `certurl` (the mTLS
host) — and no `clientsecret`. This package reads no service key: the consumer
maps those fields.

```typescript
import {
  ClientCredentialsProvider,
  tlsClientCertificate,
} from '@mcp-abap-adt/auth-providers';

// `credentials` as `cf service-key <instance> <key>` prints them.
declare const credentials: {
  url: string;
  clientid: string;
  certificate: string;
  key: string;
  certurl: string;
};

const provider = new ClientCredentialsProvider({
  uaaUrl: credentials.url,
  clientId: credentials.clientid,
  // no clientSecret: the certificate authenticates the client
  clientAuthentication: tlsClientCertificate({
    material: { cert: credentials.certificate, key: credentials.key },
    endpoint: `${credentials.certurl}/oauth/token`,
  }),
});
```

`uaaUrl` is still required; the token request goes to `endpoint` instead of
`<uaaUrl>/oauth/token`, which takes a secret. The key's certificate is
short-lived, so a consumer that keeps a provider for long creates a new key —
and a new provider — before it expires. `npm run test:xsuaa` runs this recipe
against a real XSUAA (see [Testing](#live-checks-against-xsuaa-btp-subaccount)).
ADT answered `401` to a `client_credentials` token obtained this way
(measured on a trial); why is inference — the token carries no user, and its
client is outside the ABAP system's `xsappname`. See
[docs/btp-setup.md](docs/btp-setup.md).

#### Refusals

<!-- generated:refusal-table refusals -->
| When | Kind | Reason | Hint |
|---|---|---|---|
| material without a PFX or without both certificate and key | `client-certificate` `incomplete` | the client certificate is incomplete | give a PFX, or a certificate together with its key |
| material no TLS context accepts | `client-certificate` `unusable` | the client certificate could not be used | check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2) |
| a client certificate past its `notAfter`, when pinned or before a request or logon presents it | `client-certificate` `expired` | the client certificate has expired | renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider |
| a signing key that is not a private key of the algorithm | `client-authentication` `signing-key-unusable` | the client signing key could not be used | check the private key and that it matches the algorithm |
| a strategy's result that cannot be sent | `client-authentication` `result-unsendable` | the client authentication returned a request that cannot be sent | check the client authentication strategy |
| raw `clientSecretBasic` with a client id containing ':' | `client-authentication` `basic-client-id-colon` | the client id contains ':', which raw Basic cannot carry | use encoding: 'form' or clientSecretPost |
| a bound token held, and no certificate pinned | `token-binding` `bound-to-unpinned` | the token is bound to a client certificate this provider does not present | give the provider a clientAuthentication that presents the certificate the token was issued for |
| a token renewed because it was bound to another certificate, and the new one is bound elsewhere too | `token-binding` `renewed-bound-elsewhere` | the new token is bound to a client certificate this provider does not present | the authorization server bound the new token to another certificate: check the certificate registered for this client |
| a TLS failure: `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `SELF_SIGNED_CERT_IN_CHAIN`, `DEPTH_ZERO_SELF_SIGNED_CERT`, `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | `tls` | `<operation>` failed: the server's certificate is not trusted (`<code>`) | if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS |
| a TLS failure: `CERT_HAS_EXPIRED` | `tls` | `<operation>` failed: the server's certificate has expired (`<code>`) | the server must renew its certificate; check also this machine's clock |
| a TLS failure: `ERR_TLS_CERT_ALTNAME_INVALID` | `tls` | `<operation>` failed: the host name is not in the server's certificate (`<code>`) | use the host name the server's certificate is issued for |
| a TLS failure: `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`, `ERR_SSL_TLSV1_ALERT_UNKNOWN_CA`, `ERR_SSL_SSL/TLS_ALERT_BAD_CERTIFICATE`, `ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE`, `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_UNKNOWN`, `ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN`, `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED`, `ERR_SSL_SSLV3_ALERT_CERTIFICATE_EXPIRED`, `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_REVOKED`, `ERR_SSL_SSLV3_ALERT_CERTIFICATE_REVOKED`, `ERR_SSL_SSL/TLS_ALERT_UNSUPPORTED_CERTIFICATE`, `ERR_SSL_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE` | `tls` | `<operation>` failed: the server refused the client certificate (`<code>`) | check that the server trusts the certificate's issuer and that the certificate is valid and not revoked |
<!-- /generated:refusal-table refusals -->

### SSO Providers

This package also includes SSO providers for OIDC and SAML2, plus a small factory for DI-friendly creation.

Available providers:
- `OidcBrowserProvider` (authorization code + PKCE)
- `OidcDeviceFlowProvider`
- `OidcPasswordProvider`
- `OidcTokenExchangeProvider`
- `Saml2BearerProvider` (SAML assertion exchange)
- `Saml2PureProvider` (returns SAMLResponse as token)

Factory example:

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  SsoProviderFactory,
  oidcCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

const tokenProvider = SsoProviderFactory.create({
  protocol: 'oidc',
  flow: 'browser',
  config: {
    issuerUrl: 'https://example-idp/.well-known/openid-configuration',
    clientId: '...',
    clientSecret: '...',
    scopes: ['openid', 'profile', 'email'],
    authorization: oidcCallbackStrategy({ browser: 'system' }),
  },
});

const broker = new AuthBroker({ tokenProvider }, 'none');
```

OIDC browser example (a code you already hold + explicit endpoints):

```typescript
import {
  OidcBrowserProvider,
  asOidcResult,
  staticCodeStrategy,
} from '@mcp-abap-adt/auth-providers';

const redirectUri = 'urn:ietf:wg:oauth:2.0:oob';

const provider = new OidcBrowserProvider({
  clientId: '...',
  tokenEndpoint: 'https://issuer/oauth/token',
  authorizationEndpoint: 'https://issuer/oauth/authorize',
  authorization: asOidcResult(
    staticCodeStrategy({ redirectUri, payload: '<paste-code-here>' }),
  ),
});
```

`asOidcResult` is not optional here. `OidcBrowserProvider` takes
`IAuthorizationStrategy<OidcCallbackResult>`, and the code-producing strategies
(`staticCodeStrategy`, `externalCodeStrategy`, `manualPasteStrategy`) yield a
`string`; passing one directly does not type-check. The adapter wraps the code
as `{ code }` — a value that never travelled through a redirect carries no
`state` to check — and delegates `dispose`, so wrapping costs nothing in
lifecycle terms.

The redirect URI is no longer a provider field: it belongs to the strategy,
because with an ephemeral port nothing knows it until the socket is bound. The
one the strategy reports is the one sent to the token endpoint.

Both SAML providers validate every assertion before using it, so every SAML
example below says whom to trust: an `assertionValidator` built from the
identity provider's certificates, and `idpEntityId`. The recipe
`inBrowser(config, trust)` builds the shipped validator from a `SamlTrust`
(`{ idpCertificates, clockSkewMs?, replayStore? }`); a constructor takes one
you built. See [SAML assertion validation](#saml-assertion-validation) for
what is checked and what else can be configured.

SAML bearer example (UAA or XSUAA — an IdP-initiated assertion):

```typescript
import { readFileSync } from 'node:fs';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import {
  Saml2BearerProvider,
  createSignedAssertionValidator,
  defaultReplayStore,
} from '@mcp-abap-adt/auth-providers';

// The Recipient the assertion names: the URI-binding assertion consumer
// service in the token endpoint's SAML metadata (UAA's is /oauth/token/alias/…).
const acsUrl = 'https://uaa.example.com/oauth/token/alias/uaa.example';

// An IdP-initiated login answers no AuthnRequest, so this strategy never calls
// request.buildAuthorizationUrl — with idpInitiated: true and no
// authorizationUrl, the builder refuses before producing a URL, since the only
// one it could build carries an AuthnRequest. It fetches a fresh assertion on every login;
// the same assertion presented twice is refused as a replay.
const fromSsoProxy: IAuthorizationStrategy<string> = {
  async authorize() {
    return { payload: await getSamlResponseFromSsoProxy(), redirectUri: acsUrl };
  },
};

const provider = new Saml2BearerProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'uaa.example', // the entityID in that metadata: the Audience
  acsUrl,
  uaaUrl: 'https://uaa.example.com',
  clientId: '...',
  clientSecret: '...',
  // Whom to trust: a validator holding the identity provider's signing
  // certificate, and its entity ID.
  assertionValidator: createSignedAssertionValidator({
    idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
    replayStore: defaultReplayStore,
  }),
  idpEntityId: 'https://idp.example.com/metadata',
  // UAA and XSUAA refuse an assertion carrying InResponseTo.
  idpInitiated: true,
  authorization: fromSsoProxy,
});

const broker = new AuthBroker({ tokenProvider: provider }, 'none');
```

**Who starts the login matters.** An identity provider answering an
`AuthnRequest` — which is what the provider's own URL carries, and so what every
shipped strategy that opens or shows that URL sends — puts `InResponseTo` on
the assertion's subject confirmation. The saml2-bearer grant of Cloud Foundry UAA and of SAP
XSUAA refuses any assertion that carries it: there is no request on their side
to match it against, and UAA's `disableInResponseToCheck` applies to web SSO
only. Measured: UAA, with Keycloak as the identity provider, refuses the answer
to an SP-initiated login with *"SubjectConfirmationData/@InResponseTo … did not
match the valid value: null"*, and XSUAA — measured with 3.x, which sent such an
assertion on — refuses one carrying `InResponseTo` with *"No subject
confirmation methods were met"*; both accept an IdP-initiated one — started at
the IdP, answering no request. (4.0 refuses that case itself, at
`bearerConfirmation`, before XSUAA sees it.) Against either,
supply an IdP-initiated assertion, declare `idpInitiated: true`, and use a
strategy that does not call
`buildAuthorizationUrl`: `staticCodeStrategy`, or your own as above.
`samlCallbackStrategy`, `manualSamlResponseStrategy` and `externalCodeStrategy`
all call it, and with `idpInitiated: true` and no `authorizationUrl` the builder
refuses: a `ValidationError` (`missingFields: ['authorizationUrl']`) thrown
before any URL is produced, so before a browser opens. (3.0's advice —
`externalCodeStrategy` whose `provide` ignores the URL — no longer works for
that reason.) See
[Where the expected request ID comes from](#where-the-expected-request-id-comes-from).

The `redirectUri` your strategy reports is the ACS the assertion is checked
against — its `SubjectConfirmationData/@Recipient` must equal it — so for the
bearer grant it is the token endpoint's bearer ACS, not a local callback.

**What is sent.** The saml2-bearer grant takes one SAML Assertion,
base64url-encoded (RFC 7522 §2.1). A strategy may deliver either that or the
whole `SAMLResponse` an identity provider posts, in standard base64 —
`Saml2BearerProvider` validates what it received, then takes the Assertion out
of a Response and re-encodes it, copying onto it every namespace declaration it
inherited — including one used only inside a value such as
`xsi:type="xs:string"`. The Assertion must carry its own signature: one over the
Response alone does not survive the cut, and the token endpoint refuses the
Assertion — which is why the validator this provider's `inBrowser` recipe
builds is the one that requires the Assertion to be signed. An `EncryptedAssertion` is refused before
anything is sent.

**Refresh.** When the token endpoint returns a `refresh_token` with the SAML
bearer exchange, `Saml2BearerProvider` spends it once the access token expires:
a `refresh_token` grant to the same endpoint (`tokenUrl`, or `uaaUrl` +
`/oauth/token`) with the same client credentials, and no assertion, strategy or
browser involved. Pass a stored one back as `refreshToken` in the config and the
next `getTokens()` uses it. If the grant is refused, or no refresh token was
ever issued, the provider falls back to a full login through `authorization`.

Pure SAML example (cookie-based, SP-initiated):

```typescript
import { readFileSync } from 'node:fs';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  Saml2PureProvider,
  createSignedResponseValidator,
  defaultReplayStore,
  manualSamlResponseStrategy,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2PureProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl,
  assertionValidator: createSignedResponseValidator({
    idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
    replayStore: defaultReplayStore,
  }),
  idpEntityId: 'https://idp.example.com/metadata',
  // Shows the URL the provider builds — so the response must answer that
  // request's ID — and reads the pasted SAMLResponse.
  authorization: manualSamlResponseStrategy({ redirectUri: acsUrl, read: promptUser }),
  // Convert SAMLResponse to session cookies for SAP (implementation-specific)
  cookieProvider: async (samlResponse) => {
    return exchangeSamlForCookies(samlResponse);
  },
});

const broker = new AuthBroker({ tokenProvider: provider }, 'none');
```

`cookieProvider` receives the payload unchanged, only after it has been
validated, and the session's `expiresAt` is the validated assertion's expiry.

**Stored cookies.** Pass cookies a previous login obtained as `accessToken`,
with the `expiresAt` they were obtained with (epoch ms — `onTokens` and
`getTokens()` report it). Until `expiresAt`, less a one-minute buffer, the
provider presents them and runs no login: no strategy, no validator, no
`cookieProvider`. Past it — or with no `expiresAt`, since cookies carry no
expiry of their own — the first `getTokens()` or `authorize()` logs in as
above. There is no `refreshToken`: SAML has none, so renewal is a new login.
See [Seeding a stored credential](#seeding-a-stored-credential).

**Read that `redirectUri` twice.** A SAML strategy defaults its redirect URI to
`http://localhost:61001/callback`, and the provider requires the assertion
consumer service the IdP posts to be exactly the one the strategy names. If you
declare a real `acsUrl` and leave `redirectUri` off, the login fails with
*"SAML acsUrl is … but the authorization strategy is listening on …"* before
anything is opened. Declare neither and the default is used for both, which is
consistent — and only reachable when the IdP will post to your localhost.

Both SAML providers now reject at construction when `authorizationUrl` is set
without `acsUrl`:

```
acsUrl is required when authorizationUrl is set: the ACS inside a pre-built
SAML request cannot be read, so it must be declared.
```

The ACS is buried in a deflated `SAMLRequest` this package did not build and
cannot read, so it cannot be verified against whatever the strategy binds. 1.x
accepted the combination and defaulted the ACS to
`http://localhost:3001/callback` — usually not where the IdP posted. The same
holds for the request ID: this package cannot read it out of a URL it did not
build, so a pre-built `authorizationUrl` also needs `authnRequestId` — unless
the login is declared `idpInitiated`.

### SAML assertion validation

Since 4.0.0, `Saml2BearerProvider` and `Saml2PureProvider` validate the
assertion a login delivers before anything else happens to it — before the
token exchange, before `cookieProvider`. Until 3.x nothing verified it: the
callback checked only that the payload was non-empty, and `Saml2PureProvider`
took its session lifetime from a regular expression over the unverified XML.

**Whom to trust is required.** Since 5.0.0 each provider takes its validator
as `assertionValidator` — a shipped one built from the identity provider's
certificates, or your own — and omitting it does not compile. A shipped
validator supplied without `idpEntityId` fails at construction — a
`ValidationError` whose `missingFields` names it — before any browser opens or
any request is sent. `inBrowser(config, trust)` is the recipe that builds the
shipped validator from a `SamlTrust`.

#### Configuration

On both providers' configuration (`Saml2BearerProviderConfig`, `Saml2PureProviderConfig`):

| Field | Default | Meaning |
|---|---|---|
| `assertionValidator` | — | **Required.** An `IAssertionValidator`: `createSignedResponseValidator(…)`, `createSignedAssertionValidator(…)`, or your own. The provider builds none of its own |
| `idpEntityId` | — | The `Issuer` the assertion must name, passed to the validator as `expectedIssuer`. **Required unless the `assertionValidator` supplied is your own**: a shipped validator refuses every assertion without an expected issuer, so supplying one without `idpEntityId` fails at construction. A custom validator does not need it, and receives it when given |
| `spEntityId` | — | Your entity ID. The assertion's `AudienceRestriction` must name it — whichever validator is in play |
| `authnRequestId` | — | The AuthnRequest ID this login answers, when the package did not build the request — see [Where the expected request ID comes from](#where-the-expected-request-id-comes-from) |
| `idpInitiated` | `false` | Declares that no AuthnRequest was sent, so the assertion must carry no `InResponseTo`. Required for `Saml2BearerProvider` against UAA or XSUAA |

Trust itself — the certificates, the clock skew, the replay store — is not a
provider field. It is on the shipped validator's options
(`ShippedValidatorOptions`), or on the `SamlTrust` the `inBrowser` recipe
takes:

| Field | Default | Meaning |
|---|---|---|
| `idpCertificates` | — | The identity provider's signing certificates, PEM or bare base64 DER — the form `<X509Certificate>` has in IdP metadata. A list, because providers rotate keys and two are live during a rotation. Each entry is parsed when the validator is built, so a malformed one fails there, not at login |
| `replayStore` | — on `ShippedValidatorOptions` (required); `defaultReplayStore` in the `inBrowser` recipe | An `IAssertionReplayStore` — see [Replay](#replay) |
| `clockSkewMs` | `0` | Tolerance for the time checks — see [Clock skew](#clock-skew) |

The package performs no I/O for any of these: it fetches no metadata and reads
no file. Reading the certificate is the consumer's job.

#### Choosing a validator

This is the first decision to make, and **the `inBrowser` recipe chooses
differently per provider**:

| | `createSignedResponseValidator` | `createSignedAssertionValidator` |
|---|---|---|
| The signature must cover | the `Response` | the `Assertion` — bare, or inside a Response |
| Built by `inBrowser` of | `Saml2PureProvider` | `Saml2BearerProvider` |
| Reads `Status`, `Response/Issuer`, `Destination` | yes — inside the signature | **not at all** |
| Accepts a bare `saml:Assertion` | no | yes |
| Checks performed | all twelve below | all but rows 4, 5b and 11 |

Both take the same options (`ShippedValidatorOptions`) and return the same
interface, so switching is one identifier:

```typescript
import { readFileSync } from 'node:fs';
import {
  Saml2PureProvider,
  createSignedAssertionValidator,
  defaultReplayStore,
  samlCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

const idpCertificates = [readFileSync('idp-signing.pem', 'utf8')];

const provider = new Saml2PureProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl: 'https://sp.example.com/saml/acs',
  // Still required with a shipped validator, which refuses every assertion
  // without an expected issuer; construction fails without it.
  idpEntityId: 'https://idp.example.com/metadata',
  // Our identity provider signs only its assertions.
  assertionValidator: createSignedAssertionValidator({
    idpCertificates,
    clockSkewMs: 30_000,
    replayStore: defaultReplayStore,
  }),
  authorization: samlCallbackStrategy(),
  cookieProvider: exchangeSamlForCookies,
});
```

**`createSignedResponseValidator`** requires the identity provider to sign the
`Response`. Every field all twelve checks read is then inside the signature, so
every check is a control. It is what `Saml2PureProvider.inBrowser` builds because there the
whole response is handed on to `cookieProvider`, and `Status` and `Destination`
must be inside a signature.

**`createSignedAssertionValidator`** accepts a signature over the `Assertion`,
and **does not read** `Status`, `Response/Issuer` or `Destination` at all — not
weakly: with an assertion-only signature those fields sit outside it, where
anyone able to deliver a response sets them to whatever is expected, and a check
on a field an attacker controls reads in the code and the logs as if something
had been verified. It is what `Saml2BearerProvider.inBrowser` builds because the token
endpoint receives the Assertion alone, taken out of any Response, so the
Assertion's own signature is what counts there. Configuring the signed-Response
validator on the bearer path would refuse a bare Assertion, and accept responses
signed only at the Response level, which the token endpoint then refuses.

**Who needs the second one.** Identity providers that sign only assertions —
which is many. A `Saml2PureProvider` consumer whose IdP does so gets a
`signedNode` refusal from the recipe's validator, and selects
`createSignedAssertionValidator` explicitly. What that gives up is the three
checks above. It is still sound:

- **`Status`** — a declined login carries no assertion. An identity provider
  that refuses does not mint one, so flipping `Status` to `Success` leaves an
  attacker with nothing signed to put beneath it. Success is established by a
  signed assertion passing every assertion-level check.
- **`Destination`** — addressing rests on
  `SubjectConfirmationData/@Recipient`, which is inside the signed assertion and
  required by check 10.
- **`Response/Issuer`** — the assertion's own `Issuer`, inside the signature, is
  checked against `idpEntityId`.

An identity provider that signs both the Response and the Assertion — Keycloak
does by default — satisfies either validator.

#### What the validators check

In this order; each refusal is an `AssertionValidationError` whose `check`
names the row. Rows marked *(signed-Response only)* are not performed by
`createSignedAssertionValidator`.

| # | Check | Refused when | `check` |
|---|---|---|---|
| 1 | Parses as XML, with no `DOCTYPE`; the document element is `samlp:Response` — or, for the assertion-only validator, a bare `saml:Assertion` | it is not, or it carries a `<!DOCTYPE` declaration | `document` |
| 1b | Every `ID` attribute in the document is unique | any value appears twice | `duplicateId` |
| 2 | Every signature is valid against `idpCertificates` — never against a certificate the document carries in its own `KeyInfo` | none, wrong key, content altered after signing, a malformed `Signature` element, no `ds:Reference` or more than one, a reference that is not same-document or names no element by `ID`, or a signature not inside the element it references | `signature` |
| 3 | The signed node is the node read | the Response carries no direct-child `Assertion`, or more than one; the signature does not cover the element this validator requires — the `Response`, or the bare root `Assertion` or the Response's direct-child `Assertion`; or any SAML 2.0 `Assertion` / `EncryptedAssertion`, or SAML 1.x `Assertion`, lies outside the signed assertion or inside a `ds:Signature` | `signedNode` |
| 4 | `samlp:Status` *(signed-Response only)* | absent or more than one; its `StatusCode` absent or more than one; the `StatusCode` without a `Value`; or a `Value` other than `…:status:Success` | `status` |
| 4b | `Assertion/@ID` | absent or empty | `assertionId` |
| 5 | `Assertion/Issuer` | absent, more than one, empty, not the expected issuer, or no expected issuer was given | `issuer` |
| 5b | `Response/Issuer` *(signed-Response only; optional)* | present and disagreeing with `Assertion/Issuer`, or present twice — absent is accepted | `issuer` |
| 6 | `Conditions` | absent, or more than one | `conditions` |
| 7 | `Conditions/@NotBefore` *(optional)* | present and not a valid `xsd:dateTime`, or in the future beyond `clockSkewMs` — absent is accepted | `notBefore` |
| 8 | `Conditions/@NotOnOrAfter` | absent, not a valid `xsd:dateTime`, or in the past beyond `clockSkewMs` | `notOnOrAfter` |
| 9 | `Conditions/AudienceRestriction` | absent, **any one** restriction naming no `Audience` at all, or **any one** failing to name `spEntityId` | `audience` |
| 10 | One bearer `SubjectConfirmation` | the `Subject` absent or more than one, holding no `SubjectConfirmation`, or no confirmation satisfying every part — see below | `bearerConfirmation` |
| 11 | `Response/@Destination` *(signed-Response only)* | absent, or not the ACS the response arrived at | `destination` |
| 12 | Replay | the store has already recorded this `{issuer, ID}` | `replay` |

What the table compresses:

- **Every required field is refused when absent**, not skipped: a rule
  phrased "present and not X" is one an attacker satisfies by deleting the
  field. That covers `Status` and `Destination` (signed-Response only),
  `Assertion/@ID`, `Assertion/Issuer`, `Conditions`, `Conditions/@NotOnOrAfter`,
  the `AudienceRestriction`, and, in the bearer confirmation, `Recipient`,
  `NotOnOrAfter` and — when a request ID is expected — `InResponseTo`. Of the
  fields the validators read, only these may be missing, each for a reason:
  - `Conditions/@NotBefore` and `SubjectConfirmationData/@NotBefore` — a
    missing `NotBefore` only means "valid from issue"; when present it is
    checked;
  - `Response/Issuer` — optional in SAML Core, and the assertion's own `Issuer`
    is checked inside the signature; when present it must agree (5b);
  - `NameID` — surfaced on the result, not trusted for anything.
- **The signature must cover the element that is read.** A wrapping attack
  supplies a document holding a genuinely signed fragment beside a forged one;
  the validator resolves which element each signature covers and reads the
  assertion's fields from that element only. And since a payload travels on
  whole — `Saml2PureProvider` hands it to `cookieProvider` — **every**
  SAML 2.0 `Assertion` or `EncryptedAssertion`, and every SAML 1.x
  `Assertion` (`urn:oasis:names:tc:SAML:1.0:assertion`), anywhere in the
  document must be the signed assertion or inside it, under both validators,
  but never inside a `ds:Signature`, whose subtree an enveloped signature
  leaves unsigned. An extra assertion in `Extensions`, a sibling or a wrapper
  ends the login rather than being ignored. Encrypted assertions are not
  supported.
- **Several signatures are accepted** when every one verifies against
  `idpCertificates`, carries exactly one same-document reference, and sits
  directly inside the element it references. A signature that fails refuses the
  whole document, even when another covers the element read. A document with no
  signature is refused.
- **Unique IDs (1b)** are the wrapping defence again: XML-DSig resolves its
  reference by `ID`, so a duplicate makes "which element is signed" ambiguous.
  They are refused wherever they appear, before any reference is resolved.
- **Check 10 is one element, not four fields — and one is enough.** The
  assertion must carry exactly one `Subject`, holding at least one
  `SubjectConfirmation`. It is accepted when **at least one** confirmation
  passes every sub-rule on its own; values scattered across several
  confirmations do not add up to one. A candidate's sub-rules, in the order
  they are evaluated: `Method` is `urn:oasis:names:tc:SAML:2.0:cm:bearer`; it
  holds exactly one `SubjectConfirmationData`; `InResponseTo` equals the
  expected request ID — or is **absent** for a login declared `idpInitiated`;
  `Recipient` equals the ACS the response arrived at; `NotOnOrAfter` is
  present and a valid `xsd:dateTime`; `NotBefore`, if present, is a valid
  `xsd:dateTime`; `NotOnOrAfter` has not passed beyond `clockSkewMs`;
  `NotBefore` has arrived within it. When none qualifies, the refusal names
  every candidate in document order with the first sub-rule it failed —
  `no bearer confirmation qualifies: #1 Recipient is not the ACS | #2
  NotOnOrAfter has passed` — listing at most five, then `and N more`.
- **Check 9 is AND across restrictions, OR within one**, as SAML Core §2.5.1.4
  says: every `AudienceRestriction` must name you; the `Audience` elements
  inside one are alternatives.
- **Dates are parsed strictly.** An `xsd:dateTime` must have real calendar
  components — `2026-02-30T00:00:00Z`, which `Date.parse` quietly turns into
  2 March, is refused.
- **No DTD.** A `<!DOCTYPE` anywhere in the payload is refused at `document`
  before it is parsed: a SAML message has no use for one, and the document is
  parsed twice — by `@xmldom/xmldom` 0.9 here and by the 0.8 inside
  `xml-crypto` — where a DTD is exactly what parsers disagree about.
- **Any XML fault is a refusal, and nothing reaches the console.** The parser
  is given an error handler that throws on every level, so a payload it would
  have repaired — an undeclared entity, say — is refused at `document` rather
  than validated in its repaired form, and a malformed callback never writes
  to stderr past your `ILogger`. The same holds for the bearer conversion.
- **SHA-1 is accepted.** RSA-SHA1 signatures and SHA-1 digests verify, as they
  do under `xml-crypto`'s defaults, because identity providers still emit them
  and refusing them would refuse genuine logins. To refuse them, supply an
  `assertionValidator` of your own that rejects a `SignatureMethod` or
  `DigestMethod` naming `…xmldsig#rsa-sha1` or `…xmldsig#sha1` before
  delegating to a shipped validator — and keep `idpEntityId` configured, since
  the shipped validator inside still refuses without an expected issuer.

#### Refusal messages

Since 4.1.0 no two rules under one `check` share a message, and an element
that must appear exactly once says which way it failed — absent, or more than
one. Every value a message takes from the document is JSON-quoted and cut to
64 characters, so a newline smuggled in as `&#10;` shows as `\n` and cannot
forge a log line. Match on `check` in code; the message is for the person
reading the log. `<n>` is a count of two or more; `"…"` is a quoted document
value.

| `check` | message |
|---|---|
| `document` | `the SAMLResponse carries a DOCTYPE declaration, which is never accepted` |
| `document` | `the SAMLResponse did not parse as XML` |
| `document` | `expected a samlp:Response or a saml:Assertion, got "…"` |
| `document` | `expected the document element to be a samlp:Response, got "…"` |
| `duplicateId` | `the document uses the ID "…" more than once, so which element is signed is ambiguous` |
| `signature` | `the document carries no signature` |
| `signature` | `the signature element is malformed: "…"` |
| `signature` | `the signature does not verify against any configured certificate` |
| `signature` | `the signature carries no ds:Reference` |
| `signature` | `the signature carries <n> ds:Reference; exactly one is allowed` |
| `signature` | `the signature reference is not a same-document URI: "…"` |
| `signature` | `the signature references "…", which is not in the document` |
| `signature` | `the signature is not inside the element it references, so it does not envelope it` |
| `signedNode` | `the response carries no direct-child saml:Assertion` |
| `signedNode` | `the response carries <n> direct-child saml:Assertion; exactly one is allowed` |
| `signedNode` | `the signature does not cover the samlp:Response this validator requires` |
| `signedNode` | `the signature does not cover the saml:Assertion this validator requires` |
| `signedNode` | `the document carries an Assertion or EncryptedAssertion, SAML 2.0 or 1.x, outside the one the signature covers` |
| `signedNode` | `the document carries an Assertion or EncryptedAssertion inside a ds:Signature, which is never accepted` |
| `status` | `the response carries no samlp:Status` |
| `status` | `the response carries <n> samlp:Status; exactly one is allowed` |
| `status` | `the samlp:Status carries no samlp:StatusCode` |
| `status` | `the samlp:Status carries <n> samlp:StatusCode; exactly one is allowed` |
| `status` | `the samlp:StatusCode carries no Value` |
| `status` | `the identity provider declined the login: "…"` |
| `assertionId` | `the assertion carries no ID` |
| `issuer` | `the assertion carries no saml:Issuer` |
| `issuer` | `the assertion carries <n> saml:Issuer; exactly one is allowed` |
| `issuer` | `the assertion's saml:Issuer is empty` |
| `issuer` | `no expectedIssuer was configured, so the assertion issuer cannot be trusted` |
| `issuer` | `the assertion was issued by "…", not the trusted issuer` |
| `issuer` | `the response must carry at most one saml:Issuer` |
| `issuer` | `the response and the assertion name different issuers` |
| `conditions` | `the assertion carries no saml:Conditions` |
| `conditions` | `the assertion carries <n> saml:Conditions; exactly one is allowed` |
| `notBefore` | `Conditions NotBefore is not a valid xsd:dateTime: "…"` |
| `notBefore` | `the assertion is not valid yet` |
| `notOnOrAfter` | `Conditions carries no NotOnOrAfter, so the assertion states no lifetime` |
| `notOnOrAfter` | `Conditions NotOnOrAfter is not a valid xsd:dateTime: "…"` |
| `notOnOrAfter` | `the assertion has expired` |
| `audience` | `the assertion restricts no audience` |
| `audience` | `an AudienceRestriction names no audience` |
| `audience` | `an AudienceRestriction on this assertion does not name us` |
| `bearerConfirmation` | `the assertion carries no saml:Subject` |
| `bearerConfirmation` | `the assertion carries <n> saml:Subject; exactly one is allowed` |
| `bearerConfirmation` | `the saml:Subject holds no SubjectConfirmation` |
| `bearerConfirmation` | `no bearer confirmation qualifies: #1 <reason> \| #2 <reason> \| …` |
| `destination` | `the response carries no Destination` |
| `destination` | `the response is addressed to "…", not to us` |
| `replay` | `this assertion has been presented before` |

A `bearerConfirmation` refusal naming candidates lists each one's first failed
sub-rule, in document order, joined by ` | ` — not `; `, which a count reason
such as `carries 2 SubjectConfirmationData; exactly one is allowed` contains
itself; past five candidates it ends ` | and N more`, N being how many were
not listed. The eleven reasons:

| # | `<reason>`, in the order a candidate is tested |
|---|---|
| 1 | `Method is not bearer` |
| 2 | `carries no SubjectConfirmationData` |
| 3 | `carries <n> SubjectConfirmationData; exactly one is allowed` |
| 4 | `InResponseTo is present, but this login sent no request` |
| 5 | `InResponseTo does not answer our request` |
| 6 | `Recipient is not the ACS` |
| 7 | `SubjectConfirmationData has no NotOnOrAfter` |
| 8 | `SubjectConfirmationData NotOnOrAfter is not a valid xsd:dateTime` |
| 9 | `SubjectConfirmationData NotBefore is not a valid xsd:dateTime` |
| 10 | `NotOnOrAfter has passed` |
| 11 | `NotBefore has not arrived` |

Two messages from outside a validator changed in 4.1.0 and carry no `check`.
A provider configured with both `idpInitiated: true` and `authnRequestId`
throws a `ValidationError` (`missingFields: ['idpInitiated']`) at
construction: `SAML idpInitiated is true and authnRequestId is set: an
IdP-initiated login sends no request, so the two describe different logins.
Remove one of them.` And `Saml2BearerProvider`'s conversion of a validated
payload into the bearer grant's Assertion throws a plain `Error` whose parser
text is quoted the same way — reachable only when a custom validator accepted
a payload that does not parse: `SAML bearer payload is not well-formed XML:
"…"`.

**Expiry comes from the verified document.** A validated assertion's
`expiresAt` is the earlier of `Conditions/@NotOnOrAfter` and the `NotOnOrAfter`
of the bearer confirmation accepted — the earliest, if several qualify — so a
session cannot outlive a window the assertion itself closed.
`Saml2PureProvider` takes its session's `expiresAt` from it.
`parseSamlNotOnOrAfter`, the regular expression over unverified XML it replaces,
is gone.

**What remains unproven.** The validators verify signatures with `xml-crypto`.
They are tested against signatures `xml-crypto` itself produced (through
`@mcp-abap-adt/auth-mocks`) and against Keycloak, a real identity provider, on
the provider stand. Whether every other identity provider's canonicalisation
matches is not proven; a refusal at `signature` from a genuine response is the
symptom to report.

#### Where the expected request ID comes from

`InResponseTo` must answer the request that was sent — or, where none was sent
by explicit choice, be absent. The expected ID is decided before validation,
from one of three sources, and never inferred from the assertion:

| Source | When | `InResponseTo` must be |
|---|---|---|
| minted | the strategy called `buildAuthorizationUrl`, and the package built the AuthnRequest — `samlCallbackStrategy`, `manualSamlResponseStrategy`, `externalCodeStrategy`, or the default | equal to the ID the package minted |
| declared | `authnRequestId` is configured | equal to `authnRequestId` |
| none, by declaration | `idpInitiated: true`, and no request was sent | **absent** |

`authnRequestId` is **required** whenever the package did not build the request
and the login is not declared IdP-initiated. Two flows trigger it:

- a pre-built `authorizationUrl` — the package cannot read the ID out of a
  request it did not build;
- a strategy that returns a payload without calling `buildAuthorizationUrl` —
  `staticCodeStrategy`, or your own — after a request you sent some other way.

Without it, the login fails with a `ValidationError` (`missingFields:
['authnRequestId']`) after the strategy returns and before the assertion is
read — as a configuration fault, not a refusal blamed on the assertion. A
strategy that merely forgot to call the builder must not silently switch the
provider into accepting unsolicited responses.

**`idpInitiated: true`** declares that the identity provider started the login
and no AuthnRequest exists, so the assertion must carry no `InResponseTo`.
`Saml2BearerProvider` against UAA or XSUAA needs it: both refuse an assertion
carrying `InResponseTo` on the saml2-bearer grant. What it gives up is the
**login-CSRF defence** of a request ID: with one, a response must answer the
request just sent; without it, whoever can deliver a validly signed response
of their own to your receiver can log your user in as themselves. That is
sometimes the right trade — for UAA and XSUAA it is the only one — but it must
be a decision visible in your configuration. **It is never inferred**: an
assertion without `InResponseTo` does not make a login IdP-initiated; only
`idpInitiated: true` does. The other checks apply unchanged.

`idpInitiated: true` together with a request ID is a configuration error too:
the two describe different logins. With a declared `authnRequestId` the
provider refuses at construction — a `ValidationError` (`missingFields:
['idpInitiated']`) — before any browser opens. A strategy that calls
`buildAuthorizationUrl` with no
`authorizationUrl` configured is refused inside the builder, before a URL — and
so a request ID — exists: a `ValidationError` with `missingFields:
['authorizationUrl']`. Use a strategy that does not call the builder, and leave
`authnRequestId` unset; or configure the identity provider's IdP-initiated SSO
URL as `authorizationUrl`, which the builder hands over without minting
anything.

#### Replay

The shipped replay store is **process-wide**: one module-level in-memory store,
`defaultReplayStore`, shared by every validator given it in the process — both
`inBrowser` recipes use it unless `SamlTrust.replayStore` says otherwise. An assertion accepted once is refused as a replay
(`check: 'replay'`) for as long as it could still be accepted, however many
providers are constructed; a store per provider would let a second provider
accept what the first had seen. It is keyed by `{issuer, assertionId}`, since an
ID is unique only within the identity provider that minted it. Only an assertion
that passed every other check is recorded.

What it does **not** protect: anything across processes. A second process, a
restart, or a horizontally scaled deployment each start with an empty memory.
For those, supply a shared store — `replayStore` on a shipped validator's
options, or on the `SamlTrust` given to `inBrowser`. Its `recordIfUnseen` must be
atomic — a single conditional write, never a read followed by a write — because
that race is exactly the one a replay exploits:

```typescript
import type { IAssertionReplayStore } from '@mcp-abap-adt/interfaces-auth';

const sharedReplayStore: IAssertionReplayStore = {
  async recordIfUnseen({ issuer, assertionId }, retainUntil) {
    // e.g. Redis `SET key 1 NX PXAT <ms>`: true only when newly written.
    return setIfAbsent(
      `saml-replay:${issuer.length}:${issuer}:${assertionId}`,
      retainUntil,
    );
  },
};
```

The issuer is length-prefixed, as in the in-memory store, because both parts
may contain `:` — without the length, issuer `a:b` with ID `c` and issuer `a`
with ID `b:c` would share one key, and one would be refused as the other's
replay.

`createInMemoryReplayStore()` returns a store of your own, for isolation — a
test, or a component that must not share memory with the rest of the process.
The in-memory store prunes lazily when consulted, so it holds no timer and
needs no disposal.

#### Clock skew

`clockSkewMs` defaults to **`0`**: this package applies no leniency you did not
choose. It must be a finite, non-negative integer; anything else fails at
construction. It widens the `NotBefore` and `NotOnOrAfter` checks of both
`Conditions` and the bearer confirmation. A replay entry is retained until
the earlier of `Conditions/@NotOnOrAfter` and the **latest** `NotOnOrAfter` of
a bearer confirmation that answers the request and names the ACS — one not
open yet included — plus `clockSkewMs`: the last instant the assertion could
still be accepted. That is not `expiresAt`, which takes the earliest
confirmation; with confirmations closing at +120 s and +600 s the session ends
at +120 s, but the second still admits the assertion at +200 s, so the entry
must outlive it. Neither window nor tolerance cuts a hole in replay detection.

#### What a validated assertion carries: `raw` and `signedXml`

You meet a `ValidatedAssertion` when you call a validator yourself or wrap one
in an `IAssertionValidator` of your own. The shipped validators fill
`expiresAt`, `assertionId`, `issuer`, `nameId` (the `Subject`'s `NameID`;
`undefined` when it carries none or more than one — `NameID` is surfaced,
never refused),
`raw` and `signedXml`; they leave `sessionIndex` and `attributes` unset.

- **`raw`** is the validator's input, unchanged — a `samlp:Response`, or a bare
  `saml:Assertion` where the validator accepts one. It makes no promise about
  what a provider forwards: `Saml2PureProvider` hands the payload to
  `cookieProvider` as it is, while `Saml2BearerProvider` sends the extracted
  Assertion, not `raw`. **Holding a `ValidatedAssertion` does not make all of
  `raw` trustworthy**: a Response validated by `createSignedAssertionValidator`
  carries `Status`, `Response/Issuer` and `Destination`, which nothing read and
  nothing checked.
- **`signedXml`** is what the signature covered, serialised: the `Assertion`,
  or the `Response` when that is what was signed. Anything this interface does
  not surface — attributes, a session index — must be parsed from `signedXml`,
  never from `raw`. The difference between the two is the difference between
  "signed" and "arrived".

#### Using a shipped validator directly

```typescript
import { readFileSync } from 'node:fs';
import {
  AssertionValidationError,
  createSignedResponseValidator,
  defaultReplayStore,
} from '@mcp-abap-adt/auth-providers';

const validator = createSignedResponseValidator({
  idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
  replayStore: defaultReplayStore,
});

try {
  const validated = await validator.validate(samlResponseBase64, {
    expectedInResponseTo: requestId, // omit only for an IdP-initiated login
    audience: 'my-sp-entity',
    acsUrl: 'https://sp.example.com/saml/acs',
    expectedIssuer: 'https://idp.example.com/metadata', // required — see below
  });
  console.error(validated.nameId, validated.expiresAt);
} catch (error) {
  if (error instanceof AssertionValidationError) {
    console.error(`refused at ${error.check}: ${error.message}`);
  }
  throw error;
}
```

**Pass `expectedIssuer`.** It is optional on `AssertionContext`, for custom
validators that establish trust some other way, but the shipped validators
**fail closed** without it: every assertion is refused at `issuer`, since
otherwise any issuer holding a key on your list would pass. The providers
always pass `idpEntityId` there; a caller of a shipped validator must pass it
itself. `expectedInResponseTo` follows the request-ID rule: given, the
assertion must answer it; absent, the assertion must carry no `InResponseTo`.

#### Errors

| Error | When |
|---|---|
| `AssertionValidationError` | an assertion was refused. `check` (type `AssertionCheck`) names the row above — tell "your IdP declined" (`status`) from "not addressed to us" (`audience`, `bearerConfirmation`, `destination`) without parsing the message. `code` is `'ASSERTION_VALIDATION_ERROR'` (`ASSERTION_ERROR_CODES.VALIDATION_ERROR` from `@mcp-abap-adt/interfaces-auth`) |
| `ValidationError` | configuration: `idpEntityId` missing with a shipped validator supplied as `assertionValidator` (at construction); `idpInitiated` with no `authorizationUrl` and a strategy that calls `buildAuthorizationUrl` (inside the builder, before any URL is produced); `idpInitiated` combined with a declared `authnRequestId` (at construction); `authnRequestId` missing (at login, after the strategy returns and before the assertion is read). `missingFields` names the field |
| `Error` | a certificate that is neither PEM nor base64 DER, or not a valid X.509 certificate; a `clockSkewMs` that is not a finite non-negative integer; and an empty `idpCertificates` (*"must not be empty"*) — all when the validator is built, which for `inBrowser` is when the provider is |

### With Stores

**Important**: BTP and ABAP are different entities:
- **BTP** (base BTP) - uses `BtpServiceKeyStore` and `BtpSessionStore` (without `sapUrl`)
- **ABAP** - uses `AbapServiceKeyStore` and `AbapSessionStore` (with `sapUrl`)

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  AuthorizationCodeProvider,
  ClientCredentialsProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';
import { 
  XsuaaServiceKeyStore, 
  XsuaaSessionStore,
  BtpServiceKeyStore,
  BtpSessionStore,
  AbapServiceKeyStore,
  AbapSessionStore 
} from '@mcp-abap-adt/auth-stores';

// XSUAA provider with stores (client_credentials or auth code)
const xsuaaServiceKeyStore = new XsuaaServiceKeyStore('/path/to/service-keys');
const xsuaaSessionStore = new XsuaaSessionStore('/path/to/sessions');

const xsuaaBroker = new AuthBroker({
  serviceKeyStore: xsuaaServiceKeyStore,
  sessionStore: xsuaaSessionStore,
  tokenProvider: new ClientCredentialsProvider({
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
  }),
}, 'none');

// BTP provider with stores (base BTP, without sapUrl)
const btpServiceKeyStore = new BtpServiceKeyStore('/path/to/service-keys');
const btpSessionStore = new BtpSessionStore('/path/to/sessions');

const btpBroker = new AuthBroker({
  serviceKeyStore: btpServiceKeyStore,
  sessionStore: btpSessionStore,
  tokenProvider: new AuthorizationCodeProvider({
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    authorization: browserCallbackStrategy({ browser: 'system' }),
  }),
});

// ABAP provider with stores (with sapUrl)
const abapServiceKeyStore = new AbapServiceKeyStore('/path/to/service-keys');
const abapSessionStore = new AbapSessionStore('/path/to/sessions');

// Use a custom port if 61001 is taken, or if the IdP has a different one registered
const abapBroker = new AuthBroker({
  serviceKeyStore: abapServiceKeyStore,
  sessionStore: abapSessionStore,
  tokenProvider: new AuthorizationCodeProvider({
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    authorization: browserCallbackStrategy({ browser: 'system', port: 4001 }),
  }),
});
```

### Token Providers

#### AuthorizationCodeProvider

Uses browser-based OAuth2 flow or refresh token:

```typescript
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
  authorization: browserCallbackStrategy({ browser: 'system' }),
});

// If refreshToken is provided here, uses refresh flow (no browser)
// Otherwise, opens browser for OAuth2 authorization
const result = await provider.getTokens();

// result.authorizationToken contains the JWT token
// result.refreshToken contains refresh token (if browser flow was used)
```

#### ClientCredentialsProvider

Uses `client_credentials` grant type - no browser interaction required:

```typescript
import { ClientCredentialsProvider } from '@mcp-abap-adt/auth-providers';

const provider = new ClientCredentialsProvider({
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
  logger, // optional ILogger, as every token provider takes (since 5.2.0)
});

const result = await provider.getTokens();

// result.authorizationToken contains the JWT token
// result.refreshToken is undefined (client_credentials doesn't provide refresh tokens)
```

Instead of `clientSecret` it takes a `clientAuthentication` strategy — a client
certificate (an XSUAA x509 key) or `privateKeyJwt`; never both. See
[Client authentication](#client-authentication).

#### UaaPasscodeProvider

The login `cf login --sso` uses, for UAA and XSUAA: a one-time **Temporary
Authentication Code**. Nothing opens and nothing listens on this machine — the
user opens `<uaaUrl>/passcode` in any browser, on any device, logs in however
the identity zone asks (SSO through a corporate IdP, MFA), and copies the code
shown there. The provider exchanges it for tokens and refreshes them, so the
code is asked for again only when the refresh token is gone. It suits an MCP
server on a remote machine, in a container, or behind SSH.

```typescript
import { UaaPasscodeProvider, manualPasscodeStrategy } from '@mcp-abap-adt/auth-providers';

const provider = new UaaPasscodeProvider({
  uaaUrl: 'https://<subdomain>.authentication.<region>.hana.ondemand.com',
  clientId: '...', // a client allowed the `password` grant (and `refresh_token`)
  clientSecret: '...', // omit for a public client
  // As fromTerminal(): announce <uaaUrl>/passcode, read the code from the terminal.
  // Supply `read` to take it from anywhere else — never from stdin under MCP.
  authorization: manualPasscodeStrategy({ read: askTheUser }),
});
```

The exchange is the password grant with `passcode` instead of a username and
password — a UAA extension, not an RFC. A code is single-use; a mistyped or
spent one fails with `Passcode exchange failed (401)` — the message names the
status, and the OAuth `error` only when it is a registered code (UAA's
`unauthorized` is not). What UAA said (`"Invalid passcode"`) is written
nowhere: the server's free text may echo the passcode or the client secret.

#### Device flow prompts

`OidcDeviceFlowProvider` must show the user where to go and what to enter. It
does not choose where that goes: it takes a **presenter**, an injected
collaborator like a strategy, and hands it structured data rather than text,
so a consumer's UI — an MCP client, a chat, a terminal — renders it its own
way:

```typescript
export interface DeviceCodePrompt {
  verificationUri: string;
  verificationUriComplete?: string;
  userCode: string;
  expiresInSeconds?: number;
}
export interface IDeviceCodePresenter {
  /** Show the prompt; resolves once it has been shown. */
  present(prompt: DeviceCodePrompt): Promise<void>;
}
```

`presenter` is a required constructor field. The shipped one,
`consoleDeviceCodePresenter(logger?)`, writes the prompt to the logger's
`info`, or to **stderr** without one — never to stdout, which carries protocol
traffic under an MCP or LSP stdio transport. `OidcDeviceFlowProvider.toConsole(config)`
is the recipe that assembles it from `config.logger`:

```typescript
import {
  OidcDeviceFlowProvider,
  type IDeviceCodePresenter,
} from '@mcp-abap-adt/auth-providers';

// The usual choice: logger or stderr.
const provider = OidcDeviceFlowProvider.toConsole({
  issuerUrl: 'https://idp.example.com/realms/sap',
  clientId: '...',
});

// Or your own UI.
const presenter: IDeviceCodePresenter = {
  async present({ verificationUri, userCode }) {
    await showToTheUser(`Open ${verificationUri} and enter ${userCode}`);
  },
};
const custom = new OidcDeviceFlowProvider({
  issuerUrl: 'https://idp.example.com/realms/sap',
  clientId: '...',
  presenter,
});
```

A presenter that throws makes `prepare()` / `rejected()` answer Oops with the
fixed reason "showing the device code failed"; the device code is never part
of a refusal.

#### Callback port and lifetime

**Note**: the callback port is set on the strategy (`browserCallbackStrategy({ port })`
and its OIDC/SAML siblings), not on the provider — the 1.x `redirectPort` field
is gone. The default is **61001**, was 3001. If the requested port is already in
use, an error is thrown; specify a different port or free it before starting
authentication. `port: 0` binds an ephemeral port, which works only where the
identity provider accepts a loopback redirect on any port.

**Port lifetime**: the callback port is held for the login and nothing longer. It is bound when the login window opens and released when the login ends — by success, by the identity provider's refusal, by another failure, or by an abort — and the returned promise settles only after the listening socket is closed. No timer is involved: a connection still open is ended gracefully and let go, never waited for. An error therefore always means the port is already available, and the port is released *before* the authorization code is exchanged for a token, so a slow identity provider cannot hold it either.

**No built-in timeout** (since 6.0.0): an interactive login — browser, OIDC, SAML, or a manual paste — waits until its result arrives, the identity provider refuses, or the consumer's `AbortSignal` aborts it; it then ends `interactive-login` `aborted` and the port is free. The `timeoutMs` options, `DEFAULT_LOGIN_TIMEOUT_MS` and the 30 s / 300 s defaults are gone: a consumer that passed `timeoutMs` passes `signal: AbortSignal.timeout(ms)` instead (to the strategy, or to `inBrowser` / `fromTerminal` as `{ signal }`); one that passed nothing now waits until it aborts.

**Incomplete callbacks**: a `/callback` carrying neither a code nor an error no longer ends the login. It is answered, counted, and the tally is reported when the login is aborted (`the browser login was aborted; 2 incomplete request(s) reached /callback and were ignored`) — so a browser prefetch or a stray probe cannot cancel a login the user is still completing.

**Cancellation**: pass `signal` to the strategy, or call `dispose()` on it. Both are honoured before the bind, during it, and while waiting; `dispose()` resolves only once the socket is free.

**Process termination**: the callback server no longer installs its own `SIGTERM` / `SIGINT` / `SIGHUP` / `exit` handlers. A terminating process releases its listening sockets to the operating system anyway — measured at 0-1 ms after the process disappears — and the handlers were part of the cleanup tangle removed in 1.2.0. If a client kills the process mid-login, the port comes back with the process.

**Cross-Platform Browser Support**: The browser authentication works across Linux, macOS, and Windows:
- **Linux**: Automatically sets `DISPLAY=:0` if neither `DISPLAY` nor `WAYLAND_DISPLAY` environment variables are set. Supports multiple browser executable names (`google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` for Chrome; `firefox`, `firefox-esr` for Firefox).
- **Windows**: Uses proper `cmd /c start ""` syntax for reliable browser opening.
- **macOS**: Uses native `open -a` command.

**Headless Mode (SSH/Remote)**: For environments without a display (SSH sessions, Docker, CI/CD), leave `browser` at its default or set it explicitly:

```typescript
const provider = new AuthorizationCodeProvider({
  uaaUrl, clientId, clientSecret,
  authorization: browserCallbackStrategy({ browser: 'headless' }),
});

const result = await provider.getTokens();
```

In headless mode the authorization URL is shown — to the logger if there is one, to stderr otherwise — and the server waits for the user to complete authentication manually. The user can open the URL on any machine, and the callback reaches the server because it listens on all interfaces; the shipped UAA transport also prints where to paste the code if the redirect cannot reach back.

**Browser Options** (`browserCallbackStrategy({ browser })`):
- `'none'` (default): Shows the URL, waits for the callback or a paste
- `'headless'`: Same as `'none'`
- `'system'`: Opens the system default browser
- `'auto'`: Tries to open a browser; on failure the URL is shown and the login continues
- `'chrome'`, `'edge'`, `'firefox'`: Opens a specific browser

### Token Validation

Providers can perform **local JWT validation** by checking the `exp` (expiration) claim:

```typescript
const isValid = await provider.validateToken(token, serviceUrl);
```

- No HTTP requests are made to the SAP server
- Returns `true` if token has valid JWT format and `exp` is in the future (with 60s buffer)
- Returns `false` if token is expired, invalid format, or will expire within 60 seconds
- Network issues (ECONNREFUSED, timeout) do NOT trigger token refresh
- HTTP errors (401/403) are handled by retry mechanism in `makeAdtRequest` wrapper

```typescript
// Local validation (no HTTP)
const provider = new AuthorizationCodeProvider({
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
  authorization: browserCallbackStrategy({ browser: 'system' }),
});
const isValid = await provider.validateToken(token);  // serviceUrl optional
// Checks JWT exp claim locally, no network request
```

This approach prevents unnecessary token refresh and browser authentication when:
- Server is unreachable (ECONNREFUSED, timeout)
- Network is slow or unstable
- Running in offline/disconnected mode

### Seeding a stored credential

A token provider can start from a credential a previous run obtained — what
`onTokens` reported, or what a session store kept — and use it until it
expires instead of logging in. The seed is optional config; a provider without
one logs in at the first `getTokens()`.

| Provider | `accessToken` | `refreshToken` | `expiresAt` |
|---|---|---|---|
| `AuthorizationCodeProvider` | the token | yes | for a token with no `exp` |
| `UaaPasscodeProvider` | the token | yes | for a token with no `exp` |
| `OidcBrowserProvider` | the token | yes | for a token with no `exp` |
| `OidcDeviceFlowProvider` | the token | yes | for a token with no `exp` |
| `OidcPasswordProvider` | the token | yes | for a token with no `exp` |
| `OidcTokenExchangeProvider` | the token | yes | for a token with no `exp` |
| `Saml2BearerProvider` | the token | yes | for a token with no `exp` |
| `Saml2PureProvider` | the session cookies | — (SAML has none) | always: cookies carry no expiry |
| `ClientCredentialsProvider` | — | — | — |

- **When a seed expires.** A JWT's own `exp` claim decides, and wins over an
  `expiresAt` passed beside it. `expiresAt` (epoch ms) is used only when the
  token has no `exp` — an opaque token, or `Saml2PureProvider`'s cookies — and
  only when it is a finite, non-negative number; `Infinity`, `NaN` or a string
  from an unparsed file states no expiry. A numeric `exp`, `0` included, is
  the token's own. With neither, the seed counts as expired.
- **Revoked before it expires.** A `401` on the seed is the credential's
  (`rejected()`): the provider renews once, and a renewal that yields the seed
  again is refused — *the renewal returned the credential that was refused*.
- **Until then** `getTokens()` and `authorize()` answer the seed, less the
  usual one-minute buffer; no request is made and `onTokens` is not called —
  it reports only new tokens.
- **After** the provider renews as usual: the `refreshToken` when there is one
  and the grant has a refresh, else one login through the configured
  strategy. What it obtains replaces the seed and goes to `onTokens`, with its
  `expiresAt`.
- `ClientCredentialsProvider` takes no seed: a new token costs one request and
  no user, so it obtains one.

```typescript
const provider = new Saml2PureProvider({
  ...samlConfig,
  accessToken: stored.sessionCookies,
  expiresAt: stored.expiresAt,
  onTokens: async ({ authorizationToken, expiresAt }) =>
    save({ sessionCookies: authorizationToken, expiresAt }),
});
```

### Token Refresh

Providers handle refresh automatically inside `getTokens()`: while the cached token is valid it
is returned, once it expires the refresh token is used, and a login follows when there is none or
the refresh is refused.

The clock is not the only judge, though. When the server refuses a token the cache still
considers valid — a 401 — ask for a new one with `refreshTokens()`. It skips the cache, takes the
same refresh-then-login path, and replaces the cache with what it obtains:

```typescript
let { authorizationToken } = await provider.getTokens();
let response = await call(authorizationToken);
if (response.status === 401) {
  ({ authorizationToken } = await provider.refreshTokens());
  response = await call(authorizationToken);
}
```

```typescript
try {
  const result = await provider.getTokens();
  // Returns new access token and refresh token (if available)
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Missing fields:', error.missingFields);
  } else if (error instanceof BrowserAuthError) {
    // the login timed out, the IdP refused, the port was taken, ...
    console.error('Browser auth failed:', error.message, error.cause);
  }
}
```

### Cancelling a login

There is no built-in bound on a login: it ends on a result, the identity provider's refusal, or
your `AbortSignal`. A renewal — one refresh, then at most one login — is shared by everyone who
needs a token at the same time, and each of them is a **waiter** with a signal of its own:

```typescript
// This caller no longer needs the token (an MCP request cancelled, say):
const tokens = await provider.getTokens({ signal: request.signal });
await provider.refreshTokens({ signal: request.signal });
```

- One waiter's abort releases only that waiter: its call rejects with an `AuthProviderFailure` of
  kind `interactive-login`, outcome `aborted`. The login runs on for the others.
- A waiter without a signal never aborts, so a login it waits on runs to its end.
- When every waiter has aborted, the login itself is aborted: the strategy's request signal
  aborts, the callback socket is released, the device-code polling stops, every request the
  login has on the wire is cut — and the next caller starts a fresh login.

**A login a moment starts** (`prepare`, `authorize`, `rejected`, …) has no per-call signal. It
waits on the provider's **attached parties**: the `signal` in the provider's config, and every
`attach(signal)` after it (`attach` returns a `detach()`; the same signal twice is one party; an
aborted signal is not added; a party leaves when its signal aborts or it is detached). Such a
login is aborted when every party live at its start, and every party attached while it runs, has
aborted. **With no live party — none attached, or all of them gone — it runs unbounded**, as a
consumer that gave no signal chose.

```typescript
const provider = new AuthorizationCodeProvider({ ...config, signal: session.signal });
const detach = provider.attach(otherSession.signal);
```

The limit: a moment cannot tell which session called it. A login started while a signalled
session is attached is bounded by that session; if it closes mid-login, an unsignalled session
that joined the same login through its own moment gets Oops `aborted` for that moment — and its
next moment starts a fresh, unbounded login and gets a token.

**A strategy must honour the request's signal.** Every login hands its strategy an
`AuthorizationRequest` carrying `signal` (`SignalledAuthorizationRequest` until interfaces-auth
6.0.0); the shipped strategies combine it with their own `signal` option, so either one ends the
login. A replacement login waits until the aborted one's strategy has **settled** its `authorize`
— its callback port closed, its stdin reader released (a manual strategy's custom `read` gets
the same signal, and the strategy settles only once that `read` has) — before it starts its own authorization
(never `busy`, never `port-in-use`). A consumer strategy that ignores the signal never settles,
and blocks the next login until it does; one that settles before releasing its socket lets the
next login meet it. A request on the wire is never waited for: it holds nothing local.

**A refresh is never cut.** Once a refresh request carrying refresh token R is sent, the server
may have spent R and issued R2, so the request runs on whatever its waiters do — they are
released at once, and its answer, when it comes, is committed if nothing newer was committed
meanwhile (R2 is kept), and discarded otherwise. R itself is never sent again by this provider:
it is quarantined for the provider's lifetime, so the next renewal logs in. A refresh whose
server never answers lingers until the server or the OS ends the socket; nothing waits for it.
On a rotating endpoint a cancelled refresh can therefore force one interactive login.

**What persistence is told.** Every `onTokens` call carries `refreshTokenDisposition`:
`'replace'` (a new usable refresh token), `'keep'` (none returned, nothing discarded: the stored
one stands) or `'clear'` (the held refresh token was refused, cut or quarantined: the stored one
must go). A discarded refresh token is notified at once, with the held access token and
`'clear'`, before the login that follows; a `'clear'` or `'replace'` whose `onTokens` failed is
said again by the next notification until one succeeds. A re-sent `'replace'` may carry a refresh token the provider no longer holds in memory — the one persistence never heard of, after a later result without a refresh token replaced the in-memory one. The quarantine lives in memory: a
process that dies between a cut refresh and that `'clear'` reaching the store may send the stored
R once after a restart.

**Commits run one at a time.** Every effect of a renewal — the tokens, the pinned certificate,
`onTokens` — is applied by a commit in one queue per provider, in order, never two at once; a
late result of an aborted login changes nothing. An `onTokens` that never settles therefore
blocks every later commit of that provider (each waiter still releasable by its own signal).

### Error Handling

The package provides typed error classes for better error handling:

```typescript
import {
  TokenProviderError,
  ValidationError,
  RefreshError,
  SessionDataError,
  ServiceKeyError,
  AssertionValidationError,
  CertificateMaterialError,
  ClientAuthenticationError,
  ClientAuthenticationResultError,
} from '@mcp-abap-adt/auth-providers';
import { isAuthProviderFailure } from '@mcp-abap-adt/auth-errors';

try {
  const result = await provider.getTokens();
} catch (error) {
  if (error instanceof AssertionValidationError) {
    // A SAML provider refused the assertion; `check` says which check failed
    console.error('Assertion refused at:', error.check); // e.g. 'audience'
    console.error('Error code:', error.code); // 'ASSERTION_VALIDATION_ERROR'
  } else if (error instanceof ValidationError) {
    // provider config validation failed
    console.error('Missing required fields:', error.missingFields);
    console.error('Error code:', error.code); // 'VALIDATION_ERROR'
  } else if (isAuthProviderFailure(error)) {
    // Since 6.0.0 an interactive login ends with an `interactive-login`
    // failure (`readFailure(error, operation).facts.outcome`: 'aborted',
    // 'port-in-use', 'identity-provider-refused', 'browser-launch-failed',
    // 'failed', …); its message is the error's words.
    console.error('Login failed:', error.message);
  }
}
```

**Error Types**:
- `TokenProviderError` - Base class with `code: string` property
- `ValidationError` - provider config validation failed, includes `missingFields: string[]`
- `BrowserAuthError` - exported, but thrown by nothing since 6.0.0 (removed in 6.0.0's final release): every end of an interactive login — the identity provider's refusal, a busy callback port, a browser that would not open, an abort, a disposed or busy strategy, an empty or unreadable paste — is an `AuthProviderFailure` of kind `interactive-login`, thrown by every shipped strategy. Its words keep this package's own ("Port N is already in use", `BrowserCallbackStrategy has been disposed`); the identity provider's refusal names only its registered code (`the identity provider refused the login (consent_required)`), never `error_description` or `error_uri`; anything else — a custom transport's error — is `the browser login failed (…)` naming only an HTTP status, a registered OAuth `error` and an allowlisted code, with no `cause`
- `TokenEndpointError` - a token request failed at a site that wraps it (UAA refresh, client credentials, passcode, OIDC device initiation, password grant); a plain `Error`, not a `TokenProviderError`; carries `status`, `oauthError` (a registered OAuth / OIDC code only) and `code` (an allowlisted system or TLS code only); its `cause` is the safe `AxiosError` the request was reduced to, never what the request rejected with (since 5.4.2)
- `RefreshError`, `SessionDataError`, `ServiceKeyError` - exported, but no provider throws them: a refused refresh falls back to a login inside `getTokens()`/`refreshTokens()`, and sessions and service keys are read by `@mcp-abap-adt/auth-stores`, not here
- `AssertionValidationError` - a SAML assertion was refused, includes `check: AssertionCheck` naming the check that failed — see [SAML assertion validation](#errors)
- `CertificateMaterialError` - client certificate material cannot be used, includes `incomplete: boolean` (no PFX and not both a certificate and its key, versus material no TLS context accepts); its message is fixed and carries nothing of the material. Thrown by `tlsClientCertificate` and by a provider pinning a strategy's certificate. Its `words` getter is deprecated: use `refusalWords` (the package never reads `words` from a thrown value, since any object can carry its own)
- `ClientAuthenticationError` - `privateKeyJwt`'s key is not a private key of its algorithm, or cannot sign; fixed message, nothing of the key
- `ClientAuthenticationResultError` - what a client authentication strategy returned cannot be sent (a non-string value, a header with a line break, a parameter or header replacing the request's own, an endpoint that is not an absolute `https:` URL); thrown before anything is sent, fixed message

A failed token request throws without the request it sent — no form body, no
`Authorization` header, no TLS agent — and never with what its promise
rejected with: anything that reached it (an axios failure, or what a global
response interceptor of yours threw — the server's text, a primitive, an
object with throwing getters) is replaced by a fresh `AxiosError` of fixed
words, an integer status and an allowlisted code — an aborted request by a
`CanceledError`, so `axios.isCancel` still holds — and a successful answer is
read only as a snapshot of its expected string and number fields, so a
response interceptor's hostile data cannot throw through either (since
5.4.2); and with the server's body reduced to
its `error` when that is a registered OAuth code; the server's
`error_description` and `error_uri` go nowhere — no error, no log line
(since 5.4.2).

#### Relaying a refusal: `refusalWords`

A consumer that catches an error from this package — a strategy's
`tlsMaterial()` checked eagerly, say — and reports it in its own error should
relay the words this package would refuse with, not copy them:

```typescript
import { refusalWords, tlsClientCertificate } from '@mcp-abap-adt/auth-providers';

try {
  await tlsClientCertificate({ material: loader }).tlsMaterial?.();
} catch (error) {
  const { reason, hint } = refusalWords(error, 'loading the client certificate');
  throw new MyConfigError(hint ? `${reason}: ${hint}` : reason);
}
```

`refusalWords(error: unknown, what: string): IAuthRefusal` answers exactly the
`reason` and `hint` a provider's refusal would carry for that thrown value —
for a `CertificateMaterialError`, its kind's words from the
[Refusals](#refusals) table, hint included. The words are fixed per class of
this package, decided by `instanceof`, plus allowlisted facts (a known config
field, an HTTP status, a registered OAuth code, a system or TLS code); for
anything else, `<what> failed (unknown error)`. Never an error's message,
`cause` or body. It never throws: a Proxy or a throwing getter gets fixed
words. `what` is the consumer's own description of what it was doing, and
appears only in the words for an error this package has no fixed words for.

The guarantee covers what a thrown value carries and the package's public
surface. Code running in the same process that patches built-ins (say
`Map.prototype.get`) or imports `dist/` files directly can change anything the
package computes; no library can defend against that from inside the process.

All error codes are defined in `@mcp-abap-adt/interfaces-auth` package as `TOKEN_PROVIDER_ERROR_CODES` — `CertificateMaterialError`'s is `CERTIFICATE_MATERIAL_ERROR`; `ClientAuthenticationError` and `ClientAuthenticationResultError` share `CLIENT_AUTHENTICATION_ERROR` — and `AssertionValidationError`'s as `ASSERTION_ERROR_CODES`.

## Upgrading from 4.0 to 4.1

4.1.0 changes no export, configuration field or error class. It closes what
the 4.0.0 reviews deferred, and three refusals get stricter.

**What now fails that used to pass:**

- a document carrying a SAML 1.x `Assertion`
  (`urn:oasis:names:tc:SAML:1.0:assertion`) outside the signed assertion — in
  an unsigned `Extensions`, say — under either validator (`signedNode`). 4.0
  refused a stray SAML 2.0 assertion but not a SAML 1.x one;
- a document carrying an `Assertion` or `EncryptedAssertion` (SAML 2.0) or a
  SAML 1.x `Assertion` inside a `ds:Signature` — in `ds:Object`, say — under
  either validator (`signedNode`). An enveloped signature leaves its own
  subtree unsigned, and 4.0's assertion-only validator accepted such an
  element inside the signed assertion's signature, `Saml2BearerProvider`'s
  default included;
- a provider configured with both `idpInitiated: true` and `authnRequestId`.
  Its constructor now throws a `ValidationError` (`missingFields:
  ['idpInitiated']`); in 4.0 it constructed, and a `ValidationError` with the
  same `missingFields` came only after `authorize()` returned. It could never
  log in. A `Saml2BearerProvider` seeded with a `refreshToken` did work in 4.0
  until that token lapsed, since a refresh never reaches the strategy; it now
  fails at construction.

Nothing else 4.0 accepted is refused now, and no refusal moved to a different
`check`. Every other count rule — one `ds:Reference` per signature, one
`Status`, `StatusCode`, `Issuer`, `Conditions`, `Subject` and
`SubjectConfirmationData`, an `AudienceRestriction` naming an `Audience` —
refused the same documents in 4.0; only its message is new.

**Also changed:**

- **Refusal messages are reworded** so each names its rule — see
  [Refusal messages](#refusal-messages). `check` is unchanged for every
  refusal. Code matching on message text must match on `check` instead.
- `bearerConfirmation` refusals list why each candidate failed, in document
  order, at most five.
- Values from the document are quoted and cut in every message, including
  the `Status` code, the issuer, `Destination`, the `Conditions` dates,
  xml-crypto's own messages about a malformed signature, and the parser
  message in `Saml2BearerProvider`'s bearer conversion.
- The `bin` commands `auth-authorization-code` and `auth-client-credentials`
  are removed. They never ran from an npm install: they pointed at `.ts`
  files needing `tsx`, a devDependency, and imported `src/`, which is not
  published.

## Migrating from 3.x to 4.0

4.0.0 changes nothing outside the two SAML providers. For those, it validates
every assertion — see [SAML assertion validation](#saml-assertion-validation) —
and a 3.x configuration no longer constructs:

```
The default assertion validator needs the identity provider it should trust:
missing idpCertificates, idpEntityId. Supply these, or supply an
assertionValidator of your own.
```

What to add, on `Saml2BearerProvider` and `Saml2PureProvider` alike:

- **Whom to trust: `idpCertificates` and `idpEntityId`, or an
  `assertionValidator`.** The certificates are the identity provider's signing
  certificates, PEM or the bare base64 of `<X509Certificate>` in its metadata;
  `idpEntityId` is the `Issuer` its assertions carry — its `entityID`. A
  shipped validator supplied as `assertionValidator` still needs
  `idpEntityId`; only a validator of your own does without.
- **`spEntityId` must be your real entity ID.** It was already required, but in
  3.x it only named the issuer of the AuthnRequest, and a login that never built
  one never used it. It is now the `Audience` every `AudienceRestriction` must
  name — for the bearer grant against UAA or XSUAA, the `entityID` in their SAML
  metadata.
- **`idpInitiated: true` for `Saml2BearerProvider` against UAA or XSUAA**, whose
  saml2-bearer grant refuses an assertion carrying `InResponseTo`. With it, use
  a strategy that does not call `buildAuthorizationUrl` — `staticCodeStrategy`
  or your own. The 3.0 advice, `externalCodeStrategy` whose `provide` ignores
  the URL, now fails: with `idpInitiated: true` and no `authorizationUrl`, the
  builder refuses before producing a URL, since the only one it could build
  carries an AuthnRequest.
- **`authnRequestId` when the package does not build the request**: with a
  pre-built `authorizationUrl`, or a strategy that returns a payload without
  calling `buildAuthorizationUrl` after a request you sent — unless the login is
  `idpInitiated`. Without either, the login fails before the assertion is read.
- **The strategy's `redirectUri` must be the ACS the assertion names** in
  `SubjectConfirmationData/@Recipient` — for the bearer grant, the token
  endpoint's bearer ACS. `staticCodeStrategy` defaults it to
  `http://localhost:61001/callback`, which such an assertion does not name.

For the bearer grant against UAA or XSUAA, a 3.x configuration becomes:

```typescript
// 3.x
new Saml2BearerProvider({
  idpSsoUrl, spEntityId, uaaUrl, clientId, clientSecret,
  authorization: externalCodeStrategy({ provide: async () => fetchAssertion() }),
});

// 4.0
new Saml2BearerProvider({
  idpSsoUrl, uaaUrl, clientId, clientSecret,
  spEntityId: uaaEntityId,              // the entityID in UAA's SAML metadata
  acsUrl: uaaBearerAcs,                 // its bearer ACS: the Recipient
  idpCertificates: [idpSigningCertPem],
  idpEntityId: 'https://idp.example.com/metadata',
  idpInitiated: true,
  authorization: {
    // Never calls buildAuthorizationUrl; a fresh assertion per login.
    authorize: async () => ({ payload: await fetchAssertion(), redirectUri: uaaBearerAcs }),
  },
});
```

**What now fails that used to pass:**

- an unsigned assertion, one signed with a key not in `idpCertificates`, or one
  altered after signing (`signature`);
- under `Saml2PureProvider`'s default, a response whose `Response` is not
  signed — an identity provider that signs only assertions. Select
  `createSignedAssertionValidator` for it (`signedNode`);
- under `Saml2PureProvider`'s default, a response whose `Status` is absent or
  not `Success` (`status`), or whose `Destination` is absent or not the ACS it
  arrived at (`destination`). `Saml2BearerProvider`'s default,
  `createSignedAssertionValidator`, does not read `Status`, so a bearer
  consumer sees no change there — a declining identity provider mints no
  signed assertion, and the login is refused for want of one;
- an assertion from another issuer (`issuer`), for another audience
  (`audience`), expired or not yet valid (`notOnOrAfter`, `notBefore`,
  `bearerConfirmation`), or whose bearer confirmation names another ACS as
  `Recipient`, or none (`bearerConfirmation`);
- an `InResponseTo` that does not answer the request sent, one present on a
  login declared `idpInitiated`, or one missing from a login that sent a
  request (`bearerConfirmation`);
- the same assertion presented twice while it is still valid (`replay`) — for
  instance a `staticCodeStrategy` payload reused by a second login;
- a document carrying a second assertion, or an `EncryptedAssertion`, outside
  the signed one (`signedNode`), or a duplicated `ID` (`duplicateId`).

**Also changed:**

- `Saml2PureProvider`'s `expiresAt` comes from the validated assertion — the
  earlier of the `Conditions` and bearer-confirmation windows — not from the
  first `NotOnOrAfter` a regular expression found. It can be earlier than
  under 3.x.
- `parseSamlNotOnOrAfter` is removed; `buildSamlAuthorizationUrl` returns
  `{ url, requestId? }` instead of a string, and `getSamlAssertion` a
  `SamlAssertionResult` instead of the payload string. None was exported from
  the package root; only a deep import of `dist/auth/saml2Auth` or
  `dist/providers/saml2Utils` is affected.
- `@mcp-abap-adt/interfaces-auth` is `^2.0.0`, where
  `AssertionContext.expectedInResponseTo` is optional. That matters only to an
  implementer of `IAssertionValidator`, which must refuse an assertion carrying
  `InResponseTo` when it is absent.
- `xml-crypto` is a new runtime dependency, for signature verification.

## Migrating from 2.x to 3.0

3.0.0 changes no provider's configuration, but it drops a provider, a command
and the Node versions nothing supports any more.

- **Node.js 22, 24 or 26.** `engines` is `"^22 || ^24 || ^26"` (26 since 4.2.1).
  Node 18 and 20 are past their end of life and SAP has removed 20; 23 and 25,
  odd releases, are too. Move the process to 22, 24 or 26.
- **`DeviceFlowProvider` is gone**, with `DeviceFlowProviderConfig` and the
  `auth-device-flow` command. It sent the device grant to
  `<uaaUrl>/oauth/device_authorization`, which no server we know of serves —
  neither UAA nor XSUAA offers the device grant at all. Replace it with:

  ```typescript
  // A server that implements RFC 8628 (Keycloak, Spring Authorization Server, …):
  new OidcDeviceFlowProvider({ issuerUrl, clientId, logger });

  // UAA or XSUAA — a headless SSO login, the way `cf login --sso` does it:
  new UaaPasscodeProvider({
    uaaUrl, clientId, clientSecret,
    authorization: manualPasscodeStrategy({ read: askTheUser }),
  });
  ```

- **`Saml2BearerProvider` now sends one base64url Assertion** (RFC 7522),
  taken out of the `SAMLResponse` a login delivers. Before, it forwarded the
  whole response, which UAA and XSUAA refuse — so nothing that worked stops
  working. Note what the live checks showed, though: both refuse an assertion
  carrying `InResponseTo`, which an identity provider sets whenever it answers
  an AuthnRequest. Against them, supply an IdP-initiated assertion — see
  *Who starts the login matters* under `Saml2BearerProvider`.
- `@xmldom/xmldom` is a new runtime dependency, for that conversion.

## Migrating from 1.x to 2.0

Every field that described *how* an interactive login is conducted is gone from
the provider configs, replaced by a single `authorization` strategy.

| 1.x field | 2.0 |
|---|---|
| `browser: 'system'` | `authorization: browserCallbackStrategy({ browser: 'system' })` |
| `browser: 'system'`, `redirectPort: 4001` | `authorization: browserCallbackStrategy({ browser: 'system', port: 4001 })` |
| `redirectUri: uri` (OIDC) | `redirectUri` on the strategy — the strategy owns it |
| `authorizationCode: 'abc'` (OIDC) | `authorization: asOidcResult(staticCodeStrategy({ redirectUri, payload: 'abc' }))` |
| `authorizationCodeProvider: fn` (OIDC) | `authorization: asOidcResult(externalCodeStrategy({ redirectUri, provide: fn }))` |
| `assertionFlow: 'browser'` (SAML) | `authorization: samlCallbackStrategy()` — or omit `authorization` entirely |
| `assertionFlow: 'manual'`, `manualInput: fn` (SAML) | `authorization: manualSamlResponseStrategy({ redirectUri: acsUrl, read: fn })` |
| `assertionFlow: 'assertion'`, `assertionProvider: fn` (SAML) | `authorization: externalCodeStrategy({ redirectUri: acsUrl, provide: fn })` |

Four things in that table are easy to get wrong.

**The default callback port changed from 3001 to 61001** — for the UAA flow and
for SAML alike, the latter because the SAML ACS used to default to
`http://localhost:3001/callback` and now comes from the strategy. If you relied
on the default and registered `http://localhost:3001/callback` with your
identity provider, **the IdP rejects the redirect**, so the error you see is
foreign and says nothing about this package. Either register the new URI, or
keep the old one with one line:

```ts
authorization: browserCallbackStrategy({ browser: 'system', port: 3001 })
```

(61001 was chosen because it sits above Linux's `ip_local_port_range`, so an
outbound connection never squats on it, and well away from the 3001/3333 range
that servers and proxies in this family use.)

**`redirectUri` is not optional in the SAML manual and assertion migrations.**
The rows above show it for a reason: `manualSamlResponseStrategy` and
`externalCodeStrategy` default their redirect URI to
`http://localhost:61001/callback`, and both SAML providers require the ACS they
were told about to match the URI the strategy names. Declare a real `acsUrl`,
omit `redirectUri`, and the login fails the guard before anything opens:

```
SAML acsUrl is https://sp.example.com/saml/acs, but the authorization strategy
is listening on http://localhost:61001/callback. They must match.
```

Pass `redirectUri: acsUrl` and it works. (Declaring neither leaves both at the
default, which is consistent but only useful when the IdP posts to localhost.)

**`asOidcResult` is required for `OidcBrowserProvider`.** It takes
`IAuthorizationStrategy<OidcCallbackResult>`; `staticCodeStrategy`,
`externalCodeStrategy` and `manualPasteStrategy` yield a `string`. The obvious
one-line migration does not type-check without the adapter:

```ts
// 1.x
new OidcBrowserProvider({ clientId, tokenEndpoint, authorizationEndpoint,
  authorizationCode: 'abc', redirectUri: 'urn:ietf:wg:oauth:2.0:oob' });

// 2.0
const redirectUri = 'urn:ietf:wg:oauth:2.0:oob';
new OidcBrowserProvider({ clientId, tokenEndpoint, authorizationEndpoint,
  authorization: asOidcResult(staticCodeStrategy({ redirectUri, payload: 'abc' })) });

// 2.0, code fetched by your own flow
new OidcBrowserProvider({ clientId, tokenEndpoint, authorizationEndpoint,
  authorization: asOidcResult(externalCodeStrategy({ redirectUri, provide: fetchCode })) });
```

`samlCallbackStrategy` needs no adapter: SAML strategies yield a string and the
SAML providers take a string.

**`acsUrl` is now required whenever `authorizationUrl` is set** on either SAML
provider, and is rejected at construction rather than at login. 1.x accepted the
combination and silently defaulted the ACS to `http://localhost:3001/callback`;
since the real ACS is buried in a deflated `SAMLRequest` this package did not
build, it cannot be inferred and must be declared.

Three more changes that are not fields:

- **The terminal-paste channel is gone from the browser strategy.** In 1.x a
  `none` / `headless` login also accepted the code on stdin, without the
  consumer choosing anything. `browserCallbackStrategy` no longer reads stdin at
  all — under a stdio RPC transport that stream carries the protocol. If your
  users pasted codes into the terminal, switch that flow to
  `manualPasteStrategy({ redirectUri, read })`, which is the same capability as
  an explicit choice; otherwise the paste form on `/` is the remaining fallback
  for a browser on another machine.
- **Device flow prompts no longer go to stdout.** `DeviceFlowProviderConfig`
  accepted `logger?: ILogger`; the verification URI and user code go to that
  logger, or to stderr when there is none. Anything that captured stdout to read
  the device code must read stderr or supply a logger. (`DeviceFlowProvider`
  itself was removed in 3.0.0 — see the changelog; `OidcDeviceFlowProvider`
  behaves the same way.)
- **A `/callback` carrying neither a code nor an error no longer ends the
  login.** It is answered and counted, and the tally appears in the timeout
  message if the login later expires.

## Testing

The package includes both unit tests (with mocks) and integration tests (with real files and services).

### Unit Tests

```bash
npm test
```

`npm test` also runs both shipped assertion validators end to end, through
`Saml2PureProvider` and a real callback, against responses produced by a
separately published mock identity provider, `@mcp-abap-adt/auth-mocks`. Every
corruption variant it ships is refused at the check it targets — except
`statusFailure` and `wrongDestination`, which the assertion-only validator,
reading neither field, accepts; both halves are asserted.

### Integration Tests

Integration tests work with real files from `tests/test-config.yaml`:

1. Copy `tests/test-config.yaml.template` to `tests/test-config.yaml`
2. Fill in real destination name
3. Run tests - integration tests will use real services if configured

```yaml
# Destination name (used for service key file: <destination>.json and session file: <destination>.env)
destination: "trial"  # Example: "trial" -> looks for trial.json and trial.env

# Optional: Destination directory (base directory for service keys and sessions)
# If not specified, uses default platform paths:
#   Unix: ~/.config/mcp-abap-adt
#   Windows: %USERPROFILE%\Documents\mcp-abap-adt
# Uncomment and set if you need a custom path:
# destination_dir: ~/.config/mcp-abap-adt
```

Integration tests will skip if `test-config.yaml` is not configured or contains placeholder values.

**Test Scenarios**:
- **Scenario 1 & 2**: Token lifecycle - login via browser and reuse token from previous scenario
- **Scenario 3**: Expired session + expired refresh token - provider should re-authenticate via browser
- **Token validation**: Explicit validation of token expiration in all scenarios

**Note**: 
- Integration tests use `AbapServiceKeyStore` and `AbapSessionStore` for loading service keys and sessions
- Tests may open a browser for authentication if no refresh token is available. This is expected behavior.
- The interactive test asks the OS for a free port rather than pinning one, so it cannot collide with a running server
- Tests use `browserCallbackStrategy({ browser: 'system' })` for interactive authentication (not `'none'`)

### Providers against real authorization servers (UAA and Keycloak)

The providers are also tested against two real, widely used authorization
servers running locally in Docker from their official images — [Cloud Foundry
UAA](https://github.com/cloudfoundry/uaa) (`cfidentity/uaa`), the open-source
server XSUAA is built from, and [Keycloak](https://www.keycloak.org/)
(`quay.io/keycloak/keycloak`). It needs Docker and nothing else — no SAP
system, no setup step:

```bash
npm run test:stand    # start UAA and Keycloak, run the suites, stop both
```

`test:stand` starts both containers with `docker compose`, waits until both
answer, runs the suites, and stops the containers again — also when a test
fails, with the suites' exit code, after printing the last 200 lines of each
server's log. A full run takes well under a minute. CI runs exactly this as its
own job, on Node 22 and 24. To keep the stand up between runs, start it
yourself; `test:stand` then leaves it running. Ownership is per server: if only
one of the two was running, the run starts the other and removes only that one
afterwards:

```bash
npm run stand:up      # start and keep running
npm run test:stand    # as often as needed
npm run stand:down    # stop
```

`STAND_KEEP=1 npm run test:stand` keeps a stand the run started. `UAA_PORT`
(8080), `KEYCLOAK_PORT` (8081) and `KEYCLOAK_HTTPS_PORT` (8444) move the
servers. A server that is already running is never changed: if it is published
on another port than the one asked for, `test:stand` refuses and says so,
rather than let Compose recreate it. **A stand started before 5.3.0 must be
stopped once** (`npm run stand:down`): its Keycloak has no HTTPS port, and
`test:stand` refuses it for that reason.

Keycloak also listens on HTTPS (`KEYCLOAK_HTTPS_PORT`, loopback only), asking
for a client certificate without requiring one, so a request with none or with
another reaches it and is refused by the rule under test rather than by the
handshake. Its certificates are the throwaway fixtures in
`tests/stand/keycloak/tls/` — a CA whose key was deleted after signing, the
server certificate, client certificates `client-a` (mapped) and `client-b`
(mapped to nothing), and a `private_key_jwt` signing pair — regenerated by
`tests/stand/keycloak/tls/generate.sh`. `test:stand` sets
`NODE_EXTRA_CA_CERTS` to that CA for the suites: no provider is given a `ca`.
`npm run stand:up` prints the variables a run by hand needs.

| provider | server | what the suite proves |
|---|---|---|
| `Saml2BearerProvider` | UAA | a bearer assertion — and a whole `SAMLResponse` — passes the shipped signed-assertion validator, declared `idpInitiated`, and is exchanged for a token; UAA issues a refresh token exactly when the client may hold one, and the provider refreshes without its authorization strategy |
| `Saml2BearerProvider` | Keycloak → UAA | end to end with no assertion built by the tests: an IdP-initiated Keycloak login passes validation and becomes a UAA token; the answer to the provider's own AuthnRequest passes validation against the ID it minted, and UAA refuses it for its `InResponseTo` |
| `Saml2PureProvider` | Keycloak | the identity-provider half: Keycloak accepts the provider's AuthnRequest and posts a response, signed at both levels, to the ACS it named; the default signed-Response validator accepts it against the ID the provider minted, and it reaches `cookieProvider` unchanged |
| `ClientCredentialsProvider` | UAA | a client token |
| `UaaPasscodeProvider` | UAA | a code fetched from `/passcode` after logging in there, exchanged for tokens; a refresh that does not ask for another code; a spent code refused |
| `AuthorizationCodeProvider` | UAA | a login through UAA's own form, and a refresh without logging in again |
| `OidcPasswordProvider` | Keycloak | the password grant through discovery, and a refresh that works with a wrong password — so it is a refresh, not a second login |
| `OidcBrowserProvider` | Keycloak | authorization code with S256 PKCE, which the client requires, through Keycloak's login page |
| `OidcDeviceFlowProvider` | Keycloak | a token once the user logs in and grants access on Keycloak's device pages, read from the verification URI the provider announces |
| `OidcTokenExchangeProvider` | Keycloak | RFC 8693: another client's access token exchanged for the requester's own |
| `ClientCredentialsProvider` + `tlsClientCertificate` | Keycloak HTTPS (client `mtls`) | a token bound to `client-a`'s certificate (`cnf.x5t#S256` equals its thumbprint); a token request presenting `client-b` refused in the fixed words |
| the bound token at a resource | Keycloak HTTPS (userinfo) | the certificate `establish()` hands the logon target is `client-a`'s; userinfo answers 200 with it, 401 with none and 401 with `client-b` |
| `OidcPasswordProvider` + `tlsClientCertificate` | Keycloak HTTPS (client `mtls`) | a refresh over mTLS, and the new token bound to the same certificate |
| `OidcPasswordProvider` + `privateKeyJwt` | Keycloak HTTPS (client `jwt`) | a token with the default audience, the token endpoint |
| `OidcDeviceFlowProvider` + `privateKeyJwt` | Keycloak HTTPS (client `jwt`) | the whole flow with the default audience, the token endpoint, and no `audience`; the device initiation refused with `audience` set to the device endpoint |
| `CertificateAuthProvider` | Keycloak HTTPS (client `x509-login`) | the X.509 user logon, Keycloak's analogue of ABAP `CERTRULE`: the material the provider hands a logon logs on as the user `client-a`; `client-b` and no certificate refused |
| `ClientCredentialsProvider` + `privateKeyJwt` | UAA (client `jwt_client`) | a client token with no secret, the assertion's audience UAA's issuer |

The servers' configuration is committed as test fixtures —
`tests/stand/uaa/config/uaa.yml`, `tests/stand/keycloak/realm-test.json`, the
test identity provider's key in `tests/stand/uaa/idp/` and the TLS fixtures in
`tests/stand/keycloak/tls/` — so every machine and CI
run the same stand. The keys and passwords in them are trusted by nothing but
that local stand; they are not secrets, and must not be reused.

For the Keycloak → UAA case the suite makes UAA trust Keycloak at run time —
it registers Keycloak as a SAML identity provider through UAA's API, from the
metadata Keycloak publishes — and configures Keycloak's IdP-initiated SSO to
post to UAA's bearer ACS, since both depend on the ports and on keys Keycloak
generates when it starts.

Interactive logins are played by `src/__tests__/integration/stand/formLogin.ts`,
which submits each server's own login and consent forms over HTTP.

Not covered: the cookie half of `Saml2PureProvider`, which belongs to the
consumer's `cookieProvider` and needs a real SAP system.

Not covered either: an ABAP system's `CERTRULE` mapping a certificate to a
user — the Keycloak X.509 logon is its analogue, not a proof.

A plain `npm test` skips these suites: they run only with `UAA_URL`,
`KEYCLOAK_URL` or `KEYCLOAK_HTTPS_URL` set, which `test:stand` does.

### Live checks against XSUAA (BTP subaccount)

The stand proves the wire contracts against open-source servers. What only a
real XSUAA can answer is checked by `npm run test:xsuaa`, against a BTP
subaccount you are logged in to — a trial one is enough:

```bash
cf login -a https://api.cf.<region>.hana.ondemand.com --sso -o <org> -s <space>
XSUAA_CF_API=https://api.cf.<region>.hana.ondemand.com XSUAA_CF_ORG=<org> \
  XSUAA_CF_SPACE=<space> npm run test:xsuaa
```

It creates, in the targeted space, an `xsuaa`/`application` instance whose
client may use saml2-bearer, refresh_token, password and client_credentials,
and authenticate with a secret or a client certificate (`credential-types:
["binding-secret", "x509"]`), with two service keys — `key`, created with
`{"credential-type": "binding-secret"}`, and `x509-key`, created with
`{"credential-type": "x509"}` afresh on every run, since its certificate lives
about seven days; an `xsuaa`/`apiaccess`
instance, used only to manage trust; and a SAML trust to a test identity
provider whose key is generated locally and never leaves the gitignored
`tests/xsuaa/.local/`. Then it runs the suite and removes all of it — also when
a test fails. Two rules keep it from touching anything else:

- **Target.** The scripts refuse to run unless `cf` targets exactly
  `XSUAA_CF_API`, `XSUAA_CF_ORG` and `XSUAA_CF_SPACE`. There are no defaults, so
  a `cf` left pointing at another org or space cannot receive anything.
- **Ownership.** Everything setup creates is recorded in
  `tests/xsuaa/.local/owned` with its immutable ID — the service instance's
  GUID, each service key's GUID, the trust's id — and the record names the API, org and space it
  belongs to. A resource is treated as ours only when its name and its current
  ID both match a record, checked right before it is reused, refreshed or
  deleted. A name held by anything else — never created here, or recreated
  after ours was deleted — is refused by setup and left alone by teardown, and
  a record from another target is refused outright.

The run fails — non-zero — when the tests fail or the teardown does. A
teardown that fails stops at once and keeps `tests/xsuaa/.local/`, keys and
record included, so `tests/xsuaa/teardown.sh` can be run again to finish. A
lookup that fails — no session, no network, an API error — is a failure, never
read as "already gone": `cf service` exits 1 for both, so only its exact
not-found message counts as absence.
`XSUAA_KEEP=1` keeps the environment for another run. A full run takes about a minute and
a half. It is not part of CI.

Results of the 4.0 suite on a BTP trial subaccount, 2026-09-25 — 4 passed,
1 skipped. Every SAML login is validated first, by `Saml2BearerProvider`'s default
assertion-only validator, against the per-run test identity provider's
certificate, declared `idpInitiated`:

| check | result on XSUAA |
|---|---|
| `Saml2BearerProvider`, assertion without `InResponseTo` (IdP-initiated) | passes validation; token and refresh token |
| `Saml2BearerProvider`, a whole `SAMLResponse` | converted by the provider, accepted |
| `Saml2BearerProvider`, refresh | never reaches the strategy |
| `Saml2BearerProvider`, assertion with `InResponseTo` | refused locally at `bearerConfirmation`, before any request reaches XSUAA |
| `UaaPasscodeProvider` (with `XSUAA_PASSCODE=<code from /passcode>`) | skipped — no `XSUAA_PASSCODE` was set |

Teardown removed everything setup had created.

The x509 case — `ClientCredentialsProvider` with `tlsClientCertificate` and
the `x509-key`'s `certificate`, `key` and `certurl`, no secret anywhere
(`src/__tests__/integration/xsuaa/x509.test.ts`) — is new in 5.3.0. Results
on a BTP trial subaccount, 2026-10-04 — 2 suites, 6 passed, 1 skipped (the
passcode case, no `XSUAA_PASSCODE`): the `x509-key` holds `certificate`, `key`
and `certurl` and no `clientsecret`, and the provider got a
`client_credentials` token whose client id is the key's, with no secret
configured. Only `client_credentials` was run — no user grant — and whether
ADT accepts a token obtained this way stays unproven (see
[docs/btp-setup.md](docs/btp-setup.md)). Teardown removed everything setup had
created.

`UaaPasscodeProvider` was also checked by hand with an ABAP environment's own
service key: its client accepts the passcode, and the token opens ADT. That
depends on the user being known to the ABAP system — a user from an identity
provider not propagated to it gets a token and a 401 from ADT.

### Debug Logging

To enable detailed logging during tests or runtime, set environment variables:

```bash
# Enable logging for auth providers (short name)
DEBUG_PROVIDER=true npm test

# Or use long name (backward compatibility)
DEBUG_AUTH_PROVIDERS=true npm test

# Or enable via general DEBUG variable
DEBUG=true npm test

# Or include in DEBUG list
DEBUG=provider npm test
# Or
DEBUG=auth-providers npm test

# Set log level (debug, info, warn, error)
LOG_LEVEL=debug npm test
```

Logging uses `@mcp-abap-adt/logger` package with structured logging:
- Token exchange stages (what we send, what we receive)
- Token information (lengths, previews, expiration)
- Token validation checks (expiration, validity)
- Errors in fixed words (see below)

Example output:
```
[INFO] ℹ️ [browserAuth] Exchanging code for token...
[INFO] ℹ️ Tokens received: accessToken(2263 chars), refreshToken(34 chars)
[DEBUG] 🐛 [BaseTokenProvider] Token validation check {"expiresAt":"2025-12-25 11:08:15 UTC","isValid":true}
[INFO] ℹ️ [browserAuth] Authorization URL: https://.../oauth/authorize?...
[INFO] ℹ️ [browserAuth] Browser: system
```

**Logging Features**:
- **No tokens in logs**: a token the provider holds or sent is never logged, not even in part. A log line carries only `<redacted, N chars>` (since 4.1.2; earlier versions logged a short refresh token whole). Since 5.4.2 a token endpoint's error body contributes only a registered `error` code and the status — to a thrown error and to one `debug` line; its `error_description` and `error_uri` reach neither. An `error` that is a registered OAuth error code (`invalid_grant`, `authorization_pending`, `slow_down`, …) is kept verbatim: it is a protocol word, and the device poll reads it. Before 5.4.2, a new opaque token a server wrote into `error_description` could not be recognised and passed through; the description is now written nowhere.
- **No error message in logs**: a log line about a thrown value — a refresh that failed, a strategy, loader, presenter, validator, `onTokens`, browser launcher or SNC locator/probe that threw — carries only the words its refusal would (fixed per error class, an allowlisted TLS or system code, else `unknown error`) and the HTTP status when there is one, never the error's message, `cause` or stack: a consumer's collaborator may throw text holding a key, a passphrase or a token. Diagnose a collaborator's failure where it throws, not from this package's log.
- **Date Formatting**: Expiration dates are displayed in readable format (YYYY-MM-DD HH:MM:SS UTC) instead of ISO format
- **Browser Information**: Logs browser type and authorization URL for debugging
- **Token Lifecycle**: Detailed logging of token acquisition, validation, and refresh operations

## Dependencies

- `@mcp-abap-adt/interfaces-auth` (^3.1.0) - `IAuthProvider`, token provider, authorization, client-authentication and assertion-validation contracts (`ITokenProvider`, `IAuthorizationStrategy`, `IClientAuthentication`, `CallbackServerFactory`, `IAssertionValidator`, `IAssertionReplayStore`) and error code constants
- `@mcp-abap-adt/interfaces-auth-sap` (^2.0.0) - XSUAA authorization configuration (`IAuthorizationConfig`) and `ICertificateMaterialLoader`
- `@mcp-abap-adt/interfaces-utils` (^1.1.0) - `ILogger`
- `@xmldom/xmldom` - XML parsing: SAML assertion validation, and taking the Assertion out of a SAMLResponse for the saml2-bearer grant
- `xml-crypto` - XML-DSig signature verification for SAML assertion validation
- `axios` - HTTP client
- `express` - OAuth2 callback server
- `open` - Browser opening utility

Requires Node.js 22, 24 or 26 (`engines: "^22 || ^24 || ^26"`). 22 and 24 are
what SAP BTP, Cloud Foundry's Node.js buildpack offers; 26 is supported as well,
because a machine that runs it otherwise gets an older release of this package
from npm without a word. CI tests all three. Odd-numbered releases are never
supported — they reach end of life within months.

## License

**GNU Lesser General Public License v3.0 only** (`LGPL-3.0-only`).
Earlier published versions were MIT and stay MIT — a licence change is not
retroactive.

Copyright © 2025–2026 Oleksii Kyslytsia

This library is free software: you can redistribute it and/or modify it under the
terms of the GNU Lesser General Public License as published by the Free Software
Foundation, version 3.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU Lesser General Public License for more details.

Both texts ship with the package and both are needed: [`LICENSE`](LICENSE) is the
LGPL, [`COPYING`](COPYING) is the GPL it is written on top of, since the LGPL is a
set of additional permissions over the GPL and cannot be read alone.

**What this means if you depend on this package.** Linking it into your own
program — importing it, as every consumer of an npm package does — does not put
your program under the LGPL. What the licence asks is that changes *to this
library* stay free, and that your users can replace it with their own build.

