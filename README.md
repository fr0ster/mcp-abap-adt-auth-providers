# @mcp-abap-adt/auth-providers
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

Token providers for MCP ABAP ADT auth-broker.

This package provides token provider implementations for the `@mcp-abap-adt/auth-broker` package.

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Overview

This package implements the `ITokenProvider` interface from `@mcp-abap-adt/interfaces`:

- **AuthorizationCodeProvider** - Uses browser-based OAuth2 authorization code flow (user token)
- **ClientCredentialsProvider** - Uses `client_credentials` grant type (no browser required)

Providers are configured via constructor; `getTokens()` takes no parameters and handles refresh/login internally.

Since 2.0.0 an interactive login is conducted by an **authorization strategy**
(`IAuthorizationStrategy` from `@mcp-abap-adt/interfaces`) passed as
`authorization`. The provider owns what it can compute — the authorization URL
and the token exchange; everything between them (reaching the URL, receiving
what comes back, the port, the timeout) belongs to the strategy, which a
consumer may replace wholesale. See
[Choosing an authorization strategy](#choosing-an-authorization-strategy) and,
if you are on 1.x, [Migrating from 1.x to 2.0](#migrating-from-1x-to-20).

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

1. **Implementing token provider interface**: Provides concrete implementations of `ITokenProvider` interface defined in `@mcp-abap-adt/interfaces`
2. **Token acquisition**: Handles OAuth2 flows (browser-based, refresh token, client credentials) to obtain JWT tokens
3. **Token validation**: Validates JWT locally by checking exp claim (no HTTP requests)
4. **OAuth2 flows**: Manages browser-based OAuth2 authorization code flow and refresh token flow

#### What This Package Does

- **Implements ITokenProvider**: Provides concrete implementations (`AuthorizationCodeProvider`, `ClientCredentialsProvider`)
- **Handles OAuth2 flows**: Browser-based OAuth2, refresh token, and client credentials grant types
- **Obtains tokens**: Makes HTTP requests to UAA endpoints to obtain JWT tokens
- **Validates tokens**: Validates JWT locally by checking exp claim (no HTTP requests)
- **Returns tokens**: Returns `ITokenResult` with `authorizationToken` and optional `refreshToken`

#### What This Package Does NOT Do

- **Does NOT store tokens**: Token storage is handled by `@mcp-abap-adt/auth-stores`
- **Does NOT orchestrate authentication**: Token lifecycle management is handled by `@mcp-abap-adt/auth-broker`
- **Does NOT know about service keys**: Service key loading is handled by stores
- **Does NOT manage sessions**: Session management is handled by stores
- **Does NOT return `serviceUrl` if unknown**: Providers may not return `serviceUrl` because they only handle token acquisition, not connection configuration

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
| `timeoutMs` | `30000` (`DEFAULT_LOGIN_TIMEOUT_MS`) | How long the login may wait for its callback |
| `browser` | `'none'` | `'none'` / `'headless'` print the URL; `'system'`, `'auto'`, `'chrome'`, `'edge'`, `'firefox'` open it |
| `callbackServer` | the one this package ships | Your own `CallbackServerFactory`, to reuse a server you already run |
| `openUrl` | the built-in launcher | Receives `(url, browser, redirectUri)` |
| `remoteHint` | the paste hint, only for the shipped UAA transport | Extra guidance printed in `'none'` / `'headless'` mode |
| `signal` | — | `AbortSignal` cancelling the login |

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
  timeoutMs: 30000,
});
```

#### Bringing your own

```typescript
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces';

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

SAML bearer example (manual paste):

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  Saml2BearerProvider,
  manualSamlResponseStrategy,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2BearerProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl,
  uaaUrl: 'https://uaa.example.com',
  clientId: '...',
  clientSecret: '...',
  // `redirectUri` must equal `acsUrl`, or the provider refuses the mismatch.
  authorization: manualSamlResponseStrategy({ redirectUri: acsUrl, read: promptUser }),
});

const broker = new AuthBroker({ tokenProvider: provider }, 'none');
```

**Read that `redirectUri` twice.** A SAML strategy defaults its redirect URI to
`http://localhost:61001/callback`, and the provider requires the assertion
consumer service the IdP posts to be exactly the one the strategy names. If you
declare a real `acsUrl` and leave `redirectUri` off, the login fails with
*"SAML acsUrl is … but the authorization strategy is listening on …"* before
anything is opened. Declare neither and the default is used for both, which is
consistent — and only reachable when the IdP will post to your localhost.

SAML bearer example (headless, assertion fetched elsewhere):

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  Saml2BearerProvider,
  externalCodeStrategy,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2BearerProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl,
  uaaUrl: 'https://uaa.example.com',
  clientId: '...',
  clientSecret: '...',
  authorization: externalCodeStrategy({
    redirectUri: acsUrl,
    provide: async (_authorizationUrl) => getSamlResponseFromSsoProxy(),
  }),
});

const broker = new AuthBroker({ tokenProvider: provider }, 'none');
```

Pure SAML example (cookie-based):

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  Saml2PureProvider,
  manualSamlResponseStrategy,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2PureProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl,
  authorization: manualSamlResponseStrategy({ redirectUri: acsUrl, read: promptUser }),
  // Convert SAMLResponse to session cookies for SAP (implementation-specific)
  cookieProvider: async (samlResponse) => {
    return exchangeSamlForCookies(samlResponse);
  },
});

const broker = new AuthBroker({ tokenProvider: provider }, 'none');
```

Both SAML providers now reject at construction when `authorizationUrl` is set
without `acsUrl`:

```
acsUrl is required when authorizationUrl is set: the ACS inside a pre-built
SAML request cannot be read, so it must be declared.
```

The ACS is buried in a deflated `SAMLRequest` this package did not build and
cannot read, so it cannot be verified against whatever the strategy binds. 1.x
accepted the combination and defaulted the ACS to
`http://localhost:3001/callback` — usually not where the IdP posted.

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
});

const result = await provider.getTokens();

// result.authorizationToken contains the JWT token
// result.refreshToken is undefined (client_credentials doesn't provide refresh tokens)
```

#### DeviceFlowProvider

`DeviceFlowProviderConfig` now accepts `logger?: ILogger`. The verification URI
and the user code are a prompt the user must see, not a log line: they go to the
logger when one is supplied and to **stderr** otherwise. They no longer go to
stdout — capturing stdout to read the device code will read nothing, and the
change exists because stdout carries protocol traffic under an MCP or LSP stdio
transport. `OidcDeviceFlowProvider` behaves the same way.

#### Callback port and lifetime

**Note**: the callback port is set on the strategy (`browserCallbackStrategy({ port })`
and its OIDC/SAML siblings), not on the provider — the 1.x `redirectPort` field
is gone. The default is **61001**, was 3001. If the requested port is already in
use, an error is thrown; specify a different port or free it before starting
authentication. `port: 0` binds an ephemeral port, which works only where the
identity provider accepts a loopback redirect on any port.

**Port lifetime**: the callback port is held for the login and nothing longer. It is bound when the login window opens and released when the login ends — by success, by failure, by timeout, or by cancellation — and the returned promise settles only after the socket is actually free. An error therefore always means the port is already available, and the port is released *before* the authorization code is exchanged for a token, so a slow identity provider cannot hold it either.

**Timeout**: an interactive login waits 30 seconds for its callback, adjustable with `timeoutMs`. This applies to the browser, OIDC and SAML flows alike; before 1.2.0 the OIDC and SAML flows had no timeout at all, so an abandoned login held its port for the life of the process.

**Incomplete callbacks**: a `/callback` carrying neither a code nor an error no longer ends the login. It is answered, counted, and the tally is reported if the login later times out — so a browser prefetch or a stray probe cannot cancel a login the user is still completing.

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
});
const isValid = await provider.validateToken(token);  // serviceUrl optional
// Checks JWT exp claim locally, no network request
```

This approach prevents unnecessary token refresh and browser authentication when:
- Server is unreachable (ECONNREFUSED, timeout)
- Network is slow or unstable
- Running in offline/disconnected mode

### Token Refresh

Providers handle refresh automatically inside `getTokens()`. No separate refresh methods are needed.

```typescript
try {
  const result = await provider.getTokens();
  // Returns new access token and refresh token (if available)
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Missing fields:', error.missingFields);
  } else if (error instanceof RefreshError) {
    console.error('Browser auth failed:', error.cause);
  }
}
```

### Error Handling

The package provides typed error classes for better error handling:

```typescript
import {
  TokenProviderError,
  ValidationError,
  RefreshError,
  SessionDataError,
  ServiceKeyError,
  BrowserAuthError,
} from '@mcp-abap-adt/auth-providers';

try {
  const result = await provider.getTokens();
} catch (error) {
  if (error instanceof ValidationError) {
    // provider config validation failed
    console.error('Missing required fields:', error.missingFields);
    console.error('Error code:', error.code); // 'VALIDATION_ERROR'
  } else if (error instanceof RefreshError) {
    // Token refresh operation failed
    console.error('Refresh failed:', error.message);
    console.error('Original error:', error.cause);
    console.error('Error code:', error.code); // 'REFRESH_ERROR'
  } else if (error instanceof BrowserAuthError) {
    // Browser authentication failed
    console.error('Browser auth failed:', error.cause);
  }
}
```

**Error Types**:
- `TokenProviderError` - Base class with `code: string` property
- `ValidationError` - provider config validation failed, includes `missingFields: string[]`
- `RefreshError` - Token refresh failed, includes `cause?: Error`
- `SessionDataError` - Session data invalid, includes `missingFields: string[]`
- `ServiceKeyError` - Service key data invalid, includes `missingFields: string[]`
- `BrowserAuthError` - Browser auth failed, includes `cause?: Error`

All error codes are defined in `@mcp-abap-adt/interfaces` package as `TOKEN_PROVIDER_ERROR_CODES`.

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
  accepts `logger?: ILogger`; the verification URI and user code go to that
  logger, or to stderr when there is none. Anything that captured stdout to read
  the device code must read stderr or supply a logger.
- **A `/callback` carrying neither a code nor an error no longer ends the
  login.** It is answered and counted, and the tally appears in the timeout
  message if the login later expires.

## Testing

The package includes both unit tests (with mocks) and integration tests (with real files and services).

### Unit Tests

```bash
npm test
```

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
- Errors with details

Example output:
```
[INFO] ℹ️ [browserAuth] Exchanging code for token...
[INFO] ℹ️ Tokens received: accessToken(2263 chars), refreshToken(34 chars)
[DEBUG] 🐛 [BaseTokenProvider] Token validation check {"expiresAt":"2025-12-25 11:08:15 UTC","isValid":true}
[INFO] ℹ️ [browserAuth] Authorization URL: https://.../oauth/authorize?...
[INFO] ℹ️ [browserAuth] Browser: system
```

**Logging Features**:
- **Token Formatting**: Tokens are logged in truncated format (start...end) for security
- **Date Formatting**: Expiration dates are displayed in readable format (YYYY-MM-DD HH:MM:SS UTC) instead of ISO format
- **Browser Information**: Logs browser type and authorization URL for debugging
- **Token Lifecycle**: Detailed logging of token acquisition, validation, and refresh operations

## Dependencies

- `@mcp-abap-adt/interfaces` (^11.6.0) - Interface definitions (`ITokenProvider`, `IAuthorizationStrategy`, `CallbackServerFactory`) and error code constants
- `axios` - HTTP client
- `express` - OAuth2 callback server
- `open` - Browser opening utility

Requires Node.js `>=18.2.0`.

## License

**GNU Lesser General Public License v3.0 only** (`LGPL-3.0-only`).
Earlier published versions were MIT and stay MIT — a licence change is not
retroactive.

Copyright © 2025 Oleksii Kyslytsia

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

