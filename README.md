# @mcp-abap-adt/auth-providers
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

Token providers for MCP ABAP ADT auth-broker.

This package provides token provider implementations for the `@mcp-abap-adt/auth-broker` package.

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Overview

This package implements the `ITokenProvider` interface from `@mcp-abap-adt/interfaces-auth`:

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

Providers are configured via constructor; `getTokens()` takes no parameters and handles refresh/login internally.

Since 2.0.0 an interactive login is conducted by an **authorization strategy**
(`IAuthorizationStrategy` from `@mcp-abap-adt/interfaces-auth`) passed as
`authorization`. The provider owns what it can compute — the authorization URL
and the token exchange; everything between them (reaching the URL, receiving
what comes back, the port, the timeout) belongs to the strategy, which a
consumer may replace wholesale. See
[Choosing an authorization strategy](#choosing-an-authorization-strategy).

Since 4.0.0 both SAML providers **validate the assertion before trusting it** —
its signature, issuer, audience, recipient, time window, the request it answers,
and whether it has been seen before — and must therefore be told which identity
provider to trust. This is a breaking change: a 3.x SAML configuration fails at
construction. See [SAML assertion validation](#saml-assertion-validation).

If you are on an earlier major, see
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
- **Validates SAML assertions**: Ships two validators (`createSignedResponseValidator`, `createSignedAssertionValidator`) and an in-memory replay store; both SAML providers use one by default, and a consumer may supply its own `IAssertionValidator` or `IAssertionReplayStore`

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
example below says whom to trust: `idpCertificates` and `idpEntityId`. See
[SAML assertion validation](#saml-assertion-validation) for what is checked and
what else can be configured.

SAML bearer example (UAA or XSUAA — an IdP-initiated assertion):

```typescript
import { readFileSync } from 'node:fs';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import { Saml2BearerProvider } from '@mcp-abap-adt/auth-providers';

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
  // Whom to trust: the identity provider's signing certificate and entity ID.
  idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
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
Assertion — which is why this provider's default validator is the one that
requires the Assertion to be signed. An `EncryptedAssertion` is refused before
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
  manualSamlResponseStrategy,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2PureProvider({
  idpSsoUrl: 'https://idp.example.com/sso',
  spEntityId: 'my-sp-entity',
  acsUrl,
  idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
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

**This is a breaking change.** Each provider constructs its validator in its
constructor, and a configuration that does not say whom to trust fails there —
a `ValidationError` whose `missingFields` names what is missing — before any
browser opens or any request is sent. Supply `idpCertificates` and
`idpEntityId`, or an `assertionValidator` of your own.

#### Configuration

On both providers' configuration (`Saml2BearerProviderConfig`, `Saml2PureProviderConfig`):

| Field | Default | Meaning |
|---|---|---|
| `idpCertificates` | — | The identity provider's signing certificates, PEM or bare base64 DER — the form `<X509Certificate>` has in IdP metadata. A list, because providers rotate keys and two are live during a rotation. **Required unless `assertionValidator` is supplied.** Each entry is parsed at construction, so a malformed one fails there, not at login |
| `idpEntityId` | — | The `Issuer` the assertion must name, passed to the validator as `expectedIssuer`. **Required unless the `assertionValidator` supplied is your own**: a shipped validator (`createSignedResponseValidator`, `createSignedAssertionValidator`) refuses every assertion without an expected issuer, so supplying one without `idpEntityId` fails at construction. A custom validator does not need it, and receives it when given |
| `spEntityId` | — | Your entity ID. The assertion's `AudienceRestriction` must name it — whichever validator is in play |
| `assertionValidator` | the provider's default | An `IAssertionValidator`: `createSignedResponseValidator(…)`, `createSignedAssertionValidator(…)`, or your own. When supplied, the provider builds no default, and `idpCertificates`, `clockSkewMs` and `assertionReplayStore` are not used — set them on the validator's own options. `idpEntityId` is still required with a shipped one |
| `assertionReplayStore` | the process-wide in-memory store | An `IAssertionReplayStore` for the default validator — see [Replay](#replay) |
| `clockSkewMs` | `0` | Tolerance for the default validator's time checks — see [Clock skew](#clock-skew) |
| `authnRequestId` | — | The AuthnRequest ID this login answers, when the package did not build the request — see [Where the expected request ID comes from](#where-the-expected-request-id-comes-from) |
| `idpInitiated` | `false` | Declares that no AuthnRequest was sent, so the assertion must carry no `InResponseTo`. Required for `Saml2BearerProvider` against UAA or XSUAA |

The package performs no I/O for any of these: it fetches no metadata and reads
no file. Reading the certificate is the consumer's job.

#### Choosing a validator

This is the first decision to make, and **the default differs by provider**:

| | `createSignedResponseValidator` | `createSignedAssertionValidator` |
|---|---|---|
| The signature must cover | the `Response` | the `Assertion` — bare, or inside a Response |
| Default of | `Saml2PureProvider` | `Saml2BearerProvider` |
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
  }),
  cookieProvider: exchangeSamlForCookies,
});
```

**`createSignedResponseValidator`** requires the identity provider to sign the
`Response`. Every field all twelve checks read is then inside the signature, so
every check is a control. It is `Saml2PureProvider`'s default because there the
whole response is handed on to `cookieProvider`, and `Status` and `Destination`
must be inside a signature.

**`createSignedAssertionValidator`** accepts a signature over the `Assertion`,
and **does not read** `Status`, `Response/Issuer` or `Destination` at all — not
weakly: with an assertion-only signature those fields sit outside it, where
anyone able to deliver a response sets them to whatever is expected, and a check
on a field an attacker controls reads in the code and the logs as if something
had been verified. It is `Saml2BearerProvider`'s default because the token
endpoint receives the Assertion alone, taken out of any Response, so the
Assertion's own signature is what counts there. Configuring the signed-Response
validator on the bearer path would refuse a bare Assertion, and accept responses
signed only at the Response level, which the token endpoint then refuses.

**Who needs the second one.** Identity providers that sign only assertions —
which is many. A `Saml2PureProvider` consumer whose IdP does so gets a
`signedNode` refusal from the default, and selects
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
| 2 | Every signature is valid against `idpCertificates` — never against a certificate the document carries in its own `KeyInfo` | none, wrong key, content altered after signing, more than one reference, a reference outside the document, or a signature not inside the element it references | `signature` |
| 3 | The signed node is the node read | the signature does not cover the element this validator requires — the `Response`, or the bare root `Assertion` or the Response's direct-child `Assertion` — the response does not hold exactly one `Assertion`, or any `saml:Assertion` / `saml:EncryptedAssertion` lies outside the signed assertion | `signedNode` |
| 4 | `samlp:Status` *(signed-Response only)* | absent, or its `StatusCode` is not `…:status:Success` | `status` |
| 4b | `Assertion/@ID` | absent or empty | `assertionId` |
| 5 | `Assertion/Issuer` | absent, not the expected issuer, or no expected issuer was given | `issuer` |
| 5b | `Response/Issuer` *(signed-Response only; optional)* | present and disagreeing with `Assertion/Issuer`, or present twice — absent is accepted | `issuer` |
| 6 | `Conditions` | absent | `conditions` |
| 7 | `Conditions/@NotBefore` *(optional)* | present and not a valid `xsd:dateTime`, or in the future beyond `clockSkewMs` — absent is accepted | `notBefore` |
| 8 | `Conditions/@NotOnOrAfter` | absent, not a valid `xsd:dateTime`, or in the past beyond `clockSkewMs` | `notOnOrAfter` |
| 9 | `Conditions/AudienceRestriction` | absent, or **any one** restriction fails to name `spEntityId` | `audience` |
| 10 | One bearer `SubjectConfirmation` | no single confirmation satisfies every part of it — see below | `bearerConfirmation` |
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
  SAML-namespace `Assertion` or `EncryptedAssertion` anywhere in the document
  must be the signed assertion or inside it, under both validators. An extra
  assertion in `Extensions`, a sibling or a wrapper ends the login rather than
  being ignored. Encrypted assertions are not supported.
- **Several signatures are accepted** when every one verifies against
  `idpCertificates`, carries exactly one same-document reference, and sits
  directly inside the element it references. A signature that fails refuses the
  whole document, even when another covers the element read. A document with no
  signature is refused.
- **Unique IDs (1b)** are the wrapping defence again: XML-DSig resolves its
  reference by `ID`, so a duplicate makes "which element is signed" ambiguous.
  They are refused wherever they appear, before any reference is resolved.
- **Check 10 is one element, not four fields.** There must be a single
  `SubjectConfirmation` with `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"`,
  under exactly one `Subject`, whose own `SubjectConfirmationData` satisfies
  all of: `InResponseTo` equal to the expected request ID — or **absent** for a
  login declared `idpInitiated`; `Recipient` equal to the ACS the response
  arrived at; `NotOnOrAfter` present, a valid `xsd:dateTime` and not past beyond
  `clockSkewMs`; `NotBefore`, if present, not in the future beyond it. Values
  scattered across several confirmations do not add up to one.
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
- **SHA-1 is accepted.** RSA-SHA1 signatures and SHA-1 digests verify, as they
  do under `xml-crypto`'s defaults, because identity providers still emit them
  and refusing them would refuse genuine logins. To refuse them, supply an
  `assertionValidator` of your own that rejects a `SignatureMethod` or
  `DigestMethod` naming `…xmldsig#rsa-sha1` or `…xmldsig#sha1` before
  delegating to a shipped validator — and keep `idpEntityId` configured, since
  the shipped validator inside still refuses without an expected issuer.

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
the two describe different logins. With a declared `authnRequestId` it is a
`ValidationError` (`missingFields: ['idpInitiated']`) after the strategy
returns. A strategy that calls `buildAuthorizationUrl` with no
`authorizationUrl` configured is refused inside the builder, before a URL — and
so a request ID — exists: a `ValidationError` with `missingFields:
['authorizationUrl']`. Use a strategy that does not call the builder, and leave
`authnRequestId` unset; or configure the identity provider's IdP-initiated SSO
URL as `authorizationUrl`, which the builder hands over without minting
anything.

#### Replay

The default replay store is **process-wide**: one module-level in-memory store,
`defaultReplayStore`, shared by every default validator in the process — both
providers, every instance. An assertion accepted once is refused as a replay
(`check: 'replay'`) for as long as it could still be accepted, however many
providers are constructed; a store per provider would let a second provider
accept what the first had seen. It is keyed by `{issuer, assertionId}`, since an
ID is unique only within the identity provider that minted it. Only an assertion
that passed every other check is recorded.

What it does **not** protect: anything across processes. A second process, a
restart, or a horizontally scaled deployment each start with an empty memory.
For those, supply a shared store — `assertionReplayStore` on the provider, or
`replayStore` on a shipped validator's options. Its `recordIfUnseen` must be
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
`expiresAt`, `assertionId`, `issuer`, `nameId` (when the `Subject` has one),
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
} from '@mcp-abap-adt/auth-providers';

const validator = createSignedResponseValidator({
  idpCertificates: [readFileSync('idp-signing.pem', 'utf8')],
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
| `ValidationError` | configuration: `idpCertificates` or `idpEntityId` missing with no `assertionValidator`, or `idpEntityId` missing with a shipped validator supplied as `assertionValidator` (at construction); `idpInitiated` with no `authorizationUrl` and a strategy that calls `buildAuthorizationUrl` (inside the builder, before any URL is produced); `authnRequestId` missing, or `idpInitiated` combined with a declared `authnRequestId` (at login, after the strategy returns and before the assertion is read). `missingFields` names the field |
| `Error` | a certificate that is neither PEM nor base64 DER, or not a valid X.509 certificate; a `clockSkewMs` that is not a finite non-negative integer; and, for a shipped validator called directly, an empty `idpCertificates` (*"must not be empty"*) — all at construction. Through a provider, an empty `idpCertificates` is a `ValidationError` instead |

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
  // The default: announce <uaaUrl>/passcode, read the code from the terminal.
  // Supply `read` to take it from anywhere else — never from stdin under MCP.
  authorization: manualPasscodeStrategy({ read: askTheUser }),
});
```

The exchange is the password grant with `passcode` instead of a username and
password — a UAA extension, not an RFC. A code is single-use; a mistyped or
spent one fails with `Passcode exchange failed (401): Invalid passcode`.

#### Device flow prompts

`OidcDeviceFlowProvider` accepts `logger?: ILogger`. The verification URI and
the user code are a prompt the user must see, not a log line: they go to the
logger when one is supplied and to **stderr** otherwise — never to stdout,
which carries protocol traffic under an MCP or LSP stdio transport.

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
  AssertionValidationError,
} from '@mcp-abap-adt/auth-providers';

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
- `AssertionValidationError` - a SAML assertion was refused, includes `check: AssertionCheck` naming the check that failed — see [SAML assertion validation](#errors)

All error codes are defined in `@mcp-abap-adt/interfaces-auth` package as `TOKEN_PROVIDER_ERROR_CODES`, and `AssertionValidationError`'s as `ASSERTION_ERROR_CODES`.

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

- **Node.js 22 or 24.** `engines` is `"^22 || ^24"`, following SAP BTP, Cloud
  Foundry. Node 18 and 20 are past their end of life and SAP has removed 20;
  23 and 25, odd releases, are too. Move the process to 22 or 24.
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
(8080) and `KEYCLOAK_PORT` (8081) move the servers. A server that is already
running is never changed: if it is published on another port than the one
asked for, `test:stand` refuses and says so, rather than let Compose recreate
it.

| provider | server | what the suite proves |
|---|---|---|
| `Saml2BearerProvider` | UAA | a bearer assertion — and a whole `SAMLResponse` — passes the default validator, declared `idpInitiated`, and is exchanged for a token; UAA issues a refresh token exactly when the client may hold one, and the provider refreshes without its authorization strategy |
| `Saml2BearerProvider` | Keycloak → UAA | end to end with no assertion built by the tests: an IdP-initiated Keycloak login passes validation and becomes a UAA token; the answer to the provider's own AuthnRequest passes validation against the ID it minted, and UAA refuses it for its `InResponseTo` |
| `Saml2PureProvider` | Keycloak | the identity-provider half: Keycloak accepts the provider's AuthnRequest and posts a response, signed at both levels, to the ACS it named; the default signed-Response validator accepts it against the ID the provider minted, and it reaches `cookieProvider` unchanged |
| `ClientCredentialsProvider` | UAA | a client token |
| `UaaPasscodeProvider` | UAA | a code fetched from `/passcode` after logging in there, exchanged for tokens; a refresh that does not ask for another code; a spent code refused |
| `AuthorizationCodeProvider` | UAA | a login through UAA's own form, and a refresh without logging in again |
| `OidcPasswordProvider` | Keycloak | the password grant through discovery, and a refresh that works with a wrong password — so it is a refresh, not a second login |
| `OidcBrowserProvider` | Keycloak | authorization code with S256 PKCE, which the client requires, through Keycloak's login page |
| `OidcDeviceFlowProvider` | Keycloak | a token once the user logs in and grants access on Keycloak's device pages, read from the verification URI the provider announces |
| `OidcTokenExchangeProvider` | Keycloak | RFC 8693: another client's access token exchanged for the requester's own |

The servers' configuration is committed as test fixtures —
`tests/stand/uaa/config/uaa.yml`, `tests/stand/keycloak/realm-test.json` and the
test identity provider's key in `tests/stand/uaa/idp/` — so every machine and CI
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

A plain `npm test` skips these suites: they run only with `UAA_URL` or
`KEYCLOAK_URL` set, which `test:stand` does.

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
client may use saml2-bearer, refresh_token and password; an `xsuaa`/`apiaccess`
instance, used only to manage trust; and a SAML trust to a test identity
provider whose key is generated locally and never leaves the gitignored
`tests/xsuaa/.local/`. Then it runs the suite and removes all of it — also when
a test fails. Two rules keep it from touching anything else:

- **Target.** The scripts refuse to run unless `cf` targets exactly
  `XSUAA_CF_API`, `XSUAA_CF_ORG` and `XSUAA_CF_SPACE`. There are no defaults, so
  a `cf` left pointing at another org or space cannot receive anything.
- **Ownership.** Everything setup creates is recorded in
  `tests/xsuaa/.local/owned` with its immutable ID — the service instance's
  GUID, the trust's id — and the record names the API, org and space it
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

- `@mcp-abap-adt/interfaces-auth` (^2.0.0) - Token provider, authorization and assertion-validation contracts (`ITokenProvider`, `IAuthorizationStrategy`, `CallbackServerFactory`, `IAssertionValidator`, `IAssertionReplayStore`) and error code constants
- `@mcp-abap-adt/interfaces-auth-sap` (^1.0.1) - XSUAA authorization configuration (`IAuthorizationConfig`)
- `@mcp-abap-adt/interfaces-utils` (^1.1.0) - `ILogger`
- `@xmldom/xmldom` - XML parsing: SAML assertion validation, and taking the Assertion out of a SAMLResponse for the saml2-bearer grant
- `xml-crypto` - XML-DSig signature verification for SAML assertion validation
- `axios` - HTTP client
- `express` - OAuth2 callback server
- `open` - Browser opening utility

Requires Node.js 22 or 24 (`engines: "^22 || ^24"`). The supported versions
follow SAP BTP, Cloud Foundry, whose Node.js buildpack offers exactly these two;
CI tests both. Odd-numbered releases are never supported — they reach end of
life within months — and a new major joins only once SAP offers it.

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

