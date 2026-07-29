# Authorization strategies: moving callback reception behind an injectable boundary

**Date:** 2026-07-29
**Issue:** [#11](https://github.com/fr0ster/mcp-abap-adt-auth-providers/issues/11)
**Status:** approved, not implemented

## Why

`auth-providers@1.2.0` gave every callback flow a single owner and a single
release point. It did not move the boundary. The three factories
(`withBrowserCallbackServer`, `withOidcCallbackServer`, `withSamlCallbackServer`)
are still module-internal, so a consumer cannot supply its own way of receiving
an authorization code — it can only name a port and hope. Three items were
deferred rather than done, and this spec resolves all three:

1. Callback reception still lives inside the authorization library.
2. Ephemeral ports (`port: 0`) are rejected, because OIDC and SAML build their
   authorization URL before the server binds.
3. A `/callback` carrying neither `code` nor `error` still ends the login.

The driver for (1) is dependency inversion as such, not one consumer's need.
`@mcp-abap-adt/proxy` is the only consumer today, but the goal is that any
consumer can compose its provider as it sees fit: take the callback server this
package ships, or bring its own implementation of the interface.

## What the design is

The consumer chooses an **authorization strategy** — how the user reaches the
authorization URL and how the payload comes back. The callback server stays a
separate, independently replaceable detail that a strategy is composed of. The
package ships default strategies so that nobody is forced to write one.

### The contract — `@mcp-abap-adt/interfaces`

New file `src/auth/IAuthorizationStrategy.ts`, beside the existing
`ICallbackServer.ts`:

```ts
/** What the provider tells a strategy about the login to conduct. */
export interface AuthorizationRequest {
  /**
   * Build the authorization URL for a redirect URI the strategy has settled on.
   * Called once the strategy knows its redirect URI — which is what makes an
   * ephemeral port possible. May not be called at all: a strategy that already
   * holds a code needs no URL.
   */
  buildAuthorizationUrl(redirectUri: string): string;

  /** For progress messages. Absent means silence — never stdout. */
  readonly logger?: ILogger;
}

/** How the login ended. */
export interface AuthorizationOutcome<TResult> {
  /** What the redirect carried: a code, `{code, state}`, a SAMLResponse. */
  readonly payload: TResult;
  /** The redirect_uri that actually took part — the exchange must send the same one. */
  readonly redirectUri: string;
}

export interface IAuthorizationStrategy<TResult> {
  authorize(request: AuthorizationRequest): Promise<AuthorizationOutcome<TResult>>;
  /** Release long-lived resources. Called by whoever constructed the strategy. */
  dispose?(): Promise<void>;
}
```

Three decisions that are not self-evident:

**Timeout and `signal` are absent from the request; they belong to the
strategy's constructor.** The issue states it directly — listener, browser
launch, stdin, port and *timeout* move to the consumer. Leaving the timeout in
`AuthorizationRequest` would have the provider dictate again how long the
transport lives, which is the defect #11 opened with, wearing a new coat.
Consequence: `LOGIN_TIMEOUT_MS` disappears from `AuthorizationCodeProvider`.

**`authorize` returns the `redirectUri`, not only the payload.** Without it an
ephemeral port is impossible: OAuth2 requires the exchange to carry the same
`redirect_uri` as the authorization request, and with `port: 0` the provider
does not know it. It is also the only way to serve a strategy that already holds
a code and never called `buildAuthorizationUrl`.

**`buildAuthorizationUrl` is the provider's closure, and it closes the PKCE
hole.** Today `OidcBrowserProviderConfig.authorizationCodeProvider` sees neither
the URL nor the `code_challenge`, while the provider keeps its own verifier for
the exchange (`OidcBrowserProvider.ts:102-115`) — so an external code source
could not work against an IdP that enforces PKCE. When the provider builds the
URL on the strategy's request, challenge and verifier stay one pair by
construction.

**Lifecycle: whoever constructs, disposes.** A consumer that passes its own
strategy keeps it; the provider must not tear it down, because the whole point
of a long-lived resource is to outlive one login. A provider given no strategy
constructs the default one per login and disposes of it when that login ends —
providers have no lifecycle of their own to hang it on, and a default strategy
holds nothing between logins anyway. `authorize` may be called again sequentially
(the provider does exactly that when a refresh fails and it falls back to
login); the shipped strategies reject an overlapping call with a clear error,
since they hold a fixed port.

`dispose` carries four obligations, and they belong to the contract rather than
to any one implementation:

- **Idempotent.** Any call after the first is a no-op that resolves.
- **Legal during an active `authorize`, and it ends it.** Releasing resources
  while a socket is still bound would make "released" untrue, so `dispose`
  aborts the in-flight authorization, which rejects with a cancellation error —
  the same outcome an `AbortSignal` produces.
- **Resolves only once the resources are actually free**, matching what
  `CallbackServerFactory` already promises about its port.
- **Never masks the original failure.** The provider calls it from a `finally`;
  if `authorize` threw and `dispose` throws too, the error that propagates is
  the one from `authorize`, and the cleanup failure is logged.

### What the package ships — `@mcp-abap-adt/auth-providers`

`BrowserCallbackStrategy<TResult>`, parameterised by a
`CallbackServerFactory<TResult>`, so a consumer can substitute the receiver and
keep the rest (browser launch, timeout, port) ours. Three ready constructors on
top of it, so the common case needs no knowledge of factories:

```ts
browserCallbackStrategy(opts?) : IAuthorizationStrategy<string>              // UAA code
oidcCallbackStrategy(opts?)    : IAuthorizationStrategy<OidcCallbackResult>  // code (+state)
samlCallbackStrategy(opts?)    : IAuthorizationStrategy<string>              // SAMLResponse

// opts: { port = 61001, timeoutMs = 30_000, browser = 'none',
//         callbackServer?, openUrl?, signal? }   // port: 0 → ephemeral
```

Two more replace today's hand-rolled fields:

```ts
manualPasteStrategy(opts?)          : IAuthorizationStrategy<string>  // OAuth/OIDC code
manualSamlResponseStrategy(opts?)   : IAuthorizationStrategy<string>  // SAMLResponse
externalCodeStrategy({ redirectUri, provide })  // provide(authorizationUrl) → payload

// manual* opts: { redirectUri = 'http://localhost:61001/callback', read? }
```

There are two manual strategies rather than one, because the payload is not
acquired the same way. `manualPasteStrategy` relies on the code appearing in the
browser's address bar after the redirect — true for an authorization code, false
for SAML: our own `AuthnRequest` declares
`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`
(`saml2Auth.ts:62`), so the IdP POSTs `SAMLResponse` in a form body and it never
reaches the URL. `manualSamlResponseStrategy` therefore prompts for a value the
user must take from the POST body — browser devtools, or whatever their IdP
offers — and says so in the prompt. This is exactly what today's
`assertionFlow: 'manual'` already asks for (`saml2Utils.ts:72-79`); naming it
separately stops a single "paste" strategy from implying an acquisition route
that does not exist.

Both still need a redirect URI: the authorization request must carry one, and
for OAuth the exchange must repeat it. The default matches the browser
strategy's port so one registration at the IdP serves both. `read` overrides
where the pasted value comes from, for a consumer with its own prompt.

`manualPasteStrategy` writes its prompt to **stderr**, not stdout — this fixes
`readManualInput` (`src/auth/manualInput.ts:10`), which writes to stdout today
and would corrupt an MCP/LSP stdio transport; `browserAuth` already avoids that
deliberately (`src/auth/browserAuth.ts:307-313`). It reads stdin only when
`process.stdin.isTTY`, and otherwise fails with a clear message rather than
consuming bytes that belong to the protocol.

`externalCodeStrategy` is the repaired `authorizationCodeProvider`: it
**receives the assembled URL**, so the code a consumer brings back is bound to
the same PKCE verifier.

The callback server factories themselves (`withBrowserCallbackServer`,
`withOidcCallbackServer`, `withSamlCallbackServer`) are exported from
`index.ts`. That is what "take the callback server this package gives" means in
code.

### Provider configuration

| Provider | Removed | Added |
|---|---|---|
| `AuthorizationCodeProvider` | `browser`, `redirectPort` | `authorization?: IAuthorizationStrategy<string>` |
| `OidcBrowserProvider` | `browser`, `redirectPort`, `redirectUri`, `authorizationCode`, `authorizationCodeProvider` | `authorization?: IAuthorizationStrategy<OidcCallbackResult>` |
| `Saml2BearerProvider`, `Saml2PureProvider` | `browser`, `redirectPort`, `assertionFlow`, `assertionProvider`, `manualInput` | `authorization?: IAuthorizationStrategy<string>` |

Omitting `authorization` means the default strategy of the matching type — port
61001, `browser: 'none'`, 30 s. `DeviceFlowProvider`, `OidcDeviceFlowProvider`,
`ClientCredentialsProvider`, `OidcPasswordProvider` and
`OidcTokenExchangeProvider` are untouched: they have no redirect.

Two escape hatches survive, with a guard. `authorizationUrl` (a pre-built URL)
and SAML's `acsUrl` embed the redirect inside themselves, so
`buildAuthorizationUrl` returns them unchanged — and then an ephemeral port
becomes a lie: the strategy binds a random port while the IdP returns the user
to the baked-in one. The guard differs by flow, because what the redirect is
embedded *in* differs:

- **OAuth / OIDC, pre-built `authorizationUrl`.** The redirect is a plain query
  parameter. Before the exchange, compare the `redirect_uri` inside the URL with
  `outcome.redirectUri` and fail with an explanation, rather than with an opaque
  `invalid_grant` from UAA.
- **SAML, request generated by us.** The ACS is `acsUrl`, known directly.
  Compare it with `outcome.redirectUri`; a mismatch fails before the browser is
  ever opened.
- **SAML, pre-built `authorizationUrl`.** There is no `redirect_uri` parameter
  to read: the ACS lives inside the `SAMLRequest` parameter as deflated base64
  (`saml2Auth.ts:74-76`), and for an arbitrary pre-built URL the library cannot
  know it at all. So the pair is constrained instead of inspected — when
  `authorizationUrl` is set for a SAML provider, `acsUrl` becomes **required**,
  and it is that declared value which is compared with `outcome.redirectUri`.
  Without it the configuration is rejected at construction rather than
  half-verified at runtime. Ephemeral ports are therefore unusable with a
  pre-built SAML URL — as they are with any registered ACS.

Explicitly out of scope: OIDC `state`. The provider does not send it today
(`OidcBrowserProvider.ts:105-111`) even though `OidcCallbackResult` carries it.
That is a separate CSRF-class defect; folding it into a boundary change would
hide it.

### Callback server changes — items 2 and 3

**Ephemeral port.** `ICallbackServerOptions.port` starts accepting `0`;
validation becomes `0..65535`, and the comment in `ICallbackServer.ts` that
explains *why* zero is rejected is replaced by one explaining the condition
under which it is allowed — the URL is built after the bind.

The structural detail: the handle is assembled before `listen` today and
carries `options.port` (`callbackServer.ts:215-230`), which is a lie when the
port is `0`. The handle moves inside the `listen` callback — where `use(handle)`
is already invoked — and takes the real port from `server.address()`.
`redirectUri` is composed from that, so the strategy receives a URI that is
genuinely being listened on.

The `isPortAvailable` pre-check is skipped when `port` is `0`; there is nothing
to check. For fixed ports it stays, wording included: `AuthBroker` matches
`/already in use/i` to tell a busy port from other failures.

**A code-less callback.** `Settle<TResult>` gains a third method:

```ts
export interface Settle<TResult> {
  ok(value: TResult, res?: express.Response): void;
  err(error: Error, res?: express.Response): void;
  /** This was not our redirect. Answer it and keep waiting. */
  ignore(reason: string, res?: express.Response): void;
}
```

The counter lives in the scope, beside the rest of its state — the same "one
owner" principle that governs the socket: a route reports the fact, the decision
and the bookkeeping stay in one place. `ignore` logs a warning and ends nothing.

Routes that change: `GET /callback` with neither `code` nor `error`
(`callbackServer.ts:333-337`) and SAML `GET`/`POST /callback` without
`SAMLResponse` (`saml2Auth.ts:142-146`) — both from `settle.err` to
`settle.ignore`. An explicit `error=` from the IdP still ends the login at once,
as it should.

The SAML route needs one change beyond swapping the settle call. It answers
`200 "SAML authentication complete"` **before** it looks at the payload
(`saml2Auth.ts:138-147`), so a request without `SAMLResponse` is shown a success
page today while the login fails behind it. The response must be decided after
the check: `200` with the completion page only when a `SAMLResponse` is present,
`400` otherwise. Without this, "ignore" would keep telling the user they had
authenticated when nothing arrived.

The timeout message carries the tally:

> `Authentication timeout after 30 seconds. Please try again.` plus, when the
> counter is non-zero, `3 request(s) reached /callback without an authorization
> code and were ignored.`

This is the diagnosis that buys back what ignoring costs. Ignoring a stray
request means a genuinely misconfigured IdP — one that redirects without a
`code` and without an `error` — no longer fails fast with a precise message; it
hangs until the timeout. The reason does not disappear, it moves from the moment
of failure to the summary.

To give `ignore` somewhere to write, `ICallbackServerOptions` gains
`logger?: ILogger` — transport level, the same level that already carries the
port and the timeout.

## Testing

`callbackServer.test.ts` gains three cases: an ephemeral bind (`port: 0` →
`handle.port` is not zero, `redirectUri` carries it, the port is free after the
scope); an ignored request (a stray `GET /callback` → 400, the scope still
alive, a subsequent real `code` resolves); a timeout message with the tally.

The SAML routes get their own two cases, `GET` and `POST` separately, asserting
both halves of the change: a request without `SAMLResponse` is answered `400`
and not with the completion page, and the scope stays alive. They are separate
tests because the two routes read the payload from different places — query
versus form body — and a shared handler makes it easy to fix one and miss the
other.

A new file covers the strategies: `BrowserCallbackStrategy` against a fake
`CallbackServerFactory`; `manualPasteStrategy` and `manualSamlResponseStrategy`
under an intercepted `process.stdout.write` (not one byte to stdout);
`externalCodeStrategy` receiving a URL with `code_challenge` in it. `dispose` is
covered against its four obligations: called twice, called mid-`authorize` (the
authorization rejects and the port is free when `dispose` resolves), and
throwing from `dispose` after `authorize` already threw (the `authorize` error
is what propagates).

At provider level: with no `authorization`, the default strategy is used (port
61001 is visible in the URL); with one injected, the provider binds no socket at
all; the `redirect_uri` mismatch guard fires on the pair "pre-built
`authorizationUrl` + ephemeral port".

Side benefit: `AuthorizationCodeProvider timeout ownership` waits the full 30 s
today and says so — "the provider exposes no way to shorten it"
(`AuthorizationCodeProvider.test.ts:336-338`). Strategies provide the way:
`browserCallbackStrategy({ timeoutMs: 1000 })`. The suite loses about 30 s of
its 40.

## Release chain

| Package | Version | Nature |
|---|---|---|
| `interfaces` | 11.5.0 | purely additive: new file, `port: 0` allowed, `logger` option |
| `auth-providers` | 2.0.0 | breaks provider configuration |
| `proxy` | 1.7.0 | `btpProxy.ts:295-298` → `browserCallbackStrategy({ port: browserAuthPort ?? 3333 })` |
| `auth-broker` | 1.0.9 | nothing functional; its integration tests construct the provider with `redirectPort` and must be updated |

The proxy's `--browser-auth-port` flag stays alive and does what it did — its
3333 default is preserved explicitly. The 61001 default applies only to whoever
configured nothing.

## Documentation

This package's `README.md` shows `browser:` and `redirectPort:` in seven places
(lines 89, 159, 279, 295-296, 314, 344, 359); every example is rewritten in
terms of strategies, and the section on browser modes becomes a section on
choosing a strategy. A 1.x → 2.0 migration section is added: a "field was →
strategy is" table, a separate note that `authorizationCodeProvider` is replaced
by `externalCodeStrategy` and that `assertionFlow` maps by value —
`'browser'` → `samlCallbackStrategy`, `'manual'` → `manualSamlResponseStrategy`,
`'assertion'` → `externalCodeStrategy` — and that the default port changed. `docs/REFACTORING_PROPOSAL.md` is checked for currency — it
describes an `ITokenProvider` refactor that has already shipped — and updated or
deleted. In the proxy, the description of `--browser-auth-port` is updated if it
describes internal mechanics.

## Risks, stated plainly

Changing the default port from 3001 to 61001 is a behavioural break for anyone
who constructs a provider without an explicit port and has already registered
`http://localhost:3001/callback` with their IdP. It sits inside a major release
and will be in the migration note, but it is not merely "a new default": such a
consumer's login fails on the IdP's side with `invalid redirect_uri`, so the
message they see is foreign and unhelpful.

SAML gains strategies, but an ephemeral port stays practically out of reach for
it: `acsUrl` is embedded in the `AuthnRequest` itself (`saml2Auth.ts:63`) and
must be registered with the IdP. The mechanism will permit it; reality will not.
Recorded here so the next reader does not take it for an omission.
