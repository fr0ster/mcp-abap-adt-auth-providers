# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A migration, not an update: 6.0.0 replaces the error contract. Every refusal
and every throw of this package is now an error of one closed list of
**kinds**, minted by `@mcp-abap-adt/auth-errors` from allowlisted facts —
never a class to match with `instanceof`, never words to parse. Together with
it, no login, request or registry query is bounded by a timeout of the
package's choosing any more: the consumer's `AbortSignal` is the bound. How a
token provider renews, and what it tells a store, are now strategies the
consumer gives (`renewal`, required; `persistence`, replacing `onTokens`).
And a login is bound to its attempt (`state`, PKCE, a gated loopback
callback). See *Migrating to 6.0.0* in the README for what a 5.x consumer must
now do. The surface changes below are taken from a diff of every exported
declaration against the published 5.4.2.

### Breaking

- **A refusal is an `IAuthProviderError`** (`@mcp-abap-adt/interfaces-auth`
  6.0.0: `IAuthRefusal = IAuthProviderError`). `AuthOutcome` is `{ ok: true }`
  or `{ ok: false, refusal }`, the refusal a frozen object of `kind`,
  `variant` (for `saml-assertion`, `snc`, `configuration`), `facts`,
  `reason`, `hint?` and `diagnostics?`. `refusal.reason` / `refusal.hint`
  read as before; a refusal cannot be built from free words, copied or
  mutated — an object that is not minted by `@mcp-abap-adt/auth-errors` is
  rebuilt from its `kind` and `facts` (its diagnostics dropped) wherever it is
  read, and a provider answering one is answered `unknown`.
- **Every throw is an `AuthProviderFailure`** (`@mcp-abap-adt/auth-errors`):
  an `Error` whose `error` is one minted `IAuthProviderError`, whose
  `message` is `reason` or `reason — hint`, and which has no `cause`.
  Constructors, factories and loaders throw it for a configuration fault
  (kind `configuration`, `facts.case`, `facts.fields`); `getTokens()` and
  `refreshTokens()` throw nothing else — a strategy's, loader's or
  presenter's own error is classified, never rethrown as itself, and no
  `AxiosError` escapes. Read what was thrown with `readFailure(thrown,
  operation)`, test with `isAuthProviderFailure(value)`, never `instanceof`.
- **The words changed.** Each kind renders its own words from its facts
  (auth-errors' `render`). Notably: a refused token request reads
  `<operation> failed (HTTP <status>[, <registered code>])` —
  `the passcode exchange failed (HTTP 401)`, `the refresh failed (HTTP 400,
  invalid_grant)` — instead of `TokenEndpointError`'s
  `Passcode exchange failed (401)`; a TLS failure reads
  `<operation> failed: <the kind's words> (<code>)`; an unfamiliar thrown
  value `<operation> failed (unknown error[, CODE])` with an operation of a
  closed list (`OPERATIONS`), never a class label; a SAML refusal names its
  rule and carries no document value in the words (the value is a
  diagnostic); the SNC library's path and each candidate's path are
  diagnostics, not words; a configuration error says its case's fixed words.
  Code matching on words must match on `kind` and `facts`. The README's
  tables are generated from the words the package renders.
- **No server text, in errors or logs, by default or with `authDebug`.** A
  token endpoint's `error_description` and `error_uri` are read by nothing:
  they reach no error, no failure, no response data and no log line. The
  registered OAuth `error` survives as the fact `oauthError` (5.4.2's
  reduced `err.response.data.error` is `failure.error.facts.oauthError`). A
  failed request still writes 5.4.2's `debug` line of safe facts (`{ status,
  error? }`, now with an allowlisted `code`); the UAA code exchange's `200`
  without `access_token` keeps 5.4.2's `error`-level line, verbatim (status
  and registered code only). A consumer that read the server's description
  from an error or a log no longer finds it anywhere.
- **No URL and no configured value in a log line.** 5.4.2 logged the token,
  device-authorization and discovery endpoints, the UAA URL, the client id
  and the redirect URI at `info`, and an authorization URL in a launcher's
  error line — a discovered endpoint is the server's text (a newline in it
  forged a line), a configured one may hold a credential. Every such line now
  carries fixed words and admitted facts only, `authDebug` or not. The
  authorization URL and the device flow's verification URI still reach the
  user — in the **prompt**, and only as an `http:` / `https:` serialisation of
  printable ASCII; one that cannot be shown so is named in fixed words.
  `consoleDeviceCodePresenter` shows the user code only when it is printable
  ASCII and rejects without a showable URI and code (`device-code-not-shown`).
  The manual strategies' prompt is two lines, never one line with a line
  break inside it.
- **A browser that does not open no longer ends the login.** A launcher
  that throws or rejects (`openUrl`, or the built-in one) gets one log line
  in fixed words and the authorization URL as a prompt, and the login keeps
  waiting on the same callback, so the URL shown is live — the way to finish
  where no browser can be opened. 5.4.2 ended the login with a
  `BrowserAuthError`; there is no `browser-launch-failed` outcome either
  (interfaces-auth 6.0.0 had one, 7 removed it). A consumer that matched a
  launch failure must stop, and bounds the login with its `signal`.
- **Token answers are read by type.** An answer's `access_token`,
  `refresh_token`, `id_token` and the device fields are kept only as
  non-empty strings, `expires_in` and `interval` only as finite non-negative
  JSON numbers (RFC 6749 §5.1; a numeric string such as `"3600"` is not one).
  An `access_token` of another type is no token: `request-failed`
  `no-access-token`, nothing presented (5.4.2 handed `42` on as the token and
  `"abc"` as `expiresIn`). A `refresh_token` or `expires_in` of another type
  is absent.
- **Options are read as own data.** Every exported constructor and factory
  reads its options once as a plain snapshot of own data properties: a getter
  is not run and reads as absent, and a throwing Proxy reads as absent — so a
  hostile options object throws only the constructor's own `configuration`
  failure, never its own text. **A consumer that defined an option by a
  getter, or on a prototype, passes a plain object instead.** The shipped
  validators now refuse at construction what 5.4.2 refused at the first
  validation or with a `TypeError`: `idpCertificates` that is not an array
  (`validator-no-certificates`), an entry that is not a string
  (`idp-certificate-invalid`), a missing `replayStore`
  (`required-fields-missing`, `replayStore`). A strategy, loader or presenter
  called directly by the consumer, outside a moment, may still reject with
  what its own collaborator threw (README, "Errors outside the moments").
- **No built-in timeouts.** Removed: `DEFAULT_LOGIN_TIMEOUT_MS` (30 s);
  `timeoutMs` on `BrowserCallbackStrategyOptions`, `CallbackStrategyOptions`
  (`browserCallbackStrategy`, `oidcCallbackStrategy`, `samlCallbackStrategy`)
  and `ManualStrategyOptions`; the `{ timeoutMs }` options of
  `AuthorizationCodeProvider.inBrowser`, `OidcBrowserProvider.inBrowser`,
  `Saml2BearerProvider.inBrowser`, `Saml2PureProvider.inBrowser` and
  `UaaPasscodeProvider.fromTerminal` (whose default was 300 s), now
  `LoginFactoryOptions` (`{ signal }`); `ICallbackServerOptions.timeoutMs`
  (interfaces-auth 6.0.0); the callback server's shutdown grace; the client
  credentials request's 30 s timeout; the SNC registry query's 5 s timeout.
  A login ends on its result, the identity provider's refusal or the
  consumer's `AbortSignal`; a request ends when the server or the OS ends it,
  or on the signal. **A consumer that passed `timeoutMs` passes
  `signal: AbortSignal.timeout(ms)` instead; one that passed nothing now waits
  until it aborts.** The "Authentication timeout after N seconds" and "did not
  arrive in time" messages are gone with them.
- **Subclassing a provider.** Every provider extends the new
  `AuthProviderBase`, which owns `prepare()`, `establish()`, `authorize()`
  and `rejected()` and runs each inside auth-errors' `guard`; a subclass
  implements the protected `onPrepare()`, `onEstablish(logon)`,
  `onAuthorize(request)` and `onRejected(rejection)` instead of overriding
  the four. `BaseTokenProvider`'s constructor takes its options as required
  (`renewal` is in them). Its protected `performLogin()` is now
  `performLogin(attempt: AttemptContext)` — the strategy gets
  `attempt.signal` — and `performRefresh()` is
  `performRefresh(refreshToken: string, signal, dispatched: () => void)`: a
  subclass must send the refresh token it is given (reading
  `this.refreshToken` may send one the renewal strategy discarded), and must
  call `dispatched()` right before the request leaves — the shipped sites do
  it through the new protected `refreshSiteOptions(dispatched)`. A refresh
  that never reports its dispatch counts as never sent, so an abort never
  applies `ifCut` to its refresh token. `pin()` takes an optional `signal`;
  new protected members: `grant()`, `siteOptions(signal?)`,
  `refreshSiteOptions(dispatched)`, `authDebug`.
- **Strategies honour the request's signal.** `externalCodeStrategy`'s
  `provide` is `(authorizationUrl, signal) => Promise<string>`. A manual
  strategy's custom `read(prompt, signal)` that ignores its signal now blocks
  that strategy's `authorize` — and the next login, which waits for the
  aborted one to settle — where 5.x settled through a race. A consumer's own
  `IAuthorizationStrategy` must end on `request.signal`.
- **Device polling follows RFC 8628 §3.5.** `slow_down` adds 5 s to the
  interval for that poll and every later one (cumulative); the server's
  `interval` counts only as a finite, non-negative number, else 5 s; `0`
  waits not at all. `authorization_pending` / `slow_down` keep the poll
  waiting only with status `400` — with any other status the poll ends with
  the failure.
- **Every token provider requires a renewal strategy.** `renewal:
  IRenewalStrategy` (interfaces-auth 7) is a required field of every token
  provider's config, and so of `inBrowser`, `fromTerminal`, `toConsole` and
  `SsoProviderFactory.create`; there is no default. Missing, or with a `next`
  that is not a function: `configuration` `required-fields-missing`,
  `fields: ['renewal']`, at construction. The strategy is asked before every
  step of every renewal — `refresh` (with a required `ifCut`), `login` or
  `stop`, and after a refresh that failed once sent, a required
  `sentRefreshToken: 'keep' | 'discard'` — and the provider takes no step it
  did not ask for. **`refreshThenLogin()` takes 5.x's steps**: one refresh,
  then one login when there is no refresh token or the refresh failed;
  `refreshOnly()` never logs in. An unusable answer (a throw, an invalid
  decision, a foreign thenable or a promise with its own `then`, never
  called) ends the renewal `unknown` with the new operation
  `renewal-strategy`; `next` is raced with the renewal's signal. The strategy
  receives frozen copies of minted errors and allowlisted facts, never a
  token; `aborted(observation)`, optional, is told of each aborted step,
  never awaited.
- **Rule 5 is a reading the renewal strategy receives.** `rejected()` no
  longer returns early for a rejection that is not the credential's: it
  starts a renewal with `cause.reading` `not-credential`, and the shipped
  strategies stop at once with the neutral `system-refused` refusal, nothing
  sent — the 5.x answer. A strategy of your own may renew there.
- **A cut refresh: `ifCut` decides.** A refresh whose waiters all aborted
  after it was sent runs on; its refresh token is discarded or kept as the
  `ifCut` of the decision that started it says. The shipped strategies say
  `'discard'` — that refresh token is never sent again by the provider, so
  the next renewal may cost one login. A refresh aborted before it was sent
  (OIDC discovery, a client-authentication strategy) touches no refresh
  token.
- **What a renewal answers, where it cannot produce a usable credential: it
  throws** (with `refreshThenLogin()`): a renewal whose new token is still
  bound to another certificate than the pinned one — `getTokens()` /
  `refreshTokens()` throw `token-binding` `renewed-bound-elsewhere` (5.4.2
  returned the token), `rejected()` with a `401` answers Oops (5.4.2: Ok); a
  held token remembered as bound elsewhere — `getTokens()` throws the
  remembered error (5.4.2 returned the token), and `prepare()` no longer
  clears what is remembered but renews once more (the remembered error
  reaches the strategy as `cause.lastRenewal`); a remembered expired
  certificate is refused again by the pin, an equal refusal rather than the
  same object. A credential a step obtained stays committed either way.
- **New kind `renewal-declined`** (interfaces-auth 7, auth-errors 2): "the
  renewal strategy declined to renew the credential", `facts.trigger` — a
  strategy that stops before any step with no other refusal to answer
  (`refreshOnly()` with an expired token and no refresh token, say). An
  exhaustive switch over kinds must handle it.
- **`onTokens` is replaced by `persistence`.** The config field
  `onTokens?: (result) => Promise<void>` is removed; `persistence?:
  ITokenPersistence` (interfaces-auth 7) receives one report per change of
  the provider's credentials, from inside its commit queue in commit order —
  `credential` (a new credential, with `refreshToken` `{ change: 'new',
  value }` or `{ change: 'none' }`) or `refresh-token-discarded` (the
  credential still held) — never for a cache hit, never twice. A report is
  `awaited` while a caller of the renewal is still waiting: the provider
  awaits it, and **its failure fails that call** (`unknown`,
  `persisting-tokens`), the credentials staying committed and no login
  following — where a failing `onTokens` was only logged. A detached report
  is not awaited; its failure is logged once, `[BaseTokenProvider]
  Persisting the tokens failed`. Without `persistence` nothing is persisted.
  `refreshStatePersistence(write, { onWriteFailure: 'continue' })` is the
  5.x `onTokens` behaviour. A `persistence` that is not an object with a
  callable `report` is `configuration` `invalid-value` naming `persistence`.
  `refreshTokenDisposition`, which interfaces-auth 6.0.0 had added to
  `ITokenResult`, is removed in interfaces-auth 7 with
  `RefreshTokenDisposition`; no release of this package carries it, and what
  `getTokens()` / `refreshTokens()` return carries the refresh token held or
  `refreshToken: undefined`.
- **Consumers on the new contract follow this release.**
  `@mcp-abap-adt/connection` 13.0.0 (built on interfaces-auth 7 and
  auth-errors 2, its suites run against the published 6.0.0),
  `@mcp-abap-adt/auth-stores` 4.0.0 and `@mcp-abap-adt/auth-broker` 5.0.0
  are released after 6.0.0; until then no published connection reads these
  providers' refusals — 11.x reads the old refusal, and 12.0.0 (published
  only under `next`) is built on interfaces-auth 6. Keep one copy each of
  interfaces-auth and auth-errors.
- **Log lines about a thrown value** carry auth-errors' `logFields`:
  `{ error, kind, status?, diagnostics? }` instead of `{ error, status? }`.

### Added

- **`AuthProviderBase`** (with the types `Moment` and `MomentOperations`):
  the abstract base owning the four moments, exported for a consumer writing
  a provider of its own. `lint:check` runs auth-errors' shape check
  (`tools/check-provider-shape.mjs`, a byte-identical copy, rules 1–8 with
  `--base ./src/auth/AuthProviderBase#AuthProviderBase`) over this package:
  every provider reaches the base and declares none of the four moments, no
  cast to a contract type, diagnostics only at the approved extraction sites
  (`tools/diagnostic-sites.json`), `guard` reads nothing before its boundary,
  and no `Basic ` value outside `legacyBasic` / `clientSecretBasic`.
- **`authDebug`** (`TokenProviderDebug`, joined into `TokenProviderHooks` and
  so into every token provider's config): off by default, `true` itself
  only, never read from the environment. With it, a failed token request
  writes `[<operation>] token endpoint said` with `{ status, error?, code?,
  sent }` instead of the safe-facts line, and a `200` without a token adds
  `sent` to its line: `sent` names each secret the request carried
  (`client_secret`, `client_assertion`, `refresh_token`, `code`, `basic`,
  `basic_secret`, …), each prepared at the point of logging — at most its
  first 4 and last 4 characters around `<redacted, N chars>`, the length only
  below 16 characters. Never the server's text.
- **Cancellation.** `getTokens({ signal })` / `refreshTokens({ signal })`
  (interfaces-auth 6.0.0's `ITokenRequestOptions`): one caller's abort
  releases that caller (`interactive-login` `aborted`); the shared login is
  aborted when every caller has. `attach(signal): () => void` on every token
  provider and `SncLogonProvider`, and `signal` in every token provider's
  config and in `SncLogonProviderConfig`: the parties a moment's login waits
  on; with none live it runs unbounded. `signal` on `ManualStrategyOptions`,
  `ExternalCodeStrategyOptions` and `LoginFactoryOptions` (the factories).
- **SNC signal plumbing.** `SncLogonProvider.forSecureLoginClient({ …,
  signal })`, and an optional `signal` on `ISncLibraryLocator.locate`,
  `ISncProductProbe.appliesTo` and `SncSystem.readRegistryValue`: the
  shipped ones pass it to `reg.exe`, whose query has no timeout — an abort
  kills it and `prepare()` ends `aborted`. A locator or probe of your own that
  ignores the argument still compiles.
- **`LoginFactoryOptions`** — `{ signal? }`, what `inBrowser` and
  `fromTerminal` take.
- **`refreshThenLogin()`, `refreshOnly()`** — the shipped renewal
  strategies, stateless and synchronous (README, "Renewal strategy", with
  their decision table).
- **`refreshStatePersistence(write, { onWriteFailure, logger? })`**, with
  the types `PersistedTokens` and `RefreshStatePersistenceOptions` — the
  shipped persistence strategy, for a store that keeps its stored refresh
  token when a write carries none. `write` gets `refreshToken` as a string
  (write it), `null` (clear the stored one: the provider discarded it) or
  `undefined` (leave it). It keeps a logical state (`held`, `cleared` after
  a discard), writes one report at a time in report order — detached ones
  included — and delivers a failed new refresh token again with the next
  report until a write succeeds or something newer supersedes it; a failed
  write is logged `[refreshStatePersistence] Writing the tokens failed`.
  `onWriteFailure` is required, no default: `'continue'` never throws,
  `'fail'` rethrows for an awaited report (so the call fails
  `persisting-tokens`). Refused at construction as `configuration`
  `invalid-value` naming `onWriteFailure` and/or `write`.

### Changed

- **Dependencies:** `@mcp-abap-adt/interfaces-auth ^7.3.0` (was ^3.2.0; 7.3.0
  for the callback gate, `host` and `allowedHosts`),
  `@mcp-abap-adt/interfaces-auth-sap ^3.3.0` (was ^2.0.0), and the new
  `@mcp-abap-adt/auth-errors ^2.0.1` (2.0.1: an aborted login's tally reads
  `N request(s) to the callback server were refused and ignored`, since the
  count now holds every refused request, not only incomplete callbacks).
- **`getTokens()` / `refreshTokens()`** take an optional
  `ITokenRequestOptions` (`{ signal }`).
- **Collaborator answers are awaited normally.** What a consumer's own code
  answers — an authorization or persistence strategy, a loader, a refresher,
  a validator, a presenter, a replay store, `cookieProvider`, an SNC locator,
  probe or system, a logger — is adopted like any `await` adopts it, so a
  native promise, Bluebird, Q or any Promises/A+ thenable works; a renewal
  strategy's `next()` alone must answer a decision or a native promise of
  one (above). Values crossing a
  trust boundary — a thrown value being classified, a target's answer —
  never have a foreign `then` called. A collaborator answer that never
  settles is bounded only by the consumer's `AbortSignal`;
  `CertificateAuthProvider` and `TokenAuthProvider.from` take no signal, so a
  never-settling loader or refresher hangs their moment.
- **The signed-Response validator reads `Status` before counting the
  Assertion**, so a login the identity provider declined — which carries no
  Assertion — is refused `declined` with its status code rather than
  `no-direct-assertion`.
- **Configuration is checked at construction where it can be.** An
  unparseable `authorizationUrl` is `configuration` `invalid-value` ("a
  configured value cannot be used: authorizationUrl", interfaces-auth 7) at
  construction and at login. A `myName` that is not a string on
  `SncLogonProvider` is still `required-fields-missing` naming `myName` — a
  known wording limit. A callback `port` that is not an integer in
  0..65535 is refused before any socket is touched.
- **The refresh token held survives a result without one.** A commit
  installs a result's refresh token only when it is usable (non-empty, not
  one the provider discarded); a refresh answered without a new refresh
  token, or a login without one, leaves the one held in place — 5.4.2
  dropped it. A refresh that failed before it was sent no longer drops the
  refresh token (5.4.2 dropped it on any refresh failure).
- **`rejected()` for a token a renewal already replaced** answers Ok before
  reading the rejection — what is presented has changed — also for a `403`
  (5.4.2 answered the neutral refusal).
- **One `debug` line per renewal decision**, `[BaseTokenProvider] Renewal
  step` with `{ trigger, moment, next }`.
- **The callback server's release waits on nothing.** At release the
  listener is closed (the port is free once the factory settles); an idle
  connection is ended and unreferenced; one whose request body is unfinished
  is destroyed; one whose complete request is still being answered is
  unreferenced and its response goes on. Measured limits: Node's
  `http.Server.close()` itself destroys a connection whose request was
  parsed, even mid-flush of a large response to a client that does not read
  (so that client may get a cut response), and a write still pending to such
  a client would otherwise keep the process alive whatever `unref()` says.
- **OIDC discovery keeps a snapshot** of the fields the providers read
  (`authorization_endpoint`, `token_endpoint`,
  `device_authorization_endpoint`, their mTLS aliases); an aborted or failed
  discovery is not cached.
- **`DEFAULT_CALLBACK_PORT`** stays 61001; the default login wait is
  unbounded (above).

### Removed

- **The error classes:** `TokenProviderError`, `ValidationError`,
  `RefreshError`, `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`,
  `AssertionValidationError` (and the `AssertionCheck` re-export — import it
  from `@mcp-abap-adt/interfaces-auth`), `CertificateMaterialError`,
  `ClientAuthenticationError`, `ClientAuthenticationResultError`,
  `BasicClientIdError` and `TokenEndpointError`. Their information is a kind
  and its facts: `error.code` → `kind`; `missingFields` → `facts.fields`;
  `check` → `facts.check` (with `facts.rule`);
  `CertificateMaterialError.incomplete` / `.expired` / `.words` →
  `client-certificate` `facts.problem`; `TokenEndpointError.status` /
  `.oauthError` / `.code` → `request-failed` `facts.status` /
  `.oauthError` / `.code`. `SessionDataError` and `ServiceKeyError` had no
  producer and have no replacement. The error-code constants
  (`TOKEN_PROVIDER_ERROR_CODES`, `ASSERTION_ERROR_CODES`) are gone from
  interfaces-auth 6.0.0.
- **`refusalWords(error, what)`** → auth-errors' `classify(error,
  operation)`, `.reason` / `.hint`. A caller that passed its own `what` must
  name an `Operation` of the closed list: `'unfamiliar-error'` answers the
  unfamiliar-error words ("an authentication error of a kind this version
  does not know") and no hint — a TLS failure's `NODE_EXTRA_CA_CERTS` hint
  included; an operation of the list keeps its words and hints.
- **`DEFAULT_LOGIN_TIMEOUT_MS`** and every `timeoutMs` option (Breaking,
  above).
- **`onTokens`** on every token provider's config and `TokenProviderHooks`
  → `persistence` (Breaking, above).
- **The redactor.** 5.4.2's redaction of the server's text
  (`oauthErrorFields`, `describeOAuthErrorBody`, the base64 and JWT passes)
  is deleted with every regular expression over server text: nothing of the
  server's text is kept, so there is nothing to redact. A secret reaches a log
  line only through the secret preparer, under `authDebug`.
- **Internal:** `asContract` (interfaces-auth 6.0.0 declares optional fields
  `?: T | undefined`), `refusalFrom`, `loggedError`, `safely`, `oops`,
  `withoutRequest`, `tokenEndpointError`, `CallbackScopeError`,
  `AuthorizationRefusedError`, `DeviceCodePresentationError`,
  `SncLibraryNotFoundError` and `src/errors/`.

### Fixed

- **Security: the browser was opened through a shell.** Through 5.4.2 the
  fallback without the `open` package handed the authorization URL — which
  may come from an OIDC discovery document — to a shell inside double
  quotes, so a `$(…)` or a backtick in it ran as a command. Only an `http:` /
  `https:` URL is opened now, as its serialisation (unsafe characters refused
  or percent-encoded), and every launcher is started with an argument array:
  `xdg-open` or a named browser on Linux, `open` on macOS, and on Windows
  `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler` or
  PowerShell's `Start-Process` reading the URL from an environment variable
  — never `cmd`. The Windows launchers were measured on Windows 11
  (2026-10-07): the URL arrives unchanged, and no command interpreter is
  started.
- **The legacy Basic credential, as shipped in 5.4.2, carried forward.**
  Without a client-authentication strategy, every site that sends
  `Authorization: Basic base64(id:secret)` builds it only through one helper
  (`legacyBasic`), which names the credential's secrets (`basic`,
  `basic_secret`) for `sent`; 5.4.1 left a server-echoed base64 credential in
  errors and the code exchange's log line, and 5.4.2 redacted it. 6.0.0 goes
  further: nothing the server wrote is kept at all, so no echo of the header
  reaches an error or a log line, with `authDebug` or without.

### Security

- **Login CSRF: a login is bound to its attempt.** Through 5.4.2 no provider
  sent or checked the OAuth `state`: the UAA authorization URL carried
  neither `state` nor PKCE, the OIDC one PKCE but no `state`, and the
  callback server settled on the first `/callback` it got — so a page in the
  user's browser could hand the waiting login a code of its own, and the
  user ended up logged in as someone else (RFC 6749 §10.12, RFC 9700 §4.7).
  Now:
  - every URL `AuthorizationCodeProvider` and `OidcBrowserProvider` build
    carries a fresh `state` (32 random bytes, base64url) and a PKCE pair
    (S256) — new for UAA — whose verifier the exchange sends. A configured
    `authorizationUrl` is used unchanged and a code no URL was built for
    (`staticCodeStrategy`) is exchanged without a `code_verifier`: binding
    those is the consumer's. Measured on the provider stand (2026-10-07):
    Cloud Foundry UAA returns the `state`, accepts the verifier, and refuses
    a code exchanged with another verifier or none. XSUAA is not yet
    measured with PKCE (`docs/btp-setup.md`, Pending);
  - `browserCallbackStrategy` and `oidcCallbackStrategy` open their
    transport `gated` (interfaces-auth 7.3.0): closed from the bind on, armed
    with the URL's `state` (`expectState`) before the browser opens, then
    settling only a callback — code or `?error=` — with that `state`; every
    other request is answered `400`, counted and ignored, and the login
    keeps waiting. **Breaking:** a consumer's `callbackServer` for them must
    implement `expectState`, or the login is refused before anything opens
    (`configuration` `invalid-value`, `fields: ['callbackServer']`); a
    direct `new BrowserCallbackStrategy` takes a required `stateGate`
    (`samlCallbackStrategy` passes `false`: a SAML response is bound by
    `InResponseTo`);
  - **Breaking:** the shipped transports bind loopback (`127.0.0.1` and
    `::1`) instead of every interface, and refuse a request whose `Host` is
    not loopback with the bound port before serving anything (DNS
    rebinding). `Host` and `allowedHosts` are compared in the WHATWG URL
    host parser's canonical form (one trailing dot dropped); a loopback
    authority — `localhost`, `127.0.0.0/8`, `[::1]`, `[::ffff:127.x.y.z]`, in
    any spelling the parser reads as one — counts only from a loopback peer,
    so a network client sending `Host: localhost` to a wildcard bind is
    refused; `0.0.0.0` and `[::]` are never an authority.
    New strategy options `host` (the bind address) and `allowedHosts` (the
    authorities a browser on another machine may use) open it up — and
    every client that can reach an allowed authority can then settle the
    login with a code of its own (the README warns of it); an SSH tunnel to
    the port works with the default and is the safe route; a loopback
    authority listed in `allowedHosts` admits no network peer. A port not free on
    `::1` — fixed, or the one the OS gave `127.0.0.1` for `port: 0` — fails
    the login `port-in-use`, never leaving it on `127.0.0.1` alone. The UAA
    paste hint names the tunnel or the first allowed authority, never a
    guessed host;
  - **Breaking:** the UAA paste form carries a per-login token, and
    `/submit` settles only with it — and a pasted redirected URL only with
    this login's `state`. `manualPasteStrategy` asks again for a pasted URL
    of another login. A bare code — no `?`, `&`, `=`, `/` or `#` — is taken
    as before; anything else is a URL whose `state` must match and whose code
    comes from the query alone (`…/callback&code=X` is refused);
  - every comparison of a `state` or token is constant time
    (`crypto.timingSafeEqual` over SHA-256 digests), and none of them is
    logged.

## [5.4.2] - 2026-10-05

### Changed

- **The token endpoint's free text reaches no thrown error and no log line,
  on either path.** A server's `error_description` and `error_uri` are its
  own text: a misbehaving or hostile one can echo any secret of the request
  in them, in encodings no redaction can enumerate — the Fixed items below
  are bypasses found one after another (line-wrapped base64 the last). By
  default nothing the server wrote and no secret goes anywhere. A thrown
  error carries only safe facts: a `TokenEndpointError`'s message is
  `<label> (<status>)`, plus `: <code>` when the OAuth `error` is a
  registered code (`Token refresh failed (400): invalid_grant`), and the
  reduced `AxiosError`'s `response.data` keeps only that registered `error`
  — `err.response.data.error` still reads it — and is `{}` otherwise. A
  failed request is noted in one `debug` line through the provider's logger
  with the same facts (`<site>: the token endpoint refused the request`,
  `{ status, error? }`), none for the device poll's `authorization_pending`
  / `slow_down`, none without a logger, a logger that throws ignored;
  `refreshJwtToken` and `getTokenWithClientCredentials` (internal) take the
  provider's logger for it. The UAA code exchange's `error` line for a `200`
  without `access_token` names the status and a registered code only. A
  consumer that matched words of the server's description in a message or a
  log line can no longer; an opt-in diagnostic mode comes with 6.0.0.

### Fixed

- **Security: what a token request's promise rejected with was kept.** The
  reduction rebuilt only values that looked like axios failures; anything
  else passed through unchanged. A consumer's global axios response
  interceptor throwing `new Error(r.data.error_description)` — or a
  primitive, or an object whose getters throw — therefore reached the
  consumer with the server's text, in the OIDC sites' message and rendering,
  and as the `cause` of the `TokenEndpointError` the wrapping sites throw.
  Every rejection is now replaced, on both paths and in OIDC discovery, by a
  fresh `AxiosError` of fixed words carrying only an integer status, an
  allowlisted (or axios's own) code and a registered OAuth `error` — never the
  original, not even as `cause`. The device poll's `authorization_pending` /
  `slow_down` still continue. A cancellation stays one: an aborted request
  becomes a `CanceledError` in fixed words, so `axios.isCancel` and
  `axios.isAxiosError` both hold. A consumer's logger that throws while a
  token site reports a failure (the SAML exchange and refresh, the device
  poll's wait) is ignored, so it can no longer replace the safe rejection
  with its own text. A successful answer is not trusted either: a fulfilled
  interceptor may hand over data whose getter, Proxy trap or `toJSON`
  throws the server's text into the site's parsing. Every site now reads
  only a snapshot — an integer status and the expected fields
  (`access_token`, `refresh_token`, `id_token`, `token_type`, `expires_in`,
  `scope`, the device fields, `error`) that are strings or numbers, each
  read safely — and OIDC discovery a plain copy of its document; a field
  whose read throws is absent, a copy that throws is fixed words.

- **Security: a server echoing the Basic header could expose the client
  credential, on the path without a client-authentication strategy.** Without
  a strategy, the UAA code exchange, the UAA refresh, the passcode exchange,
  the SAML bearer exchange and refresh, and the OIDC authorization code,
  refresh, token exchange, device poll and password grant send
  `Authorization: Basic base64(id:secret)`, but redacted only the configured
  `clientSecret` and the grant's secrets from the answer — not the base64
  credential, from which `id:secret` decodes. A token endpoint that echoes
  request headers into `error_description` or `error_uri` therefore left it
  in: the message of the `TokenEndpointError` the UAA refresh, the passcode
  exchange and the password grant throw (a message every catcher logs); the
  reduced `response.data` of the `AxiosError` the other sites rethrow; and the
  `error`-level log line of the UAA code exchange's `200` without
  `access_token`. Each of these sites now builds its header only through one
  helper, which also yields the credential's secrets — the base64 credential
  and the secret, through the same extraction a strategy's Basic credential
  already went through — and every redaction of that request's answer joins
  them, as sent, encoded and form-decoded. The path with a strategy was not
  affected. Nothing else changed: the request sent, the messages and the
  error shapes are as in 5.4.1; a logger that throws while the code exchange
  logs a `200` without `access_token` no longer replaces its failure.
- **Security: a secret echoed in an equivalent encoding escaped the
  redaction, on both paths.** Redaction matched a fixed list of spellings, so
  a server echoing a secret in another, equally readable one left it in the
  same three places: a base64 credential without its padding, with other
  padding or in the URL-safe alphabet; a percent escape in lower or mixed
  case (`%2f` for `%2F`); a space as `+` or `%20`. Every secret the request
  carried — the client secret, the grant's (refresh token, code, verifier,
  assertion, passcode, password, device code, subject / actor token) and a
  strategy's (`client_secret`, `client_assertion`, a Basic credential) — is
  now matched with each character — unreserved ones included (`%41` for `A`)
  — as itself or percent-escaped in any case, a space also as `+`; then every
  base64 run of the answer (either alphabet, any padding, any of its
  characters escaped or not) is decoded, and the smallest span of it that
  decodes to text holding a secret is redacted. Markers are never scanned
  again, so the output stays bounded; base64 broken by whitespace — a space,
  a tab, a line break, escaped or not (`c3Vw\r\nZXJz…`, `%0D%0A`) — is
  decoded with the whitespace dropped and its whole span redacted. Since the
  server's words are written nowhere in 5.4.2 (Changed), the redactor is
  defence in depth here. **Limits**, not covered: an escape
  escaped again (`%252F`); an echo truncated inside a secret, which holds
  only part of it; and a secret of one or two characters, which is redacted
  wherever it appears — in decoded base64 too, so unrelated words may be
  removed.

## [5.4.1] - 2026-10-05

### Changed

- **A stricter compiler.** `tsconfig.json` adds `noImplicitReturns`,
  `noFallthroughCasesInSwitch`, `noImplicitOverride`,
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`, for the source
  and the tests alike. Every error was fixed on its merits: an index that may
  be absent is read once and checked, never asserted.
- **Optional fields accept an explicit `undefined`.** No runtime shape
  changed: every object this package returns or hands to a strategy, a
  callback server, a validator, a presenter or `onTokens` carries exactly the
  keys it carried in 5.4.0 — an optional field without a value is present as
  `undefined` (`refreshToken: undefined`), which a consumer merging
  `{ ...stored, ...result }` relies on; `resultShapes.test.ts` pins it. For
  the contract types of `@mcp-abap-adt/interfaces-auth`, which declare
  `?: T`, one helper (`asContract`, internal) states that shape. The exported
  declarations widened, each field from `?: T` to `?: T | undefined`. No
  consumer without `exactOptionalPropertyTypes` stops compiling. A consumer
  with it that assigns one of these values to a type of its own declared
  `?: T` must widen that type to `?: T | undefined` — above all where it reads
  what the package hands it: `DeviceCodePrompt` (a presenter),
  `OidcCallbackResult` (a custom OIDC callback server or strategy), and
  `BaseTokenProvider`'s protected `authorizationToken`, `refreshToken`,
  `expiresAt`, `logger` and `clientAuthentication` (a subclass); the config
  types are written by a consumer, rarely read. The widened fields:
  - `AuthorizationCodeProviderConfig`: `clientSecret`, `authorizationUrl`,
    `accessToken`, `refreshToken`, `expiresAt`, `logger`
  - `ClientCredentialsProviderConfig`: `clientSecret`, `logger`
  - `OidcBrowserProviderConfig`: `issuerUrl`, `clientSecret`, `scopes`,
    `authorizationEndpoint`, `tokenEndpoint`, `accessToken`, `refreshToken`,
    `expiresAt`, `logger`
  - `OidcDeviceFlowProviderConfig`: `issuerUrl`, `clientSecret`, `scopes`,
    `deviceAuthorizationEndpoint`, `tokenEndpoint`, `accessToken`,
    `refreshToken`, `expiresAt`, `logger`
  - `OidcPasswordProviderConfig`: `issuerUrl`, `clientSecret`, `scopes`,
    `tokenEndpoint`, `accessToken`, `refreshToken`, `expiresAt`, `logger`
  - `OidcTokenExchangeProviderConfig`: `issuerUrl`, `clientSecret`, `scope`,
    `audience`, `actorToken`, `actorTokenType`, `tokenEndpoint`,
    `accessToken`, `refreshToken`, `expiresAt`, `logger`
  - `Saml2BearerProviderConfig` and `Saml2PureProviderConfig`: their own
    `logger`, `accessToken`, `expiresAt` (and `refreshToken` for bearer), and
    the shared SAML fields `acsUrl`, `relayState`, `authorizationUrl`,
    `logger`, `idpEntityId`, `authnRequestId`, `idpInitiated` (bearer also
    `tokenUrl`, `uaaUrl`, `clientId`, `clientSecret`)
  - `UaaPasscodeProviderConfig`: `clientSecret`, `accessToken`,
    `refreshToken`, `expiresAt`, `logger`
  - `SncLogonProviderConfig`: `qop`, `myName`, `logger`
  - `TokenProviderHooks.onTokens`; the `clientAuthentication` every token
    provider config takes
  - `SamlTrust`: `clockSkewMs`, `replayStore`; `ShippedValidatorOptions`:
    `clockSkewMs`
  - `CallbackStrategyOptions` (and `BrowserCallbackStrategyOptions`): `port`,
    `timeoutMs`, `browser`, `callbackServer`, `openUrl`, `remoteHint`,
    `signal`
  - `ManualStrategyOptions`: `redirectUri`, `read`, `timeoutMs`;
    `ExternalCodeStrategyOptions` and `StaticCodeStrategyOptions`:
    `redirectUri`
  - `PrivateKeyJwtConfig`: `keyId`, `audience`; `TlsClientCertificateConfig`:
    `endpoint`
  - `DeviceCodePrompt`: `verificationUriComplete`, `expiresInSeconds`;
    `OidcCallbackResult`: `state`
  - `BaseTokenProvider`'s protected `authorizationToken`, `refreshToken`,
    `expiresAt`, `logger`, `clientAuthentication`
- **The tests are type-checked.** `npm run test:check` now covers
  `src/__tests__` too; `tsconfig.build.json` still leaves the tests out of
  `dist`.
- **CI gates on the type check and the lint.** The build-and-test job runs
  `npm run test:check` and `npm run lint:check`.
- **Lint.** `noExplicitAny` is an error outside the tests, and
  `npm run lint:check` fails on a warning (`--error-on-warnings`); `src` has
  no explicit `any`, no lint warning, and one `as unknown as` (the reduced
  `AxiosResponse`, which has no `config` on purpose). `SsoProviderFactory`
  stays a class holding only a static member — it is public — so
  `noStaticOnlyClass` is off for that one file in `biome.json`.

### Fixed

- `SsoProviderFactory.create()` given a protocol and flow no provider has (a
  consumer without types) threw an error whose message was the whole config
  serialised — the client secret, a password, the tokens. Its message is now
  fixed words: "Unsupported SSO provider config: no provider for this
  protocol and flow".
- `OidcDeviceFlowProvider`'s poll reads the status and OAuth `error` of what
  a poll threw through `readSafely`, like every other read of a foreign
  error: a thrown value whose property read throws (a Proxy) is rethrown as
  it is, no longer replaced by the error its read raised.

## [5.4.0] - 2026-10-05

### Added

- **`refusalWords(error, what)`**, exported from the package index: the
  `{ reason, hint? }` a provider's refusal would carry for a thrown value — the
  same derivation as the providers' own (fixed words per class of this
  package, allowlisted facts, else `<what> failed (unknown error)`), never an
  error's message, cause or body, and total for a hostile value. A consumer
  that reports a failure in its own error — the broker checking a client
  certificate eagerly — relays the package's words, hint included, instead of
  copying them. See *Relaying a refusal* in the README.

### Fixed

A forged error — an object whose prototype is one of this package's classes,
or an instance given its own properties — can no longer put its own text into
a refusal or a log line, nor make building one throw:

- A `CertificateMaterialError`'s words are chosen from its `incomplete` and
  `expired` flags, each read once and only when exactly `true`, and never read
  from its `words` — in `refusalFrom` (and so `refusalWords`, `loggedError`
  and every provider's refusal, a token provider's pinning included) and in
  the material check behind `CertificateAuthProvider.prepare()`, where a
  consumer's loader can throw one.
- An `AssertionValidationError`'s `check` is read once: the value tested
  against the allowlist is the value named.
- A `ValidationError`'s, `ServiceKeyError`'s or `SessionDataError`'s
  `missingFields` is read element by element, at most 64 elements, with none
  of the array's own methods called; only allowlisted names are kept.
- Every shared word object is frozen — the certificate, client-authentication,
  bound-token and TLS words, and the `OK` outcome a provider hands out.
  `CertificateMaterialError.words` returned the very object the refusal and
  the constructor read, so changing it (from a forged error's flag getter, or
  anywhere else) changed every later refusal, log line and message.
  The guarantee stops at the public surface: in-process code that patches
  built-ins or imports `dist/` files directly is outside it.

### Changed

- `CertificateMaterialError`'s constructor stores `incomplete` and `expired`
  as `=== true` (was: as given, chosen by truthiness), as the refusal reads them.

### Deprecated

- `CertificateMaterialError.words`: use `refusalWords(error, what)`. The
  package no longer reads it from a thrown value.

## [5.3.0] - 2026-10-04

A token provider's client can authenticate with a client certificate or a
signed assertion instead of a secret, and a token bound to that certificate is
presented only together with it. A consumer that passes no strategy sends the
same requests as before; three things change for it too, listed under
*Changed* (a seeded token carrying `cnf`, a token request that no longer
follows a redirect, and a thrown token-request error that no longer carries
the request).
See *Client authentication* in the README.

Requires `@mcp-abap-adt/interfaces-auth` `^3.2.0` (was `^3.0.0`), which adds
`IClientAuthentication`, `ITokenRequestDraft` (with its `tokenEndpoint`, the
authorization server's token endpoint also for the device authorization),
`ITokenRequestAuthentication` and the error codes `CERTIFICATE_MATERIAL_ERROR`
and `CLIENT_AUTHENTICATION_ERROR`.

### Added

- **Five client-authentication strategies**, each a factory returning
  `IClientAuthentication`: `noClientAuthentication()` (`client_id` in the
  body), `clientSecretBasic(secret, { encoding })`, `clientSecretPost(secret)`,
  `tlsClientCertificate({ material, endpoint? })` (`tls_client_auth`: the
  request goes over mTLS to `endpoint`, else the server's mTLS alias, else the
  configured endpoint; `material` is the certificate or a loader, read and
  checked once, a failed load retried; `endpoint` replaces the URL of every
  request, so the device flow should rely on discovery's
  `mtls_endpoint_aliases` instead) and
  `privateKeyJwt({ key, algorithm, keyId?, audience? })` (RS256 or ES256
  through `node:crypto`; a 60-second assertion whose `aud` is `audience`, else
  the draft's `tokenEndpoint`, else the endpoint the request goes to). A
  consumer may write its own.
- **`clientSecretBasic`'s `encoding` is required: `'raw'` or `'form'`**, with
  no default, because servers disagree (measured 2026-10-04, for the
  measured ids and secrets): XSUAA accepted only the raw `id:secret` (trial,
  `client_credentials`, by hand); Cloud Foundry UAA (`client_credentials`) and
  Keycloak (`password`) decode each component (RFC 6749 §2.3.1) and refused a
  raw secret holding `+` and `%`, accepting it form-encoded. That an id
  holding `+` or `%`, or an id or secret holding a space, needs `'form'` there
  too is inference from the same rule, not measured. A missing or other value is a
  `ValidationError` naming `encoding`. With `'raw'`, a client id containing
  `:` is refused before anything is sent — a `BasicClientIdError`, *the
  client id contains ':', which raw Basic cannot carry*. A provider without a
  strategy still sends its `clientSecret` raw, as before. An error body is
  redacted of every secret as sent, encoded and form-decoded — the whole
  value, `&` and `=` included, a malformed `%` left as it is: with `'form'`
  the original and the encoded secret, with `'raw'` and for a `clientSecret`
  sent without a strategy the secret and what a decoding server read. The stand measures
  both encodings on UAA and Keycloak (`clientSecretBasic.test.ts`, clients
  `basic_reserved`, `basic-reserved` and `basic:colon`).
- **Every draft names the token endpoint** (`ITokenRequestDraft.tokenEndpoint`):
  a token request its own endpoint; the device authorization the provider's
  plain token endpoint — configured or discovered, never its mTLS alias. So
  `privateKeyJwt`'s default audience is the token endpoint for the device
  flow too: Keycloak refuses an assertion whose `aud` is the device
  authorization endpoint, and the device flow now completes there without
  `audience`.
- **`clientAuthentication` on eight token providers** —
  `ClientCredentialsProvider`, `AuthorizationCodeProvider`,
  `UaaPasscodeProvider`, `Saml2BearerProvider`, `OidcBrowserProvider`,
  `OidcDeviceFlowProvider`, `OidcPasswordProvider`,
  `OidcTokenExchangeProvider`: every request the provider sends to the server
  (first token, refresh, device authorization and poll, token exchange) is
  authenticated by it. `clientSecret` beside a strategy is a `ValidationError`
  naming `clientSecret` — an empty `clientSecret: ''` included; where
  `clientSecret` was required, a strategy satisfies it. What a strategy
  returns is checked before anything is sent (strings only, no line break in
  a header, nothing replacing the request's own parameters or headers, an
  absolute `https:` endpoint), and no token request follows a redirect.
- **One certificate per provider, pinned.** A provider reads its strategy's
  `tlsMaterial()` once, before its first request or logon, checks it, takes
  the `x5t#S256` thumbprint of its leaf certificate, and keeps a copy for its
  lifetime; every token request, refresh and logon uses it — the logon target
  gets a copy each time, so a target changing it changes nothing later. A
  rotated certificate is a new provider instance. A certificate past its
  `notAfter` is refused — when pinned, and before every token request and
  logon that presents it — as "the client certificate has expired", nothing
  sent and a refresh token kept; `CertificateAuthProvider` checks the same in
  `prepare()` and before each logon.
- **The binding check.** Before presenting a token, `establish()` and
  `authorize()` read its binding: a JWT with `cnf` (bound) is presented only
  with the pinned certificate of that thumbprint, else Oops "the token is
  bound to a client certificate this provider does not present"; a JWT
  without `cnf` (unbound) goes as a Bearer; anything else (unknown — an opaque
  token) is treated as bound when a certificate is pinned. `establish()` hands
  the logon target the pinned certificate when the token may need it, and
  decides on the token held without obtaining one. Seeded and restored tokens
  are checked like obtained ones. An opaque token bound to a certificate needs
  the certificate strategy configured: without it the provider cannot know
  the binding.
- **A token bound to the previous certificate is renewed, not refused.** When
  a certificate is pinned and the held token is bound to another thumbprint
  (or its `cnf` names none readably) — a token restored after a rotation —
  `getTokens()` and `authorize()` renew it once through the pinned certificate
  (refresh, else one login), like an expired token, and check the new one;
  only a new token still bound elsewhere is refused by `authorize()`, as "the
  new token is bound to a client certificate this provider does not present"
  — and remembered: later attempts do not renew it again (no token request, no
  login per request); `getTokens()` returns it, `authorize()` refuses it. A
  renewal that throws is remembered too, with its own refusal: later attempts
  answer the same words (an expired client certificate stays "the client
  certificate has expired"), without a token request or a login, until the
  token changes; the latest renewal's words are the ones kept. An expired
  token whose renewal fails is renewed again on the next attempt, as before. In both cases the
  next `prepare()` renews once more; `rejected()` renews once more when the
  refused token is the one held, and answers Ok without a renewal when the
  refused token was already superseded (rule 6, as before). With no
  certificate pinned, `getTokens()` returns a bound token as before and
  `establish()` / `authorize()` refuse it.
- **Only `establish()` and `authorize()` present the certificate.**
  `getTokens()` and `refreshTokens()` — the token API the broker uses — return
  a token that may be bound to the certificate; a consumer sending it on its
  own connection must present the same certificate itself, or use the
  `IAuthProvider` methods.
- **mTLS endpoint aliases** (RFC 8705 §5): an OIDC provider that discovers an
  endpoint hands the strategy the server's `mtls_endpoint_aliases` entry for it
  (`token_endpoint`, `device_authorization_endpoint`).
- **Error classes** `CertificateMaterialError` (carries `incomplete` and
  `expired`),
  `ClientAuthenticationError` (an unusable signing key) and
  `ClientAuthenticationResultError` (a strategy result that cannot be sent),
  each with a fixed message and fixed refusal words. `CertificateAuthProvider`
  and `tlsClientCertificate` share one material check, and its refusals.
- **A TLS failure is refused naming its code, in words fixed per kind.** A
  server certificate Node does not trust (`SELF_SIGNED_CERT_IN_CHAIN`, …) gets
  the hint `NODE_EXTRA_CA_CERTS` — how a private CA is trusted; there is no
  `ca` option and `rejectUnauthorized` is never set. An expired server
  certificate (`CERT_HAS_EXPIRED`) and a host name it does not name
  (`ERR_TLS_CERT_ALTNAME_INVALID`) get their own words and hints. The alerts a
  server sends when it refuses the client certificate
  (`ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED`,
  `ERR_SSL_TLSV1_ALERT_UNKNOWN_CA`, `ERR_SSL_SSL/TLS_ALERT_…` and the older
  `ERR_SSL_SSLV3_ALERT_…` for a bad, unknown, expired, revoked or unsupported
  certificate) are refused as "the server refused the client certificate".
- **Stand checks** (`npm run test:stand`): Keycloak gains HTTPS
  (`KEYCLOAK_HTTPS_PORT`, default 8444, loopback) with throwaway TLS fixtures
  in `tests/stand/keycloak/tls/`, trusted by the suites through
  `NODE_EXTRA_CA_CERTS`; a token bound to the certificate and accepted by
  userinfo only with it, a refresh that stays bound, `private_key_jwt` on
  Keycloak and on UAA, the device flow with the default assertion audience
  (and Keycloak's refusal of the device endpoint as `aud`), and the X.509
  user logon (`CertificateAuthProvider`, the analogue of ABAP `CERTRULE`). A
  stand started before this release must be stopped once
  (`npm run stand:down`).
- **XSUAA check** (`npm run test:xsuaa`, not in CI): the test instance allows
  the `x509` credential type, and an `x509-key` created afresh per run gets a
  client token through `ClientCredentialsProvider` and `tlsClientCertificate`
  at its `certurl`, with no secret — passed on a BTP trial on 2026-10-04
  (`client_credentials` only; ADT accepting such a token is unproven). Service keys are now recorded in the
  ledger by GUID, like instances and trusts.

### Changed

- **A token provider without a strategy refuses a seeded or restored JWT that
  carries `cnf`** ("the token is bound to a client certificate this provider
  does not present") in `establish()` and `authorize()`; it used to send it as
  a Bearer. `TokenAuthProvider.fixed()` still sends such a token unchecked.
- **`getTokens()` may throw a `CertificateMaterialError`** (unusable or
  expired material) when the cached token is bound and the strategy presents
  a certificate: it pins the certificate to compare thumbprints, where it used
  to return the cached token.
- **A token request without a strategy no longer follows a redirect**: a
  `3xx` from the token or device endpoint fails the request (an `AxiosError`
  with the `3xx` status) where axios used to follow it. An authorization
  server reached through a redirecting URL must be configured with the URL it
  redirects to. See *Security*.
- **A thrown token-request error carries no request**, with or without a
  strategy: no form body, no `Authorization` header, no TLS agent with a key,
  PFX or passphrase. It is still an `AxiosError` — `instanceof AxiosError` and
  `axios.isAxiosError()` hold — but a new one, built without `config`,
  `request` or `cause` (so its `toJSON()` serialises no config): it keeps
  `code` and `status`, a rebuilt message — axios's `Request failed with
  status code N`, or `the token request failed (<code>)` when no response
  came — and a `response` of `status`, an empty `statusText`, empty `headers`
  and the server's body reduced to `error`, `error_description` and
  `error_uri`, every secret the request sent redacted. `response.headers`
  (now empty), `response.statusText` (now `''`: the reason phrase is the
  server's free text), `response.config` and the transport's own message for
  a network failure are what a caller loses.
- **A token request that failed is a `TokenEndpointError`** (new, exported)
  at the sites that wrap it — UAA refresh, client credentials, passcode, OIDC
  device initiation and password grant (were plain `Error`s). It carries the
  safe facts as properties: `status`, `oauthError` (a registered OAuth / OIDC
  code only; OIDC Core §3.1.2.6's codes joined the registered list) and
  `code` (an allowlisted system or TLS code only) — the constructor drops
  any other value, so its properties and JSON can be trusted whoever built
  it; `cause` is the original.
  The message keeps its form, `<label> (<status>): <redacted OAuth summary>`;
  without a response it is `<label>: <fixed words>` (was the transport's
  message), and the device initiation and password grant no longer say
  `(unknown): no error given` for a network failure.
- **A configuration mismatch found by the provider is a `ValidationError`**:
  a pre-built `authorizationUrl` whose `redirect_uri` differs from the
  strategy's, a SAML `acsUrl` the strategy is not listening on, and a missing
  OIDC authorization endpoint (same words, `missingFields` `authorizationUrl`
  / `acsUrl` / `authorizationEndpoint`). They were plain `Error`s — and,
  raised while a browser strategy built the URL, reached the caller as a
  `BrowserAuthError` carrying their text; they now pass through the
  strategy unchanged, and their refusal names the field.
- **An IdP refusal on the browser callback** rejects with
  `the identity provider refused the login (<registered code>)` (was
  `OAuth2 authentication failed: <error>: <error_description> (<error_uri>)`
  or `OIDC authentication failed: …`).
- **The passcode exchange and the OIDC password grant report the server's
  error through `describeOAuthErrorBody`**, with the passcode (or the password),
  the client secret and what a strategy sent redacted. The messages read
  `Passcode exchange failed (401): "unauthorized": "Invalid passcode"` and
  `OIDC password grant failed (401): "invalid_grant": "…"` (were
  `… (401): Invalid passcode` and `… (401): invalid_grant - …`).
- **A failed device authorization says what the server answered**:
  `OIDC device authorization failed (<status>): "<error>": "<description>"`,
  instead of the transport's `Request failed with status code 400`.
- **Known secrets are redacted longest first**, so a short secret (a
  password) redacted inside a longer one (an assertion) no longer leaves the
  rest of the longer one readable.
- **A registered OAuth error code is never redacted**: an `error` equal to
  one of RFC 6749 §5.2 / §4.1.2.1, RFC 8628 §3.5, RFC 6750 §3.1 or
  RFC 8693 §2.2.2's codes is kept verbatim, so a secret that happens to be a
  substring of it (`a` in `authorization_pending`) no longer rewrites the code
  and stops the device poll after its first pending answer. Any other `error`
  value, and every `error_description` and `error_uri`, is redacted as before.

### Security

- No key, passphrase, certificate content or client assertion reaches a
  refusal, a log line or a thrown error: the new error classes carry fixed
  words only, and `noTokensInLogs.test.ts` covers the strategies.
- No token request follows a redirect, with a strategy or without
  (`maxRedirects: 0` on every request of every site, device initiation and
  poll included): a 307/308 would re-send the client secret, the refresh
  token, the code, the passcode, the password or the assertion, and present
  the certificate, to wherever it points. OIDC discovery, a GET for public
  metadata that sends no secret, still follows redirects.
- The TLS agent of a token request is built from exactly `cert`, `key`, `pfx`
  and `passphrase`; any other field the material carries at run time
  (`rejectUnauthorized`, `ca`) never reaches it.
- **No message of a thrown value reaches a log line.** A consumer's
  collaborator — a client-authentication strategy (`authenticate()`,
  `tlsMaterial()`), a certificate loader, the interactive strategy, a
  device-code presenter, a SAML validator, `onTokens`, a browser launcher, an
  SNC locator or probe — may throw text holding a key, a passphrase or a
  token, and so may a network failure; `[BaseTokenProvider] Refresh failed`
  logged it whole. Every log line about a thrown value now carries only the
  words its refusal would (`loggedError`, `src/auth/refusal.ts`: fixed per
  class by `instanceof`, allowlisted codes, else `unknown error`) and the
  HTTP status when there is one — no message, `cause`, `stack` or
  stringified error, for this package's own classes too. The UAA code
  exchange's "no `access_token`" line logs the body through
  `describeOAuthErrorBody` (was its raw `error`).
- **A thrown token-request error keeps nothing of the reason phrase**: a
  server answering `401 <secret>` put the secret in
  `error.response.statusText`, now always `''`; the message is rebuilt from
  the status (or the code), never copied.
- **A thrown error's message carries no foreign text either** — whoever
  catches it logs it. The UAA refresh and client-credentials sites, for a
  failure without an HTTP response, throw `Token refresh failed: <fixed
  words>` / `Client credentials authentication failed: <fixed words>` (the
  refusal's words with an allowlisted code, e.g. `ECONNREFUSED`) with the
  original as `cause` (were `…: <its message>`). A `BrowserAuthError` keeps
  the message of this package's own callback failures (timeout, "already in
  use", abort); for the identity provider's refusal or a custom transport's
  or launcher's error its message is `the browser login failed (unknown
  error)` and the original is `cause`. `EADDRINUSE`, `ECONNABORTED`,
  `EPROTO` and `ERR_NETWORK` join the allowlisted system codes. Fixed words
  still name the safe facts: a refusal and a log line add an integer HTTP
  status, a registered OAuth / OIDC `error` code and an allowlisted system or
  TLS code (e.g. `the refresh failed (HTTP 401, invalid_grant)` — the same
  words for a `TokenEndpointError` and for a reduced `AxiosError`; "unknown
  error" leads only when no server answered), never a description. Every
  such property of a foreign error is read under a guard: a throwing getter
  or a Proxy reads as absent, and `refusalFrom` / `loggedError` are total —
  whatever still throws is `unknown error`, never an exception across the
  contract. The SAML bearer exchange and refresh log the same safe facts
  (they logged the redacted `error_description`). An identity provider's `?error=` on the browser callback
  names only its registered code — `BrowserAuthError("the identity provider
  refused the login (consent_required)")`, refused as such — and drops
  `error_description`, `error_uri` and an unregistered code (they reach only
  the escaped error page). A configured IdP
  certificate that is not X.509 is refused as `a configured certificate is
  not a valid X.509 certificate`, OpenSSL's text only in `cause`.
- **The local callback pages no longer reflect HTML.** The IdP's `error` and
  `error_description` — query parameters anyone can put in a link to the
  callback — were written into the UAA error page unescaped, and the OIDC
  callback answered them as an HTML body: a reflected HTML/script injection
  on `localhost`. Every value a page interpolates is now escaped (`&`, `<`,
  `>`, `"`, `'`); the OIDC refusal uses the same escaped page; the short
  answers (OIDC and SAML success, a stray request) are `text/plain`. Every
  response of the callback server carries `X-Content-Type-Options: nosniff`
  and `Content-Security-Policy: default-src 'none'; style-src
  'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors
  'none'`, and its pages `Content-Type: text/html; charset=utf-8`.

## [5.2.3] - 2026-10-04

### Fixed

- **`CertificateAuthProvider` proves its material in `prepare()`.** The loader
  only reads bytes, so a wrong PFX passphrase, a key that is not the
  certificate's, or a damaged file passed `prepare()` and `establish()` with Ok,
  and the failure surfaced as the transport's raw TLS error (`mac verify
  failure`, a key mismatch). `prepare()` now builds a TLS context from the
  material and refuses it in fixed words — "the client certificate could not be
  used" — with nothing of what it read; material without a PFX or without both a
  certificate and its key — which a TLS context accepts, sending no client
  certificate at all — is refused as incomplete; a refused material is never
  presented, also after an earlier `prepare()` succeeded (measured 2026-10-04).

## [5.2.2] - 2026-10-03

### Fixed

- **A named browser opens on every platform.** `browser: 'chrome'` (and
  `'edge'`, `'firefox'`) reached `open` as a bare executable name; Chrome is no
  `chrome` on Linux, so the launch failed with ENOENT and the login never
  opened (measured 2026-10-03). The name now goes through `open`'s `apps`, the
  per-platform names of each browser (`google-chrome`, `google-chrome-stable`,
  `chromium`, … on Linux).

## [5.2.1] - 2026-10-02

### Fixed

- **`OidcDeviceFlowProvider` discovers each endpoint it was not given.** With
  `issuerUrl` and only one of `deviceAuthorizationEndpoint` / `tokenEndpoint`,
  it skipped discovery and failed at login for want of the other; discovery
  ran only when both were missing. `OidcBrowserProvider` already worked this
  way.
- **An empty endpoint is none, at login and at refresh, in every OIDC
  provider.** `OidcPasswordProvider` and `OidcTokenExchangeProvider` took
  `tokenEndpoint: ''` as given and failed at login; `OidcPasswordProvider` and
  `OidcDeviceFlowProvider` refreshed through a gate that still took it as
  given, skipped discovery, dropped the refresh token and logged in again —
  for the device flow, a second prompt to the user; `OidcBrowserProvider`
  took `''` as given for both its endpoints. All of them now discover an
  endpoint given as `''`, exactly as one not given.

### Changed

- **Dev dependency `@mcp-abap-adt/auth-stores` `^3.1.0`** (was `^1.2.1`), so
  the dev tree holds one `interfaces-auth-sap`. The session-file integration
  cases read a session file the 3.x way: the client through
  `EnvDestinationStore`, the token through `AbapSessionStore` — a 3.x session
  store answers the secret only. No change to the package.

## [5.2.0] - 2026-10-02

### Added

- **`ClientCredentialsProvider` takes a `logger`**, as every other token
  provider does. Its config had none, so the token lifecycle the base class
  logs (a cached token answered, a new one obtained, a failed `onTokens`) went
  nowhere — a consumer passing its logger, such as `@mcp-abap-adt/auth-broker`,
  saw nothing for its `client_credentials` destinations.

## [5.1.0] - 2026-10-01

A consumer that keeps a provider's credential between runs can now hand every
interactive provider back what it stored, cookies included, and have it used
until it expires.

### Added

- **`Saml2PureProvider` takes a stored session: `accessToken` (the cookies)
  and `expiresAt` (epoch ms).** Until `expiresAt`, less the one-minute buffer,
  `getTokens()` answers the cookies and `authorize()` presents them, with no
  login. Past it, or without `expiresAt` — cookies carry no expiry of their
  own — the provider logs in as before. No `refreshToken`: SAML has none.
- **`expiresAt` beside a seeded `accessToken`** on `AuthorizationCodeProvider`,
  `UaaPasscodeProvider`, `OidcBrowserProvider`, `OidcDeviceFlowProvider`,
  `OidcPasswordProvider`, `OidcTokenExchangeProvider` and
  `Saml2BearerProvider`. It is used only when the token carries no `exp` — an
  opaque token; a JWT's own `exp` wins. Before, an opaque seed always counted
  as expired. `ClientCredentialsProvider` still takes no seed.
- A stored `expiresAt` counts only as a finite, non-negative number; anything
  else (`Infinity`, `NaN`, a string) states no expiry, so the seed is renewed.

### Fixed

- **A JWT with `exp: 0` is expired by it.** The parser read `exp` as truthy,
  so `0` stated no expiry; a numeric `exp` is now the token's own, `0`
  included.

The README's *Seeding a stored credential* lists what each provider takes.

### Changed

- **`@mcp-abap-adt/interfaces-auth-sap` `^2.0.0`** (was `^1.1.0`). The three
  types this package imports from it — `IAuthorizationConfig`, `ISapConfig`,
  `ICertificateMaterialLoader` — are identical in 1.1.0 and 2.0.0; nothing a
  consumer passes changes shape.

## [5.0.1] - 2026-09-30

### Fixed

- **`rejected()` blames the credential only when the system refused it.**
  A `401` or the RFC SDK's `RFC_LOGON_FAILURE` is the credential; a `403`, a
  redirect, a `5xx`, any other status or RFC key is answered with a neutral
  refusal naming only that status or key. Before, `BasicAuthProvider`,
  `CertificateAuthProvider`, `SamlAuthProvider` and a fixed `TokenAuthProvider`
  answered every rejection with their own refusal — a network failure on an
  RFC logon read "the user or password was refused".
- **Token providers renew only a refused credential.** `BaseTokenProvider`
  and `TokenAuthProvider.from` no longer refresh or log in again on a `403`,
  a redirect, a `5xx` or another RFC key: a new token would be refused the
  same way, and the Ok it earned invited a retry that could not succeed. A
  rejection that carries neither a status nor a known key still gets one
  renewal.
- **`SncLogonProvider`** explains a GSS code first, as before, and otherwise
  answers a status or key that is not about the logon neutrally, instead of
  "SNC logon refused".

The rule lives in one place, `readRejection` (`src/auth/rejection.ts`); the
README's *What `rejected()` answers* lists every answer.

## [5.0.0] - 2026-09-29

A migration, not an update: every provider this package ships now implements
`IAuthProvider` (`@mcp-abap-adt/interfaces-auth` 3.0.0) and can be handed to a
`@mcp-abap-adt/connection` 10.0.0 process with no wrapper and no check of what
it is. See *Migrating to 5.0.0* in the README.

### Breaking — a migration

- **`IAuthProvider` on every provider.** `prepare()` / `establish(logon)` /
  `authorize(request)` / `rejected(rejection)`, each answering
  `{ ok: true }` or `{ ok: false, refusal: { reason, hint? } }`, with no
  exception ever crossing the boundary — a provider's own work, a
  collaborator, and a target's `header` / `cookies` / `logonParameters` /
  `tlsMaterial` all become Oops instead.
- **`BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider`.**
  Every token provider — `AuthorizationCodeProvider`, `ClientCredentialsProvider`,
  `OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`,
  `OidcTokenExchangeProvider`, `Saml2BearerProvider`, `Saml2PureProvider`,
  `UaaPasscodeProvider` — **is** an `IAuthProvider` with no wrapper. The
  broker's token API (`getTokens()` / `refreshTokens()`) is unchanged.
- **`onTokens`.** Every token provider's config takes an optional
  `onTokens?: (result: ITokenResult) => Promise<void>`, called after every
  *new* token — a login or a refresh, never a cache hit — and awaited before
  the provider answers. A store that used to persist after `getTokens()`
  passes this instead. Best effort: a failing `onTokens` is logged by class
  name only and does not fail the authentication.
- **`Saml2PureProvider` presents cookies.** Its `applyToken` override calls
  `request.cookies(...)` instead of writing an `Authorization` header — its
  "token" is the SAML session's cookies.
- **One renewal, no Ok on an unchanged credential.** `rejected()` is at most
  one refresh, then — only if the refresh is refused or there is no refresh
  token — one login through the injected strategy; no provider retries
  anything itself. A renewal that returns the credential already presented is
  Oops "the renewal returned the credential that was refused", for
  `BaseTokenProvider` and `TokenAuthProvider.from` alike. A provider's own
  refresh never logs in — a failed refresh throws and the base runs the one
  login; a provider with no refresh grant (`ClientCredentialsProvider`,
  `OidcTokenExchangeProvider`, `Saml2PureProvider`) goes straight to that one
  login. Concurrent renewals share one in flight (one refresh, at most one
  login), and a `rejected()` whose presented token a renewal has already
  replaced answers Ok without renewing again.
- **Refusals from fixed wording and allowlists, never an error's message.** A
  refusal is built only from wording chosen per error class, plus metadata
  only when its value is on an allowlist this package owns — config field
  names (`KNOWN_CONFIG_FIELDS`), an `AssertionValidationError`'s `check`, a
  fixed set of system error codes, a fixed set of RFC SDK keys (SNC), or a
  class label by `instanceof`. No `message`, `cause` or body of any error
  reaches a refusal, and a `name` property is never read.
- **No implicit defaults — the consumer composes.** A constructor takes every
  collaborator explicitly: the interactive strategy, the device-code
  presenter, the SAML assertion validator, the SNC locator and probes.
  Omitting one no longer compiles. Static factories assemble the named,
  common recipe: `AuthorizationCodeProvider.inBrowser`,
  `OidcBrowserProvider.inBrowser`, `Saml2PureProvider.inBrowser`,
  `Saml2BearerProvider.inBrowser`, `UaaPasscodeProvider.fromTerminal`,
  `OidcDeviceFlowProvider.toConsole`, `CertificateAuthProvider.fromFiles`,
  `SncLogonProvider.forSecureLoginClient`.
- **SAML configuration moved.** `idpCertificates`, `clockSkewMs` and
  `assertionReplayStore` are no longer fields of `Saml2BearerProviderConfig` /
  `Saml2PureProviderConfig`; both now take `assertionValidator:
  IAssertionValidator` directly. `SamlTrust`
  (`{ idpCertificates, clockSkewMs?, replayStore? }`) is what the `inBrowser`
  recipes take instead. `ShippedValidatorOptions.replayStore` is now
  required — a direct call to `createSignedResponseValidator` /
  `createSignedAssertionValidator` must pass one (`defaultReplayStore`, or
  your own).
- **Manual strategies gain `timeoutMs` and `dispose()`.**
  `manualPasteStrategy`, `manualSamlResponseStrategy` and
  `manualPasscodeStrategy` accept `timeoutMs?: number`; on expiry, or when
  `dispose()` is called, the pending read is abandoned with a
  `BrowserAuthError` and the terminal `readline` it opened is closed —
  `dispose()` ends every concurrent `authorize()`, and resolves once all
  have settled. `read`
  is now `(prompt: string, signal: AbortSignal) => Promise<string>`.
- **`IDeviceCodePresenter`.** `OidcDeviceFlowProvider` no longer writes the
  verification URI and user code to the logger or stderr itself; it hands a
  `DeviceCodePrompt` to an injected `presenter: IDeviceCodePresenter`.
  `consoleDeviceCodePresenter(logger?)` is today's behaviour as a named
  choice, and `OidcDeviceFlowProvider.toConsole(config)` is the recipe. A
  presenter that throws is an Oops "showing the device code failed" — the
  device code itself never reaches a refusal.
- **Moved in from `@mcp-abap-adt/connection`:** `BasicAuthProvider`,
  `CertificateAuthProvider`, `SamlAuthProvider`, `TokenAuthProvider`,
  `FileCertificateMaterialLoader` (`src/credentials/`); `connection` 10.0.0
  removes its own copies. `TokenAuthProvider` is built only through
  `TokenAuthProvider.fixed(token)` or `TokenAuthProvider.from(refresher)`.
- **`SncLogonProvider`** — passwordless RFC logon through an installed SNC
  product. Resolves the SNC library (explicit, or `SNC_LIB_64` / `SNC_LIB` /
  the Windows registry / the macOS app bundle, in order), notes which product
  probe applies to it, and hands `RfcTransport` the logon parameters; it
  opens no connection and loads no SAP library itself. An unusable library is
  an Oops naming each candidate tried — its source, path and a fixed reason
  (`missing`, `not a library`, `wrong architecture`); an explicit `sncLib`
  names that one. The product is **named, not checked**
  (`ISncProductProbe { product; appliesTo(libraryPath) }`): `prepare()` is Ok
  with the Secure Login Client not running, because the library starts the
  client on demand — so an RFC open can wait on the client's logon window
  until the user answers it. Only the shipped `SecureLoginClientProbe` yields
  the Secure Login Client hint in `rejected()`. Measured 2026-09-29 against an
  on-premise system (Windows, Secure Login Client 3.0.3): SNC logon,
  discovery, reads and LOCK/UNLOCK, each RFC conversation its own SNC logon;
  with the client logged out, closing its logon window failed the open with
  `A2200019`, and `rejected()` answered "the SNC library has no credential to
  present (A2200019)". See *Passwordless RFC logon (SNC)* in the README and
  `docs/passwordless-sso.md`.
- **Dependencies:** `@mcp-abap-adt/interfaces-auth` `^3.0.0` (was `^2.1.0`),
  `@mcp-abap-adt/interfaces-auth-sap` `^1.1.0` (was `^1.0.1`). No new runtime
  dependency.

## [4.2.1] - 2026-09-27

### Changed

- **Node.js 26 is supported**: `engines` is `"^22 || ^24 || ^26"`. Under Node 26 npm skipped every release whose `engines` did not admit it and installed the newest one that did — silently an older major, for this package one without the restriction. Measured: `npm i -g @mcp-abap-adt/proxy` on Node 26.7.0 installed 4.2.0 while 5.0.1 was `latest`. CI tests 22, 24 and 26.

## [4.2.0] - 2026-09-26

### Added

- **`refreshTokens()`** on every provider, through `BaseTokenProvider`: a new
  token, never the cached one — the refresh token when there is one, the login
  flow when there is none or the refresh is refused — and it replaces the
  cache. `getTokens()` answers the cache while the token looks valid, so a
  caller holding a 401 had no way to ask for another; auth-broker's
  `refreshToken()` got the refused token back. Every provider now implements
  `IRefreshableTokenProvider` from `@mcp-abap-adt/interfaces-auth` 2.1.0
  (decision 39 there). `getTokens()` is unchanged: it now calls
  `refreshTokens()` once the cache is not valid, which is the same path it
  took inline before.
- **`SsoProviderFactory.create()` answers `IRefreshableTokenProvider`**, and
  `SsoProviderInstance` is that type, so a provider from the factory can be
  handed to anything requiring the refreshable contract without a cast. Every
  provider it builds already was one.

### Fixed

- **A failed browser login is a `BrowserAuthError`.** The class was exported
  and documented as "browser auth failed", and thrown nowhere: a timeout, the
  identity provider's refusal (`OAuth2 authentication failed: …`), a busy
  callback port, a browser that would not open and an abort all reached the
  caller as a plain `Error`, so the one type a caller could catch for them
  never arrived. `BrowserCallbackStrategy` — and so `browserCallbackStrategy`,
  `oidcCallbackStrategy` and `samlCallbackStrategy` — now throws it, with the
  original message and the original error as `cause`; an error that already
  has a type (a `ValidationError` from building the URL) passes unchanged.
  Found by auth-broker, whose migration note had nothing to point at.
- The README's error-handling example caught `RefreshError` as "browser auth
  failed". No provider throws `RefreshError`, `SessionDataError` or
  `ServiceKeyError`; the README now says so.

### Changed

- `@mcp-abap-adt/interfaces-auth` `^2.1.0` (was `^2.0.1`), which declares
  `IRefreshableTokenProvider`.

### Documentation

- `docs/btp-setup.md`: what each provider needs on the SAP side — XSUAA
  client, trust, user, ABAP mapping — and whether ADT accepts its token, with
  every claim tagged by source (SAP, Community, Measured, Inference) and the
  open questions still to be settled live.
- `docs/passwordless-sso.md`: SAP GUI's passwordless SNC login, why Eclipse
  ADT's on-premise SSO runs over RFC, the HTTP equivalents (X.509 client
  certificates, SPNego, IAS), what a Node.js client can reach, and options for
  this package.

## [4.1.3] - 2026-09-26

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
