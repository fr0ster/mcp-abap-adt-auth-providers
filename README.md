# @mcp-abap-adt/auth-providers
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

Every implementation of `IAuthProvider` for SAP ABAP ADT: the credential a
process delegates to, and the token providers behind it.

Token providers, the Basic/Certificate/SAML/Token credentials and passwordless
SNC logon are each an `IAuthProvider` the process takes as it is — whether it
is handed over directly to a connection, or through
`@mcp-abap-adt/auth-broker` for the stateful token API
(`getTokens()`/`refreshTokens()`).

## Migrating to 6.0.0 — the error contract

6.0.0 replaces how this package says what went wrong. Every refusal and every
throw is now an **error of one closed list of kinds**, minted by
[`@mcp-abap-adt/auth-errors`](https://www.npmjs.com/package/@mcp-abap-adt/auth-errors)
from allowlisted facts — not a class to match with `instanceof`, not words to
parse. And nothing is bounded by a timeout of the package's choosing any more:
your `AbortSignal` is the bound. What a consumer on 5.x must now do:

- **Install the contract it is read with.** `@mcp-abap-adt/auth-errors`
  (`^2.1.1`) to read errors; `@mcp-abap-adt/interfaces-auth` (`^7.5.0`) is
  what every provider here implements, and where the parts of an
  authorization strategy (`IAuthorizationPresentation`, `IAnswerTransport`,
  `IAuthorizationProtocol`, `IBrowser`) are declared. The consumers on the same contract
  are **released after this 6.0.0, not yet available**:
  `@mcp-abap-adt/connection` 13.0.0 (its suites run against the published
  auth-providers 6.0.0), `@mcp-abap-adt/auth-stores` 4.0.0 and
  `@mcp-abap-adt/auth-broker` 5.0.0. Until they are, no published connection
  reads these providers' refusals: 11.x reads the old refusal, and 12.0.0
  (published only under `next`) is built on interfaces-auth 6. Keep one copy
  of each: `npm ls @mcp-abap-adt/interfaces-auth` and
  `npm ls @mcp-abap-adt/auth-errors` should show one deduplicated version.
- **Every token provider requires `renewal`.** How a renewal proceeds —
  whether to refresh, whether to log in, when to stop, what becomes of a
  refresh token that was sent — is now a strategy the consumer gives
  (`renewal: IRenewalStrategy`). There is no default: a token provider (and
  `inBrowser`, `fromTerminal`, `toConsole`, `SsoProviderFactory.create`)
  constructed without one, or with one whose `next` is not a function, throws
  `configuration` `required-fields-missing` with `fields: ['renewal']`.
  **`renewal: refreshThenLogin()` takes the steps 5.x took** — one refresh,
  then one login when there is no refresh token or the refresh failed;
  `refreshOnly()` never logs in. See [Renewal strategy](#renewal-strategy).

  ```typescript
  import { ClientCredentialsProvider, refreshThenLogin } from '@mcp-abap-adt/auth-providers';

  const provider = new ClientCredentialsProvider({
    uaaUrl, clientId, clientSecret,
    renewal: refreshThenLogin(),
  });
  ```
- **`onTokens` is gone; pass `persistence`.** The config field `onTokens`
  is replaced by `persistence?: ITokenPersistence`, which receives one report
  per change of the provider's credentials (see
  [Persistence strategy](#persistence-strategy)). **The 5.x behaviour of
  `onTokens` — called with every new token, best effort — is
  `refreshStatePersistence(write, { onWriteFailure: 'continue' })`**:

  ```typescript
  // 5.x
  onTokens: async (result) => save(result),
  // 6.0.0
  persistence: refreshStatePersistence(
    async ({ authorizationToken, refreshToken, expiresAt }) =>
      save({ authorizationToken, refreshToken, expiresAt }),
    { onWriteFailure: 'continue' },
  ),
  ```

  `write`'s `refreshToken` is a string (a new one: write it), `undefined`
  (the result carried none: leave the stored one, as a 5.x `onTokens`
  result without a refresh token meant) or `null` — new — (the provider
  discarded the refresh token: clear the stored one, so it is never sent
  again after a restart). `onWriteFailure` is required, with no default: `'continue'`
  logs a failed write and goes on, as `onTokens` failures did; `'fail'`
  makes the call that caused the write fail with it. **A persistence strategy
  of your own whose awaited report throws now fails that call**
  (`getTokens()`, `refreshTokens()`, or the moment) — `unknown`, operation
  `persisting-tokens` — where 5.x only logged a failing `onTokens`; the
  credentials stay committed and the next `getTokens()` answers them.
  Without `persistence` nothing is persisted.
- **No `refreshTokenDisposition`.** interfaces-auth 6.0.0 added it to
  `ITokenResult`; interfaces-auth 7 removed it again, with the type
  `RefreshTokenDisposition`, and no release of this package carries it. What
  `getTokens()` / `refreshTokens()` return carries the refresh token the
  provider holds, or `refreshToken: undefined` — nothing more. A store learns
  what became of the refresh token from the persistence reports.
- **What a renewal answers changed where it could not produce a usable
  credential** — it now throws, and what follows (log in again, give up) is
  yours. With `refreshThenLogin()`:
  - a renewal that obtains a token still bound to another certificate than
    the pinned one: `getTokens()` / `refreshTokens()` throw `token-binding`
    `renewed-bound-elsewhere` (5.x returned the token);
  - a held token remembered as bound elsewhere: `getTokens()` throws the
    remembered error (5.x returned the token); `prepare()` no longer clears
    what is remembered — it renews once more;
  - `rejected()` with a `401` whose renewal is still bound elsewhere: Oops
    `renewed-bound-elsewhere` (5.x answered Ok);
  - a remembered expired client certificate is refused again by the pin —
    an equal refusal, no longer the same object;
  - a result that carries no usable refresh token — a refresh answered
    without a new one, a login without one — leaves the refresh token held
    in place (5.x dropped it), so the next renewal can still refresh;
  - a `403` for a token a renewal has already replaced: Ok, since what is
    presented changed;
  - a refresh that failed **before it was sent** (discovery, a
    client-authentication strategy or a loader failed first) no longer
    discards the refresh token.
- **A new kind, `renewal-declined`** — "the renewal strategy declined to
  renew the credential", `facts.trigger` — for a renewal strategy that stops
  before taking any step, with no other refusal that explains it (for
  instance `refreshOnly()` with an expired token and no refresh token). An
  exhaustive `matchKind` / `unreachableKind` must handle it.
- **`invalid-value` is a configuration case**, "a configured value cannot be
  used: `<fields>`": an unparseable `authorizationUrl` (5.x
  `required-fields-missing`), a `persistence` without a callable `report`,
  `refreshStatePersistence`'s `onWriteFailure` or `write`, a part of an
  authorization strategy that cannot be used (below).
- **Catch with `readFailure`, never `instanceof`.** Every throw of this
  package — a constructor's configuration fault, a factory's, a loader's,
  `getTokens()` / `refreshTokens()` — is an `AuthProviderFailure`. Read what
  you caught with `readFailure(thrown, operation)`, which answers an
  `IAuthProviderError` for anything (a failure of another installed copy of
  auth-errors included, a forged one rebuilt from its kind and facts); test
  with `isAuthProviderFailure(value)` when you need a yes/no. An `instanceof`
  answers false across two copies of the package and true for a forgery, so
  it is never the test.

  ```typescript
  import { matchKind, readFailure } from '@mcp-abap-adt/auth-errors';

  try {
    await provider.getTokens({ signal });
  } catch (thrown) {
    const error = readFailure(thrown, 'token-request');
    const advice = matchKind(error, {
      configuration: (e) => `fix ${e.facts.fields.join(', ')}`,
      'interactive-login': (e) => (e.facts.outcome === 'aborted' ? 'cancelled' : e.reason),
      'request-failed': (e) => `${e.reason}${e.facts.oauthError ? ` [${e.facts.oauthError}]` : ''}`,
      // … every kind: a missing handler does not compile …
      unknown: (e) => e.reason,
    });
  }
  ```

  Switch on `kind` with one of auth-errors' two exhaustiveness patterns —
  `matchKind(error, handlers)`, or a `switch` whose `default` calls
  `unreachableKind(error)` — so that a kind added by a later major stops your
  build instead of falling through at run time. A plain `switch` is not
  checked.
- **The classes are gone.** `TokenProviderError`, `ValidationError`,
  `RefreshError`, `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`,
  `AssertionValidationError`, `CertificateMaterialError`,
  `ClientAuthenticationError`, `ClientAuthenticationResultError`,
  `BasicClientIdError` and `TokenEndpointError` are no longer exported, and
  `AssertionCheck` is imported from `@mcp-abap-adt/interfaces-auth`. What each
  carried is a kind and its facts:

  | 5.x | 6.0.0 |
  |---|---|
  | `ValidationError` (`missingFields`) | `configuration` — `facts.case`, `facts.fields` ([Configuration errors](#configuration-errors)) |
  | `BrowserAuthError` | `interactive-login` — `facts.outcome` (`aborted`, `port-in-use`, `identity-provider-refused`, `busy`, `disposed`, `no-terminal`, …) |
  | `TokenEndpointError` (`status`, `oauthError`, `code`); the reduced `AxiosError` | `request-failed` — `facts.operation`, `facts.problem`, `facts.status`, `facts.oauthError`, `facts.code`; `tls` — `facts.code` |
  | `AssertionValidationError` (`check`) | `saml-assertion` — `facts.rule`, `facts.check` ([Refusal messages](#refusal-messages)) |
  | `CertificateMaterialError` (`incomplete`, `expired`) | `client-certificate` — `facts.problem` (`incomplete`, `unusable`, `expired`) |
  | `ClientAuthenticationError`, `ClientAuthenticationResultError`, `BasicClientIdError` | `client-authentication` — `facts.problem` (`signing-key-unusable`, `result-unsendable`, `basic-client-id-colon`) |
  | `RefreshError` | `credential-refused` `refresh-token` — with `refreshThenLogin()`, as before, a refused refresh falls back to one login inside the provider |
  | `SessionDataError`, `ServiceKeyError` | nothing: they had no producer |
  | `error.code` (`TOKEN_PROVIDER_ERROR_CODES`, `ASSERTION_ERROR_CODES`) | `kind` — the constants are gone from interfaces-auth 6.0.0 |
- **`refusalWords(error, what)` → `classify(error, operation)`**
  (auth-errors), then `.reason` / `.hint`. `what` was free text; an operation
  is one of the closed list `OPERATIONS` of interfaces-auth
  (`'loading-certificate'`, `'token-request'`, …). A caller that passed a
  `what` of its own and wants no operation's words passes
  `'unfamiliar-error'`, which answers "an authentication error of a kind this
  version does not know" and no hint — a TLS failure's `NODE_EXTRA_CA_CERTS`
  hint included; an operation of the list keeps its words and hints. See
  [Relaying a refusal](#relaying-a-refusal-classify).
- **A refusal is frozen, and only a minted one is trusted.** `AuthOutcome`'s
  refusal is the `IAuthProviderError` itself (`IAuthRefusal =
  IAuthProviderError`): `refusal.reason` and `refusal.hint` read as before, and
  `refusal.kind` / `refusal.facts` say what happened. Do not copy or edit one:
  it is frozen, so a mutation throws in strict code, and a copy (`{ ...refusal }`,
  a `structuredClone`, a JSON round-trip) is no longer minted — wherever it is
  read again it is rebuilt from its `kind` and `facts`, its diagnostics
  dropped; a provider of yours answering an outcome that is not one is
  answered `unknown`. Build an error you need with auth-errors' `authError`
  builders.
- **The words changed; match on facts.** Every reason and hint is rendered
  from the kind and its facts. A token request refused reads `the passcode
  exchange failed (HTTP 401)` instead of `Passcode exchange failed (401)`; an
  unfamiliar thrown value `loading the certificate failed (unknown error,
  ENOENT)` instead of naming a class or your `what`; a SAML refusal names its
  rule and no value of the document; the SNC library's path is a diagnostic,
  not a word. Code that matched words must match `kind` and `facts` instead.
- **No `timeoutMs` anywhere.** `DEFAULT_LOGIN_TIMEOUT_MS`, every strategy's
  `timeoutMs`, the factories' `{ timeoutMs }` and the 30 s (browser) and 300 s
  (passcode) defaults are removed, and so are the client credentials
  request's 30 s timeout and the SNC registry query's 5 s. **A consumer
  passing `timeoutMs` must pass `signal: AbortSignal.timeout(ms)` instead —
  to the strategy, or to `inBrowser` / `fromTerminal` as `{ signal }`; one
  passing nothing now waits until it aborts** — a login until its result or
  the identity provider's refusal, a request until the server or the OS ends
  it. See [Cancelling a login](#cancelling-a-login).
- **A browser that does not open is no longer an error.** A browser that
  throws or rejects (yours, or a shipped one) gets one log line in fixed
  words and the authorization URL as a prompt on stderr, and the login
  **keeps waiting**: the callback still listens, so the URL shown — the only
  way to finish where no browser can be opened (SSH, a host without a
  desktop) — is live. The `browser-launch-failed` outcome is gone, and a
  launch failure never ends the login; code that matched it must stop. Bound
  the login with a `signal` (`AbortSignal.timeout(ms)`), or it ends on its
  result, the identity provider's refusal or your abort.
- **A login is bound to its attempt (login CSRF).** Every URL
  `AuthorizationCodeProvider` and `OidcBrowserProvider` build carries `state`
  (and, for UAA, a PKCE challenge, S256); a configured `authorizationUrl`
  without `state` gets the provider's, which the identity provider must echo.
  The shipped protocols accept a redirect — a code or an `?error=` — only with
  that `state`; a consumer's own strategy that receives the redirect itself
  must check `state` itself. **The shipped listeners bind loopback only**,
  and answer only `Host: localhost` / `127.0.0.1` / `[::1]` with their port,
  from a loopback peer: a browser on another machine reaches them through an
  SSH tunnel, or through a transport of your own. The paste page's `/submit`
  needs the form's token. See [Login CSRF: `state`, PKCE and where the
  callback listens](#login-csrf-state-pkce-and-where-the-callback-listens),
  and [Interactive login: strategies by
  composition](#interactive-login-strategies-by-composition) below for what
  changed in the strategies.
- **Your strategies end on the request's signal.** Every
  `AuthorizationRequest` carries `signal`. `externalCodeStrategy`'s `provide`
  is `(authorizationUrl, signal)`, and a manual strategy's `read(prompt,
  signal)` must settle when its signal aborts: one that ignores it now blocks
  that strategy's `authorize` — and the next login, which waits for the
  aborted one to settle — where 5.x settled through a race.
- **The server's text is gone, also from logs.** A token endpoint's
  `error_description` and `error_uri` are read by nothing, in errors and in
  log lines, by default and with `authDebug`; only a registered OAuth `error`
  survives, as `facts.oauthError` (5.4.2's `err.response.data.error`). A
  consumer that read `error_description` from a log or an error no longer
  finds it. `authDebug: true` on a token provider adds, to its one line for a
  failed request, the secrets the request sent — each prepared: at most its
  first 4 and last 4 characters plus its length, the length only below 16
  characters — and never the server's text. See [Debug Logging](#debug-logging).
- **A subclass of `BaseTokenProvider`.** `performLogin()` is now
  `performLogin(attempt)` — hand `attempt.signal` to whatever the login waits
  on — and `performRefresh()` is `performRefresh(refreshToken, signal,
  dispatched)`: send the refresh token you are given — reading
  `this.refreshToken` instead may send one the renewal strategy discarded, a
  spent one — and call `dispatched()` right before the request leaves (pass
  `this.refreshSiteOptions(dispatched)` to a shipped token site, which does
  it). A refresh that never calls `dispatched()` counts as never sent: an
  abort then never applies the decision's `ifCut`, and its refresh token
  stays held although the server may have spent it. A subclass's constructor passes `renewal` through its config like any other
  token provider. A provider of your own extends `AuthProviderBase` and
  implements `onPrepare()`, `onEstablish(logon)`, `onAuthorize(request)` and
  `onRejected(rejection)`; the base owns the four moments and runs each
  inside auth-errors' `guard`. See
  [Writing a provider of your own](#writing-a-provider-of-your-own-authproviderbase).
- **A cut refresh: the strategy decided before it was sent.** A refresh
  whose callers all aborted after it was sent runs on; what becomes of the
  refresh token it sent is the `ifCut` of the decision that started it.
  `refreshThenLogin()` and `refreshOnly()` say `'discard'` — that refresh
  token is never sent again by the provider, so with `refreshThenLogin()`
  the next renewal may log in, as in 5.x; a strategy of your own may say
  `'keep'`. A refresh aborted before it was sent touches no refresh token.
  See [Cancelling a login](#cancelling-a-login).
- **A declined SAML login is refused `declined`.** The signed-Response
  validator reads `Status` right after the signature checks, before counting
  the `Assertion`, so a login the identity provider declined — which carries
  no Assertion — is refused `declined` with its status code, where 5.x
  refused it as carrying no direct-child Assertion (`no-direct-assertion`).
- **Device polling follows RFC 8628.** `slow_down` adds 5 s to every later
  poll, cumulatively; an `interval` that is not a finite, non-negative number
  is 5 s; `authorization_pending` / `slow_down` keep the poll going only with
  status `400`.

**What is no longer available anywhere** (each decided with the change; the
facts that remain are listed with it):

- the token endpoint's `error_description` and `error_uri` (the registered
  `error` stays, as `facts.oauthError`);
- a `cause` on any error, and the identity of a thrown value: a strategy's,
  loader's or presenter's own error reaches you classified, never as itself,
  and no `AxiosError` escapes;
- a rejected configuration value — the callback `port`, the SNC `qop`, a
  `clockSkewMs` (the field name stays, and for `qop` the allowed values);
- each configuration error's own sentence, replaced by its case's fixed words;
- the text of an exception inside a SAML refusal (xml-crypto's, the XML
  parser's);
- a document value that fails admission (a control, bidirectional or
  line-separator character, or the wrong shape) — dropped, not escaped;
- values moved from the words to `diagnostics` — the SNC library path, each
  SNC candidate's path, the two URIs of an ACS or redirect mismatch: shown by
  `renderDiagnostics(error)`, not by `reason` / `hint`;
- your own `what` in a relayed refusal (an operation of the closed list
  instead);
- the class label in "`<what>` failed (`<Class>`)", and which of the abort
  moments or empty inputs a login met;
- `error.code`, `missingFields`, `check` as a property,
  `CertificateMaterialError.incomplete` / `.expired` / `.words`,
  `TokenEndpointError.status` / `.oauthError` / `.code` — each now a fact;
- the diagnostics of an error that crosses another installed copy of
  auth-errors, or that was not minted (its kind and facts stay);
- every built-in login timeout and its message ("Authentication timeout
  after N seconds", "did not arrive in time");
- the authorization URL in a log line: it is prompted on stderr only, and
  the logger gets "the authorization URL was shown";
- the log lines of 5.x's `'auto'` browser, and the `DISPLAY=:0` 5.x set for
  `'system'` and a named browser: a browser has no logger, and the package
  writes nothing into `process.env`;
- the `open` and `express` dependencies.

### Interactive login: strategies by composition

An authorization strategy is now **composed of three parts**, each a
contract of `@mcp-abap-adt/interfaces-auth` 7.4.0 (`IBrowser` is 7.5.0's): a **presentation** (how
the URL reaches the user), a **transport** (how the user's answer comes
back) and a **protocol** (what an answer is and how it is checked). The
named strategies are compositions of the shipped parts, under the same
names (see [Composing a strategy from parts](#composing-a-strategy-from-parts)).
What a consumer on 5.x must now do:

- **`browserCallbackStrategy` / `oidcCallbackStrategy` /
  `samlCallbackStrategy` with `port`, `signal`, `remoteHint`: no change.**
  `browser` is an `IBrowser`, no longer a string — no browser is named by a
  string anywhere — and you pick it for the platform you run on:

  | 5.x | Linux | macOS | Windows |
  |---|---|---|---|
  | `'system'`, `'auto'` | `linuxDefaultBrowser()` | `macDefaultBrowser()` | `windowsDefaultBrowser()` |
  | `'chrome'` | `linuxBrowser('google-chrome')` | `macBrowser('Google Chrome')` | `windowsBrowser('chrome')` |
  | `'edge'` | `linuxBrowser('microsoft-edge')` | `macBrowser('Microsoft Edge')` | `windowsBrowser('msedge')` |
  | `'firefox'` | `linuxBrowser('firefox')` | `macBrowser('Firefox')` | `windowsBrowser('firefox')` |
  | any other name (`'msedge'` included) — 5.x opened the system default browser | `linuxDefaultBrowser()` | `macDefaultBrowser()` | `windowsDefaultBrowser()` |
  | `'none'`, `'headless'`, absent | no `browser` | no `browser` | no `browser` |

  ```typescript
  // 5.x: browserCallbackStrategy({ browser: 'system' })
  browserCallbackStrategy({ browser: linuxDefaultBrowser() })
  ```

  **There is no platform check:** each factory runs exactly its program,
  and on another OS it does whatever a program of that name does there —
  see [The six shipped browsers](#the-six-shipped-browsers). Pick the one
  for your platform. A consumer whose configuration holds a browser name
  maps it itself.
- **No list of candidates.** 5.x handed a named browser to the `open`
  package, which on Linux took the first of `google-chrome`,
  `google-chrome-stable`, `chromium`, `chromium-browser` (for `'chrome'`) or
  `microsoft-edge`, `microsoft-edge-dev` (for `'edge'`) that was installed,
  and `firefox` for `'firefox'`; only when `open` could not be loaded did a
  shell fallback try its own list. Now pass the executable that is installed
  — `linuxBrowser('google-chrome-stable')`, `linuxBrowser('chromium')`,
  `linuxBrowser('/usr/bin/firefox-esr')` — a name on `PATH` or an absolute
  path, as given.
- **`'auto'` and `'system'` are one: the platform's default browser.** The
  log lines 5.x's `'auto'` wrote while it tried launchers are gone (an
  `IBrowser` has no logger); a browser that fails shows only as the
  composer's fixed-words line `Failed to present the authorization URL: …`
  and the URL prompted on stderr.
- **No `DISPLAY=:0`.** 5.x set `DISPLAY=:0` on Linux, for `'system'` and a
  named browser, when neither `DISPLAY` nor `WAYLAND_DISPLAY` was set. The package now writes nothing into
  `process.env`: without a display the launcher does what it does there
  (`xdg-open` fails, or starts a console browser it finds); a launch that
  fails has the URL shown once on stderr while the login waits. A display of your choice — or a remote Chrome,
  a console browser, WSL, an ssh-forwarded X — is a browser of your own
  ([A browser of your own](#a-browser-of-your-own)).
- **The `open` package is gone** (and `express`): every launch is the
  package's own, a program started with an argument array, never a shell. A
  shipped browser binary (`linuxBrowser`) resolves as soon as it has started;
  a hand-off launcher (`xdg-open`, `open`, `rundll32`, PowerShell's
  `Start-Process`) when it exits `0`.
- **`openUrl` is gone.** One hook per decision: a callback that only opened
  the URL becomes an `IBrowser`, passed as `browser`; one that needed the
  redirect URI, or showed the URL in its own UI, becomes
  `consumerPresentation({ show })`, composed with `composeAuthorization`
  ([Where the URL is shown](#where-the-url-is-shown)).

  ```typescript
  // 5.x: browserCallbackStrategy({ browser: 'system', openUrl: (url) => myOpen(url) })
  browserCallbackStrategy({ browser: { open: (url) => myOpen(url) } })
  ```

  In TypeScript `openUrl` no longer compiles. **From plain JavaScript it is
  an unknown key, ignored without a word** — so a 5.x JavaScript consumer
  that used `openUrl` to keep the URL (and the `state` it carries) off stderr
  now gets them on stderr, unless it passes its own `IBrowser` or
  presentation.
- **`callbackServer` is gone.** A receiver of your own is an
  `IAnswerTransport`, composed: `composeAuthorization({ presentation,
  transport: myTransport, protocol: oauthCode(), endpoint: '/callback' })`.
  The transport hands each answer to the protocol's judge and never returns
  a payload: the composer takes only the payload the protocol accepted
  ([A transport of your own](#a-transport-of-your-own)). The
  `BrowserCallbackStrategy` class, `BrowserCallbackStrategyOptions`,
  `withBrowserCallbackServer`, `withOidcCallbackServer` and
  `withSamlCallbackServer` are removed — use `composeAuthorization` and the
  parts. `CallbackServerFactory`, `ICallbackServerOptions` and
  `ICallbackServerHandle` stay in interfaces-auth 7.4.0, deprecated and
  implemented by nothing.
- **A listener on another address is your own transport.** The shipped
  listeners bind loopback only and advertise only what they bind. A
  listener on a network address, a hostname, a wildcard, behind a proxy or a
  translated port is an `IAnswerTransport` of yours, which builds its
  redirect from its own origin and the endpoint path — or keep the loopback
  listener and tunnel (`ssh -L <port>:localhost:<port> <this machine>`; see
  [The SSH tunnel](#the-ssh-tunnel)). (The `host` and `allowedHosts` options
  of the 6.0.0 prereleases never shipped.)
- **The terminal and consumer-code strategies need `redirectUri`.**
  `manualPasteStrategy()`, `manualSamlResponseStrategy()` and
  `externalCodeStrategy({ provide })` without `redirectUri` throw
  `configuration` `required-fields-missing` naming `redirectUri`: pass the
  redirect registered with the identity provider (the ACS for SAML). Their
  `http://localhost:61001/callback` default is gone — it reached whatever held
  port 61001. `manualPasscodeStrategy`'s `redirectUri` is gone (it was
  unused). `staticCodeStrategy` is unchanged.
- **`externalCodeStrategy` takes OAuth codes only.** A SAML response or a
  passcode handed over by your code composes `consumerHandoff` with
  `samlResponse()` or `passcode()`:

  ```typescript
  const { presentation, transport } = consumerHandoff({
    redirectUri: acsUrl,
    provide: (url, signal) => ourSsoProxy.login(url, signal),
  });
  const strategy = composeAuthorization({
    presentation, transport, protocol: samlResponse(), endpoint: '/callback',
  });
  ```
- **The paste page's `/submit` is a `POST`** (urlencoded, `form_token` and
  `input`, up to 5 MB), and every listener serves the paste page for its
  protocol — OIDC and SAML too, which had none. A page of yours that `GET`s
  `/submit` must `POST`.
- **Overlap is `busy`.** A second `authorize` on one strategy while the
  first runs is `interactive-login` `busy`, for every composition — two
  terminal readers on one stdin are never right.
- **Every redirect callback is closed until the URL exists**, the SAML one
  included; there is no gate to opt out of.
- **The authorization URL is prompted on stderr only.** 5.x wrote the prompt
  to the logger's `info` when there was one. The URL carries `state`, and a
  configured one may carry anything, so it reaches no log line: the logger
  gets "the authorization URL was shown". Where the callback waits and the
  SSH hint still go to the logger (stderr without one). A consumer whose
  stderr is collected into its logs — an MCP server, say — shows the URL in
  its own UI with `consumerPresentation`.
- **A configured `authorizationUrl` without `state` gets one.** The provider
  appends its minted `state` to it, so the identity provider must echo it
  (RFC 6749 §4.1.2); a URL that already carries one `state` keeps it. No
  redirect is accepted without this attempt's `state`.
- **A strategy of your own written from scratch** (`IAuthorizationStrategy`)
  is unaffected: `IAuthorizationStrategy` and `AuthorizationRequest` did not
  change.

## Migrating to 5.0.0 — a migration, not an update

> This section and the migrations after it describe earlier majors: their
> code shows the API of the version they migrate to, and the version they
> migrate from. Coming from one of them, apply them in order and then
> [Migrating to 6.0.0](#migrating-to-600--the-error-contract) — above all
> for `browser`, now an `IBrowser` rather than a name, and for the manual and
> consumer-code strategies, which now require `redirectUri`.

*History: what 5.0.0 changed. Where 6.0.0 changed it again — `onTokens`
(now `persistence`), the `timeoutMs` of the manual strategies,
`BrowserAuthError`, the connection version —
[Migrating to 6.0.0](#migrating-to-600--the-error-contract) is what holds.*

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
`myName` is sent only when set. A missing `partnerName` or another `qop` is
thrown by the constructor as an `AuthProviderFailure` of kind `configuration`
(`snc-partner-name-missing`, `snc-qop-invalid` — see the configuration errors
table); the rejected `qop` value is never echoed.

**No timeout of its own.** `prepare()` may wait on the machine: on Windows the
locator and the Secure Login Client probe read the registry through
`reg.exe` (by its absolute path under `%SystemRoot%\System32`, no shell).
Since 6.0.0 that query has no built-in timeout — it runs until `reg.exe`
answers, or until the provider's signal aborts, which kills the child. Pass
`signal` (in the config, or to `forSecureLoginClient`) or `attach(signal)`
for each party sharing the provider; `prepare()` then ends Oops `aborted`
(`interactive-login`) once every attached party has aborted. With no signal
it waits for `reg.exe`; bounding it is the consumer's decision
(`AbortSignal.timeout(ms)`). A locator or probe of your own receives the same
signal as `locate(signal)` / `appliesTo(path, signal)`. The abort is tested
with a real child process on a POSIX system, and measured on a Windows host
(2026-10-07, Windows 11 x64): the library found through the real `reg.exe`
(`HKLM\Software\SAP\SecureLogin`, `InstallPath64`), and an abort answering
`aborted` with the `reg.exe` child ended and none left running. Localised
`reg.exe` output is not measured.

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
search; empty or whitespace environment variables count as unset, and the
registry value is trimmed before it becomes a path. Nothing usable →
`prepare()` is Oops, kind `snc`, variant `library-not-found`, listing every
candidate tried by its source and its reason, e.g. "no usable SNC library was
found: SNC_LIB (wrong architecture); registry (missing)" — the source is one
of `SNC_LIB_64`, `SNC_LIB`, `registry`, `macOS bundle`, and the reason one of
`missing`, `not a library`, `wrong architecture`. **Since 6.0.0 the paths are
not in the words** (they are local values, kept apart so a logger can drop
them): `error.facts.candidates[i]` holds each source, reason and — for a wrong
architecture — the architectures the file was built for, `facts.processArch`
this process's, and `error.diagnostics.candidatePaths[i]` the path tried,
index for index (`null` for a path the admission check refused, e.g. one
holding a control character). `renderDiagnostics(error)` prints them as
`candidates: SNC_LIB "C:\\…\\sapcrypto.dll" (wrong architecture); registry
"C:\\…\\sapcrypto.dll" (missing)`. No error message is ever part of it, and it
needs no logger. An **explicit** `sncLib` is the only candidate: unusable,
and the Oops names that one — "no usable SNC library was found: sncLib
(missing)", the path in diagnostics — with no fallback to automatic
discovery. With no candidate at all: "no usable SNC library was found: no
candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client
installation was found)". A locator of your own that throws gets "no usable
SNC library was found" alone: the candidate facts and paths are read only
from `DefaultSncLibraryLocator`'s own failure. The hint is always "set sncLib
to the SNC (GSS) library of your SNC product".
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

- **`A2200019`** — kind `snc`, variant `no-credential`; reason "the SNC
  library has no credential to present (A2200019)"; hint "log on in the
  Secure Login Client, to the profile used for SAP applications" when the
  Secure Login Client probe applied, otherwise "make sure the SNC product
  behind the SNC library is logged on" (since 6.0.0 the library's path is
  `error.diagnostics.library`, not a word). Measured
  2026-09-29: with the client logged out, closing its logon window failed the
  RFC open with `GSS-API(min): A2200019:Operation aborted by user or
  application`, and `rejected()` answered with this reason.
- **`SNCERR_INIT`** (or "gssapi library invalid/missing") — variant
  `library-init-failed`; reason "the RFC SDK could not initialise the SNC
  library (`<archs>`) as its SNC library (SNCERR_INIT)", the path in
  `error.diagnostics.library`, no hint — usually the architecture mismatch
  above, if a mismatched library somehow reached this point.
- `RFC_LOGON_FAILURE`, or a rejection with neither a status nor an RFC key —
  variant `logon-refused`; reason "SNC logon refused", plus the key in
  parentheses (and as `facts.rfcKey`) when there is one — never the
  underlying message or object.
- any other status or allowlisted RFC key (`RFC_CLOSED`,
  `RFC_COMMUNICATION_FAILURE`, …) — the neutral `system-refused` /
  `rfc-failure` of rule 5, not an `snc` refusal. Measured 2026-10-07
  (Windows 11, Secure Login Client, Kerberos profile): a wrong partner name
  failed the RFC open with `RFC_CLOSED` and no GSS code the provider
  explains, and so did, once, a logon with the client stopped and no
  credential to present; `rejected()` answered `system-refused` /
  `rfc-failure` both times.

The GSS codes are found by plain substring search, never a regular
expression over the SDK's text. `establish()` before `prepare()` is
`not-prepared` ("the SNC provider is not prepared" — "connect() prepares it
first"); a locator that answers no path is "no usable SNC library was found:
the locator returned no path"; anything else escaping a moment is `unknown`,
"the SNC provider failed while `<moment>` (unknown error)". A product probe
that throws is logged ("an SNC product probe failed: the probe failed (unknown
error)") and names nothing; "SNC library not found: `<reason>`" is logged with
the paths only as the line's `diagnostics` field.

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Overview

Every provider here is an `IAuthProvider` (`@mcp-abap-adt/interfaces-auth`
7) — `prepare()`, `establish()`, `authorize()`, `rejected()`, each answering
an `AuthOutcome` and never throwing — handed to the process as it is. An
`AuthOutcome` is `{ ok: true }` or `{ ok: false, refusal }`, the refusal an
`IAuthProviderError` minted by `@mcp-abap-adt/auth-errors`: its `kind` and
`facts` say what happened, `reason` / `hint` say it in words (see
[Error Handling](#error-handling)):

```typescript
import { AuthorizationCodeProvider, refreshThenLogin } from '@mcp-abap-adt/auth-providers';

const provider = AuthorizationCodeProvider.inBrowser({
  uaaUrl: 'https://...',
  clientId: '...',
  clientSecret: '...',
  renewal: refreshThenLogin(), // required: how every renewal proceeds
});
// A process of connection 13.0.0 (released after this package's 6.0.0)
// calls prepare() on connect, authorize() per request, and rejected() on a 401: one renewal through the renewal
// strategy — with refreshThenLogin(), a refresh, else one login.
```

### What `rejected()` answers

A provider blames its credential only when the rejection says the credential
was refused: status `401`, or the RFC SDK's `RFC_LOGON_FAILURE`. Anything else
is answered with a neutral refusal that names only the status or the SDK key.
For a token provider this is a **reading** its renewal strategy receives
(`cause.reading`: `credential`, `not-credential`, `unknown`): the shipped
strategies stop on `not-credential` without a step and answer the neutral
refusal, so nothing is renewed; a strategy of your own may renew anyway (see
[Renewal strategy](#renewal-strategy)):

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

Providers are configured via constructor; `getTokens()` handles refresh/login internally and takes only an optional `{ signal }` — this caller's cancellation (see [Cancelling a login](#cancelling-a-login)). `refreshTokens()` obtains a new token even while the cached one looks valid — what a caller holding a 401 needs. Either throws only an `AuthProviderFailure`.

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
what comes back, the port) belongs to the strategy, which a consumer may
replace wholesale. How long to wait is no one's choice but the consumer's:
a login ends on its result, the identity provider's refusal or the consumer's
`AbortSignal`. See
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
[Migrating to 6.0.0](#migrating-to-600--the-error-contract),
[Migrating to 5.0.0](#migrating-to-500--a-migration-not-an-update),
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

- **`@mcp-abap-adt/interfaces-auth`**: the contracts it implements and is handed — `IAuthProvider`, the token provider and strategy contracts (the authorization strategy's parts and `IBrowser` among them), `IClientAuthentication`, the assertion validator and replay store, and the error contract's types and allowlists (`IAuthProviderError`, its kinds and facts)
- **`@mcp-abap-adt/interfaces-auth-sap`**: the XSUAA configuration and `ICertificateMaterialLoader`
- **`@mcp-abap-adt/interfaces-utils`**: `ILogger` — the package logs only through the logger it is given, never through a concrete logger
- **`@mcp-abap-adt/auth-errors`**: the one runtime dependency of the error contract — every refusal and every throw is minted there, and `guard` is the boundary of each moment (`AuthProviderBase`)
- **No dependency on the broker, the stores or `@mcp-abap-adt/connection`**: they use this package through those contracts, never the reverse

## Usage

### Basic Usage

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  AuthorizationCodeProvider,
  ClientCredentialsProvider,
  browserCallbackStrategy,
  linuxDefaultBrowser,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

// User token via authorization_code (browser flow)
const authCodeBroker = new AuthBroker({
  tokenProvider: new AuthorizationCodeProvider({
    renewal: refreshThenLogin(),
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    // Linux; macDefaultBrowser() on macOS, windowsDefaultBrowser() on Windows.
    authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser() }),
  }),
});

// Service token via client_credentials (no browser)
const clientCredsBroker = new AuthBroker({
  tokenProvider: new ClientCredentialsProvider({
    renewal: refreshThenLogin(),
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
  }),
}, 'none');
```

### Choosing an authorization strategy

`authorization` decides how an interactive login is conducted, and it is
required: a provider builds no strategy of its own (since 5.0.0). Pass one of
the named strategies, compose one from the parts, or call a provider's static
factory — `inBrowser`, `fromTerminal` — which uses the usual one
(`inBrowser`'s callback strategy is given no `browser`: it shows the URL and
waits; to open a browser, construct the provider with
`browserCallbackStrategy({ browser })`). Every strategy is an
`IAuthorizationStrategy`, so a consumer can pass its own instead.

| Strategy | For | What it does |
|---|---|---|
| `browserCallbackStrategy(opts)` | `AuthorizationCodeProvider` | Listens on loopback, shows the URL or opens it in `browser`, waits for `?code=` with this login's `state` |
| `oidcCallbackStrategy(opts)` | `OidcBrowserProvider` | The same, yielding `{ code, state }` |
| `samlCallbackStrategy(opts)` | `Saml2BearerProvider`, `Saml2PureProvider` | The same, receiving a `SAMLResponse` (posted, or in the query) |
| `manualPasteStrategy({ redirectUri, read? })` | code flows | Shows the URL, reads the pasted code or redirected URL (stdin by default) |
| `manualSamlResponseStrategy({ redirectUri, read? })` | SAML flows | Shows the URL, reads the pasted `SAMLResponse` |
| `manualPasscodeStrategy({ read? })` | `UaaPasscodeProvider` | Shows the passcode page, reads the pasted passcode |
| `externalCodeStrategy({ redirectUri, provide })` | code flows | Hands the assembled URL and the login's signal to your `provide(url, signal)`, takes back the code |
| `staticCodeStrategy({ redirectUri?, payload })` | either | You already hold the payload; the URL is never built |
| `composeAuthorization({ … })` | any | Your own composition of a presentation, a transport and a protocol ([below](#composing-a-strategy-from-parts)) |
| your own | any | Implement `IAuthorizationStrategy<TResult>` and pass it |

Each named strategy is a composition of the shipped parts — today's values
live in these names and nowhere else; the parts have no default:

| Strategy | Presentation | Transport | Protocol |
|---|---|---|---|
| `browserCallbackStrategy` | `browser` absent: `showUrl()`; else `openInBrowser({ browser })` | `loopback({ port: port ?? DEFAULT_CALLBACK_PORT })` | `oauthCode()` |
| `oidcCallbackStrategy` | the same | the same | `oidcCode()` |
| `samlCallbackStrategy` | the same | the same | `samlResponse()` |
| `manualPasteStrategy` | `showUrl()` | `terminalPaste({ redirectUri, read })` | `oauthCode()` |
| `manualSamlResponseStrategy` | `showUrl()` | `terminalPaste({ redirectUri, read })` | `samlResponse()` |
| `manualPasscodeStrategy` | `showUrl()` | `terminalPaste({ read })` | `passcode()` |
| `externalCodeStrategy` | `consumerHandoff({ redirectUri, provide })` | (the same pair) | `oauthCode()` |

Every one answers at `/callback` (the composition's `endpoint`), and every
one returns a strategy with `dispose()`. A missing required `redirectUri` is
`configuration` `required-fields-missing` naming `redirectUri`, at
construction.

Options of the three callback strategies:

| Option | Default | Meaning |
|---|---|---|
| `port` | `61001` (`DEFAULT_CALLBACK_PORT`) | Port to bind. `0` binds an ephemeral one — usable only where the identity provider accepts a loopback redirect on any port, never where a fixed redirect URI is registered |
| `browser` | none: the URL is shown on stderr | An `IBrowser` that opens the URL: one of the six below, or your own. Never a name |
| `remoteHint` | the listener's SSH-tunnel hint | `(redirectUri) => string`: replaces the hint shown beside the URL for a user whose browser is elsewhere |
| `signal` | — | `AbortSignal` cancelling the login — the only bound there is (no login times out on its own): pass `AbortSignal.timeout(ms)` for a deadline |

**Nothing is opened unless you pass a `browser`.** Without one the URL is
shown on stderr — never stdout, so an MCP/LSP stdio transport is not
corrupted — and the callback waits. A browser that fails (yours, or a
shipped one) does not end the login: it is logged once in fixed words, the
URL is prompted on stderr, and the callback keeps waiting for it.

#### The six shipped browsers

Each is **one fixed launch**: a program started with an argument array,
never through a shell, the URL one argument of it, and only an `http:` /
`https:` URL as its serialisation. There is no platform switch, no fallback
chain and no platform check — **you pick the one for the machine you run
on**. Each runs exactly its program, with these arguments; on another OS it
does whatever a program of that name does there. Where there is none, the
launch fails to start: the URL is shown once on stderr and the login waits.
Where there is one, it runs — on Debian and Ubuntu `/usr/bin/open` is an
alternative for `xdg-open` or `run-mailcap`, so `macDefaultBrowser()` there
may open that machine's default browser, and `macBrowser(app)` hands
`xdg-open` an `-a` it was never meant to take.

| Factory | Launch | Settles |
|---|---|---|
| `linuxDefaultBrowser()` | `xdg-open <url>` | at its exit: `0` resolves, anything else rejects |
| `linuxBrowser(executable)` | `<executable> <url>` — a name on `PATH` or an absolute path, as given (`'google-chrome'`, `'firefox'`, `'/opt/…/microsoft-edge'`) | once the browser has started; its exit is never awaited |
| `macDefaultBrowser()` | `open <url>` | at its exit |
| `macBrowser(app)` | `open -a <app> <url>` (`'Google Chrome'`, `'Microsoft Edge'`, `'Firefox'`) | at its exit |
| `windowsDefaultBrowser()` | `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler <url>` | at its exit |
| `windowsBrowser(program)` | `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -Command` with the fixed text `Start-Process -FilePath $env:MCP_ABAP_ADT_BROWSER_PROGRAM -ArgumentList $env:MCP_ABAP_ADT_AUTHORIZATION_URL` (`'chrome'`, `'msedge'`, `'firefox'`, or a path) | at its exit |

```typescript
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
  linuxDefaultBrowser,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  renewal: refreshThenLogin(),
  uaaUrl, clientId, clientSecret,
  // macDefaultBrowser() on macOS, windowsDefaultBrowser() on Windows.
  authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser() }),
});
```

- **No environment is guessed or changed.** Nothing is written into
  `process.env` — no `DISPLAY=:0`, as 5.x set. Without a display the
  launcher does what it does there; a launch that fails has the URL shown.
- **On Windows** the launchers are the system's own, by absolute path under
  `%SystemRoot%\System32`, never a program found in the current directory,
  and never `cmd`, which parses `&`, `|`, `^` and `%` whatever the quoting.
  `windowsBrowser` passes the program and the URL to PowerShell only in the
  environment, never in its command text. A URL whose serialisation still
  holds a space, a quote, `<`, `>`, `^`, `|`, a backslash or a control
  character, or whose host is not a valid host name or address, is not
  opened at all (nothing is repaired). Measured 2026-10-07 (Windows 11 x64):
  the default browser through `rundll32` delivered the URL's path and query
  (with `&` and a `%20`) unchanged, and no command interpreter was started.
  The same day Chrome and Edge, through an earlier `Start-Process` command
  that named the program in its text, did the same: the URL reached the page
  unchanged and no command interpreter was a direct child of the launcher.
  Chrome itself runs `cmd /c` below itself for the native-messaging hosts of
  its extensions (seen for SentinelOne and Nexthink) — the browser's own
  children, not the launcher's. Measured 2026-10-08 (Windows 11 x64) for
  `windowsBrowser`'s current command, the program read from
  `$env:MCP_ABAP_ADT_BROWSER_PROGRAM`: Chrome and Edge got the URL
  unchanged, with only `conhost.exe` below the launcher; a program path
  holding `[ab]` started exactly that file and none of the files `[ab]`
  would match as a wildcard; a path holding `*` (no file can have that
  name) and a program string holding quotes, `;` and a PowerShell command
  each rejected `opening-browser`, with nothing started.
- A browser that could not be asked rejects with an `AuthProviderFailure`
  (`unknown`, operation `opening-browser`, an allowlisted code only), or
  `interactive-login` `aborted` on the login's signal. A browser that started
  is never killed.
- A hand-off launcher keeps the process alive until it exits, so an
  `open()` awaited on its own, in a script that holds nothing else, still
  settles at that exit; once the signal aborts, a launcher still running
  holds the process no longer. A browser binary (`linuxBrowser`) holds it no
  longer once it has started. Inside a composition the composer aborts the
  signal when the login ends. **Calling `open(url, signal)` yourself, the
  signal is yours:** a hand-off launcher that does not exit — `xdg-open` in
  its generic mode runs the browser in the foreground and exits only when
  the browser closes — keeps `open()` pending and the process alive until
  it exits or your signal aborts, so pass a signal you abort when you stop
  waiting.

Through 5.4.2 the fallback without the `open` package handed the URL to a
shell inside double quotes, so a `$(…)` or a backtick in it — from an OIDC
provider's discovery document, say — ran as a command. No launch goes
through a shell now.

#### A browser of your own

Anything else — a display of your choice, a remote Chrome, a console
browser, WSL, an ssh-forwarded X — is an `IBrowser` of yours:
`open(url, signal)` resolves once the browser was asked to open the URL (not
when the user finished), and rejects when it could not be — a presentation
failure: the URL is prompted and the login keeps waiting.

```typescript
import { execFile } from 'node:child_process';
import type { IBrowser } from '@mcp-abap-adt/interfaces-auth';

// A browser on display :1 — the package sets no environment of its own.
const onDisplayOne: IBrowser = {
  open: (url, signal) =>
    new Promise<void>((resolve, reject) => {
      execFile(
        'xdg-open',
        [url],
        { env: { ...process.env, DISPLAY: ':1' }, signal },
        (error) => (error ? reject(error) : resolve()),
      );
    }),
};

const strategy = browserCallbackStrategy({ browser: onDisplayOne });
```

#### Composing a strategy from parts

A strategy is three parts and the composer that joins them, each part a
contract of `@mcp-abap-adt/interfaces-auth`:

- a **presentation** (`IAuthorizationPresentation`) — how the authorization
  URL reaches the user. It knows no payload and no transport;
- a **transport** (`IAnswerTransport`) — how the user's answer comes back: a
  listener, a terminal, the consumer's code. It knows no payload: it hands
  each answer to the protocol's judge and acts on the verdict;
- a **protocol** (`IAuthorizationProtocol`) — what an answer is and how it is
  checked: it reads the expected `state` from the URL, accepts, refuses (the
  login keeps waiting) or ends the login. It knows no socket and no
  terminal.

`composeAuthorization({ presentation, transport, protocol, endpoint,
signal? })` runs one login in this order: open the transport; build the URL
from the redirect the channel advertises; `begin` the protocol on that URL;
arm the channel with the protocol's judge; present the URL (not awaited);
wait. Until the channel is armed, every answer is refused. The payload the
strategy returns is the one the protocol accepted — never anything a
transport hands back — and the first accepted (or ending) answer wins: every
later one is refused. `authorize` settles only once the transport is
released (the port free, the reader closed); an overlapping `authorize` is
`busy`; `dispose()` ends the login in flight and resolves once it has
settled.

`endpoint` is required — the named strategies pass `'/callback'` — and must
survive URL parsing unchanged (no encoded dot segment, backslash, space,
control character, `?` or `#`) and not be one of the listener's own routes
(`/`, `/submit`), else `configuration` `invalid-value` naming `endpoint`. A
missing part is `required-fields-missing` naming `presentation`,
`transport` or `protocol`. A protocol whose URL carries a redirect, over a
transport that advertises none, is `required-fields-missing` naming
`redirectUri`.

**Presentations:**

| Part | Does |
|---|---|
| `openInBrowser({ browser })` | Calls `browser.open(url, signal)` with exactly the URL and the login's signal. A browser that throws or rejects: the URL is prompted once, on stderr, and the failure logged in fixed words |
| `showUrl()` | Writes the URL to stderr only; the logger gets "the authorization URL was shown", then where the channel waits and its hint |
| `consumerPresentation({ show, onFailure? })` | `show(url, { redirectUri, signal })` is your UI. A throw or rejection is logged in fixed words; **no URL is printed** — `onFailure(url, context)`, when given, is your own fallback, run once |

**Transports:**

| Part | Binds | Advertises |
|---|---|---|
| `loopback({ port })` | `127.0.0.1`, then `::1` on the same port (skipped where the machine has no `::1`) | `http://localhost:<port><endpoint>` |
| `loopback4({ port })` | `127.0.0.1` only | `http://127.0.0.1:<port><endpoint>` |
| `loopback6({ port })` | `::1` only | `http://[::1]:<port><endpoint>` |
| `terminalPaste({ redirectUri?, read? })` | nothing; reads one line (`readFromTerminal` by default: prompt on stderr, stdin only when it is a TTY) | `redirectUri` as given |
| `consumerAnswer({ redirectUri?, receive })` | nothing; `receive(signal)` is your code | `redirectUri` as given |
| `consumerHandoff({ redirectUri?, provide })` | the pair `{ presentation, transport }` from one `provide(url, signal)` that shows the URL and returns the answer | `redirectUri` as given |

`port` is required on every listener (`0` binds an ephemeral one; not an
integer in 0..65535 is `callback-port-invalid`, before any socket is
touched). A port already held is `interactive-login` `port-in-use`. A
transport without a socket advertises no redirect of its own: a protocol
that needs one needs your `redirectUri` — the one registered with the
identity provider.

**Protocols:**

| Part | Payload | Redirect arrives with | A redirect binds by |
|---|---|---|---|
| `oauthCode()` | the code (`string`) | `GET` | `state` |
| `oidcCode()` | `OidcCallbackResult` (`{ code, state }`) | `GET` | `state` |
| `samlResponse()` | the `SAMLResponse` (`string`) | `GET`, `POST` | nothing here: `InResponseTo` and the assertion validator |
| `passcode()` | the passcode (`string`) | takes no redirect | — |

Each has its paste words: the prompt of a terminal, and the label and
instructions of a listener's paste page.

An OIDC login whose code the user pastes — the pasted URL's `state` checked:

```typescript
import {
  OidcBrowserProvider,
  composeAuthorization,
  oidcCode,
  refreshThenLogin,
  showUrl,
  terminalPaste,
} from '@mcp-abap-adt/auth-providers';

const provider = new OidcBrowserProvider({
  renewal: refreshThenLogin(),
  issuerUrl: 'https://idp.example.com/realms/sap',
  clientId: '...',
  authorization: composeAuthorization({
    presentation: showUrl(),
    transport: terminalPaste({ redirectUri: 'http://localhost:61001/callback' }),
    protocol: oidcCode(),
    endpoint: '/callback',
  }),
});
```

#### Where the URL is shown

**The authorization URL never reaches a log line.** It carries the login's
`state`, and a configured one may carry anything. `showUrl()` — and the
prompt a failed browser falls back to — writes it to **stderr only**, never
through the `ILogger`, never to stdout, and only as an `http:` / `https:`
serialisation of printable ASCII; the logger gets the fixed line "the
authorization URL was shown". Where the callback waits and the SSH hint
carry no secret and go to the logger's `info` (stderr without one).

A consumer whose stderr is collected into its logs — an MCP server, say —
shows the URL in its own UI with `consumerPresentation`:

```typescript
import {
  AuthorizationCodeProvider,
  DEFAULT_CALLBACK_PORT,
  composeAuthorization,
  consumerPresentation,
  loopback,
  oauthCode,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  renewal: refreshThenLogin(),
  uaaUrl, clientId, clientSecret,
  authorization: composeAuthorization({
    presentation: consumerPresentation({
      show: (url, { redirectUri }) => ourUi.showLogin(url, redirectUri),
    }),
    transport: loopback({ port: DEFAULT_CALLBACK_PORT }),
    protocol: oauthCode(),
    endpoint: '/callback',
  }),
});
```

A `show` that throws or rejects is logged in fixed words and prints no URL
— you chose your own UI because stderr may be collected; pass `onFailure`
for a fallback of your own. Either way the login keeps waiting.

#### The SSH tunnel

The shipped listeners bind loopback only. A browser on another machine
reaches one through an SSH tunnel, which arrives on loopback and needs no
option:

```bash
ssh -L 61001:localhost:61001 <this machine>
```

Then the redirect reaches the listener, and the paste page is at
`http://localhost:61001/` in that browser. Without a `browser`, the listener
prints that hint beside the URL (`remoteHint` replaces it). For `loopback4`
/ `loopback6` the tunnel goes to `127.0.0.1` / `[::1]`.

#### A transport of your own

A listener on a network address, a hostname, a wildcard, behind a proxy or a
translated port is not shipped: it is **your** `IAnswerTransport`, and its
risk is yours. The composition gives it only the endpoint path; it builds
the redirect from its own origin, so what it advertises is what it listens
on. A minimal one, for the redirect alone:

```typescript
import { createServer } from 'node:http';
import type { AnswerJudge, IAnswerTransport } from '@mcp-abap-adt/interfaces-auth';

/**
 * The request target in origin form (`/path?query`), read literally: the path
 * is the text up to the first `?`, the query is read by `URLSearchParams`.
 * Anything else — an absolute-form target, `*`, an empty one — is none.
 * Nothing here throws, whatever a client sends.
 */
function targetOf(raw: string | undefined): { path: string; query: URLSearchParams } | undefined {
  if (raw === undefined || !raw.startsWith('/')) return undefined;
  const mark = raw.indexOf('?');
  return mark < 0
    ? { path: raw, query: new URLSearchParams() }
    : { path: raw.slice(0, mark), query: new URLSearchParams(raw.slice(mark + 1)) };
}

/**
 * `origin` is what the browser elsewhere uses — `http://buildhost.example:61001`,
 * say: the redirect is built from it.
 */
function networkListener(bindAddress: string, port: number, origin: string): IAnswerTransport {
  return {
    label: 'browser',
    async open(options, use) {
      let judge: AnswerJudge<unknown> | undefined;
      let settle!: { resolve(): void; reject(error: unknown): void };
      const answered = new Promise<void>((resolve, reject) => {
        settle = { resolve, reject };
      });
      answered.catch(() => undefined); // awaited by the composer once armed

      const server = createServer((req, res) => {
        // Every request is anyone's: nothing it carries may throw out of
        // this handler, where it would end the process.
        try {
          const target = targetOf(req.url);
          if (target === undefined) {
            res.writeHead(400).end();
            return;
          }
          if (req.method !== 'GET' || target.path !== options.endpoint) {
            res.writeHead(404).end();
            return;
          }
          // Closed until armed: nothing settles before the URL exists.
          if (judge === undefined) {
            res.writeHead(400).end();
            return;
          }
          // The protocol decides: it checks `state` and reads the code.
          let verdict: ReturnType<AnswerJudge<unknown>>;
          try {
            verdict = judge({ via: 'redirect', method: 'GET', params: target.query });
          } catch (error) {
            // A judge that throws has ended the login.
            res.writeHead(500).end();
            settle.reject(error);
            return;
          }
          if (verdict.verdict === 'refuse') {
            res.writeHead(400).end(); // ignored: the login keeps waiting
            return;
          }
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end(verdict.verdict === 'accept' ? 'Signed in. You can close this tab.' : 'The login was refused.');
          if (verdict.verdict === 'accept') settle.resolve();
          else settle.reject(verdict.error);
        } catch {
          // Fixed words only, and the login waits on.
          if (!res.headersSent) res.writeHead(500);
          res.end();
        }
      });

      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, bindAddress, () => resolve());
      });
      const onAbort = () => settle.reject(options.signal.reason);
      options.signal.addEventListener('abort', onAbort, { once: true });
      try {
        return await use({
          redirectUri: `${origin}${options.endpoint}`,
          arm(armedWith) {
            judge = armedWith;
            return { answer: () => answered };
          },
        });
      } finally {
        options.signal.removeEventListener('abort', onAbort);
        // Settle only once released: the port is free when `open` settles.
        const closed = new Promise<void>((resolve) => server.close(() => resolve()));
        server.closeAllConnections();
        await closed;
      }
    },
  };
}

const strategy = composeAuthorization({
  presentation: showUrl(),
  transport: networkListener('0.0.0.0', 61001, 'http://buildhost.example:61001'),
  protocol: oauthCode(),
  endpoint: '/callback',
});
```

> **Warning — a listener on the network is open to the network.** Every
> machine that can reach it can send it requests while a login waits; the
> code and the `state` cross the network in clear over plain HTTP; and what
> the shipped listeners check before anything is served — the `Host` header
> against DNS rebinding, a loopback name only from a loopback peer, the form
> token of a paste page — is now yours to check or to leave out. A paste
> page reachable from the network lets every client that can load it settle
> the login with a code of its own, so the user then works as whoever that
> code belongs to. Prefer the [SSH tunnel](#the-ssh-tunnel) to the loopback
> listener; use a network listener only where every machine that can reach
> the port is trusted, and behind TLS where the network is not.

The transport hands the judge each answer and acts on its verdict — `accept`
ends the wait, `refuse` is answered and ignored, `end` ends the login — and
never returns a payload: the composer keeps the one the protocol accepted,
and an `answer()` that resolves without one fails the login. Its request
handler is reachable by anyone before the channel is armed, so nothing a
request carries may throw out of it: an exception in a Node `request`
handler ends the process. Parse the target as text — `new URL(req.url,
origin)` throws on a target such as `//[` — and contain every exception in
fixed words, as above.

#### Bringing your own

```typescript
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';

const fromOurPortal: IAuthorizationStrategy<string> = {
  async authorize(request) {
    const redirectUri = 'https://portal.internal/oauth/callback';
    const url = await request.buildAuthorizationUrl(redirectUri);
    // The redirect URI you return is the one sent to the token endpoint.
    return { payload: await ourPortal.login(url, request.signal), redirectUri };
  },
  async dispose() { await ourPortal.close(); },
};
```

`dispose` is optional, and whoever constructs a strategy disposes of it: a
provider builds none, so the strategy you pass in — or the one a static
factory you called composed — lives as long as the provider, serves every
login, and is yours to dispose. `dispose()` disables a strategy for good and
ends its logins in flight (`interactive-login` `disposed`); an abort of a
login's signal ends only that login (`aborted`) and leaves the strategy usable.

**Check `state` — the redirect is yours to bind.** The URL
`buildAuthorizationUrl` returns carries a fresh `state` (and a PKCE challenge,
whose verifier the provider keeps and sends in the exchange). A strategy that
receives the redirect itself — `fromOurPortal` above — must accept a code
only from a redirect whose `state` equals the one in that URL (compare in
constant time), or a page in the user's browser can hand it a code of its own
(RFC 6749 §10.12). A transport of your own composed with `oauthCode()` or
`oidcCode()` gets that check from the protocol.

**End on the request's signal.** Every `AuthorizationRequest` carries
`signal`, aborted once no caller needs the login any more (see
[Cancelling a login](#cancelling-a-login)). Your strategy must stop waiting
and release what it holds when it aborts — `fromOurPortal` above passes
`request.signal` to `ourPortal.login`. One that ignores it never settles, and
the next login waits for it.

#### The paste page, and pasting at a terminal

A shipped listener settles through either of **two** channels — whichever
finishes first wins:

1. **The redirect** — `GET /callback?code=…&state=…` (a `SAMLResponse`
   posted or in the query for SAML) on the advertised redirect URI. Works
   when the browser is on the same machine as the process.
2. **The paste page** — `GET /` serves a form with the protocol's words, and
   the user pastes the code (or the whole redirected URL, or the
   `SAMLResponse`). Works when the browser is on a *different* machine and
   the redirect cannot reach back: reach the page through
   [the SSH tunnel](#the-ssh-tunnel). Every listener serves it, for every
   protocol. The form posts `form_token` and `input` to `/submit`
   (urlencoded, up to 5 MB); `/submit` settles only with this login's form
   token, a pasted redirected URL only with this login's `state`.

A listener never reads stdin: under an MCP or LSP stdio transport stdin
carries the protocol, and an authorization library has no business
consuming it. Reading a pasted answer at a terminal is a strategy of its own:

```typescript
import {
  AuthorizationCodeProvider,
  manualPasteStrategy,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  renewal: refreshThenLogin(),
  uaaUrl, clientId, clientSecret,
  // Binds no socket at all: prints the URL, then reads one line.
  // Reads stdin when it is a TTY — pass `read` to source it anywhere else.
  authorization: manualPasteStrategy({
    redirectUri: 'http://localhost:61001/callback', // the one registered with the IdP
  }),
});
```

`manualPasteStrategy` reads from stdin only when `process.stdin.isTTY`, and
otherwise fails the login (`interactive-login` `no-terminal`: "Manual input
needs an interactive terminal. Supply `read` to source the value elsewhere.")
rather than consuming a protocol stream. Supply `read` to take the value from
somewhere else entirely — a TUI prompt, an HTTP request, a file:

```typescript
authorization: manualPasteStrategy({
  redirectUri: 'http://localhost:61001/callback',
  read: (prompt, signal) => askInOurUi(prompt, signal),
})
```

`read` gets the login's signal: when the login is aborted or the strategy
disposed, it must stop and release what it holds. The strategy settles only
once `read` has, so a `read` that ignores its signal blocks that login — and
the next one, which waits for it — until it returns. A pasted URL of
another login gets fixed words and the prompt again; an input no code can be
read from ends the login `interactive-login` `unreadable-input`.

`redirectUri` is required: it must be the one the identity provider will
redirect to, and it is also the one sent to the token endpoint. A strategy
that binds no socket has no redirect of its own to offer.

Both the paste page and `manualPasteStrategy` accept a bare code or a full
redirected URL. A **bare code** is an input with none of `?`, `&`, `=`, `/`
or `#`: it carries no `state` and is taken — the user typed it. Anything else
is read as a redirected URL (parsed with `URL`): it must carry the `state` of
the URL this login showed, and its code is taken from the query alone, never
from a fragment — `manualPasteStrategy` asks again on a mismatch, the paste
page answers `400` with the form again. So `…/callback&code=X` is not a code
that skips the check.

#### Login CSRF: `state`, PKCE and where the callback listens

A page in the user's browser can call the local callback with a code of its
own while a login waits, and the user ends up logged in as someone else
(RFC 6749 §10.12; RFC 9700 §4.7). Since 6.0.0, each part keeps its share:

- **The provider binds the URL it builds.** `AuthorizationCodeProvider` and
  `OidcBrowserProvider` put a fresh `state` (32 random bytes, base64url) in
  every authorization URL they build, and a PKCE pair (S256) — new for UAA in
  6.0.0, as OIDC already had; the verifier of the last URL built is sent in
  the exchange. Neither is logged.
- **A configured URL gets a `state` too.** A configured `authorizationUrl`
  that carries no `state` gets the provider's minted one, fresh for every
  URL built, appended to its query as text before any fragment — and nothing
  else: no PKCE challenge, no `code_verifier`. The identity provider must
  echo it (RFC 6749 §4.1.2). One that carries one `state` keeps it and is
  bound to it; an empty or a repeated `state` is refused (`configuration`
  `invalid-value` naming `authorizationUrl`) before anything is shown or
  opened — the listener is already bound by then. A code
  from `staticCodeStrategy`, which never builds the URL, is exchanged
  without a `code_verifier`: binding it is yours.
- **The protocol checks `state`.** `oauthCode()` and `oidcCode()` read the
  expected `state` from the URL and accept a redirect — a code or an
  `?error=` — only with exactly one `state` equal to it, compared in constant
  time; anything else is answered `400`, counted, and the login keeps
  waiting. A forged `?error=` therefore ends nothing. A parameter counts only
  when present exactly once. `samlResponse()` reads no `state`: a SAML
  response is bound by `InResponseTo` and the assertion validator.
- **The listener is closed until the URL exists.** From the bind on, a
  listener refuses every request to the callback and the paste page until
  the composer arms it — after the URL is built and the protocol has read
  it, before the URL is shown — for every protocol, SAML included.
- **Loopback only.** The shipped listeners bind loopback (through 5.4.2 the
  callback bound every interface) and refuse — before any page, form token or
  callback handling — a request whose `Host` is not a loopback name with the
  bound port (`localhost`, `127.0.0.1`, `[::1]`, in any spelling the WHATWG
  URL host parser reads as one), so a DNS-rebound name reads and settles
  nothing. A loopback name counts only from a loopback peer (`127.0.0.0/8`,
  `::1`, `::ffff:127.x.y.z`): a machine on the network sending
  `Host: localhost` is refused too. `loopback` binds `127.0.0.1` first, then
  `::1` on the same port. On a host without IPv6 loopback — the `::1` bind
  fails `EADDRNOTAVAIL` or `EAFNOSUPPORT` — the `::1` half is skipped and it
  listens on `127.0.0.1` alone. Only `EADDRINUSE` on `::1` — the port, fixed
  or the one the OS gave `127.0.0.1` for `port: 0`, held by someone else
  there — fails the login `port-in-use`: the redirect URI says `localhost`,
  which resolves to `::1` first, so staying on `127.0.0.1` alone would hand
  whoever holds `[::1]:<port>` the code and the `state`. Any other bind error
  ends the login `failed`. Retrying is yours. A browser elsewhere reaches a
  listener through [the SSH tunnel](#the-ssh-tunnel); a listener on the
  network is [a transport of your own](#a-transport-of-your-own), and its
  risk is yours.
- **The paste page is bound to the attempt.** Arming mints a form token (32
  random bytes, base64url) for this login only, embedded in the page as a
  hidden field and never logged; `/submit` without it, with another, or with
  two is answered `400` before the protocol sees anything. Another origin
  cannot read the page (no CORS, a CSP of `default-src 'none'` with
  `form-action 'self'`), so it cannot learn the token.
- **One answer per connection.** Every response carries
  `Connection: close`, `X-Content-Type-Options: nosniff` and the CSP; every
  value interpolated into a page is escaped. Routes are compared literally:
  the endpoint, `/` and `/submit` as exact strings, anything else `404`.

Every refused request is answered `400`, counted, and **ignored**: the login
keeps waiting, and its `aborted` words report how many there were.

> The `extractCode(input)` helper behind the paste parsing is internal; it is
> not part of the package's exports, contrary to what the 1.1.0–1.2.0 README
> said.

### Client authentication

How the *client* proves itself to the authorization server — a secret, a
client certificate, a signed assertion — is a strategy too:
`IClientAuthentication` from `@mcp-abap-adt/interfaces-auth`, passed as
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
  certificate is presented. Anything else is refused, `client-authentication`
  `result-unsendable`: *the client authentication returned a request that
  cannot be sent*. Nothing of a request is ever logged or kept on an error —
  no parameter, no header, nothing the server answered beyond its status and
  a registered OAuth `error`. Only with the provider's `authDebug: true` does
  a failed request's log line name the secrets it sent (`sent`, see
  [Debug Logging](#debug-logging)): `client_secret`, `client_assertion` and a
  Basic credential (`basic`, `basic_secret`) of a strategy, beside the grant's
  own; a secret your strategy puts in any other parameter or header is not
  named there — and is logged nowhere either way.

```typescript
import { readFile } from 'node:fs/promises';
import {
  ClientCredentialsProvider,
  OidcPasswordProvider,
  privateKeyJwt,
  tlsClientCertificate,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

// A client certificate: the token request goes over mTLS, no secret anywhere.
const service = new ClientCredentialsProvider({
  renewal: refreshThenLogin(),
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
  renewal: refreshThenLogin(),
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

- **`clientSecret` and a strategy together are a configuration error**
  (`client-secret-beside-client-authentication`) naming `clientSecret`,
  thrown by the constructor: two ways of authenticating one
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
  which adds to Node's store rather than replacing it. A TLS failure is an
  error of kind `tls` naming its code (`facts.code`) and the operation, in
  words fixed per kind of failure — an untrusted server certificate (hint:
  `NODE_EXTRA_CA_CERTS`), an expired one, a host name not in it, and the
  server's alert refusing the client certificate; the words are in the
  [Refusals](#refusals) table.

  The alert row is what a server sends when it refuses the client
  certificate in the handshake. Current OpenSSL — 3.5, bundled with Node 22
  and 24, and 3.6, both measured — spells the SSLv3-era alerts
  `SSL/TLS_ALERT_…`; older releases spelled them `SSLV3_ALERT_…`, so both are
  listed. Measured 2026-10-04 against `openssl s_server -Verify`:
  no certificate → `…CERTIFICATE_REQUIRED`, an issuer the server does not
  trust → `…UNKNOWN_CA`, an expired certificate →
  `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED`. Any other code is not a `tls`
  error: an allowlisted system code (`ECONNREFUSED`, …) is the `code` of a
  `request-failed`, anything else is *unknown error*.
- **mTLS aliases (RFC 8705 §5).** An OIDC provider that discovers an endpoint
  hands the strategy the server's `mtls_endpoint_aliases` entry for it
  (`token_endpoint`, `device_authorization_endpoint`); `tlsClientCertificate`
  sends there unless it was given `endpoint`. An endpoint given in the
  configuration comes with no alias.
- **A loader that fails with its own error** — a missing file, say — is
  refused as *`<grant>` token request failed (unknown error, ENOENT)*
  (`client_credentials token request failed (unknown error, ENOENT)`), kind
  `unknown`. The refusal names the error's code when it is on the allowlist
  (`SYSTEM_CODES`), never its message. That is by design: a loader may throw
  text holding a key or a passphrase. A loader that wants its own words
  refused throws an `AuthProviderFailure` it built with auth-errors'
  `authError` builders (a `client-certificate` error, say), which is answered
  as it is.
- **Thrown errors carry no request, and nothing of the server but facts.** A
  failed token request throws an `AuthProviderFailure` built where the
  request failed, on both paths, strategy or not: kind `tls` for an
  allowlisted TLS code, else `request-failed` with the operation, the grant,
  `problem` (`refused` with the HTTP `status`, `no-response` without one),
  the OAuth `error` as `oauthError` when it is a registered code, and an
  allowlisted system `code`. No `AxiosError` escapes, nothing keeps the form
  body, the `Authorization` header or the TLS agent with its key, and there is
  no `cause`. The server's `error_description` and `error_uri` are read by
  nothing — a hostile server can echo any secret of the request in them. A
  failed request is noted in one `debug` line through the provider's logger
  with the same safe facts (`<operation>: the token endpoint refused the
  request`, `{ status, error?, code? }`), none for the device poll's
  `authorization_pending` / `slow_down` with status `400`.

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
clientSecretPost*. A missing or other `encoding` is a configuration error
(`basic-encoding-missing`, `allowed: 'basic-encoding'`) naming `encoding`,
thrown by `clientSecretBasic` itself. A `401` is reported as the
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
  *"invalid_client": "Invalid token audience"* (on the wire; the package
  reports only `invalid_client`, as `facts.oauthError`). `OidcDeviceFlowProvider` on
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
through the [renewal strategy](#renewal-strategy) (`cause.trigger:
'bound-elsewhere'`) and the pinned certificate — with `refreshThenLogin()`,
the refresh token when there is one, else (or when the refresh fails) one
login, no step twice — and the binding check then runs on the new token. A
new token still bound elsewhere is committed (it is the server's state) and
recorded as the step's outcome `bound-elsewhere`; `refreshThenLogin()` stops
there, and the renewal fails with *the new token is bound to a client
certificate this provider does not present* (`token-binding`
`renewed-bound-elsewhere`): `getTokens()` / `refreshTokens()` throw it and
`authorize()` refuses with it. It is **remembered** with the held token: the
next renewal of that token hands the strategy that error as
`cause.lastRenewal`, and `refreshThenLogin()` / `refreshOnly()` stop on it at
once in `getTokens()` and `authorize()` — the same error, no token request and
no login — so a server that keeps binding to another certificate costs no
request per call. A renewal that *fails* while such a token is held — the
refresh and the login refused, the client certificate expired, the server
unreachable — is remembered the same way, with its own error (*the client
certificate has expired*, say), until the token changes; the error is always
that of the latest renewal. Only a token held *bound elsewhere* is
remembered: an expired token whose renewal fails is renewed again on the next
attempt. `prepare()` (once per connect) and `rejected()` for the token held
are the shipped strategies' cue to renew once more; a refused token that was
already superseded by a renewal is answered Ok without one. `getTokens()` pins
the certificate to compare thumbprints, so with a bound token held it may
throw a `client-certificate` failure when the material is unusable or
expired — refused by the pin before the strategy is asked. `establish()`
reads such a held token as unknown and presents the pinned certificate. With
**no** certificate pinned there is nothing to renew it for: `getTokens()`
returns the token, and `establish()` / `authorize()` refuse it.

| Token | Certificate pinned | `establish(logon)` | `authorize(request)` |
|---|---|---|---|
| unbound | none | presents nothing, Ok | Bearer, Ok |
| unbound | yes | presents it; Ok even when the logon takes no TLS material (the Bearer carries the token) — a logon target that throws is Oops | Bearer, Ok |
| bound to the pinned one | yes | presents it; a logon that takes no TLS material (RFC) is that logon's Oops | Bearer, Ok |
| bound to another, or `cnf` without a readable thumbprint | yes | read as **unknown**: presents the pinned one (a logon that takes no TLS material is that logon's Oops) | renewed through the renewal strategy and the pinned one, the new token checked: Bearer, Ok — or, bound elsewhere again, Oops, no header written |
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
  refreshThenLogin,
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
  renewal: refreshThenLogin(),
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
  linuxDefaultBrowser,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const tokenProvider = SsoProviderFactory.create({
  protocol: 'oidc',
  flow: 'browser',
  config: {
    renewal: refreshThenLogin(),
    issuerUrl: 'https://example-idp/.well-known/openid-configuration',
    clientId: '...',
    clientSecret: '...',
    scopes: ['openid', 'profile', 'email'],
    authorization: oidcCallbackStrategy({ browser: linuxDefaultBrowser() }),
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
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const redirectUri = 'urn:ietf:wg:oauth:2.0:oob';

const provider = new OidcBrowserProvider({
  renewal: refreshThenLogin(),
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
lifecycle terms. For a code the user pastes, compose `oidcCode()` instead
(`composeAuthorization({ presentation: showUrl(), transport:
terminalPaste({ redirectUri }), protocol: oidcCode(), endpoint: '/callback'
})`, see [Composing a strategy from parts](#composing-a-strategy-from-parts)):
it also checks a pasted URL's `state`.

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
  refreshThenLogin,
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
  renewal: refreshThenLogin(),
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
`samlCallbackStrategy`, `manualSamlResponseStrategy` and a `consumerHandoff`
composed with `samlResponse()` all call it, and with `idpInitiated: true` and
no `authorizationUrl` the builder refuses: a configuration error
(`saml-idp-initiated-without-authorization-url`) thrown before any URL is
produced, so before a browser opens. (3.0's advice —
`externalCodeStrategy` whose `provide` ignores the URL — no longer works for
that reason; since 6.0.0 `externalCodeStrategy` takes OAuth codes only.) See
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
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const acsUrl = 'https://sp.example.com/saml/acs';

const provider = new Saml2PureProvider({
  renewal: refreshThenLogin(),
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
with the `expiresAt` they were obtained with (epoch ms — the persistence
report and `getTokens()` carry it). Until `expiresAt`, less a one-minute buffer, the
provider presents them and runs no login: no strategy, no validator, no
`cookieProvider`. Past it — or with no `expiresAt`, since cookies carry no
expiry of their own — the first `getTokens()` or `authorize()` logs in as
above. There is no `refreshToken`: SAML has none, so renewal is a new login.
See [Seeding a stored credential](#seeding-a-stored-credential).

**Read that `redirectUri` twice.** The provider requires the assertion
consumer service the IdP posts to be exactly the redirect the strategy
names. `samlCallbackStrategy` advertises its loopback listener,
`http://localhost:61001/callback` by default; `manualSamlResponseStrategy`
and a `consumerHandoff` advertise the `redirectUri` you give them, which
`manualSamlResponseStrategy` requires. If you declare a real `acsUrl` and the
strategy names another address, the login fails before anything is opened
with a configuration error, `saml-acs-mismatch` — *SAML acsUrl and the
address the authorization strategy used do not match* — whose two addresses
are `diagnostics.configuredUri` and `diagnostics.strategyUri`
(`renderDiagnostics(error)` prints them), not words. Declare no `acsUrl` with
`samlCallbackStrategy` and its address is used for both, which is
consistent — and only reachable when the IdP will post to your localhost.

Both SAML providers reject at construction when `authorizationUrl` is set
without `acsUrl` — a configuration error, `saml-acs-required-with-authorization-url`:
*acsUrl is required when authorizationUrl is set: the ACS inside a pre-built
SAML request cannot be read, so it must be declared*.

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
configuration error (`saml-shipped-validator-without-issuer`) naming it —
before any browser opens or
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
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const idpCertificates = [readFileSync('idp-signing.pem', 'utf8')];

const provider = new Saml2PureProvider({
  renewal: refreshThenLogin(),
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

In this order; each refusal is an `AuthProviderFailure` of kind
`saml-assertion` whose `error.facts.check` names the row, and whose
`error.facts.rule` names the rule within it (see
[Refusal messages](#refusal-messages)). Rows marked *(signed-Response only)* are not performed by
`createSignedAssertionValidator`. One exception to the order, in the
signed-Response validator: once every signature has verified (2) and the
signature covers the `Response`, `Status` (4) is read **before** the rest of
3 — a login the identity provider declined carries no `Assertion` (Keycloak
answers a passive login with `Responder` / `NoPassive` and none), so it is
refused `declined` with its status rather than "carries no direct-child
saml:Assertion". Either order refuses; nothing is accepted on `Status`.

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

A refused assertion is an `AuthProviderFailure` whose `error` is a minted
`saml-assertion` error (from `@mcp-abap-adt/auth-errors`): `error.variant` and
`error.facts.rule` name the rule, `error.facts.check` the check that rule
belongs to (fixed by the rule), and a "carries <n>" rule carries the count as
`facts.count`. Match on `rule` in code; the words are for the person reading
the log. No two rules under one `check` share words, and an element that must
appear exactly once says which way it failed — absent, or more than one.

**No document value is in the words.** A value a rule may show — the root
element's name, a duplicated `ID`, a reference URI, an unregistered
`StatusCode`, the `Issuer`, an invalid `NotBefore` / `NotOnOrAfter`, the
`Destination` — is the rule's one **diagnostic** (`error.diagnostics`, the
table's last column; `renderDiagnostics(error)` prints it, `logFields(error)`
carries it as its own field). It is admitted by its shape or dropped: a value
holding a control, format, bidirectional or line-separator character (a
newline smuggled in as `&#10;`) is dropped, not escaped, and the error is
minted without it; a longer value or `ID` is cut at 64 code points with `…`
(a root name longer than 64 characters, which a cut would misname, is
dropped). Nothing a
parser, `xml-crypto` or OpenSSL says reaches the error at all.

The rules, in the order the validators check them — except that the
signed-Response validator reads the `status` rules right after
`response-not-signed`, before counting the `Assertion` (see above); the last six are the
bearer grant's conversion of a validated payload (`Saml2BearerProvider`),
reachable only when a custom validator accepted a payload it cannot convert:

<!-- generated:refusal-table saml -->
| `check` | `rule` | Words, after `the SAML assertion was refused (<check>): ` | Diagnostic |
|---|---|---|---|
| `document` | `doctype` | `the SAMLResponse carries a DOCTYPE declaration, which is never accepted` | — |
| `document` | `not-xml` | `the SAMLResponse did not parse as XML` | — |
| `document` | `root-not-response-or-assertion` | `expected a samlp:Response or a saml:Assertion` | `rootElement` |
| `document` | `root-not-response` | `expected the document element to be a samlp:Response` | `rootElement` |
| `duplicateId` | `duplicate-id` | `the document uses an ID more than once, so which element is signed is ambiguous` | `id` |
| `signature` | `no-signature` | `the document carries no signature` | — |
| `signature` | `signature-malformed` | `the signature element is malformed` | — |
| `signature` | `signature-not-verified` | `the signature does not verify against any configured certificate` | — |
| `signature` | `no-reference` | `the signature carries no ds:Reference` | — |
| `signature` | `several-references` | `the signature carries <n> ds:Reference; exactly one is allowed` | — |
| `signature` | `reference-not-same-document` | `the signature reference is not a same-document URI` | `referenceUri` |
| `signature` | `reference-not-found` | `the signature references an element that is not in the document` | `referenceUri` |
| `signature` | `signature-not-enveloped` | `the signature is not inside the element it references, so it does not envelope it` | — |
| `signedNode` | `no-direct-assertion` | `the response carries no direct-child saml:Assertion` | — |
| `signedNode` | `several-direct-assertions` | `the response carries <n> direct-child saml:Assertion; exactly one is allowed` | — |
| `signedNode` | `response-not-signed` | `the signature does not cover the samlp:Response this validator requires` | — |
| `signedNode` | `assertion-not-signed` | `the signature does not cover the saml:Assertion this validator requires` | — |
| `signedNode` | `assertion-outside-signed` | `the document carries an Assertion or EncryptedAssertion, SAML 2.0 or 1.x, outside the one the signature covers` | — |
| `signedNode` | `assertion-inside-signature` | `the document carries an Assertion or EncryptedAssertion inside a ds:Signature, which is never accepted` | — |
| `status` | `no-status` | `the response carries no samlp:Status` | — |
| `status` | `several-status` | `the response carries <n> samlp:Status; exactly one is allowed` | — |
| `status` | `no-status-code` | `the samlp:Status carries no samlp:StatusCode` | — |
| `status` | `several-status-codes` | `the samlp:Status carries <n> samlp:StatusCode; exactly one is allowed` | — |
| `status` | `status-code-no-value` | `the samlp:StatusCode carries no Value` | — |
| `status` | `declined` | `the identity provider declined the login`, followed by ` (<StatusCode>)` when the code is one of `SAML_STATUS_CODES` | `statusCode`, when the code is not a registered one |
| `assertionId` | `no-assertion-id` | `the assertion carries no ID` | — |
| `issuer` | `no-issuer` | `the assertion carries no saml:Issuer` | — |
| `issuer` | `several-issuers` | `the assertion carries <n> saml:Issuer; exactly one is allowed` | — |
| `issuer` | `empty-issuer` | `the assertion's saml:Issuer is empty` | — |
| `issuer` | `no-expected-issuer` | `no expectedIssuer was configured, so the assertion issuer cannot be trusted` | — |
| `issuer` | `untrusted-issuer` | `the assertion was not issued by the trusted issuer` | `issuer` |
| `issuer` | `several-response-issuers` | `the response must carry at most one saml:Issuer` | — |
| `issuer` | `issuers-differ` | `the response and the assertion name different issuers` | — |
| `conditions` | `no-conditions` | `the assertion carries no saml:Conditions` | — |
| `conditions` | `several-conditions` | `the assertion carries <n> saml:Conditions; exactly one is allowed` | — |
| `notBefore` | `not-before-invalid` | `Conditions NotBefore is not a valid xsd:dateTime` | `notBefore` |
| `notBefore` | `not-yet-valid` | `the assertion is not valid yet` | — |
| `notOnOrAfter` | `no-not-on-or-after` | `Conditions carries no NotOnOrAfter, so the assertion states no lifetime` | — |
| `notOnOrAfter` | `not-on-or-after-invalid` | `Conditions NotOnOrAfter is not a valid xsd:dateTime` | `notOnOrAfter` |
| `notOnOrAfter` | `expired` | `the assertion has expired` | — |
| `audience` | `no-audience-restriction` | `the assertion restricts no audience` | — |
| `audience` | `audience-restriction-empty` | `an AudienceRestriction names no audience` | — |
| `audience` | `audience-not-us` | `an AudienceRestriction on this assertion does not name us` | — |
| `bearerConfirmation` | `no-subject` | `the assertion carries no saml:Subject` | — |
| `bearerConfirmation` | `several-subjects` | `the assertion carries <n> saml:Subject; exactly one is allowed` | — |
| `bearerConfirmation` | `no-subject-confirmation` | `the saml:Subject holds no SubjectConfirmation` | — |
| `bearerConfirmation` | `no-bearer-qualifies` | `no bearer confirmation qualifies: #1 <reason> \| #2 <reason> \| …[ \| and N more]` | — |
| `destination` | `no-destination` | `the response carries no Destination` | — |
| `destination` | `destination-not-us` | `the response is not addressed to us` | `destination` |
| `replay` | `replayed` | `this assertion has been presented before` | — |
| `document` | `payload-not-base64-xml` | `SAML bearer payload is not base64-encoded XML` | — |
| `document` | `payload-not-well-formed` | `SAML bearer payload is not well-formed XML` | — |
| `document` | `payload-not-saml` | `SAML bearer payload is neither a SAML Response nor an Assertion` | — |
| `document` | `only-encrypted-assertion` | `SAML Response carries only an EncryptedAssertion; encrypted Assertions are not supported` | — |
| `document` | `no-assertion` | `SAML Response carries no Assertion` | — |
| `document` | `several-assertions` | `SAML Response carries <n> Assertions; a bearer grant takes one` | — |
<!-- /generated:refusal-table saml -->

A `no-bearer-qualifies` refusal names each candidate's first failed sub-rule,
in document order (`facts.candidates`, each a `reason` — with `count` for
`several-confirmation-data`), joined by ` | ` — not `; `, which a count
reason contains itself. Past five candidates the rest are counted in
`facts.moreCandidates` and the words end ` | and N more`. The eleven
reasons:

<!-- generated:refusal-table saml-candidates -->
| # | `reason` | Words |
|---|---|---|
| 1 | `method-not-bearer` | `Method is not bearer` |
| 2 | `no-confirmation-data` | `carries no SubjectConfirmationData` |
| 3 | `several-confirmation-data` | `carries <n> SubjectConfirmationData; exactly one is allowed` |
| 4 | `in-response-to-unexpected` | `InResponseTo is present, but this login sent no request` |
| 5 | `in-response-to-mismatch` | `InResponseTo does not answer our request` |
| 6 | `recipient-not-acs` | `Recipient is not the ACS` |
| 7 | `no-not-on-or-after` | `SubjectConfirmationData has no NotOnOrAfter` |
| 8 | `not-on-or-after-invalid` | `SubjectConfirmationData NotOnOrAfter is not a valid xsd:dateTime` |
| 9 | `not-before-invalid` | `SubjectConfirmationData NotBefore is not a valid xsd:dateTime` |
| 10 | `not-on-or-after-passed` | `NotOnOrAfter has passed` |
| 11 | `not-before-not-arrived` | `NotBefore has not arrived` |
<!-- /generated:refusal-table saml-candidates -->

A custom `assertionValidator` may throw anything: its throw is classified
with the operation `validating-assertion` — a shipped validator's refusal it
passes on stays as it is, diagnostics included; any other value is never
handed back, nor its message. A provider configured with both
`idpInitiated: true` and `authnRequestId` throws a configuration error
(`saml-idp-initiated-with-request-id`, `fields: ['idpInitiated',
'authnRequestId']`) at construction: `SAML idpInitiated is true, but a
request ID was also configured or minted: an IdP-initiated login sends no
request` — `remove one of them`.

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

Without it, the login fails with a configuration error
(`saml-in-response-to-undeclared`) after the strategy returns and before the assertion is
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
provider refuses at construction — a configuration error
(`saml-idp-initiated-with-request-id`) — before any browser opens. A strategy that calls
`buildAuthorizationUrl` with no
`authorizationUrl` configured is refused inside the builder, before a URL — and
so a request ID — exists: a configuration error
(`saml-idp-initiated-without-authorization-url`). Use a strategy that does not call the builder, and leave
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
  createSignedResponseValidator,
  defaultReplayStore,
} from '@mcp-abap-adt/auth-providers';
import { readFailure, renderDiagnostics } from '@mcp-abap-adt/auth-errors';

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
} catch (thrown) {
  const error = readFailure(thrown, 'validating-assertion');
  if (error.kind === 'saml-assertion') {
    // error.variant === error.facts.rule, e.g. 'untrusted-issuer'
    console.error(error.reason, renderDiagnostics(error) ?? '');
  }
  throw thrown;
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
| `AuthProviderFailure`, kind `saml-assertion` | an assertion was refused. `error.facts.rule` names the rule and `error.facts.check` the row above — tell "your IdP declined" (`declined`) from "not addressed to us" (`audience-not-us`, `no-bearer-qualifies`, `destination-not-us`) without parsing the words; the one document value a rule may show is `error.diagnostics` (see [Refusal messages](#refusal-messages)). `AssertionValidationError` is gone (6.0.0) |
| `AuthProviderFailure`, kind `configuration` | configuration: `idpEntityId` missing with a shipped validator supplied as `assertionValidator` (at construction, `saml-shipped-validator-without-issuer`); `idpInitiated` with no `authorizationUrl` and a strategy that calls `buildAuthorizationUrl` (inside the builder, before any URL is produced, `saml-idp-initiated-without-authorization-url`); `idpInitiated` combined with a declared `authnRequestId` (at construction, `saml-idp-initiated-with-request-id`); `authnRequestId` missing (at login, after the strategy returns and before the assertion is read, `saml-in-response-to-undeclared`). `facts.fields` names the fields — see [Configuration errors](#configuration-errors) |
| `AuthProviderFailure`, kind `configuration`, when the validator is built (for `inBrowser`, when the provider is) | a certificate that is neither PEM nor base64 DER, or not a valid X.509 certificate (`idp-certificate-invalid`); a `clockSkewMs` that is not a finite non-negative integer (`validator-clock-skew-invalid`, the value given not echoed); an empty `idpCertificates` (`validator-no-certificates`) |

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
  linuxDefaultBrowser,
  refreshThenLogin,
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
    renewal: refreshThenLogin(),
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
    renewal: refreshThenLogin(),
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser() }),
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
    renewal: refreshThenLogin(),
    uaaUrl: 'https://...',
    clientId: '...',
    clientSecret: '...',
    authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser(), port: 4001 }),
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
  linuxDefaultBrowser,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

const provider = new AuthorizationCodeProvider({
  renewal: refreshThenLogin(),
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
  authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser() }),
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
import { ClientCredentialsProvider, refreshThenLogin } from '@mcp-abap-adt/auth-providers';

const provider = new ClientCredentialsProvider({
  renewal: refreshThenLogin(),
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
import { UaaPasscodeProvider, manualPasscodeStrategy, refreshThenLogin } from '@mcp-abap-adt/auth-providers';

const provider = new UaaPasscodeProvider({
  renewal: refreshThenLogin(),
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
spent one fails with `request-failed` — *the passcode exchange failed (HTTP
401)* — naming the status, and the OAuth `error` (`facts.oauthError`) only
when it is a registered code (UAA's `unauthorized` is not). What UAA said
(`"Invalid passcode"`) is read by nothing: the server's free text may echo the
passcode or the client secret.

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
traffic under an MCP or LSP stdio transport. The prompt's values come from
the authorization server, so it shows the verification URI only as an
`http:` / `https:` serialisation of printable ASCII and the user code only
when it is printable ASCII; without both it shows nothing and rejects, and
the login ends `interactive-login` `device-code-not-shown`. `OidcDeviceFlowProvider.toConsole(config)`
is the recipe that assembles it from `config.logger`:

```typescript
import {
  OidcDeviceFlowProvider,
  type IDeviceCodePresenter,
  refreshThenLogin,
} from '@mcp-abap-adt/auth-providers';

// The usual choice: logger or stderr.
const provider = OidcDeviceFlowProvider.toConsole({
  renewal: refreshThenLogin(),
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
  renewal: refreshThenLogin(),
  issuerUrl: 'https://idp.example.com/realms/sap',
  clientId: '...',
  presenter,
});
```

A presenter that throws makes the login fail — `interactive-login`
`device-code-not-shown`, "showing the device code failed" — so `prepare()` /
`rejected()` answer Oops with it and `getTokens()` throws it; the device code
is never part of a refusal, and the presenter's own error reaches the log only
as its `logFields` (kind and fixed words). A presenter that never settles is
bounded only by the login's signal.

#### Callback port and lifetime

**Note**: the callback port is set on the strategy (`browserCallbackStrategy({ port })`
and its OIDC/SAML siblings), not on the provider — the 1.x `redirectPort` field
is gone. The default is **61001**, was 3001. If the requested port is already in
use, the login fails with `interactive-login` `port-in-use` (*Port N is already
in use. Please specify a different port or free the port.*, `facts.port`); a
`port` that is not an integer in 0..65535 is a configuration error
(`callback-port-invalid`) before any socket is touched. `port: 0` binds an ephemeral port, which works only where the
identity provider accepts a loopback redirect on any port.

**Port lifetime**: the callback port is held for the login and nothing longer. It is bound when the login window opens and released when the login ends — by success, by the identity provider's refusal, by another failure, or by an abort — and the strategy's `authorize` settles only after every listening socket is closed. No timer is involved, and no connection is waited for: the response that ended the login has flushed before the release; at the release an idle connection is ended and unreferenced, and one still being answered — another request, its response unfinished, or a body that never completes — is destroyed, since a pending write would otherwise keep the process alive whatever `unref()` says. Every response carries `Connection: close`, so nothing pipelined is queued behind it. An error therefore always means the port is already available, and the port is released *before* the authorization code is exchanged for a token, so a slow identity provider cannot hold it either.

**No built-in timeout** (since 6.0.0): an interactive login — browser, OIDC, SAML, or a manual paste — waits until its result arrives, the identity provider refuses, or the consumer's `AbortSignal` aborts it; it then ends `interactive-login` `aborted` and the port is free. The `timeoutMs` options, `DEFAULT_LOGIN_TIMEOUT_MS` and the 30 s / 300 s defaults are gone: a consumer that passed `timeoutMs` passes `signal: AbortSignal.timeout(ms)` instead (to the strategy, or to `inBrowser` / `fromTerminal` as `{ signal }`); one that passed nothing now waits until it aborts.

**Refused requests**: a `/callback` carrying neither a code nor an error no longer ends the login, and neither does any request a listener or its protocol refuses — a callback without this login's `state`, one before the listener is armed, a paste without the form token, a `Host` the listener does not answer for. Each is answered `400` in fixed words, counted, logged at `warn` with its reason only, and the tally is reported when the login is aborted (`the browser login was aborted; 2 request(s) to the callback server were refused and ignored`) — so a browser prefetch, a stray probe or a forged callback cannot end a login the user is still completing.

**Cancellation**: pass `signal` to the strategy, or call `dispose()` on it. Both are honoured before the bind, during it, and while waiting; `dispose()` resolves only once the socket is free.

**Process termination**: the callback listener installs no `SIGTERM` / `SIGINT` / `SIGHUP` / `exit` handlers of its own. A terminating process releases its listening sockets to the operating system anyway — measured at 0-1 ms after the process disappears — and the handlers were part of the cleanup tangle removed in 1.2.0. If a client kills the process mid-login, the port comes back with the process.

**Opening a browser** is the `browser` you pass — one of [the six shipped browsers](#the-six-shipped-browsers), one fixed launch each for one platform, or [a browser of your own](#a-browser-of-your-own). **Without a display** (SSH sessions, Docker, CI/CD) pass no `browser`:

```typescript
const provider = new AuthorizationCodeProvider({
  renewal: refreshThenLogin(),
  uaaUrl, clientId, clientSecret,
  authorization: browserCallbackStrategy(),
});

const result = await provider.getTokens();
```

The authorization URL is then shown on stderr, and the listener waits for the user to complete the login. The user can open the URL on any machine; the listener binds loopback only, so a browser elsewhere reaches it through [the SSH tunnel](#the-ssh-tunnel) to the callback port — the hint printed beside the URL says how, and where to paste the code if the redirect cannot reach back. A shipped browser that fails there (no display, no such program) does the same: the URL is shown once, and the login waits.

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
  renewal: refreshThenLogin(),
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
  authorization: browserCallbackStrategy({ browser: linuxDefaultBrowser() }),
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
its persistence strategy wrote, or what a session store kept — and use it until it
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
  (`rejected()`): the provider renews through its renewal strategy, and a
  renewal that yields the seed again is refused — *the renewal returned the
  credential that was refused* (`renewal-unchanged`).
- **Until then** `getTokens()` and `authorize()` answer the seed, less the
  usual one-minute buffer; no request is made and nothing is reported to
  persistence — a cache hit is no change.
- **After** the provider renews as usual, through its renewal strategy — with
  `refreshThenLogin()`, the `refreshToken` when there is one and the grant has
  a refresh, else one login through the configured authorization strategy.
  What it obtains replaces the seed and is reported to persistence as a
  `credential` report, with its `expiresAt`. A seeded refresh token the
  renewal strategy discards is reported as `refresh-token-discarded`, with
  the credential held (`authorizationToken: ''` when only the refresh token
  was seeded).
- `ClientCredentialsProvider` takes no seed: a new token costs one request and
  no user, so it obtains one.

```typescript
const provider = new Saml2PureProvider({
  ...samlConfig,
  accessToken: stored.sessionCookies,
  expiresAt: stored.expiresAt,
  renewal: refreshThenLogin(), // SAML has no refresh: every renewal is a login
  persistence: refreshStatePersistence(
    async ({ authorizationToken, expiresAt }) =>
      save({ sessionCookies: authorizationToken, expiresAt }),
    { onWriteFailure: 'continue' },
  ),
});
```

### Token Refresh

Providers renew automatically inside `getTokens()`: while the cached token is valid it is
returned; once it expires the provider renews it through its [renewal strategy](#renewal-strategy)
— with `refreshThenLogin()`, the refresh token is used, and a login follows when there is none or
the refresh fails.

The clock is not the only judge, though. When the server refuses a token the cache still
considers valid — a 401 — ask for a new one with `refreshTokens()`. It skips the cache, renews
through the same strategy (`cause.trigger: 'explicit'`), and replaces the cache with what it
obtains:

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
  if (isAuthProviderFailure(error)) {
    const failure = readFailure(error, 'token-request');
    if (failure.kind === 'configuration') {
      // what to fix: failure.facts.case, failure.facts.fields
    }
    // the login was aborted, the IdP refused, the port was taken, ...
    console.error('Failed:', failure.kind, failure.reason);
  }
}
```

### Renewal strategy

Every token provider takes a **renewal strategy** — `renewal:
IRenewalStrategy` (`@mcp-abap-adt/interfaces-auth` 7), required, no default
(since 6.0.0). Whenever the provider needs a credential it does not hold, the
strategy decides each step: refresh, log in, or stop, and what becomes of a
refresh token that was sent. The provider takes no step the strategy did not
ask for, and asks before every step.

```typescript
import { refreshOnly, refreshThenLogin } from '@mcp-abap-adt/auth-providers';

new AuthorizationCodeProvider({ ...config, renewal: refreshThenLogin() }); // the 5.x behaviour
new AuthorizationCodeProvider({ ...config, renewal: refreshOnly() });      // never logs in
```

**Where a renewal starts.**

| Call | When | `cause.trigger` | `moment` |
|---|---|---|---|
| `getTokens()` | nothing held | `no-token` | `get-tokens` |
| `getTokens()` | the held token expired | `expired` | `get-tokens` |
| `getTokens()` | the held token is bound to another certificate than the pinned one ([A certificate-bound token](#a-certificate-bound-token-and-its-certificate)) | `bound-elsewhere`, with `lastRenewal` when an earlier renewal of that token did not make it usable | `get-tokens` |
| `prepare()` / `authorize()` | through `getTokens()`, as above | as above | `prepare` / `authorize` |
| `refreshTokens()` | always | `explicit` | `refresh-tokens` |
| `rejected()` | always | `rejected`, with the rejection's `reading` (`credential`, `not-credential`, `unknown` — [What `rejected()` answers](#what-rejected-answers)), its `status` or `rfcKey`, and for `not-credential` the neutral `refusal` | `rejected` |

Not a renewal, and never the strategy's: a valid cached token answered by
`getTokens()`; `rejected()` for a token a renewal has already replaced (Ok —
what is presented has changed); a caller joining a renewal already running
(it shares that one).

**How a renewal runs.** The provider pins its client certificate first (an
unusable or expired one refuses the renewal before the strategy is asked),
then loops:

1. it calls `next(situation)` — `{ cause, moment, canRefresh, steps }`:
   `canRefresh` is true when the grant has a refresh and a refresh token is
   held and not discarded; `steps` lists the steps this renewal already took
   that did not end it, each `failed` (with `sent` — whether the request
   reached the wire — and the minted error) or, having obtained a credential
   that is not the one wanted, `unchanged` (the refused credential again;
   `rejected` only) or `bound-elsewhere`;
2. it applies `sentRefreshToken` when the decision carries one, then runs
   the step: `refresh` sends the held refresh token, `login` runs the
   authorization strategy (or the grant's request);
3. a usable new credential ends the renewal with it; anything else is
   recorded in `steps`, and the loop goes on.

`stop` ends the renewal with the last step's error (or, for `unchanged` /
`bound-elsewhere`, `renewal-unchanged` / `token-binding`
`renewed-bound-elsewhere`); with no step taken, with the neutral refusal of a
`not-credential` rejection, else the `lastRenewal` of a `bound-elsewhere`
cause, else **`renewal-declined`** — "the renewal strategy declined to renew
the credential", `facts.trigger`. `getTokens()` / `refreshTokens()` throw
that error, and a moment answers it as its refusal. A credential a step
obtained stays committed even when the renewal then fails: it is the
server's state.

**The decision.**

```typescript
type RenewalDecision =
  | { next: 'refresh'; ifCut: 'keep' | 'discard'; sentRefreshToken?: 'keep' | 'discard' }
  | { next: 'login'; sentRefreshToken?: 'keep' | 'discard' }
  | { next: 'stop'; sentRefreshToken?: 'keep' | 'discard' };
```

- `ifCut` is required on every `refresh`: what becomes of the refresh token
  sent if every caller aborts after the request left (see
  [Cancelling a login](#cancelling-a-login)). It is decided before the
  request is sent and applied at the abort, without calling the strategy.
- `sentRefreshToken` is required on the decision that follows a refresh that
  **failed after it was sent** — the server may have spent that refresh
  token, and nothing decides that by default — and must be absent anywhere
  else. `'discard'` drops it for the provider's lifetime (reported to
  persistence as `refresh-token-discarded`); `'keep'` leaves it held, and the
  next refresh sends it.
- A `refresh` needs `canRefresh`, and may not discard the refresh token it
  would send.

An answer that breaks one of these rules, a strategy that throws, or an
answer that is neither a decision nor a native
promise of one — a foreign thenable, a promise with its own `then` (its
`then` is never called) — ends the renewal with `unknown`, operation
`renewal-strategy` ("the renewal strategy failed (unknown error)"): the step
is not taken, and the steps already taken stay applied. The call to `next` is
raced with the renewal's signal, so a strategy that never answers is ended by
the callers' abort (`interactive-login` `aborted`), never by a timer.

**What the strategy sees.** Frozen copies: the cause, the moment and the
steps, each error a minted `IAuthProviderError` — exactly what `getTokens()`
would throw. Never a token, a refresh token's value, or the message, cause or
body of anything thrown.

**`aborted(observation)`**, optional: told of each step of this provider's
renewals that ended by the callers' abort — `{ cause, moment, step, sent,
refreshToken? }`, `refreshToken` saying for a refresh that was sent whether
`ifCut` `'kept'` or `'discarded'` it. Each observation is delivered once,
from a microtask after the abort or, at the latest, before the next `next()`
call of the provider. Its answer is never awaited; a throw is logged and
ignored.

**The refresh token the provider holds.** A result's refresh token is
installed only when it is usable — non-empty and not one the provider
discarded; otherwise the refresh token held stays (a login that returns none
after `sentRefreshToken: 'keep'` leaves the old one held). A discarded
refresh token is never sent again by that provider.

**The shipped strategies.** Both are stateless and answer synchronously.

| Situation | `refreshThenLogin()` | `refreshOnly()` |
|---|---|---|
| `rejected`, reading `not-credential` | `stop` (the neutral refusal) | `stop` |
| `bound-elsewhere` with `lastRenewal`, moment not `prepare` / `rejected` | `stop` (the remembered error) | `stop` |
| no step yet, `canRefresh` | `refresh`, `ifCut: 'discard'` | `refresh`, `ifCut: 'discard'` |
| no step yet, no refresh possible | `login` | `stop` |
| last step a refresh that `failed`, sent | `login`, `sentRefreshToken: 'discard'` | `stop`, `sentRefreshToken: 'discard'` |
| last step a refresh that `failed`, not sent | `login` | `stop` |
| last step a refresh with outcome `unchanged` / `bound-elsewhere` | `stop` | `stop` |
| last step a login | `stop` | `stop` |

`refreshOnly()` suits a process with no one to log in. A provider whose grant
has no refresh — `ClientCredentialsProvider`, `Saml2PureProvider`,
`OidcTokenExchangeProvider` — can renew only by a login, so with
`refreshOnly()` every renewal of it is declined: give those
`refreshThenLogin()`.

**Writing your own.** Any object with `next(situation)`. This one keeps the
shipped rules but keeps the refresh token of a cut refresh, and counts the
aborts:

```typescript
import type { IRenewalStrategy } from '@mcp-abap-adt/interfaces-auth';

const keepOnCut: IRenewalStrategy = {
  next({ cause, moment, canRefresh, steps }) {
    const last = steps.at(-1);
    if (last === undefined) {
      // Rule 5: a new credential would be refused the same way.
      if (cause.trigger === 'rejected' && cause.reading === 'not-credential') {
        return { next: 'stop' };
      }
      if (
        cause.trigger === 'bound-elsewhere' &&
        cause.lastRenewal !== undefined &&
        moment !== 'prepare' &&
        moment !== 'rejected'
      ) {
        return { next: 'stop' };
      }
      return canRefresh ? { next: 'refresh', ifCut: 'keep' } : { next: 'login' };
    }
    if (last.step === 'refresh' && last.outcome === 'failed') {
      return last.sent ? { next: 'login', sentRefreshToken: 'discard' } : { next: 'login' };
    }
    return { next: 'stop' };
  },
  aborted({ step, sent }) {
    abortedSteps.inc({ step, sent: String(sent) });
  },
};
```

A strategy shared by several providers is told each provider's situation
separately; one that keeps state keeps it per provider. Each decision is
logged at `debug` as `[BaseTokenProvider] Renewal step` `{ trigger, moment,
next }`.

`TokenAuthProvider.from(refresher)` takes neither a renewal nor a
persistence strategy: its renewal is your refresher, and it persists nothing.

### Persistence strategy

A token provider tells a **persistence strategy** — `persistence?:
ITokenPersistence` (`@mcp-abap-adt/interfaces-auth` 7) — every change of its
credentials, so a consumer can store them. It replaces `onTokens` (since
6.0.0). Without it nothing is persisted; the provider builds none. Given, it
must be an object whose `report` is a function, or the constructor throws
`configuration` `invalid-value` naming `persistence`.

```typescript
interface ITokenPersistence {
  report(report: PersistenceReport): void | Promise<void>;
}

type PersistenceReport =
  | {
      event: 'credential';                // a refresh or a login committed a new credential
      credential: ReportedCredential;     // { authorizationToken, tokenType, authType, expiresAt? }
      refreshToken: { change: 'new'; value: string } | { change: 'none' };
      awaited: boolean;
    }
  | {
      event: 'refresh-token-discarded';   // the renewal strategy discarded the refresh token held
      credential: ReportedCredential;     // the credential still held; authorizationToken '' when none
      awaited: boolean;
    };
```

`{ change: 'none' }` means the result carried no usable refresh token: the
one held before, if any, is still held.

- **When.** One report per change, made by the commit that changed the
  credentials, in commit order: a `credential` report for every new
  credential a refresh or a login committed, a `refresh-token-discarded`
  report when the renewal strategy discarded the refresh token held
  (`sentRefreshToken: 'discard'`, or `ifCut: 'discard'` at an abort). A cache
  hit reports nothing; a late result that a newer commit made obsolete
  reports nothing; a discard of a refresh token already replaced reports
  nothing. The provider never reports the same change twice — a strategy
  that wants a failed write delivered again keeps it itself.
- **Awaited or detached.** A report is `awaited: true` when, as it starts, the
  renewal that made the commit still has a caller waiting. The provider then
  awaits `report()` (a Promises/A+ thenable is adopted like any `await`), and
  its throw or rejection is that renewal's failure — `unknown`, operation
  `persisting-tokens` ("persisting the tokens failed (unknown error)"), the
  strategy's own error never relayed — so every caller of that renewal gets
  it. The credentials stay committed in memory, no login follows, and the
  next `getTokens()` answers them from the cache. If every caller left while
  the report ran, the failure is also logged, as below. A report is
  `awaited: false` (**detached**) when no caller is waiting any more: a
  discard at an abort, a late refresh result committed after its callers
  left, a report whose callers all aborted before it started. The provider
  calls it and does not wait; its failure is logged once at `warn` —
  `[BaseTokenProvider] Persisting the tokens failed` with `logFields` — and
  reaches no call.
- **One at a time.** Reports run inside the provider's commit queue. A report
  that never settles holds that queue — every later commit of the provider
  waits — while each caller is still released by its own signal.
- **Token values.** The persistence strategy is the one collaborator that
  receives them. The report is a fresh object: changing it changes nothing
  the provider holds.

#### `refreshStatePersistence(write, { onWriteFailure, logger? })`

The shipped strategy, for a store that keeps its stored refresh token when a
write carries none: with `onWriteFailure: 'continue'` it is what `onTokens`
was in 5.x, and it also clears a refresh token the provider discarded and
delivers a failed write again.

```typescript
import { refreshStatePersistence, type PersistedTokens } from '@mcp-abap-adt/auth-providers';

const persistence = refreshStatePersistence(
  async (tokens: PersistedTokens) => {
    // tokens.refreshToken: a string — write it; null — clear the stored one;
    // undefined — leave the stored one as it is.
    await store.save(tokens);
  },
  { onWriteFailure: 'fail', logger },
);
```

`write` receives `{ authorizationToken, tokenType, authType?, expiresAt?,
refreshToken }` — `authorizationToken` `''` when no access token is held. It
keeps a logical state, `held` or `cleared`, and decides each write from it:

| Report | State before | `refreshToken` written | State after |
|---|---|---|---|
| `credential`, `new` R | any | R | `held` |
| `credential`, `none` | `held` | `undefined` — or a new refresh token whose write failed earlier (below) | `held` |
| `credential`, `none` | `cleared` | `null` | `cleared` |
| `refresh-token-discarded` | any | `null`, with the credential reported | `cleared` |

So a store's fallback to its stored refresh token never restores a discarded
one, and a discard before any credential report (a seeded provider) clears
the stored refresh token without erasing the session.

- **One write at a time, in report order.** The provider does not await a
  detached report, so reports can overlap; the strategy queues them, each
  write starting only after the previous one settled. An awaited report's
  promise settles when its own write has.
- **A failed write** is logged at `warn`, `[refreshStatePersistence] Writing
  the tokens failed` with `logFields` (to `logger`; none without one) — never
  the store's message or a token. A failed new refresh token is kept pending
  and written again, with that token, by the next report, until a write
  succeeds or a newer refresh token or a discard supersedes it; a failed
  `null` is written again by the next report through the `cleared` state.
- **`onWriteFailure` is required, with no default.** `'continue'`: `report`
  never throws — the 5.x best effort. `'fail'`: an awaited report rethrows
  the write's failure, so the call that caused it fails `persisting-tokens`;
  a detached report never throws. Either way the failed write is delivered
  again by the next report.
- Refused at construction, `configuration` `invalid-value`: `onWriteFailure`
  missing or not `'continue'` / `'fail'` (naming `onWriteFailure`), `write`
  not a function (naming `write`), both when both.

It holds the last new refresh token it could not write — it is part of your
store.

**Writing your own.** Any object with `report(report)`. One that stores
nothing but a refresh token, for a process that restarts with a seed:

```typescript
import type { ITokenPersistence } from '@mcp-abap-adt/interfaces-auth';

const refreshTokenOnly: ITokenPersistence = {
  async report(report) {
    if (report.event === 'refresh-token-discarded') return vault.delete('refresh');
    if (report.refreshToken.change === 'new') return vault.put('refresh', report.refreshToken.value);
  },
};
```

### Cancelling a login

There is no built-in bound on a login: it ends on a result, the identity provider's refusal, or
your `AbortSignal`. A renewal — the steps its [renewal strategy](#renewal-strategy) asks for — is
shared by everyone who needs a token at the same time, and each of them is a **waiter** with a signal of its own:

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
`AuthorizationRequest` carrying `signal` (since interfaces-auth 6.0.0); the shipped strategies combine it
with their own `signal` option, so either one ends the login. A replacement login waits until the aborted one's strategy has **settled** its `authorize`
— its callback port closed, its stdin reader released (a manual strategy's custom `read` gets
the same signal, and the strategy settles only once that `read` has) — before it starts its own authorization
(never `busy`, never `port-in-use`). A consumer strategy that ignores the signal never settles,
and blocks the next login until it does; one that settles before releasing its socket lets the
next login meet it. A request on the wire is never waited for: it holds nothing local.

**A refresh is never cut once sent; what becomes of its refresh token was decided before.**
Once a refresh request carrying refresh token R is sent, the server may have spent R and issued
R2, so the request runs on whatever its waiters do — they are released at once, and its answer,
when it comes, is committed if nothing newer was committed meanwhile (R2 is kept and reported
to persistence, detached), and discarded otherwise. What becomes of R is the `ifCut` of the
decision that started the refresh, applied at the abort without calling the strategy:
`'discard'` — what `refreshThenLogin()` and `refreshOnly()` say — drops R for the provider's
lifetime and reports `refresh-token-discarded` (detached), so with `refreshThenLogin()` the next
renewal logs in unless R2 arrived first; `'keep'` leaves R held, and the next refresh sends it
again. An abort **before** the request left — during OIDC discovery, say, or a
client-authentication strategy's `authenticate()` — touches no refresh token: nothing reached the server. The
strategy's `aborted()` is told which it was (`sent`, `refreshToken: 'kept' | 'discarded'`). A
refresh whose server never answers lingers until the server or the OS ends the socket; nothing
waits for it. On a rotating endpoint a cancelled refresh can therefore force one interactive
login. A discard lives in memory: a process that dies before its `refresh-token-discarded` report
reaches the store may send the stored R once after a restart.

**Commits run one at a time.** Every effect of a renewal — the tokens, the pinned certificate,
the persistence report — is applied by a commit in one queue per provider, in order, never two
at once; a late result of an aborted login changes nothing. A persistence report that never
settles therefore blocks every later commit of that provider (each waiter still releasable by
its own signal). See [Persistence strategy](#persistence-strategy).

**Your collaborators are awaited like any `await`.** What your own code answers — an
authorization strategy, a persistence strategy, a certificate loader, a refresher, a validator, a
presenter, a replay store, `cookieProvider`, an SNC locator, probe or system, a logger — is
adopted as `await` adopts it, so a native promise, Bluebird, Q or any Promises/A+ thenable works.
The one exception is the **renewal strategy**: its `next()` answers a decision or a native
promise of one, and anything else that has a `then` is refused without calling it (see
[Renewal strategy](#renewal-strategy)). A collaborator answer that never
settles is bounded only by your `AbortSignal`, through the parties above. `CertificateAuthProvider`
and `TokenAuthProvider.from` take no signal: a loader or refresher of theirs that never settles
hangs their moment, and bounding it is yours (inside the loader or refresher). Values that cross a
trust boundary — a thrown value being classified, a logon target's answer — never have a foreign
`then` called.

**No timer of the package's choosing.** Nothing here bounds a login, a token request, OIDC
discovery or the SNC registry query with a timeout of its own; the only timer is the device poll's
interval, which the server sets. A bound is your signal (`AbortSignal.timeout(ms)`) or the called
server's.

### Error Handling

An error reaches you in one of two places, and it is the same thing in both:
an `IAuthProviderError` (`@mcp-abap-adt/interfaces-auth` 7), minted by
`@mcp-abap-adt/auth-errors`.

- **A refusal.** A moment — `prepare()`, `establish()`, `authorize()`,
  `rejected()` — never throws; it answers `{ ok: false, refusal }`, and the
  refusal is the error.
- **A throw.** A constructor, a factory or a loader with a configuration
  fault, and `getTokens()` / `refreshTokens()`, throw an
  `AuthProviderFailure`: an `Error` whose `error` is the error, whose
  `message` is its `reason` (or `reason — hint`), and which has no `cause`.
  Nothing else is thrown — not a strategy's, loader's or presenter's own
  error, which is classified, and not an `AxiosError`.

**Options are read as own data.** Every exported constructor and factory
reads its options object once, as a plain snapshot of its own data
properties: an accessor is never run (a getter reads as absent), and a Proxy
or a revoked Proxy that throws reads as absent too — so a hostile options
object makes it throw only its own `configuration` failure (the required
field it then finds missing), never what the object threw. A value that is
not an object reads as empty. Collaborators in the options (a strategy, a
logger, a validator) are kept by reference and called inside a moment's
boundary. Give options as a plain object; a field defined by a getter is not
seen.

**Errors outside the moments.** A strategy, a client-authentication
strategy, a certificate loader or a presenter called **directly by you**,
outside a provider's moments and `getTokens()` / `refreshTokens()`, is not
behind that boundary: `authorize()`, `authenticate()`, `tlsMaterial()`,
`load()` or `present()` may reject with what your own collaborator threw —
a `read` callback, a loader's `material` function, a `provide` callback.
Called by a provider, the same throw is classified and nothing of it
crosses.

An error is a frozen object: `kind` (one of a closed list), `variant` (the
rule, problem or case of `saml-assertion`, `snc` and `configuration`),
`facts` (values from allowlists only — a status, a registered OAuth code, a
field name, a rule id — never free text), `reason` and `hint?` (the default
words, rendered from `kind` and `facts`), and `diagnostics?` (for the three
variant kinds only: a value that helps a person — a library path, a SAML
issuer, two URIs — admitted by its shape, never in the words). Branch on
`kind` and `facts`; show `reason` / `hint`; print `diagnostics` only where a
person reads them.

```typescript
import {
  logFields,
  readFailure,
  renderDiagnostics,
  unreachableKind,
} from '@mcp-abap-adt/auth-errors';

try {
  const provider = new ClientCredentialsProvider(config); // may throw too
  await provider.getTokens({ signal });
} catch (thrown) {
  // Never `instanceof`: readFailure reads any copy's failure, and answers
  // `unknown` for anything else — it never throws.
  const error = readFailure(thrown, 'token-request');
  logger.error('token request failed', logFields(error));
  switch (error.kind) {
    case 'configuration':
      // what to fix: error.facts.case, error.facts.fields
      break;
    case 'request-failed':
      // error.facts.status, error.facts.oauthError (a registered code only)
      break;
    case 'interactive-login':
      // error.facts.outcome: 'aborted', 'port-in-use', 'identity-provider-refused', …
      break;
    // … every other kind …
    default:
      unreachableKind(error); // compiles only when every kind is handled
  }
  console.error(error.reason, error.hint ?? '', renderDiagnostics(error) ?? '');
}
```

A plain `switch` is not checked by the compiler; use `matchKind(error,
handlers)` or a `default` that calls `unreachableKind(error)` (auth-errors,
"Exhaustiveness: two patterns"), so that a kind added by a later major stops
your build. In the `switch` form the cases before `default` see the value as
you read it; `readFailure` already normalised it.

What this package produces, by kind (the words are in the tables of this
README, generated from what the package renders):

| Kind | When |
|---|---|
| `configuration` | a configuration fault — `facts.case`, `facts.fields` ([Configuration errors](#configuration-errors)) |
| `client-certificate` | certificate material that cannot be used — `incomplete`, `unusable`, `expired` ([Refusals](#refusals)) |
| `client-authentication` | a signing key that cannot sign, a strategy's result that cannot be sent, raw Basic with a `:` in the client id ([Refusals](#refusals)) |
| `request-failed` | a token request, refresh, device authorization or poll, passcode exchange, OIDC discovery that failed — `facts.operation`, `facts.problem`, `facts.status`, `facts.oauthError`, `facts.code` |
| `tls` | a TLS failure on the allowlist — `facts.code` ([Refusals](#refusals)) |
| `interactive-login` | every end of a login that is not a result — `facts.outcome`: `aborted`, `port-in-use`, `identity-provider-refused` (with a registered `oauthError`), `busy`, `disposed`, `callback-closed`, `no-terminal`, `no-input`, `unreadable-input`, `input-abandoned`, `device-code-not-shown`, `failed` |
| `saml-assertion` | an assertion refused — `facts.rule`, `facts.check` ([Refusal messages](#refusal-messages)) |
| `snc` | SNC: no credential, the library refused or not found, the logon refused ([Passwordless RFC logon](#passwordless-rfc-logon-snc)) |
| `credential-refused`, `system-refused` | what `rejected()` read in the rejection ([What `rejected()` answers](#what-rejected-answers)); `credential-refused` `refresh-token` is a refused refresh — with `refreshThenLogin()` a login follows |
| `renewal-unchanged` | a renewal returned the credential that was refused |
| `renewal-declined` | the renewal strategy stopped before taking any step, and no other refusal explains it — `facts.trigger` ([Renewal strategy](#renewal-strategy)) |
| `token-binding` | a certificate-bound token and no matching certificate ([A certificate-bound token](#a-certificate-bound-token-and-its-certificate)) |
| `not-prepared` | `establish()` before `prepare()` (certificate, SNC) |
| `logon-target` | a logon target that broke its contract, relayed |
| `unknown` | anything else, naming only the operation and, when there are any, an integer status, a registered OAuth code and an allowlisted system code — among them `renewal-strategy` (a renewal strategy that threw or answered something unusable) and `persisting-tokens` (an awaited persistence report that failed) |

**What never reaches an error, a refusal or a log line**: an error's
`message`, `cause`, `stack` or body; a token endpoint's `error_description`
and `error_uri`, which are read by nothing, `authDebug` or not (a hostile
server can echo any secret of the request in them); a token, a secret or key
material — a log line names a token only as `<redacted, N chars>`, and a
secret only under `authDebug`, prepared (see [Debug Logging](#debug-logging)).
A line about a thrown value carries `logFields(error)` — `{ error: reason,
kind, status?, diagnostics? }` — never the value itself.

**Serialising a failure carries its diagnostics.** `JSON.stringify`,
`util.inspect` or a logger serialising an `AuthProviderFailure` includes
`error.diagnostics` — admitted values such as a library path, but more than
the words. Log `logFields(readFailure(thrown, operation))` and leave out its
`diagnostics` field when they must not be written.

#### Configuration errors

A configuration fault is thrown — by a constructor (a constructor is not one
of the four moments, so it may throw), by a strategy factory, by a loader, or
inside a login — as an `AuthProviderFailure` of kind `configuration`:
`facts.case` says which, `facts.fields` names the configuration fields
involved (names on the `CONFIG_FIELDS` allowlist only), never a value given.
For an ACS or redirect mismatch the two addresses are in `diagnostics`
(origin and path only), never in the words. A provider moment that meets one
answers it as its refusal.

A value given but unusable is `invalid-value` (interfaces-auth 7), naming the
field — "a configured value cannot be used: authorizationUrl" — never the
value: an unparseable `authorizationUrl`, a malformed `persistence`,
`refreshStatePersistence`'s `onWriteFailure` or `write`, a part of an
authorization strategy that cannot be used (a browser name where an
`IBrowser` belongs reads as `presentation`). A missing or unusable `renewal` is
`required-fields-missing` naming `renewal`. **A known wording limit:** an `SncLogonProvider` `myName`
that is not a string is still reported as `required-fields-missing` naming
the field, although a value was given.

<!-- generated:refusal-table configuration -->
| Thrown | `case` | `fields` | Reason | Hint |
|---|---|---|---|---|
| a required field or collaborator is missing: every token provider (and `inBrowser`, `fromTerminal`, `toConsole`, `SsoProviderFactory.create`) without a usable `renewal`, `ClientCredentialsProvider` and `AuthorizationCodeProvider` without `uaaUrl`, `clientId`, or `clientSecret` and no `clientAuthentication`, a SAML provider without `assertionValidator`, a shipped validator without `replayStore`; an authorization strategy without a part or the redirect it needs — `manualPasteStrategy`, `manualSamlResponseStrategy` and `externalCodeStrategy` without `redirectUri`, a redirect protocol over a transport that advertises none (`redirectUri`), `composeAuthorization` without `presentation`, `transport`, `protocol` or `endpoint`, `openInBrowser` without `browser` (`presentation`), `consumerPresentation` without `show`, `consumerAnswer` without `receive`, `consumerHandoff` without `provide`; also an `SncLogonProvider` `myName` that is not a string (a known wording limit) | `required-fields-missing` | `<fields>` | required configuration is missing: `<fields>` | check the provider configuration |
| a configured value that cannot be used: an `authorizationUrl` that does not parse (`AuthorizationCodeProvider` at construction and at login); a `persistence` that is not an object with a callable `report` (every token provider); `refreshStatePersistence` with `onWriteFailure` missing or not `'continue'` / `'fail'`, or a `write` that is not a function (each named); a part of an authorization strategy that cannot be used: an `endpoint` that URL parsing would change or that is `/` or `/submit` (`endpoint`), a `redirectUri` that is not an absolute `http(s)` URL (`redirectUri`), a `browser` without an `open` function — a browser name included (`presentation`), a part without its methods (`presentation`, `transport`, `protocol`), a `remoteHint` that is not a function (`transport`), a `read` that is not a function (`read`), an `onFailure` that is not a function (`show`), a terminal with a protocol that has no paste words (`protocol`); an authorization URL a protocol cannot read a `state` from — none, empty or repeated (`authorizationUrl`) | `invalid-value` | `<fields>` | a configured value cannot be used: `<fields>` |  |
| a token provider constructed with both | `client-secret-beside-client-authentication` | `clientSecret` | clientSecret cannot be given beside clientAuthentication | give the secret to the clientAuthentication strategy, or drop the strategy |
| a SAML provider constructed with `authorizationUrl` and no `acsUrl` | `saml-acs-required-with-authorization-url` | `acsUrl` | acsUrl is required when authorizationUrl is set: the ACS inside a pre-built SAML request cannot be read, so it must be declared | check the provider configuration |
| a SAML provider constructed with `idpInitiated` and `authnRequestId` (`fields`: both), or a login that minted or declared a request ID (`fields`: `idpInitiated`) | `saml-idp-initiated-with-request-id` | `idpInitiated`, `authnRequestId` | SAML idpInitiated is true, but a request ID was also configured or minted: an IdP-initiated login sends no request | remove one of them |
| a SAML provider constructed with a shipped validator and no `idpEntityId` | `saml-shipped-validator-without-issuer` | `idpEntityId` | the supplied assertionValidator is a shipped one, which refuses every assertion without an expected issuer: idpEntityId is missing | check the provider configuration |
| the SAML bearer exchange without `tokenUrl` or `uaaUrl` | `saml-token-endpoint-missing` | `tokenUrl`, `uaaUrl` | the SAML bearer exchange needs tokenUrl or uaaUrl | check the provider configuration |
| a strategy asks for the URL of an `idpInitiated` login without `authorizationUrl` | `saml-idp-initiated-without-authorization-url` | `idpInitiated`, `authorizationUrl` | SAML idpInitiated is true and no authorizationUrl is configured, but the authorization strategy asked for an authorization URL | configure the IdP-initiated SSO URL as authorizationUrl, or use a strategy that does not call buildAuthorizationUrl |
| the strategy listens, or listened, elsewhere than `acsUrl`; the two addresses are `diagnostics.configuredUri` / `strategyUri` | `saml-acs-mismatch` | `acsUrl` | SAML acsUrl and the address the authorization strategy used do not match | they must match |
| a SAML login with no request ID minted, declared or declared absent | `saml-in-response-to-undeclared` | `authnRequestId`, `idpInitiated` | cannot validate InResponseTo: this login did not build its own AuthnRequest | configure authnRequestId, or idpInitiated: true if the identity provider starts this login itself |
| a SAML exchange or refresh with a `clientAuthentication` and no `clientId` | `client-id-required-with-client-authentication` | `clientId` | clientId is required with a client authentication | check the provider configuration |
| a pre-built `authorizationUrl` whose `redirect_uri` the strategy did not use; the two addresses are `diagnostics.configuredUri` / `strategyUri` | `redirect-mismatch` | `authorizationUrl` | the pre-built authorizationUrl declares a redirect_uri the authorization strategy did not use | an ephemeral port cannot be used with a pre-built URL |
| an OIDC endpoint to discover and no `issuerUrl` | `oidc-discovery-needs-issuer` | `issuerUrl` | OIDC issuerUrl is required when discovery is used | check the provider configuration |
| an OIDC endpoint neither configured nor discovered (`authorizationEndpoint`, `tokenEndpoint` or `deviceAuthorizationEndpoint`) | `oidc-endpoint-missing` | `<fields>` | OIDC `<fields>` is required (configure it, or use discovery) | check the provider configuration |
| `FileCertificateMaterialLoader`: PEM and PFX paths both given | `certificate-pem-and-pfx` | `certPath`, `certPfxPath` | certificate auth: provide either PEM (certPath + certKeyPath) or certPfxPath, not both | check the provider configuration |
| `FileCertificateMaterialLoader`: neither a PFX nor a whole PEM pair | `certificate-files-missing` | `certPfxPath`, `certPath`, `certKeyPath` | certificate auth requires certPfxPath, or certPath and certKeyPath | check the provider configuration |
| `clientSecretBasic` without `encoding: 'raw' \| 'form'` (`allowed: 'basic-encoding'`) | `basic-encoding-missing` | `encoding` | clientSecretBasic needs encoding: 'raw' or 'form' | check the provider configuration |
| `SncLogonProvider` without `partnerName` | `snc-partner-name-missing` | `partnerName` | SncLogonProvider needs partnerName — the system's SNC name | check the provider configuration |
| `SncLogonProvider` with another `qop` (`allowed: 'snc-qop'`) | `snc-qop-invalid` | `qop` | SncLogonProvider: qop must be one of 1, 2, 3, 8, 9 | check the provider configuration |
| `SsoProviderFactory.create` with no provider for the protocol and flow | `unsupported-sso-flow` | — | unsupported SSO provider config: no provider for this protocol and flow | check the provider configuration |
| a shipped validator with a `clockSkewMs` that is not a non-negative integer | `validator-clock-skew-invalid` | `clockSkewMs` | clockSkewMs must be a finite non-negative integer | check the provider configuration |
| a shipped validator with no `idpCertificates` | `validator-no-certificates` | `idpCertificates` | idpCertificates must not be empty: nothing could be verified | check the provider configuration |
| a shipped validator with a certificate that is neither PEM nor base64 DER, or no certificate | `idp-certificate-invalid` | `idpCertificates` | a configured IdP certificate is not a valid X.509 certificate in PEM or base64 DER | check the provider configuration |
| `staticCodeStrategy` without a payload | `static-code-without-payload` | `payload` | staticCodeStrategy requires a payload | check the provider configuration |
| a listener `port` (or a callback strategy's) that is not an integer in 0..65535, at construction and again when it opens | `callback-port-invalid` | `port` | invalid callback server port: it must be an integer in 0..65535 | check the provider configuration |
<!-- /generated:refusal-table configuration -->

#### Relaying a refusal: `classify`

A consumer that catches an error from this package — a strategy's
`tlsMaterial()` checked eagerly, say — and reports it in its own error should
relay the words this package would refuse with, not copy them:

```typescript
import { classify } from '@mcp-abap-adt/auth-errors';
import { tlsClientCertificate } from '@mcp-abap-adt/auth-providers';

try {
  await tlsClientCertificate({ material: loader }).tlsMaterial?.();
} catch (thrown) {
  const { reason, hint } = classify(thrown, 'loading-certificate');
  throw new MyConfigError(hint ? `${reason}: ${hint}` : reason);
}
```

`classify(thrown, operation, grant?)` (auth-errors; `readFailure` is the same
for a caught value) answers the error a provider's refusal would carry for
that value: this package's own failure as it is — for a certificate that
cannot be used, its kind's words from the [Refusals](#refusals) table, hint
included — and anything else as `unknown`, naming the operation and only
allowlisted facts (an integer HTTP status, a registered OAuth code, a system
or TLS code): `loading the certificate failed (unknown error, ENOENT)`. Never
an error's message, `cause` or body. It never throws: a Proxy or a throwing
getter gets fixed words. The operation is one of the closed list
`OPERATIONS` of `@mcp-abap-adt/interfaces-auth`; `'unfamiliar-error'` answers
"an authentication error of a kind this version does not know" for anything
that is not an error of the contract.

The guarantee covers what a thrown value carries and the package's public
surface. Code running in the same process that patches built-ins (say
`Map.prototype.get`) or imports `dist/` files directly can change anything the
package computes; no library can defend against that from inside the process.

### Writing a provider of your own: `AuthProviderBase`

Every provider here extends `AuthProviderBase`, exported for a consumer that
writes its own. The base owns the four moments: each runs your `on…` body
inside auth-errors' `guard`, so whatever the body, a collaborator or a target
throws becomes a minted refusal, and no moment ever rejects. A body answers
`OK` or a refusal built with auth-errors' `authError` builders — an outcome
that is not minted is answered `unknown`. The constructor names the
`Operation` each moment's refusals carry.

```typescript
import { authError, OK } from '@mcp-abap-adt/auth-errors';
import { AuthProviderBase } from '@mcp-abap-adt/auth-providers';
import type {
  AuthOutcome,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';

class ApiKeyProvider extends AuthProviderBase {
  readonly kind = 'api-key';

  constructor(private readonly key: string) {
    super({
      prepare: 'preparing',
      establish: 'establishing',
      authorize: 'writing-authorization-header',
      rejected: 'reading-rejection',
    });
  }

  protected onPrepare(): AuthOutcome {
    return OK;
  }

  protected onEstablish(_logon: ILogonTarget): AuthOutcome {
    return OK;
  }

  protected onAuthorize(request: IRequestTarget): AuthOutcome {
    request.header('X-Api-Key', this.key); // a throwing target is Oops, not a throw
    return OK;
  }

  protected onRejected(_rejection: IAuthRejection): AuthOutcome {
    return {
      ok: false,
      refusal: authError['credential-refused']({ credential: 'token', at: 'request' }),
    };
  }
}
```

Do not override `prepare()`, `establish()`, `authorize()` or `rejected()`:
the boundary is the base's. `@mcp-abap-adt/auth-errors` ships the shape check
this package runs in `lint:check`
(`@mcp-abap-adt/auth-errors/tools/check-provider-shape.mjs`), which refuses a
provider that does not reach the base or declares one of the four.

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
  message if the login later expires. (Since 6.0.0 there is no timeout: the
  tally appears in the `aborted` words when the login is aborted.)

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
- With no refresh token available, an interactive case (`interactive_login: true` or `MCP_ABAP_ADT_INTERACTIVE=1`) waits for you to log in: open the URL it shows in a browser of your choice.
- The interactive test asks the OS for a free port rather than pinning one, so it cannot collide with a running server
- The interactive cases use `browserCallbackStrategy()` without a `browser`: no test opens a browser or starts any program it did not register (`src/__tests__/helpers/noRealBrowser.ts`); the URL is shown on stderr for the person running them

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

**The package logs only through the `ILogger` you give a provider or a
strategy** (`logger` in its config); without one it logs nothing, except the
prompts a user must see (an authorization URL, a device code), which go to
stderr — never stdout, which carries protocol traffic under an MCP or LSP
stdio transport. It reads no environment variable to decide what to log.

**`authDebug`** — an explicit option of every token provider
(`TokenProviderDebug`, in each provider's config), **off by default** and on
only for `authDebug: true` itself (`'true'` or `1` is off). It is **never read
from the environment**: `DEBUG_AUTH_PROVIDERS` and its kin do not turn it on.
It changes one thing — the line a token site writes when a request fails:

- **Without it** (the default), a failed request writes 5.4.2's safe-facts
  line at `debug`: `<operation>: the token endpoint refused the request`,
  `{ status, error?, code? }` — the integer HTTP status (`undefined` without a
  response), the OAuth `error` only when it is a registered code, an
  allowlisted TLS or system code. None for the device poll's
  `authorization_pending` / `slow_down` with status `400`, none without a
  logger, and a logger that throws is ignored. A `200` without a token writes
  one line of the same facts — at `error` for the UAA code exchange (5.4.2's
  line, verbatim), at `debug` elsewhere.
- **With it**, that line is instead `[<operation>] token endpoint said`,
  `{ status, error?, code?, sent }` (and a `200` without a token adds `sent`
  to its line). `sent` names each secret the request carried — the grant's
  (`refresh_token`, `code`, `code_verifier`, `assertion`, `passcode`,
  `password`, `device_code`, `subject_token`, `actor_token`), the configured
  `client_secret`, a strategy's `client_secret` / `client_assertion`, and a
  Basic credential as `basic` (the base64 credential) and `basic_secret` —
  each **prepared at the point of logging**: its first 4 and last 4
  characters around `<redacted, N chars>` (`abcd…wxyz <redacted, 43 chars>`),
  and the length alone below 16 characters. Never more than 8 characters of a
  secret, never the server's text: `error_description` and `error_uri` are
  read by nothing, with `authDebug` or without.

```typescript
const provider = new ClientCredentialsProvider({
  renewal: refreshThenLogin(),
  uaaUrl, clientId, clientSecret,
  logger,           // the lines go here, at `debug`
  authDebug: true,  // only while diagnosing: names prepared secrets in `sent`
});
```

What else a provider logs, at `info` / `debug`: the stages of a token exchange
(which exchange — never where, never a secret), token lengths and expiry, the
browser launch, and each renewal decision (`debug`, `[BaseTokenProvider] Renewal
step`, `{ trigger, moment, next }`). At `warn`, each with `logFields` and nothing
else: a refresh that failed (`[BaseTokenProvider] Refresh failed`); a renewal
strategy that threw or answered something unusable (`[BaseTokenProvider] Renewal
strategy refused`); a strategy's `aborted()` that threw (`[BaseTokenProvider]
Renewal strategy failed to take an aborted step`); a persistence report that
failed with no caller left to receive it (`[BaseTokenProvider] Persisting the
tokens failed`); and `refreshStatePersistence`'s failed write
(`[refreshStatePersistence] Writing the tokens failed`, to its own `logger`). **No URL in
any log line** (since 6.0.0): an endpoint is a free value — a discovered one
is the server's, a configured one yours, and it may carry a credential or a
query secret — so no line names a discovery URL, token, device or
authorization endpoint, a UAA URL, a redirect URI, a client id or any other
configured or server-supplied string; a line carries fixed words and
admitted facts only (operation, grant, status, registered code). The one
place a URL is shown is the **prompt** that sends a user to it — the
authorization URL, the device flow's verification URI — and only as an
`http:` / `https:` serialisation of printable ASCII: a URL that cannot be
shown so is named in fixed words and not shown, and no control or bidi
character reaches a prompt. `consoleDeviceCodePresenter` shows the user code
only when it is printable ASCII; with no showable URI or code it shows
nothing and the login ends `interactive-login` `device-code-not-shown`.

The test suite's own logger (`src/__tests__/helpers/testLogger.ts`) is
switched on by environment variables — this is for running the tests, not
the package:

```bash
DEBUG_AUTH_PROVIDERS=true npm test   # or DEBUG_PROVIDER, DEBUG_BROWSER_AUTH, DEBUG=true, DEBUG=auth-providers
AUTH_LOG_LEVEL=debug npm test        # debug, info, warn, error
```

**Logging guarantees**:
- **No tokens in logs**: a token the provider holds or sent is never logged,
  not even in part — a line carries only `<redacted, N chars>` (since 4.1.2;
  earlier versions logged a short refresh token whole). A secret of a request
  appears only in `sent`, only under `authDebug`, prepared as above.
- **No server text in logs**: a token endpoint's body contributes only its
  status and a registered `error` code — a protocol word, which the device
  poll reads — to an error and to the line above. Its `error_description` and
  `error_uri` reach nothing (written nowhere since 5.4.2, read by nothing
  since 6.0.0).
- **No error message in logs**: a line about a thrown value — a refresh that
  failed, a strategy (authorization, renewal or persistence), loader,
  presenter, validator, store write, browser launcher or SNC locator/probe
  that threw — carries `logFields(error)` of
  its classification: the words its refusal would carry, its `kind`, an
  integer HTTP status and, for the three variant kinds, its admitted
  diagnostics; never the value's message, `cause` or stack: a consumer's
  collaborator may throw text holding a key, a passphrase or a token.
  Diagnose a collaborator's failure where it throws, not from this package's
  log.
- **No URL and no configured value in logs**: see above; a source test
  (`logCallSources.test.ts`) fails when a log call takes a URL, an
  endpoint, a client id or an error's message, and `endpointsInLogs.test.ts`
  proves on a real socket — hostile discovery documents and configured
  endpoints, `authDebug` absent, `false` and `true` — that no line holds
  them or a control character.
- **A throwing logger changes nothing**: every log call on a failure path is
  guarded, and a logger answering a rejecting promise is handled, so the
  failure the site throws is the one you get.

## Dependencies

- `@mcp-abap-adt/interfaces-auth` (^7.5.0) - `IAuthProvider`, token provider, authorization, renewal, persistence, client-authentication and assertion-validation contracts (`ITokenProvider`, `IAuthorizationStrategy` and its parts — `IAuthorizationPresentation`, `IAnswerTransport`, `IAuthorizationProtocol`, `IBrowser` —, `IRenewalStrategy`, `ITokenPersistence`, `IClientAuthentication`, `IAssertionValidator`, `IAssertionReplayStore`), and the error contract's types and allowlists (`IAuthProviderError`, its kinds, facts and `OPERATIONS`)
- `@mcp-abap-adt/interfaces-auth-sap` (^3.3.0) - XSUAA authorization configuration (`IAuthorizationConfig`) and `ICertificateMaterialLoader`
- `@mcp-abap-adt/auth-errors` (^2.1.1) - the error contract's runtime: the builders every error is minted with, `AuthProviderFailure`, `classify` / `readFailure`, `guard`, `logFields`, shared attempts and parties
- `@mcp-abap-adt/interfaces-utils` (^1.1.0) - `ILogger`
- `@xmldom/xmldom` - XML parsing: SAML assertion validation, and taking the Assertion out of a SAMLResponse for the saml2-bearer grant
- `xml-crypto` - XML-DSig signature verification for SAML assertion validation
- `axios` - HTTP client

The callback listener is Node's own `node:http`, and every browser is started
with `node:child_process` (an argument array, never a shell): there is no
`express` and no `open` dependency since 6.0.0.

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

