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
  (`^1.0.1`) to read errors; `@mcp-abap-adt/interfaces-auth` 6.0.0 is what
  every provider here implements. Hand the providers to a
  `@mcp-abap-adt/connection` **12.0.0** process (11.x reads the old refusal),
  and pair them with `@mcp-abap-adt/auth-stores` 4.0.0 and
  `@mcp-abap-adt/auth-broker` 5.0.0: every token result now carries
  `refreshTokenDisposition`, which auth-stores 3.x refuses
  (`RefusedFieldsError` from `saveSession`).
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
  | `RefreshError` | `credential-refused` `refresh-token` — and, as before, a refused refresh falls back to one login inside the provider |
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
- **A browser that does not open is no longer an error.** A launcher that
  throws or rejects (`openUrl`, or the built-in one) gets one log line in
  fixed words and the authorization URL as a prompt, and the login **keeps
  waiting**: the callback still listens, so the URL shown — the only way to
  finish where no browser can be opened (SSH, a host without a desktop) — is
  live. The `browser-launch-failed` outcome is gone, and a launch failure
  never ends the login; code that matched it must stop. Bound the login with a
  `signal` (`AbortSignal.timeout(ms)`), or it ends on its result, the
  identity provider's refusal or your abort.
- **A login is bound to its attempt (login CSRF).** Every URL
  `AuthorizationCodeProvider` and `OidcBrowserProvider` build carries `state`
  (and, for UAA, a PKCE challenge, S256), and the shipped callback transports
  settle only a callback — a code or an `?error=` — with that `state`. **A
  consumer's `callbackServer` for `browserCallbackStrategy` /
  `oidcCallbackStrategy` must implement `expectState`** (interfaces-auth
  7.3.0), or the login is refused before anything opens (`configuration`
  `invalid-value`, `fields: ['callbackServer']`); a consumer's redirect
  strategy must check `state` itself. **The callback listens on loopback
  only**, and answers only `Host: localhost` / `127.0.0.1` / `[::1]` with its
  port, the loopback names only from a loopback peer: a browser on another
  machine reaches it through an SSH tunnel, or through `host` and
  `allowedHosts` you set — which lets every client reaching that authority
  finish the login with its own code. The UAA paste form's `/submit`
  needs the form's token. A direct `new BrowserCallbackStrategy` takes a
  required `stateGate`. See [Login CSRF: `state`, PKCE and where the callback
  listens](#login-csrf-state-pkce-and-where-the-callback-listens).
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
  on — and `performRefresh()` is `performRefresh(refreshToken, signal)`:
  send the refresh token you are given. Reading `this.refreshToken` instead
  bypasses the quarantine of a refresh token whose refresh was cut, and may
  resend a spent one. A provider of your own extends `AuthProviderBase` and
  implements `onPrepare()`, `onEstablish(logon)`, `onAuthorize(request)` and
  `onRejected(rejection)`; the base owns the four moments and runs each
  inside auth-errors' `guard`. See
  [Writing a provider of your own](#writing-a-provider-of-your-own-authproviderbase).
- **A cut refresh may cost one login.** A refresh whose callers all aborted
  after it was sent runs on, and its refresh token is never sent again by
  that provider, so the next renewal logs in.
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
  after N seconds", "did not arrive in time").

## Migrating to 5.0.0 — a migration, not an update

*History: what 5.0.0 changed. Where 6.0.0 changed it again — the
`timeoutMs` of the manual strategies, `BrowserAuthError`, the connection
version — [Migrating to 6.0.0](#migrating-to-600--the-error-contract) is what
holds.*

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
6.0.0) — `prepare()`, `establish()`, `authorize()`, `rejected()`, each answering
an `AuthOutcome` and never throwing — handed to the process as it is. An
`AuthOutcome` is `{ ok: true }` or `{ ok: false, refusal }`, the refusal an
`IAuthProviderError` minted by `@mcp-abap-adt/auth-errors`: its `kind` and
`facts` say what happened, `reason` / `hint` say it in words (see
[Error Handling](#error-handling)):

```typescript
import { AuthorizationCodeProvider } from '@mcp-abap-adt/auth-providers';

const provider = AuthorizationCodeProvider.inBrowser({
  uaaUrl: 'https://...',
  clientId: '...',
  clientSecret: '...',
});
// A connection 12.0.0 process calls prepare() on connect, authorize() per
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

- **`@mcp-abap-adt/interfaces-auth`**: the contracts it implements and is handed — `IAuthProvider`, the token provider and strategy contracts, `IClientAuthentication`, the callback server, the assertion validator and replay store, and the error contract's types and allowlists (`IAuthProviderError`, its kinds and facts)
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

`authorization` decides how an interactive login is conducted, and it is
required: a provider builds no strategy of its own (since 5.0.0). Pass one of
the shipped strategies, or call a provider's static factory — `inBrowser`,
`fromTerminal` — which composes the usual one. Every shipped strategy is a
plain function returning `IAuthorizationStrategy`, so a consumer can pass its
own instead.

| Strategy | For | What it does |
|---|---|---|
| `browserCallbackStrategy(opts)` | `AuthorizationCodeProvider` | Binds a local callback server, opens the URL, waits for `?code=` |
| `oidcCallbackStrategy(opts)` | `OidcBrowserProvider` | The same, yielding `{ code, state }` |
| `samlCallbackStrategy(opts)` | `Saml2BearerProvider`, `Saml2PureProvider` | The same, receiving a posted `SAMLResponse` |
| `manualPasteStrategy({ redirectUri, read })` | code flows | Shows the URL, reads the pasted code (stdin by default) |
| `manualSamlResponseStrategy({ redirectUri, read })` | SAML flows | Shows the URL, reads the pasted `SAMLResponse` |
| `externalCodeStrategy({ redirectUri, provide })` | either | Hands the assembled URL and the login's signal to your `provide(url, signal)`, takes back the payload |
| `staticCodeStrategy({ redirectUri, payload })` | either | You already hold the payload; the URL is never built |
| your own | any | Implement `IAuthorizationStrategy<TResult>` and pass it |

Options common to the three callback strategies:

| Option | Default | Meaning |
|---|---|---|
| `port` | `61001` (`DEFAULT_CALLBACK_PORT`) | Port to bind. `0` binds an ephemeral one — usable only where the identity provider accepts a loopback redirect on any port, never where a fixed redirect URI is registered |
| `browser` | `'none'` | `'none'` / `'headless'` print the URL; `'system'`, `'auto'`, `'chrome'`, `'edge'`, `'firefox'` open it |
| `callbackServer` | the one this package ships | Your own `CallbackServerFactory`, to reuse a server you already run |
| `openUrl` | the built-in launcher | Receives `(url, browser, redirectUri)` |
| `remoteHint` | the paste hint, only for the shipped UAA transport | Extra guidance printed in `'none'` / `'headless'` mode. The default names an SSH tunnel to the bound port, or the first of `allowedHosts` — never a guessed hostname |
| `host` | loopback (`127.0.0.1` and `::1`) | The address the transport binds (`ICallbackServerOptions.host`). A wildcard or an interface address makes it reachable from the network — name the authorities a browser will use in `allowedHosts`. **Warning:** with `allowedHosts`, every client that can reach an allowed authority gets the paste page and its form token and can settle the login with a code of its own — prefer the SSH tunnel |
| `allowedHosts` | none | Authorities (`host` or `host:port`; no port means the bound one) a browser may use besides loopback, compared in the URL parser's canonical form; a loopback authority (any spelling of `localhost`, `127.0.0.0/8`, `[::1]`, `[::ffff:127.x.y.z]`), `0.0.0.0` and `[::]` are never one. Every other `Host` is refused before anything is served. **Warning:** every client that can reach an allowed authority gets the paste page and its form token and can settle the login with a code of its own — prefer the SSH tunnel |
| `signal` | — | `AbortSignal` cancelling the login — the only bound there is (since 6.0.0 no login times out on its own): pass `AbortSignal.timeout(ms)` for a deadline |

Note the `browser` default: **`'none'`, so nothing is opened unless you ask for
it.** A launcher that fails (yours, or the built-in one) does not end the
login: it is logged once in fixed words, the URL is prompted, and the callback
keeps waiting for it. The URL is always shown, even with no logger — it falls back to `stderr`,
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
options are the same, except `callbackServer` and `stateGate` are required —
there is no default transport to fall back on when the payload type is your
own, and the strategy does not guess whether its redirect is bound by `state`.

```typescript
import { BrowserCallbackStrategy } from '@mcp-abap-adt/auth-providers';

const strategy = new BrowserCallbackStrategy<MyPayload>({
  callbackServer: withMyOwnCallbackServer, // CallbackServerFactory<MyPayload>
  // An OAuth redirect: true — the transport is opened `gated` and armed with
  // the URL's `state`. false only for a redirect bound otherwise (SAML).
  stateGate: true,
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
provider builds none, so the strategy you pass in — or the one a static
factory you called composed — lives as long as the provider, serves every
login, and is yours to dispose. `dispose()` disables a strategy for good and
ends its logins in flight (`interactive-login` `disposed`); an abort of a
login's signal ends only that login (`aborted`) and leaves the strategy usable.

**Check `state` — the redirect is yours to bind.** The URL
`buildAuthorizationUrl` returns carries a fresh `state` (and a PKCE challenge,
whose verifier the provider keeps and sends in the exchange). A strategy that
receives the redirect itself — `fromOurPortal` above, or your
`externalCodeStrategy` `provide` — must accept a code only from a redirect
whose `state` equals the one in that URL (compare in constant time), or a page
in the user's browser can hand it a code of its own (RFC 6749 §10.12). A
`callbackServer` you give `browserCallbackStrategy` or `oidcCallbackStrategy`
must implement `ICallbackServerHandle.expectState`: honour `gated: true` (refuse
every callback until armed), then settle only a callback — a code or an
`?error=` — with the armed `state`, answering every other request `400` and
waiting on; `expectState(null)` declares a URL without `state`. A transport
without `expectState` is refused before anything opens (`configuration`
`invalid-value`, `fields: ['callbackServer']`).

**End on the request's signal.** Every `AuthorizationRequest` carries
`signal`, aborted once no caller needs the login any more (see
[Cancelling a login](#cancelling-a-login)). Your strategy must stop waiting
and release what it holds when it aborts — `fromOurPortal` above would pass
`request.signal` to `ourPortal.login`. One that ignores it never settles, and
the next login waits for it.

#### Manual paste over a callback server

With `browserCallbackStrategy` (the UAA transport), login can complete through
either of **two** channels — whichever finishes first wins:

1. **Automatic callback** — `GET /callback?code=...` on the bound redirect URI.
   Works when the browser is on the same machine as the process.
2. **Paste form** — open the form on `/` and paste the code (or the whole
   redirected URL). Works when the browser is on a *different* machine: the
   transport listens on loopback only, so reach it through an SSH tunnel
   (`ssh -L 61001:localhost:61001 <this machine>`, then
   `http://localhost:61001/` in that browser), or set `host` and
   `allowedHosts` to the address and names that browser will use. In
   `'none'` / `'headless'` mode the strategy prints the way — the tunnel, or
   the first of your `allowedHosts` — never a hostname it guessed. The form
   carries a token minted for this login; `/submit` settles only with it, and
   a pasted redirected URL only with this login's `state`.

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
the next one, which waits for it — until it returns.

The `redirectUri` you give it must be the one the identity provider will
redirect to; it is also the one sent to the token endpoint. It defaults to
`http://localhost:61001/callback`.

Both the paste form and `manualPasteStrategy` accept a bare code or a full
redirected URL. A **bare code** is an input with none of `?`, `&`, `=`, `/`
or `#`: it carries no `state` and is taken — the user typed it. Anything else
is read as a redirected URL (parsed with `URL`): it must carry the `state` of
the URL this login showed, and its code is taken from the query alone, never
from a fragment — `manualPasteStrategy` asks again on a mismatch, the paste
form answers `400`. So `…/callback&code=X` is not a code that skips the
check. (For a URL without `state` — one you configured — the 5.x leniency
stays: `code=...` and the like are read too.)

#### Login CSRF: `state`, PKCE and where the callback listens

A page in the user's browser can call the local callback with a code of its
own while a login waits, and the user ends up logged in as someone else
(RFC 6749 §10.12; RFC 9700 §4.7). Since 6.0.0:

- **The provider binds the URL it builds.** `AuthorizationCodeProvider` and
  `OidcBrowserProvider` put a fresh `state` (32 random bytes, base64url) in
  every authorization URL they build, and a PKCE pair (S256) — new for UAA in
  6.0.0, as OIDC already had; the verifier of the last URL built is sent in
  the exchange. Neither is logged.
- **What you bring stays yours.** A configured `authorizationUrl` is used
  unchanged — no `state`, no challenge, no `code_verifier` — and a code from
  `staticCodeStrategy`, or from any strategy that never built the URL, is
  exchanged without a `code_verifier`. Binding those is your job. To get
  `state` and PKCE with your own receiver, let the provider build the URL
  (`externalCodeStrategy` gets it, `state` included).
- **The callback is closed until the URL exists.** `browserCallbackStrategy`
  and `oidcCallbackStrategy` open their transport `gated`: from the bind on,
  every callback is answered `400`, counted and ignored. Once the URL is
  built, the strategy arms it with the URL's `state` (`expectState`) — before
  the browser is opened — and from then on only a callback with that `state`,
  a code or an `?error=`, settles the login; anything else is answered `400`,
  counted, and the login keeps waiting. `samlCallbackStrategy` needs no gate:
  a SAML response is bound by `InResponseTo` and the assertion validator.
- **Loopback only, unless you say otherwise.** The shipped transports bind
  `127.0.0.1` and `::1` (through 5.4.2 they bound every interface), and refuse
  — before any page, form token or callback handling — a request whose `Host`
  is not a loopback authority with the bound port, so a DNS-rebound name
  reads and settles nothing. Every `Host`, and every `allowedHosts` entry, is
  read through the WHATWG URL host parser and compared in that canonical
  form, one trailing dot dropped. **Loopback** is then `localhost`, any IPv4
  address in `127.0.0.0/8`, `[::1]` or `[::ffff:127.x.y.z]` — in whatever
  spelling the parser reads as one (`localhost.`, `127.1`, `0x7f.1`,
  `[0:0:0:0:0:0:0:1]`, `[::ffff:7f00:1]`, …). A loopback authority counts
  only from a loopback peer (`127.0.0.0/8`, `::1`, `::ffff:127.x.y.z`): the
  header is the client's to choose, so a machine on the network sending
  `Host: localhost` is refused too — and listing a loopback authority in
  `allowedHosts` changes nothing: it is never an allowed one. `0.0.0.0` and
  `[::]` are never an authority, and an entry that is not exactly an
  authority (userinfo, a path, an empty or out-of-range port, a host the
  parser refuses) matches nothing. When the
  port is not free on `::1` — a fixed one, or the one the OS gave
  `127.0.0.1` for `port: 0` — the login fails `port-in-use`: the redirect
  URI says `localhost`, which resolves to `::1` first, so staying on
  `127.0.0.1` alone would hand whoever holds `[::1]:<port>` the code and the
  `state`. Retrying is yours. An SSH tunnel arrives on loopback and works as
  it is. To serve another machine directly, set both:

  ```typescript
  browserCallbackStrategy({
    host: '0.0.0.0',                          // the bind address
    allowedHosts: ['buildhost.example:61001'], // what that browser sends as Host
  });
  ```

  The bind address is not an authority — a browser never sends
  `Host: 0.0.0.0` — and a loopback authority from a network peer is refused, so a
  wildcard bind without `allowedHosts` answers loopback peers only.

  > **Warning — `allowedHosts` opens the login to everyone who can reach
  > it.** Every client that can reach an allowed authority gets the paste
  > page and its form token, and can settle the login with an authorization
  > code of its own: the user then works as whoever that code belongs to.
  > The form token stops a page in a browser, not a client on the network.
  > Prefer the SSH tunnel (`ssh -L 61001:localhost:61001 <this machine>`),
  > which needs no `host` and no `allowedHosts`; use `allowedHosts` only on a
  > network where every machine that can reach the port is trusted.

> The `extractCode(input)` helper behind that leniency is internal; it is not
> part of the package's exports, contrary to what the 1.1.0–1.2.0 README said.

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
`client-certificate` failure when the material is unusable or expired. `establish()` reads such a held
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
refuses: a configuration error
(`saml-idp-initiated-without-authorization-url`) thrown before any URL is
produced, so before a browser opens. (3.0's advice —
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
declare a real `acsUrl` and leave `redirectUri` off, the login fails before
anything is opened with a configuration error, `saml-acs-mismatch` — *SAML
acsUrl and the address the authorization strategy used do not match* — whose
two addresses are `diagnostics.configuredUri` and `diagnostics.strategyUri`
(`renderDiagnostics(error)` prints them), not words. Declare neither and the default is used for both, which is
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

**Port lifetime**: the callback port is held for the login and nothing longer. It is bound when the login window opens and released when the login ends — by success, by the identity provider's refusal, by another failure, or by an abort — and the returned promise settles only after the listening socket is closed. No timer is involved: a connection still open is ended gracefully and let go, never waited for. An error therefore always means the port is already available, and the port is released *before* the authorization code is exchanged for a token, so a slow identity provider cannot hold it either.

**No built-in timeout** (since 6.0.0): an interactive login — browser, OIDC, SAML, or a manual paste — waits until its result arrives, the identity provider refuses, or the consumer's `AbortSignal` aborts it; it then ends `interactive-login` `aborted` and the port is free. The `timeoutMs` options, `DEFAULT_LOGIN_TIMEOUT_MS` and the 30 s / 300 s defaults are gone: a consumer that passed `timeoutMs` passes `signal: AbortSignal.timeout(ms)` instead (to the strategy, or to `inBrowser` / `fromTerminal` as `{ signal }`); one that passed nothing now waits until it aborts.

**Refused requests**: a `/callback` carrying neither a code nor an error no longer ends the login, and neither does any request the transport refuses — a callback without this login's `state`, one before the gate is armed, a paste without the form token, a `Host` the transport does not answer for. Each is answered `400`, counted, and the tally is reported when the login is aborted (`the browser login was aborted; 2 request(s) to the callback server were refused and ignored`) — so a browser prefetch, a stray probe or a forged callback cannot end a login the user is still completing.

**Cancellation**: pass `signal` to the strategy, or call `dispose()` on it. Both are honoured before the bind, during it, and while waiting; `dispose()` resolves only once the socket is free.

**Process termination**: the callback server no longer installs its own `SIGTERM` / `SIGINT` / `SIGHUP` / `exit` handlers. A terminating process releases its listening sockets to the operating system anyway — measured at 0-1 ms after the process disappears — and the handlers were part of the cleanup tangle removed in 1.2.0. If a client kills the process mid-login, the port comes back with the process.

**Cross-Platform Browser Support**: The browser authentication works across Linux, macOS, and Windows:
- **Linux**: Automatically sets `DISPLAY=:0` if neither `DISPLAY` nor `WAYLAND_DISPLAY` environment variables are set. Supports multiple browser executable names (`google-chrome`, `google-chrome-stable`, `chromium`, `chromium-browser` for Chrome; `firefox`, `firefox-esr` for Firefox).
- **Windows**: the default browser through `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler <url>` (absolute paths, never a program found in the current directory); a named one through PowerShell's `Start-Process`, which reads the URL from an environment variable. Never `cmd`, which parses `&`, `|`, `^` and `%` whatever the quoting. Measured 2026-10-07 (Windows 11 x64): the default browser through `rundll32`, Chrome and Edge through `Start-Process`, each delivered the URL's path and query (with `&` and a `%20`) unchanged, and no command interpreter was started by the launcher.
- **macOS**: Uses native `open` / `open -a <app>`.
- **No shell, anywhere** (since 6.0.0): only an `http:` / `https:` URL is opened, as its WHATWG serialisation; one whose serialisation still holds a space, a quote, `<`, `>`, `^`, `|`, a backslash or a control character, or whose host is not a valid host name or address, is not opened at all (nothing is repaired). Every launcher is started with an argument array, the URL one argument of it. Through 5.4.2 the fallback without the `open` package handed the URL to a shell inside double quotes, so a `$(…)` or a backtick in it — from an OIDC provider's discovery document, say — ran as a command.

**Headless Mode (SSH/Remote)**: For environments without a display (SSH sessions, Docker, CI/CD), leave `browser` at its default or set it explicitly:

```typescript
const provider = new AuthorizationCodeProvider({
  uaaUrl, clientId, clientSecret,
  authorization: browserCallbackStrategy({ browser: 'headless' }),
});

const result = await provider.getTokens();
```

In headless mode the authorization URL is shown — to the logger if there is one, to stderr otherwise — and the server waits for the user to complete authentication manually. The user can open the URL on any machine; the callback listens on loopback only (since 6.0.0), so a browser elsewhere reaches it through an SSH tunnel to the callback port, or through the `host` and `allowedHosts` you configure — the shipped UAA transport prints which, with where to paste the code if the redirect cannot reach back.

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
`AuthorizationRequest` carrying `signal` (interfaces-auth 6.0.0); the shipped strategies combine it
with their own `signal` option, so either one ends the login. A replacement login waits until the aborted one's strategy has **settled** its `authorize`
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

**Your collaborators are awaited like any `await`.** What your own code answers — a strategy,
`onTokens`, a certificate loader, a refresher, a validator, a presenter, a replay store,
`cookieProvider`, an SNC locator, probe or system, a logger — is adopted as `await` adopts it, so
a native promise, Bluebird, Q or any Promises/A+ thenable works. A collaborator answer that never
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
an `IAuthProviderError` (`@mcp-abap-adt/interfaces-auth` 6.0.0), minted by
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
| `credential-refused`, `system-refused` | what `rejected()` read in the rejection ([What `rejected()` answers](#what-rejected-answers)); `credential-refused` `refresh-token` is a refused refresh, which falls back to one login |
| `renewal-unchanged` | a renewal returned the credential that was refused |
| `token-binding` | a certificate-bound token and no matching certificate ([A certificate-bound token](#a-certificate-bound-token-and-its-certificate)) |
| `not-prepared` | `establish()` before `prepare()` (certificate, SNC) |
| `logon-target` | a logon target that broke its contract, relayed |
| `unknown` | anything else, naming only the operation and, when there are any, an integer status, a registered OAuth code and an allowlisted system code |

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

An unparseable `authorizationUrl` is `invalid-value` (interfaces-auth 7),
naming the field — "a configured value cannot be used: authorizationUrl" —
never the value. **A known wording limit:** an `SncLogonProvider` `myName`
that is not a string is still reported as `required-fields-missing` naming
the field, although a value was given.

<!-- generated:refusal-table configuration -->
| Thrown | `case` | `fields` | Reason | Hint |
|---|---|---|---|---|
| a required field or collaborator is missing (`ClientCredentialsProvider`, `AuthorizationCodeProvider`, a SAML provider without `assertionValidator`) | `required-fields-missing` | `<fields>` | required configuration is missing: `<fields>` | check the provider configuration |
| an `authorizationUrl` that does not parse (`AuthorizationCodeProvider`, at construction and at login) | `invalid-value` | `authorizationUrl` | a configured value cannot be used: authorizationUrl |  |
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
| a callback server port that is not an integer in 0..65535 | `callback-port-invalid` | `port` | invalid callback server port: it must be an integer in 0..65535 | check the provider configuration |
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
  uaaUrl, clientId, clientSecret,
  logger,           // the lines go here, at `debug`
  authDebug: true,  // only while diagnosing: names prepared secrets in `sent`
});
```

What else a provider logs, at `info` / `debug`: the stages of a token exchange
(which exchange — never where, never a secret), token lengths and expiry, the
browser launch, a refresh that failed and the login that follows. **No URL in
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
  failed, a strategy, loader, presenter, validator, `onTokens`, browser
  launcher or SNC locator/probe that threw — carries `logFields(error)` of
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

- `@mcp-abap-adt/interfaces-auth` (^6.0.0) - `IAuthProvider`, token provider, authorization, client-authentication and assertion-validation contracts (`ITokenProvider`, `IAuthorizationStrategy`, `IClientAuthentication`, `CallbackServerFactory`, `IAssertionValidator`, `IAssertionReplayStore`), and the error contract's types and allowlists (`IAuthProviderError`, its kinds, facts and `OPERATIONS`)
- `@mcp-abap-adt/interfaces-auth-sap` (^3.2.0) - XSUAA authorization configuration (`IAuthorizationConfig`) and `ICertificateMaterialLoader`
- `@mcp-abap-adt/auth-errors` (^1.0.1) - the error contract's runtime: the builders every error is minted with, `AuthProviderFailure`, `classify` / `readFailure`, `guard`, `logFields`, shared attempts and parties
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

