# auth-providers on `IAuthProvider`: every way in, one contract

**Status:** draft for review. No plan yet.
**Goal and path:** [`../2026-09-29-auth-providers-5-goal.md`](../2026-09-29-auth-providers-5-goal.md).
**Contract:** `@mcp-abap-adt/interfaces-auth` 3.0.0 (decision 40), with
`@mcp-abap-adt/interfaces-auth-sap` 1.1.0 — both released.

## Goal

This package becomes the home of every implementation of `IAuthProvider`. Any
provider from it can be handed to the process with no check of what it is, and
every one answers all four moments:

```ts
prepare(): Promise<AuthOutcome>;                          // once per connect
establish(logon: ILogonTarget): Promise<AuthOutcome>;     // every logon
authorize(request: IRequestTarget): Promise<AuthOutcome>; // every request attempt
rejected(rejection: IAuthRejection): Promise<AuthOutcome>; // the system said no
```

`AuthOutcome` is `{ ok: true }` or `{ ok: false, refusal: { reason, hint? } }`.

## Rules every provider here follows

1. **No exception crosses the contract.** Each of the four methods catches what
   its own work throws and answers Oops. An exception out of one is a bug.
2. **A refusal carries no secret.** `reason` and `hint` never contain a token,
   a refresh token, a password, a passphrase, key material or a cookie value —
   the rule `formatToken` and `describeOAuthErrorBody` already enforce for log
   lines extends to refusals (`noSecretsInRefusals.test.ts`).
3. **Nothing to add is Ok.** A provider with nothing for a moment writes to no
   target and answers Ok.
4. **A target's Oops is the provider's to judge.** A provider with no other way
   (SNC, certificate) returns the target's Oops as its own; one that has another
   (a password is also a header) goes on.
5. **`rejected()` decides alone; retrying is the consumer's.** Ok means "I
   changed what I will present — trying again can succeed"; Oops means "it
   cannot". Whether to try again, and how many times, is entirely the
   consumer's decision. No provider retries anything itself — not a request,
   not a refresh, not a login. A provider never answers Ok without having
   changed what it will present.

## Token providers — `BaseTokenProvider` implements both contracts

`BaseTokenProvider implements IRefreshableTokenProvider, IAuthProvider`. Every
token provider — `AuthorizationCodeProvider`, `ClientCredentialsProvider`,
`OidcBrowserProvider`, `OidcDeviceFlowProvider`, `OidcPasswordProvider`,
`OidcTokenExchangeProvider`, `Saml2BearerProvider`, `Saml2PureProvider`,
`UaaPasscodeProvider` — **is** an `IAuthProvider`, with no wrapper. The token
contract is unchanged: the broker's token API and consumers that want only a
token keep calling `getTokens()` / `refreshTokens()`.

| Member | Behaviour |
|---|---|
| `kind` | the grant type, `getAuthType()` |
| `prepare()` | `getTokens()` — the cache, a refresh, or a login → Ok; failure → Oops |
| `establish()` | nothing → Ok |
| `authorize(request)` | `getTokens()` (renews on expiry, per attempt) → `applyToken(request, token)` → Ok; failure → Oops |
| `rejected()` | `refreshTokens()` — refresh token, else login → Ok; failure → Oops |

- **`applyToken(request, result)`** is a protected hook, default
  `request.header('Authorization', `Bearer ${token}`)`. `Saml2PureProvider`
  overrides it with `request.cookies(token)` — its "token" is the SAML
  session's cookies (`tokenType: 'saml'`). The provider knows its own result;
  nothing outside asks.
- **Failure → refusal.** The error classes map to a reason and a hint:

  | Thrown | `reason` | `hint` |
  |---|---|---|
  | `BrowserAuthError` | the error message | "complete the login in the browser within the timeout" |
  | `RefreshError` | the error message | "the refresh token was refused; log in again" |
  | `ValidationError` | the error message | "check the provider configuration: <missingFields>" |
  | `ServiceKeyError` / `SessionDataError` | the error message | "check the service key / session data: <missingFields>" |
  | anything else | the error message | — |

  The messages are already secret-free (`describeOAuthErrorBody`); the
  refusal test pins it.

### Where a renewed token goes — `onTokens`

Today the broker persists after it calls `getTokens()`. Under the contract a
provider obtains tokens inside `prepare()`, `authorize()` and `rejected()`,
where the broker is not the caller. So every token provider takes an optional
**`onTokens?: (result: ITokenResult) => Promise<void>`** in its config: called
after every *new* token (a login or a refresh — never a cache hit), and awaited
before the method answers. A failing `onTokens` is logged and does not fail the
authentication — the token is valid, only its persistence failed.

The broker (step 4) injects its session store through it. A consumer without a
broker omits it.

### An interactive login inside `rejected()`

When the refresh token has also expired, `rejected()` falls back to the login
flow, which may be a browser. Its time is bounded where it is today: the
provider's strategy (`DEFAULT_LOGIN_TIMEOUT_MS`, 30 s, or the configured
timeout). The process adds no deadline of its own; a timed-out login is an
Oops with the `BrowserAuthError` hint.

## Moved in from `@mcp-abap-adt/connection`

New here on the contract; `connection` 10.0.0 removes its copies (step 3).

| Provider | `prepare` | `establish` | `authorize` | `rejected` |
|---|---|---|---|---|
| `BasicAuthProvider(username, password)` | Ok | `logonParameters({ user, passwd })`; the target's Oops ignored (the header carries it over HTTP) | `header('Authorization', 'Basic …')` | Oops "the user or password was refused", hint "check the user and password" |
| `CertificateAuthProvider(loader, config)` | `loader.load(config)` → Ok / Oops | `return logon.tlsMaterial(material)` | — | Oops "the client certificate was refused", hint "check that it is mapped to a user (CERTRULE / USREXTID)" |
| `SamlAuthProvider(sessionCookies)` | Ok | — | `cookies(sessionCookies)` | Oops "the SAML session was refused or has expired", hint "obtain a new SAML session" |
| `TokenAuthProvider(source)` | Ok | — | `header('Authorization', 'Bearer …')` from the source | see below |

- **`TokenAuthProvider`** is for a token that comes from outside this package.
  Its source is one of two, and each is its own static constructor so the
  provider holds one known kind:
  - `TokenAuthProvider.fixed(token)` — `rejected()` → Oops "the token was
    refused", hint "obtain a new token";
  - `TokenAuthProvider.from(refresher: ITokenRefresher)` — `authorize` asks
    `getToken()`, `rejected()` asks `refreshToken()` → Ok / Oops.

  No function source: its only use would need a "refused twice" rule of the
  provider's own, and nothing calls it (the server passes a string or a
  refresher, `connectionFactory.ts:80, 193`).
- **`FileCertificateMaterialLoader`** (PEM pair or PFX from files) moves with
  `CertificateAuthProvider`.

## `SncLogonProvider` — passwordless RFC logon

Through an installed SNC product (typically the SAP Secure Login Client, with
a certificate from SAP Secure Login Service or Kerberos). Measured 2026-09-29
against an on-premise system (Windows, Secure Login Client 3.0.3): an SNC
logon over `RfcTransport` with no password, then discovery, reads and
LOCK/UNLOCK — all 200; each RFC conversation is its own SNC logon (~1–1.5 s).

| Member | Behaviour |
|---|---|
| `kind` | `'snc'` |
| `prepare()` | resolve the SNC library; when a product probe applies to it, run the probe → Ok / Oops |
| `establish(logon)` | `return logon.logonParameters({ snc_mode: '1', snc_partnername, snc_qop, snc_lib, snc_myname? })` — no other way, so the target's Oops (an HTTP wire) is SNC's own |
| `authorize()` | — |
| `rejected(r)` | Oops with the GSS cause and what to do (below) |

**Config:** `partnerName` (required — the system's SNC name), `qop` (one of
`'1' | '2' | '3' | '8' | '9'`, default `'9'`; anything else refused at
construction), `sncLib?`, `myName?` (sent only when set), and the strategies
`locator?`, `probes?` (default: the Secure Login Client probe; `[]` for none),
`system?`, `logger?`. A broker builds it from `IConnectionConfig`'s
`sncPartnerName`, `sncQop`, `sncLib`, `sncMyName`.

**Finding the library** (`ISncLibraryLocator`, default `DefaultSncLibraryLocator`):
- **Explicit** `sncLib` is the only candidate; unusable (missing, not a
  library, wrong architecture) → Oops naming the path and reason.
- **Automatic** candidates in order: `SNC_LIB_64` (64-bit process), `SNC_LIB`,
  the Windows registry `HKLM\Software\SAP\SecureLogin\InstallPath64`
  (`InstallPath32` for a 32-bit process) + `lib\sapcrypto.dll`, the macOS
  bundle `/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib`.
  An unusable candidate is **skipped** with its reason kept; none usable → Oops
  listing every candidate. Empty or whitespace variables count as unset.
- **Architecture** from the file header: PE `Machine`; Mach-O thin and
  universal — `FAT_MAGIC` (`0xcafebabe`, 20-byte records) and `FAT_MAGIC_64`
  (`0xcafebabf`, 32-byte records); ELF `e_machine`. The measured trap it
  exists for: the installer sets the machine-wide `SNC_LIB` to its **x86**
  library, and a 64-bit Node needs the x64 one.

**Product probe** (`ISncProductProbe { product; appliesTo(libraryPath); check() }`):
the Secure Login Client probe applies only to a library inside the client's
installation (the registry's install paths on Windows, case-insensitive; the
app bundle on macOS), and checks that `sbus.exe` (Windows) / the app (macOS)
runs. Any other SNC library — `gsskrb5.dll`, another vendor's — is not probed.
A process list that cannot be read is an Oops saying the check could not run.
It does not check that a profile is logged on: no documented interface says
so, and a missing certificate surfaces at logon.

**Explaining a refused logon** (`rejected({ at: 'logon', error })`) — the error
may be an `Error`, a string or the SDK's plain object:
- `A2200019` → reason "the SNC library has no credential to present";
  hint "log on in the Secure Login Client, to the profile used for SAP
  applications" when the Secure Login Client probe applied, otherwise "make
  sure the SNC product behind <library> is logged on";
- `SNCERR_INIT` / `gssapi library invalid/missing` → reason "the RFC SDK could
  not initialise <library> (<arch>) as its SNC library";
- anything else → reason "SNC logon refused: <message>".

**The machine seam.** Environment, file heads, the registry (`reg query …
/reg:64`) and the process list (`tasklist` / `ps`) are behind one injectable
`SncSystem`; the default is `nodeSncSystem()`. Every rule above is tested
with a fake.

The provider depends on neither `@mcp-abap-adt/sap-rfc-lite` nor
`@mcp-abap-adt/connection`: it produces logon parameters and loads nothing.

## Package

- **Dependencies:** `@mcp-abap-adt/interfaces-auth` `^3.0.0`,
  `@mcp-abap-adt/interfaces-auth-sap` `^1.1.0`. No new runtime dependency;
  `node:child_process`, `node:fs/promises`, `node:path` only.
- **Exports added:** `BasicAuthProvider`, `CertificateAuthProvider`,
  `FileCertificateMaterialLoader`, `SamlAuthProvider`, `TokenAuthProvider`,
  `SncLogonProvider` (+ `SncLogonProviderConfig`), `DefaultSncLibraryLocator`,
  `SecureLoginClientProbe`, `nodeSncSystem`, and the types `ISncLibraryLocator`,
  `ISncProductProbe`, `SncLibrary`, `SncSystem`, `SncArch`. Internal and not
  exported: the architecture reader, the `reg` / `tasklist` / `ps` parsers,
  the refusal mapping.
- **Scope in `CLAUDE.md` and the README:** "This package provides the
  credentials a process delegates to: every `IAuthProvider`, and the token
  providers behind them." It still stores nothing, orchestrates nothing and
  opens no connection.
- **`docs/passwordless-sso.md`:** SNC over RFC marked Measured and Built
  (`SncLogonProvider`); "Rejected — an RFC/SNC transport" replaced; the
  `node-rfc` note points to `@mcp-abap-adt/sap-rfc-lite`; the Secure Login
  Client's enrolment endpoints recorded (Measured, from its profile registry).
- **Version: 5.0.0** (decided 2026-09-29). The token-provider API alone would
  allow a minor, but the release says what matters: the way credentials reach a
  connection is replaced, not extended. A consumer **migrates** to it — builds
  its providers from this package and hands them to a `connection` 10.0.0
  process — rather than updating in place. The README and the CHANGELOG say so
  under "Migrating to 5.0.0":
  - credentials come from here, not from `@mcp-abap-adt/connection`
    (`BasicAuthProvider`, `CertificateAuthProvider`, `SamlAuthProvider`,
    `TokenAuthProvider`, `FileCertificateMaterialLoader` moved);
  - a token provider is handed to the process as it is — no
    `TokenAuthProvider` around it;
  - a store that persisted after `getTokens()` passes `onTokens` instead;
  - it needs `connection` 10.0.0; 9.x speaks the old `IAuthProvider`.

## Testing

| What | How |
|---|---|
| Every exported provider satisfies `IAuthProvider` and answers each of the four moments with an `AuthOutcome` | a table-driven unit test over one instance of each, against recording targets |
| No exception crosses the contract: each provider with its work made to throw answers Oops | same table, failing collaborators |
| No secret in a refusal: tokens, refresh tokens, passwords, passphrases, cookies never appear in `reason` / `hint` | `noSecretsInRefusals.test.ts`, one case per provider |
| Token providers: `prepare` → `getTokens`; `authorize` writes `Bearer` per attempt and renews on expiry; `rejected` → `refreshTokens`; `Saml2PureProvider` writes cookies | unit, stubbed login / refresh |
| `onTokens` is called after a login and after a refresh, never on a cache hit, awaited before the answer; its failure does not fail authentication | unit |
| Error class → reason / hint mapping | unit |
| `BasicAuthProvider` writes both the header and the logon parameters, and goes on when the target refuses the parameters | unit |
| `CertificateAuthProvider` returns the target's Oops; a loader failure is an Oops from `prepare` | unit |
| `TokenAuthProvider.fixed` / `.from` — `rejected()` as specified | unit |
| No provider retries: a refusal inside `prepare` / `authorize` / `rejected` is answered once, with no second login, refresh or request | unit, counting collaborators |
| SNC: library resolution (explicit fails, automatic skips; the measured x86-`SNC_LIB` / x64-registry mix; empty variables; absent registry; `FAT_MAGIC_64` accepted and rejected by architecture), the PE / Mach-O / ELF reader, the probe (scoped, case-insensitive paths, unreadable process list), QOP allowlist, the three error shapes in `rejected` | unit, fake `SncSystem` |
| SNC end to end: prepare → establish's parameters into a real RFC conversation → discovery; profile logged out → `rejected` says "log on in the Secure Login Client" | live, manual, recorded in the PR |

Each rule gets a test that goes red when the rule is removed.

## Open questions

1. ~~**Version: 4.3.0 or 5.0.0.**~~ **5.0.0** — a migration, not an update
   (see *Package*).
2. ~~**`kind` of the token providers.**~~ **The grant type**
   (`authorization_code`, `client_credentials`, …) — a log line says which way
   in ran.
3. ~~**`TokenAuthProvider.asking`.**~~ **Dropped** — `fixed(token)` and
   `from(refresher)` only.
4. ~~**Retries.**~~ **The consumer's, all of them** — see rule 5.
