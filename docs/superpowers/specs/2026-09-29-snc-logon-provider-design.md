# SNC logon provider: passwordless RFC logon, injected into the connector

**Status:** draft for review. No plan yet.
**Repositories touched:** `mcp-abap-adt-interfaces` (`interfaces-auth-sap`),
this one, `mcp-abap-adt-auth-broker` (and its stores),
`mcp-abap-connection`, `mcp-abap-adt`.

## Goal

`mcp-abap-adt` logs on to an on-premise ABAP system **without a password**, the
way SAP GUI and Eclipse ADT do: SNC over RFC, through the SNC library of an SNC
product already installed and logged on — typically the SAP Secure Login
Client, with an X.509 certificate from SAP Secure Login Service (or Kerberos).

Success: with no `SAP_USERNAME` / `SAP_PASSWORD`, `SAP_AUTH_TYPE=snc` and
`SAP_CONNECTION_TYPE=rfc`, the server connects, `/sap/bc/adt/discovery`
answers, and the session belongs to the user the certificate maps to.

Out of scope: X.509 over HTTPS (mTLS) and SPNego — see
[passwordless-sso.md](../../passwordless-sso.md); cloud systems; shipping or
downloading any SAP software.

## What is already proven

Measured 2026-09-29 against an S/4HANA on-premise system (release 753 kernel,
Windows, Secure Login Client 3.0.3, `@mcp-abap-adt/connection` 9.4.2,
`@mcp-abap-adt/sap-rfc-lite` 0.2.1), with a hand-built RFC conversation
factory and a credential contributing nothing:

| Step | Result |
|---|---|
| `connect()` — stateful conversation, SNC logon | 938 ms |
| first call on the second conversation — SNC logon | 200, 2033 ms |
| `discovery`, quickSearch, class source read | 200, 200, 200 |
| LOCK / UNLOCK | 200 / 200 |

- `sap-rfc-lite` passes `snc_*` keys to `RfcOpenConnection` unchanged.
- Every conversation `RfcTransport` opens is its own SNC logon; the logon costs
  roughly 1–1.5 s.
- Without a certificate (profile not logged on) the logon fails in
  `gss_init_sec_context` with `A2200019: Operation aborted by user or
  application` — the library cannot show a prompt from a console process.
- Without `snc_lib` the SDK does not find the library (SAP GUI does; the SDK is
  a separate process): `SNCERR_INIT … gssapi library invalid/missing`.
- The Secure Login Client installer sets the machine-wide `SNC_LIB` to the
  **x86** `sapcrypto.dll` (for 32-bit SAP GUI) and `SNC_LIB_64` to the x64 one.
  A 64-bit Node needs the x64 one.

This supersedes the "Rejected — an RFC/SNC transport" option in
`passwordless-sso.md`: `node-rfc` has a maintained replacement
(`sap-rfc-lite`), and the part that is a *credential* — what replaces
`user`/`passwd` — is separable from the transport, which stays in
`@mcp-abap-adt/connection`.

## Design

**The credential is built here, handed out by the broker and injected into the
connector**, the way `CertificateAuthProvider` is injected today: the same
object goes to the connector (whose `connect()` calls `prepare()`) and, as a
thunk, to the wire, which reads it when it opens a conversation.

```ts
const credential = await broker.getCredential(destination); // a SncLogonProvider
new AdtOnPremConnector(
  config,
  credential,
  new RfcTransport(rfcConversationFrom(config, () => credential.rfcLogonParams()), logger),
  logger,
);
```

### 1. Contract — `interfaces-auth-sap` (minor)

SNC and RFC are SAP's, so the contract goes here, not in `interfaces-auth`.

```ts
/** A credential that logs on an RFC conversation instead of user/passwd. */
export interface IRfcLogonCredential {
  /** RFC logon parameters replacing `user`/`passwd`. Read on every conversation open. */
  rfcLogonParams(): Record<string, string>;
  /**
   * A message naming the cause and the fix, for an RFC open that failed —
   * `undefined` when this credential does not recognise the failure.
   */
  explainLogonFailure?(error: unknown): string | undefined;
}
export function isRfcLogonCredential(c: unknown): c is IRfcLogonCredential;
```

- `SapAuthType` gains `'snc'`.
- `ISapConfig` gains `sncPartnerName?`, `sncQop?`, `sncLib?`, `sncMyName?`.

A separate interface rather than a field on `IAuthProvider`, as
`IRenewableCredential` is: most credentials have no RFC logon, and
`transportMaterial()` is TLS-shaped.

### 2. Provider — this package

`SncLogonProvider implements IAuthProvider, IRfcLogonCredential`, in
`src/providers/SncLogonProvider.ts`, exported from `src/index.ts`.

| Member | Behaviour |
|---|---|
| `kind` | `'snc'` |
| `prepare()` | resolves `snc_lib` (below) and checks the SNC product is running; throws a `ValidationError` naming what is missing. Once per `connect()`. |
| `authorizationHeader()` | `null` — the RFC logon authenticates |
| `cookies()` | `null` |
| `transportMaterial()` | `{}` |
| `rfcLogonParams()` | `{ snc_mode: '1', snc_partnername, snc_qop, snc_lib, snc_myname? }`; throws if called before `prepare()` |
| `explainLogonFailure(e)` | `A2200019` → "the SNC product has no credential — log on in the Secure Login Client"; `SNCERR_INIT` / `gssapi library invalid/missing` → "`snc_lib` is not a loadable GSS library for this process (<path>, <arch>)"; otherwise `undefined` |

**Resolving `snc_lib`** — the first that applies wins, and the result must
exist and match the process's architecture:

1. the `sncLib` option;
2. `SNC_LIB_64` when `process.arch` is 64-bit, then `SNC_LIB`;
3. Windows: `HKLM\Software\SAP\SecureLogin\InstallPath64` (x64 process) or
   `InstallPath32` + `lib\sapcrypto.dll`;
4. macOS: `/Applications/Secure Login Client.app/Contents/MacOS/lib/libsapcrypto.dylib`.

On Windows the architecture is read from the DLL's PE header (the `Machine`
field), so the x86 library the installer puts in `SNC_LIB` is refused with a
message naming `SNC_LIB_64` instead of failing later inside the SDK.

**Everything pluggable is a strategy**, per this package's rule:

- `ISncLibraryLocator` — `locate(): Promise<{ path: string; arch: string }>`;
  default as above.
- `ISncProductProbe` — `check(): Promise<void>`, throws when the product is
  not usable; default: on Windows, `sbus.exe` among running processes; on
  macOS, the Secure Login Client process. It does **not** check that a profile
  is logged on — no documented API says so; that failure is caught at logon by
  `explainLogonFailure`.

The provider never logs the certificate, and there is no secret to log: the
parameters are names and paths.

### 3. Connection — `@mcp-abap-adt/connection` (minor)

Generic; the word SNC does not appear.

- `rfcConversationFrom(config, logon?: () => Record<string, string>)`. With
  `logon`, each conversation's params are `{ ashost, sysnr, client, lang,
  ...logon() }`, read at open, and `rfcParamsFrom` no longer requires
  `username`/`password`. Without it, unchanged.
- `RfcConnectionParams` gains an index signature for extra logon keys.
- An RFC open that fails is passed to the credential's
  `explainLogonFailure`, when the connector's credential is an
  `IRfcLogonCredential`, and its message leads the error.
  *Where* this happens — the connector hands the explainer to the transport
  through `IAdtEstablishContext`, or `rfcConversationFrom` takes it beside
  `logon` — is decided in the plan; the base class must not ask what kind of
  transport it holds.

### 4. Server — `mcp-abap-adt`

- For a destination whose auth type is `snc`, the credential comes from the
  broker (see *Through `auth-broker`*); the server builds no provider and reads
  no SNC setting.
- `snc` with `connectionType: 'http'` is refused with a message saying SNC is
  RFC-only.
- The RFC branch passes `() => credential.rfcLogonParams()` when the credential
  is an `IRfcLogonCredential`, as the HTTP branch passes
  `() => credential.transportMaterial()`.
- How a destination's SNC settings get into the store — env for the default
  destination, as `SAP_SNC_PARTNERNAME` / `SAP_SNC_QOP` / `SAP_SNC_LIB` /
  `SAP_SNC_MYNAME` — follows whatever the server does for its other settings
  today.

### Through `auth-broker`

The broker is what spares the server from knowing where a destination's
settings and secrets live and how they reach the authenticator: it pairs a
provider with the stores. SNC goes through it like every other way in — the
server asks the broker for a destination's credential and injects what it gets
into the connector; it never reads `SAP_SNC_*` itself.

Today the broker cannot carry this: it demands an `authorizationToken` and
persists only jwt or SAML cookies (`AuthBroker.ts:187, 301-307`), and hands
back a string. So the broker gains a second kind of result — **an injectable
credential** — beside the token:

- **Stores:** a destination's SNC settings (`sncPartnerName`, `sncQop`,
  `sncLib`, `sncMyName`) are read from the auth-config store the destination
  already has. They are names and paths, not secrets; nothing is persisted
  after a logon, since the SNC product owns the certificate and its lifetime.
- **Provider factory:** for a destination whose auth type is `snc`, the
  broker's `TokenProviderFactory` counterpart builds a `SncLogonProvider` from
  those settings.
- **Result:** the broker returns the provider as an `IAuthProvider` (here an
  `IRfcLogonCredential` too), e.g. `getCredential(destination)`. Nothing to
  refresh: `prepare()` runs at every `connect()`, and the SNC product renews
  the certificate.

The broker API's exact shape — a new method, or a result union on an existing
one — is decided in the broker's own PR, against its current code. The server
side of it is fixed: one call per destination, and the result goes straight
into the connector.

## This package's scope

Today this package "ONLY implements `ITokenProvider`", and every
`IAuthProvider` lives in `@mcp-abap-adt/connection`. `SncLogonProvider` is the
first `IAuthProvider` here. `CLAUDE.md` ("Package responsibilities") and the
README change with it: this package provides credentials — token providers
and, now, an RFC logon credential — and still stores nothing, orchestrates
nothing and opens no connection. `passwordless-sso.md` records the measurement
and replaces "Rejected" with this design.

The package gains no dependency on `sap-rfc-lite` or `@mcp-abap-adt/connection`:
it only produces parameters.

## Testing

| What | How | Where |
|---|---|---|
| `snc_lib` resolution order, each source; missing file; wrong architecture refused naming `SNC_LIB_64` | unit, with a fake file system, environment and registry reader behind the locator | here, CI |
| PE `Machine` reading | unit, on committed 64-byte PE header fixtures (x86, x64, not a PE) | here, CI |
| `prepare()` fails when the product is not running | unit, fake probe | here, CI |
| `rfcLogonParams()` before `prepare()` throws; after, no `user`/`passwd` key | unit | here, CI |
| `explainLogonFailure` for `A2200019`, `SNCERR_INIT`, unknown | unit, on the error strings measured above | here, CI |
| `logon` thunk replaces `user`/`passwd` on **every** conversation (stateful, shared, own) and is read at open | unit, recording fake client | connection, CI |
| without `logon`, behaviour unchanged (username/password still required) | unit | connection, CI |
| a destination with auth type `snc` yields a `SncLogonProvider` built from the store's settings; token destinations unchanged | unit, in-memory stores | broker, CI |
| SNC end to end | live, manual, on a machine with the Secure Login Client logged on; results recorded in the PR | server |

Each rule gets a test that goes red when the rule is removed.

## Order

1. `interfaces-auth-sap`: contract, `'snc'`, `snc*` fields — release.
2. This package: `SncLogonProvider`, strategies, docs — release.
3. `connection`: `logon` thunk, failure explanation — release.
4. `auth-broker` (and stores): SNC settings from the auth-config store, the
   credential result — release.
5. `mcp-abap-adt`: credential from the broker, routing — live check.

Steps 3 and 4 are independent of each other.

One PR per repository, each merged before the next opens.

## Open questions

1. Can the Secure Login Client be asked whether a profile is logged on, so
   `prepare()` fails before the first logon rather than at it?
2. How long does an SLS certificate live, and does a conversation opened after
   it expired — while the stateful one stays up — surface as `A2200019` too?
3. Does the x86/x64 check need an equivalent on macOS (universal binaries)?
4. Should `snc_qop` default to 9 (maximum available) or 8, and is `snc_myname`
   ever needed with SLS certificates?
5. The server currently calls the broker's 2.x API (`brokerFactory.ts`, cast
   `as any`) against broker 3.x. Does step 5 first need the server moved to
   the 3.x API, or is that a separate PR ahead of it?
