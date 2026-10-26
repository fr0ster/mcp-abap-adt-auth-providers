# Architecture

How `@mcp-abap-adt/auth-providers` is built: what it is for, its parts, the
lines it does not cross, the principles every part follows, and the decisions
behind them. The README is the reference for using the package; this document
is the map for changing it.

## What the package is

Every credential a process can delegate to when it talks to an SAP ABAP system
is an `IAuthProvider` (from `@mcp-abap-adt/interfaces-auth`). The process hands
any provider from this package the same four moments, with no check of what the
provider is:

```ts
prepare(): Promise<AuthOutcome>;                          // once per connect
establish(logon: ILogonTarget): Promise<AuthOutcome>;      // every logon
authorize(request: IRequestTarget): Promise<AuthOutcome>;  // every request attempt
rejected(rejection: IAuthRejection): Promise<AuthOutcome>; // the system said no
```

An outcome is `{ ok: true }` or `{ ok: false, refusal }`. A refusal is an
`IAuthProviderError` minted by `@mcp-abap-adt/auth-errors`: a closed `kind`,
allowlisted `facts`, words rendered from those two only.

## Packages

The repository holds two packages; neither depends on the other, and the
consumer composes them.

| Package | What it is |
|:---|:---|
| `@mcp-abap-adt/auth-providers` | Every `IAuthProvider`, the token providers, and the strategies, validators and factories they are composed with. Pure TypeScript, no native code. |
| `@mcp-abap-adt/auth-spnego-gssapi` | `gssapiTokenSource()`: an `INegotiateTokenSource` over the `kerberos` native binding (GSS-API on Linux and macOS, SSPI on Windows). The only native build in the repository. |

`SpnegoAuthProvider` takes any `INegotiateTokenSource`; `gssapiTokenSource()`
is one the consumer may choose. Keeping the native binding in its own package
means a consumer of every other provider never builds it.

## Parts

```
                 IAuthProvider (interfaces-auth)
                            │
                    AuthProviderBase  ── the four moments, each inside guard
                            │
     ┌──────────────┬───────┴────────┬────────────────┬─────────────────┐
 credentials     BaseTokenProvider  SncLogonProvider  SpnegoAuthProvider
 Basic,           │                 SNC over RFC      Negotiate over HTTP
 Certificate,     ├─ renewal strategy (required)       └─ INegotiateTokenSource
 Saml, Token      ├─ persistence strategy (optional)      (the consumer's)
                  ├─ client authentication (optional)
                  ├─ authorization strategy (interactive grants)
                  └─ assertion validator (SAML grants)
```

- **`AuthProviderBase`** (`src/auth/AuthProviderBase.ts`) owns the four
  moments. Each runs its body inside auth-errors' `guard`, so nothing thrown in
  a body, a collaborator or a target crosses the contract; an answer that is
  not a minted outcome does not pass.
- **Non-token credentials** (`src/credentials/`): `BasicAuthProvider`,
  `CertificateAuthProvider`, `SamlAuthProvider`, `TokenAuthProvider`. One way
  in, nothing to refresh.
- **Token providers** (`src/providers/`): `BaseTokenProvider` and one class per
  grant (client credentials, UAA authorization code and passcode, the four
  OIDC flows, the two SAML exchanges). The base holds the token, pins the
  client certificate, runs renewal and its commit queue, and reports to
  persistence. Each provider is both an `IAuthProvider` and the stateful token
  contract (`getTokens()` / `refreshTokens()`) the broker uses.
- **Passwordless logon**: `SncLogonProvider` (`src/snc/`) resolves an SNC
  library and produces RFC logon parameters; `SpnegoAuthProvider`
  (`src/spnego/`) writes `Authorization: Negotiate <token>` on every request,
  the token made afresh by the consumer's source and read before it is
  written.
- **Interactive login by composition** (`src/authorization/`): a strategy is
  three parts — a presentation (how the URL reaches the user), a transport
  (how the answer comes back) and a protocol (what the answer is and how it is
  checked) — joined by `composeAuthorization`. The named strategies in
  `src/strategies/` are compositions of the shipped parts.
- **Client authentication** (`src/clientAuthentication/`): how a token
  provider's client authenticates each request it sends — none, a client
  secret (Basic or form), a TLS client certificate, or a signed JWT.
- **Renewal and persistence** (`src/renewal/`, `src/persistence/`): the
  renewal strategy decides every step after a refusal or an expiry; the
  persistence strategy receives what is worth keeping. Both are the
  consumer's, with shipped ones to choose from.
- **SAML validation** (`src/validation/`): two validators and an in-memory
  replay store, all replaceable.
- **Token requests** (`src/auth/tokenRequest.ts` and its neighbours): one path
  that builds, checks and sends every request to an authorization server, and
  turns every failure into a minted error.

## Boundaries

The package depends only on contracts and on the error contract's one
implementation:

- `@mcp-abap-adt/interfaces-auth`, `@mcp-abap-adt/interfaces-auth-sap`,
  `@mcp-abap-adt/interfaces-utils` — the types and allowlists it implements and
  is handed; never `interfaces-adt`;
- `@mcp-abap-adt/auth-errors` — every refusal and every throw is minted there;
- `axios`, `xml-crypto`, `@xmldom/xmldom` — HTTP and SAML.

It does not store tokens (`auth-stores`), orchestrate authentication
(`auth-broker`), load service keys, manage sessions, open a connection or speak
RFC/HTTP to the ABAP system (`connection`, `sap-rfc-lite`), fetch identity
provider metadata, or decide how a user reaches an authorization URL. Each of
those belongs to the consumer or to another package, which uses this one
through its contracts — never the reverse.

## Principles

Each of these is a rule of the code; CLAUDE.md states it precisely and names
the tests that hold it.

- **Interface-only communication.** The package knows nothing of other
  packages' concrete classes, only the contracts.
- **Everything pluggable is a strategy, and the consumer composes.** A
  constructor takes every collaborator explicitly and builds none of its own;
  static factories assemble a named recipe the consumer chooses.
- **No exception crosses the contract.** Each moment answers an outcome, never
  a throw.
- **A refusal carries no secret.** An error's facts come from allowlists, its
  words from the kind and the facts; no thrown message, cause, stack or server
  text reaches an error or a log line.
- **The provider does not guess.** Behaviour that depends on the server is the
  consumer's explicit, required choice; there are no defaults or heuristics
  for it.
- **No timeouts of the package's choosing.** A wait ends on its result, an
  explicit error, or the consumer's `AbortSignal`.
- **Nothing writes to stdout.** Under a stdio transport stdout carries
  protocol traffic.
- **Options and foreign values are read as own data.** A getter is never run,
  a throwing Proxy reads as absent.
- **No regular expression over input.** Input-facing code is plain string
  code, a bounded scanner or the platform's parser.
- **Proved where it runs.** Wire contracts are proved on the Docker stands
  (UAA and Keycloak; the Kerberos KDC and Apache), the host needing only
  Docker; claims about real systems are tagged Measured, Pending or Inference
  in the docs.

## Decisions

### Collaborator answers are native promises

A provider accepts an asynchronous answer from a collaborator its consumer
supplied (a strategy, a source, a store, a loader, a validator, a presenter)
only as a plain native `Promise`: its prototype is `Promise.prototype`, with no
own `then` or `catch`. Anything else with a `then` — a promise library's
object, a hand-written thenable, a native promise with its own `then` — is
refused as an error of that call, and its `then` is never called.

Why: awaiting a foreign thenable runs the consumer's code outside the
provider's error boundary, where it can throw, settle twice, never settle, or
hand back another thenable. A native promise runs nothing of the consumer's.

Scope: this package. Whether it suits other packages has not been assessed.

Status: enforced for the renewal strategy's `next()` and for
`SpnegoAuthProvider`'s token source (`isPlainPromise`, `src/auth/handled.ts`).
The other collaborators still await a Promises/A+ thenable until the change
that brings them in line, a major release.
