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
- `@mcp-abap-adt/auth-errors` — every refusal and every throw is minted there,
  with one exception: `refreshStatePersistence`'s `report()` with
  `onWriteFailure: 'fail'` rejects with what the consumer's own `write`
  threw, as it is; a provider calling `report()` classifies it before it goes
  any further;
- `axios`, `xml-crypto`, `@xmldom/xmldom` — HTTP and SAML.

It talks to authorization servers itself — token requests, and OIDC discovery
(`src/auth/oidcDiscovery.ts`: the discovery document fetched when an endpoint
is not configured, and cached). It does not store tokens (`auth-stores`),
orchestrate authentication (`auth-broker`), load service keys, manage
sessions, open a connection or speak RFC/HTTP to the ABAP system
(`connection`, `sap-rfc-lite`), fetch SAML identity provider metadata (the
certificates and entity ID an assertion is checked against come from
configuration), or decide how a user reaches an authorization URL. Each of
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
- **Static types first.** A value is checked at runtime only when it comes
  from outside the type system: a thrown value, a network answer, a JWT
  payload, a SAML or XML document, a file, the environment, registry output,
  terminal input, a callback HTTP request, GSS token bytes, a field a contract
  types `unknown`. Options, collaborators, their answers and the package's own
  objects are used as typed. What a type cannot express — the shape of a URL
  or path, a range, a non-empty or printable string, CR/LF in a header, one of
  several optional fields, a cross-field rule — is a value rule, checked and
  refused as before.
- **Options are a typed copy.** Every exported constructor and factory copies
  its options once, at creation, with a shallow spread, and reads only the
  copy: a later change to the object changes nothing. A collaborator in the
  options is kept by reference and read and called only inside a moment (or a
  composed strategy's `authorize`) — except the descriptors
  `composeAuthorization` reads when it composes: the transport's `label`, the
  protocol's `redirect`, `callbackMethods` and `paste`, read as typed data;
  and the shipped-validator brand a SAML provider's constructor reads on its
  `assertionValidator` (`isShippedValidator`, guarded).
- **A throw is not a type question.** A typed value can still throw. A
  collaborator's call and every read of its answer share one failure
  boundary: a throw while reading takes the same classification, settling and
  release as a throw from the call.
- **No regular expression over input.** Input-facing code is plain string
  code, a bounded scanner or the platform's parser.
- **Proved where it runs.** Wire contracts are proved on the Docker stands
  (UAA and Keycloak; the Kerberos KDC and Apache), the host needing only
  Docker; claims about real systems are tagged Measured, Pending or Inference
  in the docs.

## Decisions

### Collaborator answers are awaited as given

A provider awaits a collaborator's asynchronous answer normally: a native
promise, a Promise subclass or any Promises/A+ thenable is adopted as `await`
adopts it, inside the moment's boundary, and then used as its contract types
it. A rejection, a throw from its `then`, or a throw while its answer is read
is a failure of that call, classified like any other. Where the package
adopts an answer itself, it does so through a fresh native promise,
`new Promise((resolve) => resolve(answer))`, which calls a promise's own
`then` as `await` does; `Promise.resolve(answer)` would return a native
promise unchanged and bypass it.

Refusing every answer that is not a plain native promise was considered and
dropped (7.1.0). It guards nothing: a collaborator that wraps a thenable in an
async function, or in `new Promise((r) => r(thenable))`, answers a plain
native promise whose resolution calls the foreign `then` all the same
(measured). The adoption `await` performs already gives what the provider
relies on — one settlement, `then` called in a later job, a throw contained —
and a collaborator's code is the consumer's, run with the consumer's rights
whether the provider calls it or adopts its answer.

An answer typed `void` — a request target's `header()` / `cookies()`, every
`ILogger` method, the renewal strategy's `aborted()` — is not an answer to
adopt: the call stays inside its `try`, a throw is handled, and a returned
value is ignored (8.0.0). An answer whose type admits a promise and that is
not awaited — a persistence `report()` made detached, a presentation's
`present()` — is adopted the same way and given a rejection handler, whose
own throw is contained; `IBrowser.open()`'s answer is adopted the same way and
awaited inside `openInBrowser`'s `try`.

What stays strict is a value that is not a collaborator's answer: a thrown
value being classified (`classify`) and a logon target's answer
(`relayOutcome`). No `then` is called on either.

Scope: this package. Whether it suits other packages has not been assessed.
