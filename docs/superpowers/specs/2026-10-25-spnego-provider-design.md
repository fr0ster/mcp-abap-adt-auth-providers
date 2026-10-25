# SPNego provider — design

Answers `docs/superpowers/2026-10-25-spnego-provider-goal.md`. Every section is
checked against its "Holds throughout".

Tags as in `docs/btp-setup.md`: **Measured** (run here), **Doc** (the cited
project's own documentation), **Inference**, **To measure** (the stand or the
second stage settles it before the claim is written as fact).

## 1. Packages and release order

| # | Package | Change | Version |
|---|---|---|---|
| 1 | `@mcp-abap-adt/interfaces-auth` | the token-source contract; the `spnego` error kind; new operations, config fields and a credential kind | **major** (8.0.0): its CHANGELOG's rule — a new kind is a major |
| 2 | `@mcp-abap-adt/auth-errors` | the `spnego` builder, its words and hints | major, following 1 |
| 3 | this repository, two packages | `@mcp-abap-adt/auth-providers` with `SpnegoAuthProvider` — **major** (7.0.0): it produces a new kind, on interfaces-auth 8; `@mcp-abap-adt/auth-spnego-gssapi` (§5), a token source over the `kerberos` npm package — first release; the stand and its suite | one release of the repository, `release:publish` publishing both |

1 and 2 are published before 3 depends on them; nothing builds against an
unpublished version of another repository. Inside this repository each package
installs its dependencies from the registry (the interfaces layout, no npm
link); the stand suite, a test of the system source's package, imports the
provider from its sibling's source, so the protocol is proved before either
is published. Neither package depends on the
other (§5); only the stand suite uses both.

**Step 0 — this repository becomes a multi-package repository**, its own PR,
merged before this work goes on: a private workspace root and every package
under `packages/` (`packages/auth-providers`, the package as it is today),
mirroring `mcp-abap-adt-interfaces` whole — its root `package.json`,
`tools/publish-changed.js`, `check:publish`, CI and release workflows. No
change to what `@mcp-abap-adt/auth-providers` publishes, so no release of its
own.

Out of this design: wiring the provider into `connection`, the broker or
`mcp-abap-adt` — a consumer composes it like any credential.

## 2. The contract (interfaces-auth 8.0.0)

### The token source

```ts
interface INegotiateTokenSource {
  token(servicePrincipal: string, options: NegotiateTokenOptions): Promise<NegotiateTokenAnswer>;
}
interface NegotiateTokenOptions { readonly signal?: AbortSignal | undefined }
type NegotiateTokenAnswer =
  | { readonly ok: true; readonly token: string }          // base64, as it goes after "Negotiate "
  | { readonly ok: false; readonly problem: NegotiateSourceProblem };
```

- The source answers **facts, not errors**: a problem from a closed list; the
  provider mints the refusal. So a source in another package — the system source or a
  consumer's own — never has to mint, and no text it holds can reach a refusal.
  A source that throws, or answers anything else, is `unknown` with the
  operation (rule 1, rule 2).
- `servicePrincipal` is the GSS host-based name, `service@host`
  (`HTTP@sap.example.com`), as the consumer stated it (§4.1). How the source
  turns it into its library's form (SSPI's `HTTP/host`) is the source's.
- A fresh token per call; a source never caches one (the goal's invariant —
  the README states it as the contract).

### Errors

- A new variant kind **`spnego`**, its `problem` from `SPNEGO_PROBLEMS`:

  | Problem | When | Hint (auth-errors words) |
  |---|---|---|
  | `no-credential` | no ticket, or an expired one (source) | obtain a ticket: `kinit`, or the domain logon |
  | `service-unknown` | the KDC does not know the service principal (source) | check `servicePrincipal` against the service's registered principal |
  | `kdc-unreachable` | no KDC answered (source) | the Kerberos configuration's realm and KDC |
  | `clock-skew` | the clock differs from the KDC's beyond its tolerance (source) | the machine's time |
  | `binding-unavailable` | the source's library cannot be loaded (source) | install the system source's native part |
  | `source-failed` | any other failure the source recognises as its own (source) | — |
  | `ntlm-token` | the token is NTLM, not Kerberos (provider, §4.3) | the service principal is not known to the domain; NTLM is not used |
  | `token-unreadable` | the token is empty, not base64, or neither Kerberos nor NTLM (provider) | — |

  `NegotiateSourceProblem` is the first six. The facts are the problem and the
  operation; no diagnostic (no value from the source is admitted).
- `OPERATIONS` gains `obtaining-negotiate-token` and
  `presenting-negotiate-token`; `CONFIG_FIELDS` gains `servicePrincipal` and
  `tokenSource`; `CREDENTIAL_KINDS` gains `kerberos-ticket` (what
  `credential-refused` names for a `401`).
- Configuration faults use the existing cases: `required-fields-missing`
  (`servicePrincipal`, `tokenSource`) and `invalid-value` (`servicePrincipal`
  not of the form in §4.1).

## 3. auth-errors

The `spnego` builder (`authError.spnego({ problem, operation })`), its words
and hints per problem as the table above, rendered from `kind` and `facts`
only; `matchKind` and the README tables gain the kind. The shape check's rules
are unchanged.

## 4. `SpnegoAuthProvider` (auth-providers)

`src/spnego/SpnegoAuthProvider.ts`, extending `AuthProviderBase`, `kind =
'spnego'`, exported from `src/index.ts`.

### 4.1 Configuration

```ts
interface SpnegoAuthProviderConfig {
  servicePrincipal: string;               // required: "service@host"
  tokenSource: INegotiateTokenSource;     // required, never defaulted (rule 7)
  logger?: ILogger | undefined;
  signal?: AbortSignal | undefined;       // the first attached party, as SncLogonProvider
}
```

- Read through `ownOptions`. `servicePrincipal` is the GSS host-based form
  `service@host` and nothing else: exactly one `@`; the service an ASCII
  letter followed by ASCII letters, digits or `-`; the host one or more labels
  of ASCII letters, digits or `-` (not starting or ending with `-`) joined by
  single `.`, no leading or trailing `.`. So `/` (the Kerberos form
  `HTTP/host@REALM`), whitespace, non-ASCII and an empty side are all refused —
  checked by plain code, no regex; else `invalid-value`. Nothing is derived
  from a URL: the provider sees none.
- `tokenSource`: an object whose `token` is a function, read through
  `readSafely`; else `required-fields-missing`.
- No static factory assembles the provider with the system source (§5): it
  would import the native package. The consumer composes,
  `new SpnegoAuthProvider({ servicePrincipal, tokenSource: gssapiTokenSource(…) })`,
  or passes a source of its own.

### 4.2 The four moments

| Moment | Operation | Does |
|---|---|---|
| `prepare()` | `obtaining-negotiate-token` | asks the source for one token and checks it (§4.3), then drops it: a missing ticket, an unknown principal or an NTLM fallback fails the connect, before any request. Nothing is kept. |
| `establish()` | `establishing` | writes nothing, answers Ok (rule 3). SPNego has nothing for a logon; over RFC the system refuses a logon without a user, and the README says SPNego is for HTTP. |
| `authorize()` | `presenting-negotiate-token` | asks the source for a **new** token, checks it (§4.3), writes `Authorization: Negotiate <token>` through the target; a target that throws is Oops (rule 1). Never reuses the token of `prepare()` or of an earlier request. |
| `rejected()` | `reading-rejection` | `refuseFor(rejection, 'kerberos-ticket')` (rule 5): a `401` is `credential-refused`, with or without a `Negotiate` continuation; anything else `system-refused`. Renewing is the next `authorize()`'s fresh token; retrying is the consumer's. |

- The source is called with the attached parties' signal (`createParties`), so
  an aborted connect is not held by a source that honours it; the system source's
  library call cannot be cancelled (§5) — no timeout of the package's choosing.
- A source answer of `{ ok: false, problem }` is minted `spnego` with that
  problem and the moment's operation. Anything else from the source — a throw,
  a foreign thenable, a non-object, an unknown problem — is `unknown` with the
  operation (`classify`), its value read nowhere.

### 4.3 Reading the token

`readNegotiateToken(token): 'kerberos' | 'ntlm' | 'unreadable'` in
`src/spnego/negotiateToken.ts`, plain code (no regex), on the base64-decoded
bytes:

- `ntlm`: the bytes start `NTLMSSP\0` (a raw NTLM message), or a SPNEGO
  `NegTokenInit` whose mechanism token is one.
- `kerberos`: a GSS-framed Kerberos token (RFC 2743 framing, mechanism OID
  `1.2.840.113554.1.2.2`), or a SPNEGO `NegTokenInit` (OID `1.3.6.1.5.5.2`)
  whose first mechanism is Kerberos (that OID, or the legacy Microsoft
  `1.2.840.48018.1.2.2`) and whose mechanism token is GSS-framed Kerberos.
- anything else, an empty or non-base64 string included: `unreadable`.

DER is read with definite lengths only, every length checked against what
remains, at most the few levels the structure has; a malformed structure is
`unreadable`, never an exception that escapes. Why the SPNEGO case matters:
Windows' Negotiate package falls back to NTLM *inside* a SPNEGO token when
Kerberos fails (Inference — Doc of the Negotiate SSP; To measure in the second
stage), so a prefix check alone would pass it.

### 4.4 What reaches a log line

Fixed words and facts only: the operation, the problem, the token's
`<redacted, N chars>` if anything about it is logged at all. Never the token,
the service principal (configured, the consumer's text), or anything the
source said. `logCallSources.test.ts` covers `src/spnego/`.

## 5. The system source's package

`@mcp-abap-adt/auth-spnego-gssapi` in `packages/auth-spnego-gssapi` of this
repository: `spnego` is what it produces, `gssapi` where the token comes
from — the system's GSS-API (SSPI, its Windows counterpart). The repository's supply-chain
policy covers it: `allowScripts` lists `kerberos` alone, built only where a job
needs the binding; every other install keeps `--ignore-scripts`.

- Depends on `interfaces-auth` (types) and `kerberos` (7.x, registry). It
  mints nothing and does not depend on auth-errors.
- `gssapiTokenSource({ mechanism })`:
  - `mechanism: 'spnego' | 'kerberos'`, **required, no default** — which one a
    service accepts is the service's (RFC 4559 names SPNEGO; servers that take
    a bare Kerberos token exist — Inference). Mapped to the binding's
    `GSS_MECH_OID_SPNEGO` / `GSS_MECH_OID_KRB5` (Doc).
  - No client principal option: the binding's Windows (SSPI) path ignores a
    principal and uses the logon credentials (Doc — its `kerberos_sspi.cc`),
    so the option would select an identity on Linux and macOS and silently not
    on Windows. The identity is the default one of the process's ticket cache
    (`KRB5CCNAME`, the domain logon); the binding takes no cache name (Doc), and
    nothing here writes the environment. A consumer needing another identity
    supplies its own source.
  - `kerberos` is loaded with a dynamic import on the first `token()` call; a
    load failure answers `binding-unavailable`.
  - Each call: `initializeClient(servicePrincipal, …)`, one `step('')`, the
    response returned; nothing kept. The binding has no cancellation (Doc): the
    signal is checked before the call, and an abort during it is answered after
    the call returns.
  - The binding's failure is mapped to a problem by reading its GSS major and
    minor status **codes** where the binding exposes them, else by plain
    substring search of fixed GSS phrases (as `sncRefusal` does), never a
    regex; the table is built from the stand's failures (To measure: which
    shape the binding's error has); unmatched is `source-failed`.
- CI, a job of its own: Linux, macOS and Windows (x64): `npm ci --ignore-scripts`, then the one
  allowed build `npm rebuild kerberos --build-from-source` (no prebuilt binary
  downloaded), then a test that loads the binding and gets
  `no-credential` from a machine with no ticket. Windows on arm64 is out.
- README: what to install per platform (headers on Linux, Xcode CLT on macOS),
  the `allowScripts` entry a consumer adds, the mechanism choice.

## 6. The stand (auth-providers `tests/stand/`)

Added to `compose.yaml`, images built from committed Dockerfiles on a pinned
`debian:bookworm-slim`:

- **`kdc`** — MIT krb5 KDC, realm `STAND.TEST`; at start creates the database,
  a user `alice` (password a committed fixture, trusted by nothing but the
  stand), the service principal `HTTP/negotiate.stand.test@STAND.TEST` (GSS
  name `HTTP@negotiate.stand.test`) with its keytab written to a volume, and a
  second service principal `HTTP/stale.stand.test@STAND.TEST` whose keytab is
  exported and whose key is then changed in the KDC (`cpw -randkey`) before
  any ticket exists: every ticket for it is encrypted with a key the service's
  keytab does not hold, so the service refuses it — a refused credential
  without touching the user. No keytab or key is committed.
- **`negotiate`** — Apache httpd with `mod_auth_gssapi`, keytab from the
  volume, one protected path answering `200` only to an accepted `Negotiate`
  token; `GssapiAllowedMech krb5`; the replay cache on. A second virtual host
  `stale.stand.test` (selected by the `Host` header) protected with the stale
  keytab. A third path answers every request `401` with a fixed, non-empty
  `WWW-Authenticate: Negotiate <base64>` — a configured answer standing for a
  continuation, not a GSS exchange Apache produced; the suite asserts the
  status and the header before it tests `rejected()`.
- Published on loopback ports: the KDC (`STAND_KDC_PORT`, UDP and TCP) and the
  service (`STAND_NEGOTIATE_PORT`).
- **The suite runs on the host**, like the other stand suites:
  `tests/stand/kerberos/krb5.conf.template` (committed) names the realm, with
  a placeholder for the KDC port; `run.sh` checks `STAND_KDC_PORT` is a port
  number, writes the rendered `krb5.conf` (`kdc = 127.0.0.1:<port>`) into a
  per-run temporary directory (removed at exit), and exports `KRB5_CONFIG` to
  it and a per-run `KRB5CCNAME` beside it for the suite process and runs `kinit` there (the host
  needs the MIT client tools and headers — CI installs them). The request
  goes to `127.0.0.1:<port>`; the service principal is stated, so no DNS
  name is needed — which is itself a test of §4.1.
- The suite is a test of the system source's package and imports the
  provider from its sibling's source (test-only, no npm link); the stand job alone builds the native part (`npm rebuild kerberos
  --build-from-source`, allowed by `allowScripts` for that one package). The
  published auth-providers carries no native code and no install script, and
  does not depend on the system source.

### What the suite proves (each rule red when removed)

| Case | Expect |
|---|---|
| ticket for `alice`, `mechanism: 'spnego'` and `'kerberos'` | `200`, the service's `REMOTE_USER` is `alice` (To measure: which mechanisms Apache accepts) |
| two requests | two different tokens; both `200` |
| the token of the first request resent by hand | the service refuses it (replay cache) — the reason the provider never reuses one |
| no ticket (`kdestroy`) | `prepare()` is `spnego` `no-credential`; nothing sent |
| a principal the KDC does not know | `spnego` `service-unknown` |
| the KDC stopped, with a cache of its own holding a valid TGT and no ticket for the service (asserted with `klist` first) | `spnego` `kdc-unreachable`; the KDC started again after |
| a ticket for `HTTP@stale.stand.test` (the service's keytab holds the old key) | `401` → `rejected()` is `credential-refused` `kerberos-ticket` |
| the configured continuation path (`401`, `WWW-Authenticate: Negotiate <token>`, both asserted) | `credential-refused`, the same |
| the token in every log line, error and refusal of every case | absent (the `noTokensInLogs` oracle) |

Clock skew is not on the stand (one clock; To measure by hand if wanted).
`readNegotiateToken` gets unit tests from fixtures captured on the stand
(Kerberos raw, SPNEGO-wrapped) and built NTLM ones (raw, inside SPNEGO,
malformed DER at every length).

## 7. Tests in auth-providers beside the stand

Unit, with a fake `INegotiateTokenSource`: the configuration checks; a fresh
`token()` call per `authorize()` and none reused from `prepare()`; every
`problem` minted with its operation; a throwing, thenable-returning or
garbage-answering source is `unknown`; a target that throws is Oops;
`establish()` writes nothing; `rejected()` per rule 5; the shape check covers
the new provider (rules 1–7; rule 8 is about bearer tokens, which it does not
handle).

## 8. Documentation

README (the provider, its configuration, the system source, "SPNego is for HTTP",
a `401` and a continuation, the refusal table rows rendered as the others),
`docs/passwordless-sso.md` (SPNego rows: Measured on the stand with the date;
against ABAP still Inference until the second stage), CLAUDE.md's provider
list and module structure (text for the owner's approval), CHANGELOG with a
migration note for the major (the new kind: a consumer's exhaustive `switch`
needs the `spnego` case).
