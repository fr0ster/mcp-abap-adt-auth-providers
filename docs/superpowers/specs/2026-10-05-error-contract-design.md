# Error contract — design spec

**Status:** draft for review, 2026-10-05. Anchor:
[`../2026-10-05-error-contract-goal.md`](../2026-10-05-error-contract-goal.md)
(approved 2026-10-05). Every "Holds throughout" invariant of the goal binds
this spec; §13 says how each is honoured and which ones are held by something
weaker than the compiler. Nothing here departs from the goal.

Line references are to the trees as they stand on 2026-10-05:
auth-providers `feat/error-contract` at `a140183`, `mcp-abap-connection`
`master` at `e0bf6b3`, `mcp-abap-adt-auth-broker` `main` at `19fbf31`,
`mcp-abap-adt-interfaces` `master` at `4377152`, `mcp-abap-adt-auth-stores`
`master` at `367dbf7`.

## 0. The decisions in one place

The goal's "Open — for the spec", answered:

1. **`reason` / `hint` stay required fields of the error** (`reason: string`,
   `hint?: string | undefined`), computed once, at minting, by the default
   renderer from `kind` and `facts`. They do not become optional: every reader
   today shows them (connection's `AuthRefusedError` message, the CLI, the
   server through that message), and an optional `reason` would break all of
   them a second time for no gain — the words cost nothing to carry. A
   consumer that wants other words renders its own from `kind` and `facts`
   (§9); it ignores the stored ones.
2. **Sixteen kinds** (§3), derived from the inventory in Appendix A.
3. **One thrown class**, `AuthProviderFailure` in `auth-errors`, holding an
   `IAuthProviderError` as `error`; every error class of auth-providers is
   deleted (§6).
4. **`IAuthRefusal` becomes the error itself**: `type IAuthRefusal =
   IAuthProviderError`. "Its refusal carries an `IAuthProviderError`" is read
   as "the refusal is one": a reader of `refusal.reason` / `refusal.hint` on
   4.x compiles unchanged; every producer stops compiling until it mints
   through `auth-errors` (§4.5).
5. **The diagnostic compatibility matrix** is Appendix A; the SAML rule table
   Appendix B; every loss of information is listed in Appendix C for the
   user's approval.
6. **A logon target builds its refusal with an `auth-errors` builder** (kind
   `logon-target`); a provider relays a target's outcome through
   `relayOutcome`, which re-mints whatever came back and never passes a
   target's object through (§7).

## 1. Inventory

Appendix A lists every refusal, every `loggedError` line and every thrown
message the chain produces today — auth-providers, connection's logon targets
and its own refusals, the broker's copied phrases — each mapped to a kind and
its facts, with the information lost named. What the inventory showed, and
what drove the kinds:

- **auth-providers refusals** come from four places: `refusalFrom`
  (`src/auth/refusal.ts:251-335`, every thrown value, chosen by `instanceof`
  on 13 own classes, `refusal.ts:162-178`), `readRejection` /
  `unknownRefusal` (`src/auth/rejection.ts:37-95`), fixed `oops(...)` calls in
  the credentials, `BaseTokenProvider` and `SncLogonProvider`, and the SNC
  wording (`src/snc/sncRefusal.ts:38-91`).
- **Thrown messages** are of three sorts: fixed words (the certificate and
  client-authentication classes, `src/errors/*.ts`), words built from
  allowlisted facts (`TokenEndpointError`, `src/auth/tokenRequest.ts:375-397`),
  and free sentences — 42 `throw new Error(...)` / `ValidationError(...)`
  sites, several interpolating configuration values (`qop`,
  `SncLogonProvider.ts:89-92`; `clockSkewMs`, `assertionValidator.ts:133-135`;
  ports and timeouts, `callbackServer.ts:56-68`; URIs, `saml2Utils.ts:168-196`,
  `AuthorizationCodeProvider.ts:163-166`).
- **SAML** refusals carry only `check` today (`refusal.ts:255-262`); the
  detail lives in `AssertionValidationError.message`, 50 messages (README
  "Refusal messages", `README.md:1372-1468`) of which 11 quote document values
  through `quoteUntrusted` (`src/validation/signedNode.ts:73-78`) and one
  (`assertionValidator.ts:206`) passes an exception's message through —
  including xml-crypto's own (`signedNode.ts:142-144`).
- **connection** produces five refusals: two logon-target refusals
  (`RfcTransport.ts:479-482`, `HttpTransport.ts:524-527`) and three of its own
  (`authErrors.ts:56-71`), and relays every provider refusal into
  `AuthRefusedError`, whose message is `reason — hint` (`authErrors.ts:25-28`)
  — the one thing the server reads (`mcp-abap-adt/src/lib/auth/errors.ts:110`).
- **The broker** copies three certificate phrases
  (`auth-broker/src/clientAuthentication.ts:78-80`) and re-chooses them from
  `CertificateMaterialError`'s flags (`:220-226`); everything else it says is
  its own configuration language (`DestinationConfigError`), not a provider's.
- **No package outside auth-providers imports `TOKEN_PROVIDER_ERROR_CODES` or
  `ASSERTION_ERROR_CODES`** (searched in the broker, the CLI, the stores,
  connection and the server, 2026-10-05).

## 2. Vocabulary

- **Error** — an `IAuthProviderError`: a frozen plain object, `kind`, `facts`,
  `reason`, `hint`, optional `diagnostics`.
- **Fact** — a value from an allowlist: a member of an `as const` array, or a
  branded integer in a fixed range (§4.3).
- **Diagnostic** — a value that helps a person and cannot be allowlisted,
  admitted by the builder from one approved extraction source (§3.3, §5.3).
- **Mint** — the one act that produces an error: `auth-errors` builds the
  object, renders `reason` / `hint`, admits diagnostics, freezes it and
  records it in a module-private `WeakSet`.
- **Classification** — turning an `unknown` (a thrown value, an outcome a
  collaborator returned) into an error (§5.4).
- **Operation** — what was being done when it failed, from a closed list
  (§4.3); it replaces every free `what` string of today.

## 3. The kinds

### 3.1 The list

| # | `kind` | Today's source (Appendix A) | Blames the credential (rule 5) |
|---|---|---|---|
| 1 | `configuration` | `ValidationError` and every configuration `Error` | no |
| 2 | `client-certificate` | `CertificateMaterialError` | no |
| 3 | `client-authentication` | `ClientAuthenticationError`, `ClientAuthenticationResultError`, `BasicClientIdError` | no |
| 4 | `request-failed` | `TokenEndpointError`, the reduced `AxiosError`, "response missing access_token" | no |
| 5 | `tls` | an allowlisted TLS code (`knownCodes.ts:470-497`) | no |
| 6 | `interactive-login` | `BrowserAuthError`, `CallbackScopeError`, `AuthorizationRefusedError`, the manual strategies, `DeviceCodePresentationError` | no |
| 7 | `saml-assertion` | `AssertionValidationError`, the bearer conversion (`samlBearerAssertion.ts`) | no |
| 8 | `snc` | `sncRefusal.ts`, `SncLogonProvider.ts:135`, `SncLibraryNotFoundError` | only `problem: 'no-credential'`, and `'logon-refused'` with `rfcKey: 'RFC_LOGON_FAILURE'` |
| 9 | `credential-refused` | the credentials' own refusals, `RefreshError` | **yes** |
| 10 | `system-refused` | `readRejection` not-credential / `unknownRefusal` | no |
| 11 | `renewal-unchanged` | "the renewal returned the credential that was refused" | **yes** |
| 12 | `token-binding` | `TOKEN_BOUND_ELSEWHERE`, `TOKEN_RENEWED_BOUND_ELSEWHERE` | no |
| 13 | `not-prepared` | "the certificate is not loaded", "the SNC provider is not prepared" | no |
| 14 | `logon-target` | connection's two target refusals; a target's unusable answer | no |
| 15 | `connection` | connection's `PROVIDER_FAILED`, `REFUSED_AGAIN`, `NO_CREDENTIAL_TO_RENEW` | only `problem: 'refused-after-renewal'` |
| 16 | `unknown` | `refusalFrom`'s "unknown error" and own-class fallbacks | no |

The blame column is `blamesCredential(error)` in `auth-errors`, a table
`satisfies` a mapped type over every kind (§5.6). It is what a consumer reads
instead of parsing words; rule 5's behaviour (a provider renews only on a
credential rejection) does not change.

Kinds 14 and 15 belong to the contract because connection's refusals travel
in the same `AuthOutcome` and the same `AuthRefusedError` as a provider's; a
consumer handling kinds exhaustively must see them.

### 3.2 Facts per kind

Every fact type is either a union drawn from an `as const` array (named in
§4.3 with its source today) or a branded integer. `?` marks a fact that is
present only when known; the builder omits the key otherwise (no
`undefined`-valued keys in an error).

| `kind` | `facts` |
|---|---|
| `configuration` | `case: ConfigCase`, `fields: readonly ConfigField[]` (≤ 8, deduplicated, in the order given), `allowed?: AllowedValueSet` |
| `client-certificate` | `problem: 'incomplete' \| 'unusable' \| 'expired'` |
| `client-authentication` | `problem: 'signing-key-unusable' \| 'result-unsendable' \| 'basic-client-id-colon'` |
| `request-failed` | `operation: Operation`, `grant?: OAuth2GrantType`, `problem: RequestProblem`, `status?: HttpStatus`, `oauthError?: OAuthErrorCode`, `code?: SystemCode` |
| `tls` | `operation: Operation`, `grant?: OAuth2GrantType`, `code: TlsFailureCode` |
| `interactive-login` | `outcome: InteractiveOutcome`, `port?: Port`, `timeoutSeconds?: Seconds`, `ignoredCallbacks?: Count`, `oauthError?: OAuthErrorCode`, `code?: SystemCode`, `status?: HttpStatus` |
| `saml-assertion` | per rule, a discriminated union: `rule: AssertionRule`, `check: CheckOf<rule>` (fixed by the rule), `count?: Count` (rules that say "carries N"), `statusCode?: SamlStatusCode` (rule `declined`), `candidates?: readonly BearerCandidate[]` (≤ 5) and `moreCandidates?: Count` (rule `no-bearer-qualifies`) |
| `snc` | `problem: SncProblem`, `rfcKey?: RfcKey`, `secureLoginClient?: boolean`, `libraryArchs?: readonly SncArch[]`, `candidates?: readonly SncCandidate[]` (≤ 8), `searched?: boolean`, `processArch?: SncArch` |
| `credential-refused` | `credential: CredentialKind`, `at?: 'logon' \| 'request'` |
| `system-refused` | discriminated by `verdict`: `'not-authorized'` / `'redirected'` / `'system-failed'` / `'other-status'` with `status: HttpStatus`; `'rfc-failure'` with `rfcKey: RfcKey`; `'unknown'`; each with `at: 'logon' \| 'request'` |
| `renewal-unchanged` | `source: 'token-source' \| 'token-provider'` |
| `token-binding` | `problem: 'bound-to-unpinned' \| 'renewed-bound-elsewhere'` |
| `not-prepared` | `provider: 'certificate' \| 'snc'` |
| `logon-target` | `wire: 'http' \| 'rfc' \| 'unknown'`, `refused: 'tls-material' \| 'logon-parameters'` |
| `connection` | `problem: 'provider-threw' \| 'refused-after-renewal' \| 'no-credential'`, `at?: 'prepare' \| 'logon' \| 'request'` |
| `unknown` | `operation: Operation`, `grant?: OAuth2GrantType`, `status?: HttpStatus`, `oauthError?: OAuthErrorCode`, `code?: SystemCode` |

For `saml-assertion`, `snc` and `configuration`, the value of `rule`,
`problem` and `case` is also the error's top-level `variant` (§4.1), so that
a consumer can narrow the whole error on it.

Composite fact types:

```ts
type BearerCandidate = {
  readonly reason: BearerCandidateReason;   // the eleven, Appendix B
  readonly count?: Count;                   // reason 'several-confirmation-data'
};
type SncCandidate = {
  readonly source: SncCandidateSource;
  readonly reason: SncUnusableReason;
  readonly archs?: readonly SncArch[];      // reason 'wrong architecture'
};
```

`request-failed`'s `problem` (`RequestProblem`): `'refused'` (a response with
a status), `'no-response'` (a transport failure, `code` when allowlisted),
`'no-access-token'` (a 2xx without `access_token`), `'incomplete-response'`
(a device authorization response without its fields, a discovery document
without `token_endpoint`).

`interactive-login`'s `outcome` (`InteractiveOutcome`): `'timeout'`,
`'port-in-use'`, `'aborted'`, `'disposed'`, `'busy'`,
`'browser-launch-failed'`, `'callback-closed'`, `'identity-provider-refused'`,
`'input-abandoned'`, `'input-timeout'`, `'no-input'`, `'unreadable-input'`,
`'no-terminal'`, `'device-code-not-shown'`, `'failed'` (anything else ending a
browser login: `code` / `status` when safe — `browserLoginWords`,
`BrowserCallbackStrategy.ts:77-82`).

`snc`'s `problem` (`SncProblem`): `'no-credential'` (A2200019),
`'library-init-failed'` (SNCERR_INIT), `'logon-refused'`,
`'library-not-found'`, `'locator-returned-no-path'`.

`CredentialKind`: `'user-password'`, `'client-certificate'`,
`'saml-session'`, `'token'`, `'refresh-token'`.

### 3.3 Diagnostics per kind

Only three kinds carry diagnostics. Each field has exactly one approved
extraction source and one admission check (§5.3); a field that fails
admission is dropped and the error is minted without it. No diagnostic is
ever part of `reason` / `hint`.

| `kind` | Field | The one extraction source | Admission |
|---|---|---|---|
| `snc` | `library` | the `path` the locator returned and `prepare()` trimmed (`SncLogonProvider.ts:133`) — the consumer's `sncLib`, `SNC_LIB_64` / `SNC_LIB`, the Secure Login Client registry install path + `lib\sapcrypto.dll`, or the fixed macOS bundle path (`DefaultSncLibraryLocator.ts:118-144`) | `LocalPath` |
| `snc` | `candidatePaths` | `SncLibraryNotFoundError.tried[i].path`, read only from an instance of the shipped locator's class, aligned index for index with `facts.candidates` | `LocalPath` each; a dropped one becomes `null`, so indices stay aligned |
| `saml-assertion` | `rootElement` | the document element's `localName` (`assertionValidator.ts:185-186`); rules `root-not-response-or-assertion`, `root-not-response` | `XmlName` |
| `saml-assertion` | `id` | the `ID` attribute value used more than once (`documentIds.ts`, `assertionValidator.ts:195`); rule `duplicate-id` | `XmlId` |
| `saml-assertion` | `referenceUri` | `ds:Reference/@URI` (`signedNode.ts:185-187`, `:200-202`); rules `reference-not-same-document`, `reference-not-found` | `DocumentValue`, printable ASCII only |
| `saml-assertion` | `statusCode` | `samlp:StatusCode/@Value` when it is not a registered code (`assertionValidator.ts:295-297`); rule `declined` | `DocumentValue`, printable ASCII only |
| `saml-assertion` | `issuer` | the assertion's `saml:Issuer` text (`assertionValidator.ts:330-332`); rule `untrusted-issuer` | `DocumentValue` |
| `saml-assertion` | `notBefore` / `notOnOrAfter` | `Conditions/@NotBefore` / `@NotOnOrAfter` as written (`assertionValidator.ts:374-376`, `:393-395`); rules `not-before-invalid`, `not-on-or-after-invalid` | `DocumentTime` |
| `saml-assertion` | `destination` | `Response/@Destination` (`assertionValidator.ts:440-442`); rule `destination-not-us` | `DocumentValue` |
| `configuration` | `configuredUri` | the provider's configured `acsUrl`, or the `redirect_uri` of the configured pre-built `authorizationUrl` (`saml2Utils.ts:168-196`, `AuthorizationCodeProvider.ts:159-166`); cases `saml-acs-mismatch`, `redirect-mismatch` | `ConfigUri` |
| `configuration` | `strategyUri` | the redirect URI the consumer's strategy reported (`AuthorizationOutcome.redirectUri`, or the bound handle's `redirectUri`), same cases | `ConfigUri` |

Which `saml-assertion` field a rule may carry is a type: `SamlDiagnosticsOf<R>`
maps each rule to at most one field (Appendix B). The `issuer`,
`statusCode`, `destination`, `referenceUri` and time values are
attacker-controlled; they are admitted because the goal names them as
selected metadata, and because admission makes them safe to print
(§5.3) — not because of where they came from. **Never admitted, by
construction:** an exception's message (xml-crypto's, the XML parser's,
OpenSSL's), any element's text other than `saml:Issuer`, a token, a secret,
key material, a server's body or reason phrase, a URL with a query or
userinfo.

## 4. Types in `@mcp-abap-adt/interfaces-auth` 5.0.0

Types and constants only — no function, no class (the interfaces package
holds no logic). Everything new lives under `src/error/`; the normal-course
files reference only `IAuthProviderError` / `IAuthRefusal` /
`IAuthProviderFailure` (goal invariant 1).

### 4.1 The error

```ts
// src/error/IAuthProviderError.ts
declare const minted: unique symbol;            // not exported: unnameable outside

interface Common<K extends AuthProviderErrorKind> {
  readonly kind: K;
  /** Rendered from kind and facts by the default renderer, at minting. */
  readonly reason: string;
  readonly hint?: string | undefined;
  readonly [minted]: true;
}

/** Only the permitted diagnostic fields are declared; none at all → `?: never`. */
type DiagOf<T, Allowed extends keyof T> = [Allowed] extends [never]
  ? { readonly diagnostics?: never }
  : { readonly diagnostics?: { readonly [F in Allowed]?: T[F] } };

/** The three kinds with diagnostics: one object type per variant. */
export type SamlAssertionError = { [R in AssertionRule]:
  Common<'saml-assertion'> & { readonly variant: R; readonly facts: SamlFactsOf<R> }
  & DiagOf<SamlDiagnosticValues, SamlDiagnosticOf<R>> }[AssertionRule];
export type SncError = { [P in SncProblem]:
  Common<'snc'> & { readonly variant: P; readonly facts: SncFactsOf<P> }
  & DiagOf<SncDiagnosticValues, SncDiagnosticOf<P>> }[SncProblem];
export type ConfigurationError = { [C in ConfigCase]:
  Common<'configuration'> & { readonly variant: C; readonly facts: ConfigFactsOf<C> }
  & DiagOf<ConfigDiagnosticValues, ConfigDiagnosticOf<C>> }[ConfigCase];

/** Every other kind: one object type, no variant, no diagnostics. */
type PlainError<K extends PlainKind> =
  Common<K> & { readonly facts: AuthProviderErrorFacts[K]; readonly diagnostics?: never };

export type AuthProviderErrorOf<K extends AuthProviderErrorKind> =
  K extends 'saml-assertion' ? SamlAssertionError
  : K extends 'snc' ? SncError
  : K extends 'configuration' ? ConfigurationError
  : K extends PlainKind ? PlainError<K> : never;

export type IAuthProviderError = {
  [K in AuthProviderErrorKind]: AuthProviderErrorOf<K>;
}[AuthProviderErrorKind];
```

**Facts and diagnostics are correlated through a top-level discriminant.**
For `saml-assertion`, `snc` and `configuration`, the value that decides which
diagnostic may appear — the rule, the problem, the case — is lifted onto the
error as **`variant`**, beside `kind` (and stays in `facts` as `rule` /
`problem` / `case`, the same value: the builder writes both, classification
rebuilds only when they are equal). `kind` and `variant` are properties of
the error itself, so `e.kind === 'saml-assertion' && e.variant ===
'untrusted-issuer'` narrows the **whole** object — `facts` and `diagnostics`
included. Narrowing on `e.facts.rule` does not: TypeScript narrows a union
only by a discriminant property of its members, not of a nested object
(measured, §11.2 probe). Each variant declares only its permitted diagnostic
fields, so reading another one is a compile error, not an access to an
optional `never`.

The maps from discriminant to permitted field are `as const` objects
(`SAML_RULE_DIAGNOSTIC`, `SNC_PROBLEM_DIAGNOSTICS`,
`CONFIG_CASE_DIAGNOSTICS`, each `satisfies Record<Discriminant, …>`), and
`SamlDiagnosticOf<R>` and its siblings are read from them, so the type and
the runtime admission table (§5.3) come from one source:

| Kind | `variant` (= `facts.rule` / `.problem` / `.case`) | Permitted diagnostics |
|---|---|---|
| `saml-assertion` | the rule | the one field of Appendix B's "Diagnostic" column, else none |
| `snc` | the problem | `no-credential`, `library-init-failed`: `library`; `library-not-found`: `candidatePaths`; `logon-refused`, `locator-returned-no-path`: none |
| `configuration` | the case | `saml-acs-mismatch`, `redirect-mismatch`: `configuredUri`, `strategyUri`; every other case: none |

So an object with `variant: 'duplicate-id'` and `diagnostics: { issuer }` is
not an `IAuthProviderError` even before the brand is considered — the pair
matches no variant. A kind without diagnostics has `diagnostics?: never`, so
it cannot be given. `AuthProviderErrorKind` is
`(typeof AUTH_PROVIDER_ERROR_KINDS)[number]`, and a type test asserts
`keyof AuthProviderErrorFacts` equals it both ways — a kind added to the array
without facts, or facts without the kind, does not compile.

**The brand** is the `[minted]` property: a symbol declared and not exported,
so no code outside the declaration file can write the key. An object literal,
a class instance or a JSON-parsed value is not an `IAuthProviderError` to the
compiler. `auth-errors` produces one with the single type assertion in its
`mint` function; a type assertion elsewhere is refused by the producers'
shape check (§8.2), not by the compiler — that limit is stated in §13.

### 4.2 Outcome, refusal, thrown failure

```ts
// src/auth/AuthOutcome.ts
export type IAuthRefusal = IAuthProviderError;
export type AuthOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly refusal: IAuthRefusal };

// src/error/IAuthProviderFailure.ts
/** What getTokens() / refreshTokens() reject with. */
export interface IAuthProviderFailure extends Error {
  readonly name: 'AuthProviderFailure';
  readonly error: IAuthProviderError;
}
```

`IAuthProvider` (`src/auth/IAuthProvider.ts`) is unchanged in shape; its
JSDoc says an Oops's refusal is an `IAuthProviderError` and that a method
never throws. `ITokenProvider.getTokens` and
`IRefreshableTokenProvider.refreshTokens` keep their signatures; their JSDoc
says they reject with an `IAuthProviderFailure` (TypeScript does not type a
rejection; `auth-errors`' `readFailure` is how a consumer reads one, §6).
`ILogonTarget` keeps returning `AuthOutcome`; its JSDoc says a target's Oops
is built through `auth-errors` (§7). `IAssertionValidator`'s JSDoc says the
shipped validators reject with an `IAuthProviderFailure` of kind
`saml-assertion`; a custom validator may throw anything — it is classified.

### 4.3 Allowlists: `as const` arrays and their unions

Each array is exported with its union type (`(typeof X)[number]`); the
runtime `Set` is built from the same array in `auth-errors` (§5.5), so the
type and the set cannot drift.

| Array (interfaces-auth 5.0.0) | Union | Source today |
|---|---|---|
| `AUTH_PROVIDER_ERROR_KINDS` | `AuthProviderErrorKind` | new (§3.1) |
| `CONFIG_FIELDS` | `ConfigField` | `KNOWN_CONFIG_FIELDS`, `refusal.ts:81-129` (47 names), plus `port`, `timeoutMs`, `payload` and `read` — field names thrown today but absent from the set (`callbackServer.ts:56-68`, `codeStrategies.ts:55`, `manualStrategies.ts:55`) |
| `CONFIG_CASES` | `ConfigCase` | new: one per configuration sentence of Appendix A §A.5 |
| `ALLOWED_VALUE_SETS` | `AllowedValueSet` | new: `'snc-qop'`, `'basic-encoding'`; their members are `SNC_QOP_VALUES` (`SncLogonProvider.ts:34`) and `BASIC_ENCODINGS` (`clientSecret.ts:44-47`), both moved here `as const` |
| `OPERATIONS` | `Operation` | every `what` passed to `safely` / `refusalFrom` / `loggedError` / `tokenEndpointError` today (Appendix A §A.8) |
| `REQUEST_PROBLEMS` | `RequestProblem` | new (§3.2) |
| `SYSTEM_CODES` | `SystemCode` | `KNOWN_SYSTEM_CODES`, `knownCodes.ts:415-430` (13) |
| `TLS_FAILURE_CODES` | `TlsFailureCode` | the keys of `TLS_CODES`, `knownCodes.ts:470-497` (18) — the words stay in the renderer |
| `OAUTH_ERROR_CODES` | `OAuthErrorCode` | `REGISTERED_ERROR_CODES`, `oauthErrorBody.ts:88-120` (25) |
| `RFC_KEYS` | `RfcKey` | `KNOWN_RFC_KEYS`, `refusal.ts:150-159` (8) |
| `ASSERTION_CHECKS` | `AssertionCheck` | `AssertionCheck`, `AssertionValidationError.ts:13-27`, and its set `refusal.ts:131-146` (14) |
| `ASSERTION_RULES` | `AssertionRule` | new: one per message, Appendix B (56) |
| `BEARER_CANDIDATE_REASONS` | `BearerCandidateReason` | `readConfirmation` and the temporal sub-rules, `assertionValidator.ts:651-679`, `:694-746` (11) |
| `SAML_STATUS_CODES` | `SamlStatusCode` | new: SAML 2.0 Core §3.2.2.2's top-level and second-level status code URIs |
| `SNC_PROBLEMS` | `SncProblem` | new (§3.2) |
| `SNC_CANDIDATE_SOURCES` | `SncCandidateSource` | `DefaultSncLibraryLocator.ts:27-32`, `:47-53` (5) |
| `SNC_UNUSABLE_REASONS` | `SncUnusableReason` | `DefaultSncLibraryLocator.ts:35-38`, `:54-58` (3) |
| `SNC_ARCHS` | `SncArch` | `libraryArchitectures.ts:11` (3) |
| `INTERACTIVE_OUTCOMES` | `InteractiveOutcome` | new (§3.2) |
| `CREDENTIAL_KINDS` | `CredentialKind` | new (§3.2) |
| `OAuth2GrantType` | (existing) | `src/token/AuthType.ts:51`, unchanged |

The small closed sets that only one kind uses (`'incomplete' | 'unusable' |
'expired'`, the `token-binding`, `not-prepared`, `logon-target`,
`connection`, `system-refused` and `renewal-unchanged` discriminants) are
`as const` arrays too, named `<KIND>_PROBLEMS` / `_VERDICTS` / … by the same
pattern, so classification can check them (§5.4).

**Branded integers.** `HttpStatus` (integer 100–599), `Count` (integer
0–1 000 000), `Port` (integer 0–65 535), `Seconds` (integer 0–86 400 000) are
`number & { readonly [brand]: … }` with unexported brand symbols, minted only
by `auth-errors`' `httpStatus()`, `count()`, `port()`, `seconds()` (each
returns `undefined` outside the range). `facts.status: 500` does not
compile; `facts.status: httpStatus(500)` does once narrowed.

**What a later release may change.** A new kind, or a new member of a
discriminant a consumer is expected to switch on (`problem`, `outcome`,
`verdict`, `case`, `rule`, `credential`, `source`, `wire`, `refused`), is a
major of `interfaces-auth` (goal invariant 5). A new member of a **code
list** — `SystemCode`, `TlsFailureCode`, `OAuthErrorCode`, `RfcKey`,
`ConfigField`, `SamlStatusCode` — is a minor; the guides say not to assert
exhaustiveness over code lists, only over kinds and discriminants.

### 4.4 What else changes in 5.0.0

- `TOKEN_PROVIDER_ERROR_CODES` / `TokenProviderErrorCode` and
  `ASSERTION_ERROR_CODES` / `AssertionErrorCode` are **removed**: they named
  thrown classes that no longer exist, and no package outside auth-providers
  imports them (§1). `STORE_ERROR_CODES` stays (the stores' own errors).
- 4.0.0's widened optional fields (`?: T | undefined`) are carried unchanged.
- `tools/package-map.json` maps every new symbol to `interfaces-auth`;
  `check:surface` and `check:graph` pass.
- `src/__typechecks__/errorContract.ts` holds the type tests of the
  contract's static rules that need no runtime (§11.2).

### 4.5 The transition for readers and producers of `IAuthRefusal`

| On 4.x a consumer… | On 5.0.0 |
|---|---|
| reads `refusal.reason` / `refusal.hint` | compiles unchanged; the words are the ones Appendix A gives (most verbatim) |
| builds `{ ok: false, refusal: { reason, hint } }` (a provider, a target, a test double) | does not compile (brand); builds through an `auth-errors` builder |
| copies or spreads a refusal into a new object | compiles (the spread keeps the brand) but is refused by the shape check (§8.2); relay the error object itself |
| matches words to decide (`reason.includes('expired')`) | switches on `refusal.kind` and `facts` (§9) |
| catches `instanceof TokenProviderError` / `ValidationError` / `CertificateMaterialError` / … from `getTokens()` | `readFailure(thrown)` and switch on `error.kind` (§6) |
| calls `refusalWords(error, what)` (auth-providers) | `classify(error, operation)` from `auth-errors`; `.reason` / `.hint` |

### 4.6 Interface siblings, by PR #123's rule

PR #123 (`mcp-abap-adt-interfaces` `9d21f14`): a sibling takes a **major**
where an exported type of its own reaches a changed type; otherwise its
dependency range is **widened** in a minor (or not touched at all).

| Package | Today | What its exported types reach in interfaces-auth | Result |
|---|---|---|---|
| `interfaces-auth` | 4.0.0 | — | **5.0.0** |
| `interfaces-auth-sap` | 3.0.0, `interfaces-auth ^4.0.0` | `ICertificateMaterial` (via `ICertificateMaterialLoader.load`) and `AUTH_TYPE_BASIC` / `AUTH_TYPE_JWT` — both unchanged in 5.0.0 | **3.1.0**: range `^4.0.0 \|\| ^5.0.0`; `__typechecks__/certificateLoaderCompatibility.ts` gains the 5.x assertion (the loader's result assigned both ways to its 4.x shape) |
| `interfaces-auth-broker` | 1.3.0, `interfaces-auth-sap ^2.0.0 \|\| ^3.0.0` | nothing in interfaces-auth (no dependency); `IAuthorizationConfig` from auth-sap, unchanged | **no release**: 3.1.0 is inside `^3.0.0` |
| `interfaces-adt-connection`, `interfaces-adt`, `interfaces-network`, `interfaces-utils`, `interfaces-calm` | — | no dependency on interfaces-auth | not touched |

## 5. `@mcp-abap-adt/auth-errors` 1.0.0

New package, own repository `fr0ster/mcp-abap-adt-auth-errors` (decided by
the user 2026-10-05). The runtime half of the contract.

### 5.1 Dependencies and layout

- `dependencies`: `@mcp-abap-adt/interfaces-auth ^5.0.0` — nothing else.
  `devDependencies` as auth-stores: `@biomejs/biome`, `typescript`, `jest`,
  `ts-jest`, `@types/jest`, `@types/node`.
- Layout, mirroring the single-package repositories (auth-stores,
  auth-providers): `package.json` (`main: dist/index.js`, `types:
  dist/index.d.ts`, `files: [dist, README.md, CHANGELOG.md, LICENSE,
  COPYING]`, `license: LGPL-3.0-only`, `engines: ^22 || ^24 || ^26`,
  `sideEffects: false`), the same scripts (`clean`, `build` = clean + biome
  errors + `tsc -p tsconfig.build.json`, `build:fast`, `test` with
  `--experimental-vm-modules`, `test:check` = `tsc --noEmit` over sources,
  tests and type tests, `lint`, `lint:check` with `--error-on-warnings`,
  `prepublishOnly`), `tsconfig.json` with auth-providers' flags verbatim
  (`strict`, `noImplicitReturns`, `noFallthroughCasesInSwitch`,
  `noImplicitOverride`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`), `tsconfig.build.json` excluding tests and
  `__typechecks__`, auth-providers' `biome.json` (`noExplicitAny` error,
  unused variables/imports warn, warnings fail `lint:check`),
  `jest.config.js`, `.github/workflows/ci.yml` (Node 22, 24, 26: `npm ci`,
  build, `test:check`, `lint:check`, `test`) and `release.yml` (on a `v*.*.*`
  tag), `CHANGELOG.md`, `README.md`, `CLAUDE.md`, `LICENSE`, `COPYING`,
  `.npmrc`, `.gitignore`.
- `src/`: `index.ts`; `allowlists.ts` (§5.5); `numbers.ts` (branded integer
  makers); `admission.ts` (§5.3); `mint.ts` (the one assertion, the
  `WeakSet`); `builders.ts` (§5.2); `words.ts` (§5.6); `diagnostics.ts`
  (renderer, §5.6); `classify.ts` (§5.4); `failure.ts` (§6); `guard.ts`
  (§8.1); `exhaustive.ts` (§9); `__tests__/`; `__typechecks__/`.

### 5.2 Builders

One builder per kind, the only exported way to obtain an error:

```ts
/** A single member of a union, else never: the correlation needs one variant. */
type One<T, A = T> = T extends unknown ? ([A] extends [T] ? T : never) : never;
/** Raw candidates, admitted by the builder: permitted fields `unknown`, the rest `never`. */
type DiagnosticsInputOf<All extends string, Allowed extends All> =
  { readonly [F in All]?: F extends Allowed ? unknown : never };

export declare const authError: {
  // kinds with diagnostics: generic over the variant, inferred from the facts
  'saml-assertion'<R extends AssertionRule>(
    facts: SamlFactsOf<One<R>>,
    diagnostics?: DiagnosticsInputOf<SamlDiagnosticField, SamlDiagnosticOf<R>>,
  ): Extract<SamlAssertionError, { variant: R }>;
  snc<P extends SncProblem>(
    facts: SncFactsOf<One<P>>,
    diagnostics?: DiagnosticsInputOf<SncDiagnosticField, SncDiagnosticOf<P>>,
  ): Extract<SncError, { variant: P }>;
  configuration<C extends ConfigCase>(
    facts: ConfigFactsOf<One<C>>,
    diagnostics?: DiagnosticsInputOf<ConfigDiagnosticField, ConfigDiagnosticOf<C>>,
  ): Extract<ConfigurationError, { variant: C }>;
} & {
  // every other kind: facts only, no diagnostics parameter at all
  readonly [K in PlainKind]: (facts: AuthProviderErrorFacts[K]) => PlainError<K>;
};

// e.g.
authError['client-certificate']({ problem: 'expired' });
authError.snc({ problem: 'no-credential', secureLoginClient: false }, { library: path });
authError['saml-assertion']({ rule: 'duplicate-id', check: 'duplicateId' }, { id: value });
```

The variant is inferred from the facts literal and the builder sets
`variant` from it; `One<…>` refuses a discriminant typed as a union (a `rule`
variable of type `AssertionRule` would otherwise widen the permitted
diagnostics to every rule's), so a producer passes a literal or narrows
first. The return type is the one variant (`Extract<…, { variant: R }>`), so
the result is a member of the correlated union of §4.1 and its diagnostics
are typed for that variant. (An input field that is forbidden is typed
`?: never`; under `exactOptionalPropertyTypes` passing any value to it is a
compile error — measured, §11.2.)

A builder: normalises the facts it is given (omits absent keys, caps and
deduplicates arrays as §3.2 says, freezes nested arrays and objects); admits
each diagnostic field (§5.3); renders `reason` / `hint` with the default words
(§5.6); calls `mint`. Facts are not re-checked at run time: their types are
the check (goal invariant 4), and `facts` from an unknown source never reach
a builder — they go through classification.

Each permitted diagnostic is `unknown` at the call: the builder, not the
caller, decides what is admitted (§5.3), and it admits a field only when the
runtime table of §4.1 permits it for the facts' discriminant — a JavaScript
caller passing a forbidden field gets it dropped, the same rule the type
enforces.

### 5.3 Diagnostics admission

The second boundary of goal invariant 4. Each check is total (it reads its
input through a guarded read, so a getter or a Proxy reads as absent) and
answers the admitted value or "drop":

| Check | Rule |
|---|---|
| `LocalPath` | a string of 1–1 024 code points; no C0 control, DEL, C1 control, U+2028/U+2029, bidirectional control (U+202A–U+202E, U+2066–U+2069) or lone surrogate; never truncated (a truncated path misleads) — longer is dropped |
| `DocumentValue` | a non-empty string with none of the characters `LocalPath` refuses; cut to 64 code points at a code-point boundary with `…` appended when longer (today's `quoteUntrusted` cap, `signedNode.ts:73-78`); the ASCII-only fields (`referenceUri`, `statusCode`) additionally refuse anything outside U+0021–U+007E |
| `XmlName` | matches `^[A-Za-z_][A-Za-z0-9._-]{0,63}$` |
| `XmlId` | matches `^[A-Za-z_][A-Za-z0-9._-]*$`, then cut as `DocumentValue` |
| `DocumentTime` | matches `^[0-9A-Za-z:.+-]{1,40}$` (an `xsd:dateTime` shape that failed strict parsing, `xsdDateTime.ts`) |
| `ConfigUri` | parses with `new URL`, protocol `http:` or `https:`, no username or password; admitted as `origin + pathname` only, ≤ 512 characters |

Admission stores the value safe to print as it is: the characters that made
`quoteUntrusted` necessary (a newline smuggled in as `&#10;`) are refused,
not escaped, so a consumer printing a raw diagnostic cannot forge a log line.
The diagnostics renderer still JSON-quotes document values, as today's
messages do.

### 5.4 Classification

```ts
export function classify(thrown: unknown, operation: Operation,
                         grant?: OAuth2GrantType): IAuthProviderError;
export function classifyOutcome(value: unknown,
                                 fallback: IAuthProviderError): AuthOutcome;
```

`classify` is the first boundary of goal invariant 4, and total — it runs
inside its own `try`, and anything that throws while reading the value
(`instanceof` with a throwing `getPrototypeOf` trap, a getter, a revoked
Proxy) answers `unknown` with the operation. In order:

1. **The value itself is minted by this copy** (`WeakSet` membership —
   a refusal handed back whole): it, as it is.
2. **Carrier extraction.** If the value is an object, its `error` property is
   read **once**, through the guarded read, into a local — whatever the
   value's class: this copy's `AuthProviderFailure`, another copy's
   `AuthProviderFailure` (whose `instanceof` against this copy's class is
   false), or any object with an `error` key. (connection's
   `AuthRefusedError` carries `refusal`, not `error`, and is not a carrier of
   this contract: it is not unwrapped.) Every later
   step reads that local, never the property again (a getter could answer
   differently twice). If the local is minted by this copy: that error, as it
   is — diagnostics included.
3. **Structural rebuild**, tried on the local of step 2 first, then on the
   value itself (a bare error object from another copy, as a refusal is): its
   `kind` is in `AUTH_PROVIDER_ERROR_KINDS` and every fact passes its runtime
   set or range (one validator per kind, `satisfies` a mapped type over the
   kinds); each property is read once, guarded. The result is **re-minted**
   with words rendered here, from `kind` and the checked `facts` only: its
   own `reason`, `hint` **and `diagnostics` are never read**. Anything that
   fails a check falls through to step 4 with the original value.
4. A TLS failure (`code` in `TLS_FAILURE_CODES`): `tls`.
5. A value with an integer status (`status`, else `response.status`), a
   registered OAuth error (`oauthError`, else `response.data.error`) or an
   allowlisted system `code`: `unknown` with those facts.
6. Anything else: `unknown` with the operation.

No `message`, `cause`, `stack`, `name`, body or string form is read at any
step — the same reads `refusalFrom` does today (`refusal.ts:222-236`), less the
`instanceof` ladder, which the single carrier class replaces.

`classifyOutcome` handles an `AuthOutcome` that came from a collaborator (a
logon target, a consumer's provider): `{ ok: true }` (exactly, read guarded)
answers the frozen `OK`; `{ ok: false, refusal }` whose refusal (read once)
passes step 1 or step 3 above answers a fresh `{ ok: false, refusal }` with
that error — this copy's minted object as it is, anything else rebuilt
without diagnostics; anything else answers `{ ok: false, refusal: fallback }`.

**Diagnostics have provenance, not only a shape.** Admission (§5.3) checks a
value's shape; it cannot tell a Secure Login Client path from a token that
happens to look like a path. So diagnostics are kept only on the one trusted
route: **a builder call made by a producer at an approved extraction site**
(§3.3), which mints the error into this copy's `WeakSet`. That membership is
the provenance mark, and it is the only one — there is no cross-copy
provenance mechanism: an error rebuilt from a structure (step 3), whatever
copy or forger it came from, keeps its kind and its allowlisted facts and
drops every diagnostic (Appendix C, L13). The approved sites are enforced by
the shape check (§8.2, rule 6): a builder call passing a diagnostics argument
is allowed only in the files and functions Appendix A names as a field's
source.

### 5.5 Allowlist runtime sets

`allowlists.ts` builds one frozen `ReadonlySet` per array of §4.3 —
`new Set(SYSTEM_CODES)` and so on — and nothing else. A type test asserts each
set's element type is the array's union. These sets are exported for
producers that check a value before choosing a fact (`isSystemCode(v): v is
SystemCode`, one guard per code list).

### 5.6 Renderers and helpers

- `WORDS` — `satisfies { readonly [K in AuthProviderErrorKind]: (facts:
  AuthProviderErrorFacts[K]) => { reason: string; hint?: string } }`, so a
  kind without words does not compile. Within a kind, every discriminant is
  rendered by a `switch` ending in `unreachable(x: never)`, so a new `case`,
  `rule`, `outcome` or `problem` without words does not compile either. The
  words are Appendix A's "new words" column; where it says *verbatim*, the
  test of §11.1 pins the exact string.
- `render(kind, facts)` — the default `{ reason, hint }`, exported so any
  consumer can produce the same words (the broker relays and copies none).
- `renderDiagnostics(error): string | undefined` — one line per field
  (`library: "C:\\…\\sapcrypto.dll"`, `candidates: SNC_LIB_64
  "/opt/…" (missing); registry "C:\\…" (wrong architecture)`,
  `issuer: "https://idp…"`), JSON-quoted; `undefined` when there is
  none. Never called by `render`.
- `logFields(error)` — what a log line may carry: `{ error: reason, kind,
  status?, diagnostics? }` (`diagnostics` as a separate field, so a consumer's
  logger can drop it); replaces `loggedError`'s `{ error, status? }`
  (`refusal.ts:366-377`).
- `blamesCredential(error): boolean` — the table of §3.1.
- `matchKind`, `unreachableKind` (§9); `guard`, `relayOutcome` (§7, §8.1);
  `AuthProviderFailure`, `readFailure`, `isAuthProviderFailure` (§6);
  `OK` (the frozen `{ ok: true }`).

## 6. Thrown token errors

**Decision: one class, holding the error.**

```ts
export class AuthProviderFailure extends Error implements IAuthProviderFailure {
  override readonly name = 'AuthProviderFailure';
  readonly error: IAuthProviderError;
  // message: error.reason, or `${reason} — ${hint}` with a hint
  //          (connection's AuthRefusedError format, authErrors.ts:26-28);
  // no `cause`, no diagnostics in the message.
}
export function readFailure(thrown: unknown, operation: Operation): IAuthProviderError; // = classify
export function isAuthProviderFailure(value: unknown): value is IAuthProviderFailure;
```

`AuthProviderFailure`'s constructor takes a minted error only (typed, and
checked against the `WeakSet` — an unminted value becomes `unknown`), so it
cannot be built with free text.

**Why not extend the existing classes.** Thirteen classes
(`refusal.ts:162-178`) each with its own message rules is the "words chosen
per class" design the contract replaces; extending them would keep two
languages — a class hierarchy and a kind — that can disagree, and every
`instanceof` across two installed copies of auth-providers fails silently
today. One class with one value has one reading, and `readFailure` reads it
across copies (§5.4, step 3).

**What happens to today's classes** (auth-providers 6.0.0):

| Class | Fate | Its information goes to |
|---|---|---|
| `TokenProviderError`, `ValidationError`, `RefreshError`, `SessionDataError`, `ServiceKeyError`, `BrowserAuthError` | deleted | `configuration`, `credential-refused` (`refresh-token`), `interactive-login`; `SessionDataError` / `ServiceKeyError` have no producer (README "Error Handling", `README.md:2062`) and go without a replacement |
| `AssertionValidationError` (and `AssertionCheck`) | deleted; `AssertionCheck` moves to interfaces-auth | `saml-assertion` `{ check, rule, … }` |
| `CertificateMaterialError` (and its deprecated `words`) | deleted | `client-certificate` |
| `ClientAuthenticationError`, `ClientAuthenticationResultError`, `BasicClientIdError` | deleted | `client-authentication` |
| `TokenEndpointError` | deleted | `request-failed` (status, OAuth code, system code as facts) |
| `DeviceCodePresentationError`, `CallbackScopeError`, `AuthorizationRefusedError`, `SncLibraryNotFoundError` (internal) | deleted | `interactive-login`, `snc` |
| the reduced `AxiosError` of `sendTokenRequest` (`tokenRequest.ts:293-341`) | no longer escapes | each site builds `request-failed` / `tls` from it before throwing |

`error.code` strings and `missingFields` disappear with the classes; `kind`
and `facts.fields` say the same (Appendix C, L12).

**Where the throw is built.** Every site that throws today throws an
`AuthProviderFailure` built with the kind of Appendix A. `getTokens()` and
`refreshTokens()` run their bodies in a `try` whose `catch` rethrows
`new AuthProviderFailure(classify(error, 'token-request', grant))` — so a
consumer's strategy, loader or presenter that throws its own error reaches
the caller as a classified failure, never as itself (Appendix C, L3). The
provider's internal control flow (a refused refresh falling back to a login,
`BaseTokenProvider.ts:475-487`) reads `error.kind`, not a class. The
`remembered` refusal (`BaseTokenProvider.ts:146-156`, `:432-451`) holds the
`IAuthProviderError` the renewal produced and answers it as is (frozen, so
the `structuredClone` at `:741` goes).

**The OAuth error description.** A token endpoint's `error_description`
(and `error_uri`) is server free text and never enters an error. Decision,
for approval (Appendix C, L1): each wrapping site logs it once at `debug`
through the provider's logger, redacted by `describeOAuthErrorBody` exactly
as today (`oauthErrorBody.ts:149-166`), beside the error's `logFields` —
a log line, not an error. The alternative is to drop it entirely.

## 7. Logon targets (connection) and rule 4

**How a target builds its refusal.** connection depends on `auth-errors` and
its two targets answer:

```ts
// RfcTransport.ts:477-487
tlsMaterial: () => ({ ok: false,
  refusal: authError['logon-target']({ wire: 'rfc', refused: 'tls-material' }) }),
// HttpTransport.ts:514-528
logonParameters: () => ({ ok: false,
  refusal: authError['logon-target']({ wire: 'http', refused: 'logon-parameters' }) }),
```

Rendered words: "this wire carries no TLS material (RFC)" and "this wire takes
no logon parameters (HTTP)" — verbatim. connection's own three refusals
(`authErrors.ts:56-71`) become `authError.connection({ problem, at })`.
Where connection acts on a refusal it reads `kind` (it does not today; the
`AuthRefusedError` it throws keeps `refusal`, now an `IAuthProviderError`,
and its message `reason — hint`).

**connection re-mints what it receives.** `guarded` (`authErrors.ts:90-98`)
passes every provider answer through `classifyOutcome(answer, fallback)`, with
`fallback = authError.connection({ problem: 'provider-threw', at })`: a
consumer's own `IAuthProvider` written in JavaScript can return any object,
and an `AuthRefusedError` message built from it would carry its free text.
A provider's throw stays `provider-threw` (today's `PROVIDER_FAILED`).

**How a provider relays a target's answer (rule 4).** A provider never
returns a target's object. `auth-errors` exports:

```ts
export interface RelayedOutcome {
  readonly outcome: AuthOutcome;
  /** The call threw (a broken target), as opposed to answering. */
  readonly thrown: boolean;
}
export function relayOutcome(
  call: () => unknown,                 // logon.tlsMaterial(...) / logonParameters(...)
  refused: 'tls-material' | 'logon-parameters',
  operation: Operation,
): RelayedOutcome;
```

It runs the call inside a `try`: a throw becomes `{ outcome: { ok: false,
refusal: classify(thrown, operation) }, thrown: true }` (today `atTarget`,
`BaseTokenProvider.ts:812-821`, which returns the same pair); a returned
value goes through `classifyOutcome` with fallback
`authError['logon-target']({ wire: 'unknown', refused })` and `thrown:
false` — even when the value is unusable, because the target answered. The
disposition is kept beside the normalised outcome because a provider decides
on it: the same refusal object means "the wire cannot take this" when
returned and "the target is broken" when thrown. A connection refusal minted
by the same `auth-errors` passes through as the same frozen object; one from
another copy is rebuilt (without diagnostics); anything else is the fallback.
Then:

- **no other way in** — `CertificateAuthProvider.establish`
  (`CertificateAuthProvider.ts:60-74`) and `SncLogonProvider.establish`
  (`SncLogonProvider.ts:172-189`): return `relayOutcome(...).outcome` — the
  target's Oops, returned or thrown, is the provider's own;
- **another way in** — `BasicAuthProvider.establish`
  (`BasicAuthProvider.ts:25-30`): `relayOutcome` runs; its outcome is
  discarded and the provider answers `OK`, as today (today a throwing
  `logonParameters` is caught by `safely` and answers Oops; that stays:
  `thrown: true` answers its outcome, `thrown: false` answers `OK`);
- **token providers** — `BaseTokenProvider.establish`
  (`BaseTokenProvider.ts:669-702`): unchanged decision table, reading both
  fields as it reads `atTarget`'s today (`:692-700`): an unbound token answers
  `OK` unless `thrown`, then `outcome`; a bound or unknown one answers
  `outcome`. `authorize()`'s write of the token (`:732-737`) uses the same
  pair.

Tests (auth-providers): for each of the three shapes above, the same minted
refusal object **returned** by the target and **thrown** by it — with an
unbound token, a bound one and an unknown one for `BaseTokenProvider`, and for
`BasicAuthProvider` — asserting the answers differ exactly as the table says
(returned + unbound → `OK`; thrown + unbound → Oops); and a target returning
garbage versus throwing garbage (`logon-target` fallback, `thrown: false`,
versus `unknown`, `thrown: true`). Load-bearing: collapsing the pair to the
outcome alone turns the returned+unbound case red.

## 8. Rule 1 held structurally

TypeScript does not track what a function throws; a brand on a result proves
only where the result came from. Rule 1 is held by three things together.

### 8.1 One owner of the four methods

`auth-errors` exports the boundary:

```ts
export async function guard(
  operation: Operation,                       // a value, already validated
  body: () => AuthOutcome | Promise<AuthOutcome>,
  grant?: () => unknown,                      // read inside the boundary
): Promise<AuthOutcome>;
```

Everything that can throw runs inside one `try`, the reading of the grant
included: on entry `guard` holds `operation` (a plain value its caller
validated) and `g = undefined`; inside the `try` it calls `grant?.()`, keeps
the result only if it is in the `OAuth2GrantType` set, then runs `body()`.
The `catch` uses only those two locals — never a property of the provider —
and `classify`, which is total. A throwing `grant` therefore becomes a
refusal naming the operation without a grant; nothing is evaluated outside
the `try` but the two locals' initial values.

auth-providers adds `AuthProviderBase` (`src/auth/AuthProviderBase.ts`,
exported for consumers who write a provider of their own):

```ts
type Moment = 'prepare' | 'establish' | 'authorize' | 'rejected';
/** Fixed, used when a configured operation is not on the list. */
const FALLBACK: Readonly<Record<Moment, Operation>> =
  { prepare: 'preparing', establish: 'establishing',
    authorize: 'authorizing', rejected: 'reading-rejection' };

export abstract class AuthProviderBase implements IAuthProvider {
  abstract readonly kind: string;
  /** Base-owned, captured and validated once: no subclass can override it. */
  readonly #moments: Readonly<Record<Moment, Operation>>;

  protected constructor(moments: Readonly<Record<Moment, Operation>>) {
    // Each entry read once, guarded, checked against the OPERATIONS set;
    // anything else (a throwing getter, a value off the list) is FALLBACK's.
    this.#moments = Object.freeze(validatedMoments(moments, FALLBACK));
  }
  /** Read only inside guard's try. */
  protected grant(): OAuth2GrantType | undefined { return undefined; }

  prepare()                   { return guard(this.#moments.prepare,   () => this.onPrepare(),     () => this.grant()); }
  establish(l: ILogonTarget)  { return guard(this.#moments.establish, () => this.onEstablish(l), () => this.grant()); }
  authorize(r: IRequestTarget){ return guard(this.#moments.authorize, () => this.onAuthorize(r), () => this.grant()); }
  rejected(x: IAuthRejection) { return guard(this.#moments.rejected,  () => this.onRejected(x),  () => this.grant()); }

  protected abstract onPrepare(): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onEstablish(logon: ILogonTarget): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onAuthorize(request: IRequestTarget): AuthOutcome | Promise<AuthOutcome>;
  protected abstract onRejected(rejection: IAuthRejection): AuthOutcome | Promise<AuthOutcome>;
}
```

Every provider — the five credentials, `SncLogonProvider`, `BaseTokenProvider`
(and so all nine token providers) — extends it. `safely`
(`refusal.ts:380-389`), SNC's `bounded` (`SncLogonProvider.ts:56-65`) and the
unguarded `oops` before `safely` in `CertificateAuthProvider.establish`
(`CertificateAuthProvider.ts:55-59`) disappear: the guard is outside every
body. The words of SNC's outer boundary ("the SNC provider failed while
resolving the SNC library (unknown error)") come from the SNC operations'
words, so they stay verbatim.

Nothing a subclass controls is evaluated outside `guard`'s `try`: the
operations live in an ECMAScript private field (`#moments`) of the base,
which a subclass can neither override nor shadow with a getter — a subclass
declaring its own `moments` getter changes nothing the base reads — and they
were validated against `OPERATIONS` when captured, so a constructor argument
with a throwing getter or a value off the list yields the fixed `FALLBACK`
operation instead of throwing out of a method later. `grant()` (which
`BaseTokenProvider` implements over the overridable `getAuthType()`) and the
`on…` dispatch are called inside the `try`. `#moments` is read on a frozen
object of `Operation` strings, which cannot throw; `classify` is total; so
`guard` cannot reject. (A constructor that throws is not a moment of the
contract: rule 1 covers the four methods.) The four fallback operations join
`OPERATIONS` (Appendix A §A.8).

Fixtures (runtime, §8.3): a subclass whose `grant()` throws; one whose
`getAuthType()` throws (through `BaseTokenProvider`); one that defines a
throwing `moments` getter; one constructed with a `moments` object whose
`establish` getter throws and one whose `prepare` is `'not-an-operation'` —
each method of each answers Oops with a minted error (the fallback
operation, no grant, where the metadata failed) and never rejects.
Load-bearing: moving `this.grant()` back out of the thunk turns the first
fixture red.

### 8.2 The shape check (the lint rule)

TypeScript has no `final`, so "cannot bypass" is a check, run by `lint:check`
after Biome: `tools/check-provider-shape.mjs` in auth-providers, built on the
TypeScript compiler API (it needs type information — whether a class reaches
`AuthProviderBase` through any chain of `extends` — which Biome's GritQL
plugins do not have). It refuses, in `src/` outside tests:

1. a class that `implements IAuthProvider` other than `AuthProviderBase`;
2. a class that reaches `AuthProviderBase` and declares a member named
   `prepare`, `establish`, `authorize` or `rejected`;
3. an object that structurally satisfies `IAuthProvider` (an object literal
   or a function returning one) — every provider is a class reaching the base;
4. a type assertion (`as`, `<T>`) whose target is or contains
   `IAuthProviderError`, `IAuthRefusal`, `AuthOutcome`,
   `IAuthProviderFailure` or a branded integer;
5. a spread or `Object.assign` whose source is typed `IAuthProviderError` (a
   spread keeps the brand and would let `{ ...minted, reason }` compile);
6. a builder call (`authError.<kind>(facts, diagnostics)`) passing a
   diagnostics argument outside the approved extraction sites — a list in
   `tools/diagnostic-sites.json` (file and function per diagnostic field),
   reviewed with Appendix A's sources (§3.3) and changed only with it;
7. a call of `guard` whose `grant` argument is not a function expression, or
   any read of a provider property in a `guard` call's argument list other
   than `this.#moments` (the base's own field) — so no metadata is evaluated
   before the boundary.

connection runs the same script for rules 4, 5 and 6 (it has no providers,
and its refusals carry no diagnostics, so its site list is empty);
`auth-errors` runs rule 4 with one allowed site, `mint` in `mint.ts`; the
broker runs rules 4, 5 and 6 (empty list). Each repository's test suite runs the script
against fixtures that break each rule and expects each to be reported
(§11.3).

### 8.3 Runtime tests

A table-driven suite in auth-providers (`src/__tests__/contract/rule1.test.ts`)
calls every method of every provider with every collaborator throwing each
hostile value of §11.1 — the strategy, the client authentication and its
`tlsMaterial`, the certificate loader, the device-code presenter, the
assertion validator and replay store, `onTokens`, the browser launcher, the
SNC locator and probes, the logger, the logon and request targets, the
`ITokenRefresher` — and asserts each call resolves (never rejects) to an
outcome whose refusal, if any, is minted (`isMinted`), and that no secret
placed in the thrown value appears in the outcome's JSON, `reason`, `hint` or
`renderDiagnostics`.

## 9. Exhaustiveness for consumers

The required pattern — one of two, both checked by the compiler:

```ts
import { matchKind, unreachableKind } from '@mcp-abap-adt/auth-errors';

// A: a handler map typed over every kind
const text = matchKind(error, {
  configuration: (e) => …, 'client-certificate': (e) => …, /* … all sixteen */
  unknown: (e) => …,
});

// B: a switch with an exhaustiveness check in default
switch (error.kind) {
  case 'configuration': …; break;
  // … every kind …
  default: return fallback(unreachableKind(error));   // error: never here
}
```

- `matchKind<R>(error, handlers: { readonly [K in Kind]: (e:
  AuthProviderErrorOf<K>) => R }): R` — a missing handler does not compile.
  **At run time a handler only ever receives an error this copy minted.**
  `matchKind` first normalises its argument: an error minted by this copy
  (the `WeakSet`) is dispatched as it is; anything else — an error minted by
  another copy, one from a newer contract whose `kind` this build does not
  know, a known kind whose facts carry a member this build does not know —
  goes through `classify(error, 'unfamiliar-error')` (§5.4). A known kind
  with valid facts comes back rebuilt as that kind (without diagnostics,
  L13); everything else comes back as a minted `unknown` error with
  `facts.operation: 'unfamiliar-error'` — the required facts of the
  `unknown` handler's type are therefore always there. `classify` is total,
  so the map never throws for a foreign value either.
- `unreachableKind(error: never): IAuthProviderError` — compiles only when
  every kind was handled; at run time it returns the same normalisation:
  `classify(error, 'unfamiliar-error')`, a minted error of a kind this build
  knows, with its facts complete — never the foreign object typed as the
  union — so a default branch can render it generically, or read its facts,
  instead of throwing.

`'unfamiliar-error'` joins `OPERATIONS` (A.8); its words: "an
authentication error of a kind this version does not know".

Tests (auth-errors, version skew): an object shaped as a minted error from a
newer contract — `kind: 'future-kind'`, and separately `kind: 'tls'` with
`code` outside `TLS_FAILURE_CODES`, and `kind: 'snc'` with an unknown
`problem` — passed to `matchKind` with handlers that read their required
facts (`unknown: (e) => e.facts.operation.length`, `tls: (e) =>
e.facts.code.length`): no handler throws, the `unknown` handler receives
`operation: 'unfamiliar-error'`, and a valid foreign `tls` error reaches the
`tls` handler; the same values through a `switch` whose `default` calls
`unreachableKind(e as never)` and reads `facts.operation` of the result.
Load-bearing: passing the argument through unnormalised turns the
`future-kind` case red (a `TypeError` reading `facts.operation`).

A `switch` with neither is not checked by TypeScript; the auth-errors README,
the interfaces-auth JSDoc of `IAuthProviderError` and auth-providers' README
say so and require one of the two. A new kind is a major of interfaces-auth,
so a consumer following the pattern stops compiling on its upgrade, not at
run time (goal invariant 5).

## 10. Per repository

Order and gating are the goal's Path (steps 5–10); versions below.

### 10.1 `mcp-abap-adt-interfaces` — interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0

- `packages/interfaces-auth/src/error/`: `IAuthProviderError.ts`, `kinds.ts`
  (arrays and unions of §4.3), `facts.ts`, `diagnostics.ts`,
  `IAuthProviderFailure.ts`, `numbers.ts` (branded integer types);
  `src/auth/AuthOutcome.ts` (§4.2); JSDoc of `IAuthProvider`,
  `IAuthTargets`, `IAssertionValidator`, `ITokenProvider`,
  `IRefreshableTokenProvider`; `src/token/TokenProviderErrorCodes.ts` and
  `src/auth/AssertionErrorCodes.ts` deleted; `src/index.ts`;
  `src/__typechecks__/errorContract.ts`.
- `packages/interfaces-auth-sap`: dependency range, compatibility type check,
  CHANGELOG, migration note "nothing to do".
- `tools/package-map.json`; both CHANGELOGs; interfaces-auth README: the error
  contract section, the exhaustiveness requirement, a "Migrating to 5.0.0"
  note (§4.5).

### 10.2 `mcp-abap-adt-auth-errors` 1.0.0 (new)

As §5. README: what an error is; the sixteen kinds with their facts and
words (generated table, §11.4); diagnostics and their admission; the two
exhaustiveness patterns; `classify` / `readFailure` for catching;
`guard` / `relayOutcome` / `AuthProviderBase` (pointer) for producers;
the brand and its limit.

### 10.3 `mcp-abap-connection` 12.0.0

- `package.json`: `interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0`,
  `auth-errors ^1.0.0` (it is on `^3.0.0` / `^2.0.0` today, so this also
  takes interfaces-auth 4.0.0's widened fields). Major: `AuthRefusedError`'s
  `refusal` changes type, and its exported refusal constants change shape.
- `src/connection/authErrors.ts`: the three constants become minted errors;
  `guarded` re-mints (§7); `AuthRefusedError` unchanged in shape and message
  format.
- `src/connection/RfcTransport.ts:477-487`, `HttpTransport.ts:514-528`: the
  targets (§7).
- `AbstractAbapConnection.ts:975`, `:1612`: the minted errors.
- `tools/check-provider-shape.mjs` rules 4–5, wired into `lint:check`.
- README / CHANGELOG: migration note (a custom `ILogonTarget` builds its
  refusal through `auth-errors`; `AuthRefusedError.refusal.kind`).

`interfaces-adt-connection` stays where it is: moving connection to its 2.0.0
is not this work.

### 10.4 `mcp-abap-adt-auth-providers` 6.0.0 (this PR)

- `package.json`: `interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0`,
  `auth-errors ^1.0.0`.
- New: `src/auth/AuthProviderBase.ts`; `tools/check-provider-shape.mjs`.
- Rewritten on the builders and `classify`: `src/auth/refusal.ts` (only
  `KNOWN_*` move out; `refusalFrom`, `refusalWords`, `loggedError`, `safely`,
  `oops`, the word constants go), `src/auth/rejection.ts` (answers
  `credential-refused` / `system-refused`), `src/auth/knownCodes.ts` (code
  lists move to interfaces-auth; `readSafely` stays), `src/auth/tokenRequest.ts`
  (`tokenEndpointError` builds `request-failed` / `tls`), every token site of
  Appendix A §A.4, `src/auth/callbackServer.ts` and
  `src/strategies/*` (`interactive-login`), `src/snc/*` (`snc`),
  `src/validation/*` (`saml-assertion`, the rule ids of Appendix B),
  `src/auth/samlBearerAssertion.ts`, `src/auth/certificateMaterial.ts`,
  `src/clientAuthentication/*`, the credentials, `BaseTokenProvider`,
  every provider's configuration throws.
- Deleted: `src/errors/` (all five files), `src/auth/callbackScopeError.ts`,
  `src/auth/contractShape.ts` (`asContract`, goal step 8), `refusalWords` and
  the error classes from `src/index.ts`.
- README: "What `rejected()` answers" (`README.md:217-235`), "Refusals"
  (`:894-905`), "Refusal messages" (`:1372-1468`), "Errors" (`:1649-1656`),
  "Error Handling" and "Relaying a refusal" (`:2018-2107`) rewritten on kinds;
  the refusal tables generated (§11.4); a "Migrating to 6.0.0" section
  (catch with `readFailure`, switch on `kind`, `refusalWords` → `classify`,
  the classes removed, Appendix C's losses stated).
- `CLAUDE.md`: provider rules 1, 2, 5, 8 and "Error classes" restated on
  kinds; the module structure; `docs/passwordless-sso.md:235-237` quotes "the
  SNC library has no credential to present (A2200019)", which stays verbatim
  — checked, unchanged. `docs/btp-setup.md` quotes no refusal (checked).
- Deleted at release: this spec, the plan and the goal
  (`docs/superpowers/`).

### 10.5 `mcp-abap-adt-auth-stores` 4.0.0

Its unreleased change is already breaking (Node 22/24/26 engines,
`CHANGELOG.md` "Unreleased"), so it releases as a major anyway. Moves to
`interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0`,
`interfaces-auth-broker ^1.3.0`; deletes its `asContract`. It produces no
auth refusal (it uses only `STORE_ERROR_CODES`, `StoreErrors.ts:5-6`), so no
kind. Migration note: none beyond the versions.

### 10.6 `mcp-abap-adt-auth-broker` 5.0.0 and `auth-broker-cli` 3.0.0

- Dependencies: interfaces-auth `^5.0.0`, interfaces-auth-sap `^3.1.0`,
  interfaces-auth-broker `^1.3.0`, auth-errors `^1.0.0`, auth-providers
  `^6.0.0`, auth-stores `^4.0.0`.
- `clientAuthentication.ts:77-80` (the copied certificate phrases) and
  `:220-226` deleted. `resolveClientAuthentication` catches the strategy's
  throw with `readFailure(error, 'client-authentication-strategy')`; the
  `DestinationConfigError` it throws gains `readonly error?:
  IAuthProviderError` and its reason becomes `the clientAuthentication
  strategy refused: ${error.reason}` for `client-certificate`, else `the
  clientAuthentication strategy failed` — the same words as today for every
  case, rendered, not copied. The broker's own `ClientUnavailableError` words
  (`:62-63`, "the destination has no client certificate / secret"),
  `CERTIFICATE_HINT` (`destinations.ts:146-147`) and every other
  `DestinationConfigError` are the broker's configuration language, not a
  provider's, and stay.
- `destinations.ts:247-255`: `error instanceof ValidationError` becomes
  `readFailure(error, …).kind === 'configuration'`, `facts.fields` mapped
  through `SNC_FIELDS` as today.
- `getTokens` / `refreshTokens` relay the provider's `AuthProviderFailure`
  unchanged.
- `tools/check-provider-shape.mjs` rules 4–5.
- Major: what `AuthBroker.getTokens()` rejects with changes class, and
  `DestinationConfigError` gains a field. The CLI is a major because what it
  prints for a failed login changes (`generateEnv.ts:262-264`,
  `mcp-auth.ts:587-591`): the message is the rendered `reason — hint`, and
  it prints `renderDiagnostics(error)` on its own line after it.
- README / CHANGELOG / migration notes of both packages.

## 11. Testing and release gates

### 11.1 Runtime tests

In `auth-errors`:

- **Hostile values through `classify` and `classifyOutcome`:** a Proxy whose
  every trap throws; a revoked Proxy; getters throwing on `status`, `code`,
  `response`, `error`, `oauthError`, `ok`, `refusal`; an `instanceof` whose
  `getPrototypeOf` trap throws; a forged carrier `{ error: { kind:
  'client-certificate', facts: { problem: 'expired' }, reason: '<secret>' } }`
  (re-minted, the secret gone); a carrier with an unknown `kind`; facts out of
  their sets; `null`, `undefined`, strings, numbers, symbols, functions.
- **Carriers from another copy:** an `AuthProviderFailure` instance built by
  a second copy of the package (loaded under another path), for every kind —
  classified by the first copy into the same kind and facts, re-rendered; the
  same with a getter on `error` that answers a valid error on the first read
  and a forged one on the second (only the first is used); a foreign carrier
  whose `error` is invalid falls through to steps 4–6 on the carrier.
- **Forged diagnostics:** a structurally valid `snc` error (own copy's shape,
  not minted) whose `diagnostics.library` holds a JWT-shaped token that passes
  `LocalPath`, a `saml-assertion` error whose `diagnostics.issuer` holds an
  exception message, and a foreign-copy `AuthProviderFailure` carrying the
  same — each classified (`classify`, `classifyOutcome`, `relayOutcome`):
  the result has its kind and facts and **no** `diagnostics`, and the marker
  appears in none of its renderings. A same-copy minted error with
  diagnostics keeps them through every relay (the positive case).
- **Exception text excluded:** for each kind, an `Error` whose `message`,
  `cause`, `stack` and `name` hold a marker secret is classified and built
  through every path; the marker appears in no `JSON.stringify(error)`,
  `reason`, `hint`, `renderDiagnostics(error)`, `logFields(error)` or
  `AuthProviderFailure.message`.
- **Diagnostics admission:** each check of §5.3 with an accepted value, each
  refused character class (C0, DEL, C1, U+2028/9, each bidi control, a lone
  surrogate), the length limits on both sides, a non-string, a throwing
  getter; attacker-shaped assertion values (`&#10;`-decoded newlines in an
  Issuer, a 10 000-character Destination, an `xsd:dateTime` with a quote, a
  `referenceUri` with a space); a `ConfigUri` with userinfo, a query, a
  fragment, a `javascript:` scheme. Each refused value is dropped and the
  error still minted.
- **Words:** every kind × every discriminant value renders; each row of
  Appendix A marked *verbatim* asserts the exact string; no rendered string
  contains a diagnostic value (each diagnostic built with a marker).
- **Re-mint across copies:** a second copy of the built package loaded under
  another path; an error minted by one — bare, and inside that copy's
  `AuthProviderFailure` — is classified by the other and comes out equal in
  kind and facts, re-rendered, without diagnostics.

In auth-providers: the rule 1 suite (§8.3); `noTokensInLogs.test.ts` and
`thrownMessages.test.ts` rewritten on `logFields` and `AuthProviderFailure`;
every inventory row of Appendix A asserts its new kind and facts at its site
(one test per row, named by the row number); `samlValidation.test.ts` and the
validator tests assert `rule` and the one diagnostic of Appendix B per rule;
`rejectedReadsTheRejection.test.ts` on `credential-refused` / `system-refused`
and `blamesCredential`. In connection: the two targets' errors; `guarded`
re-minting a forged provider refusal and a provider that throws. In the
broker: `DestinationConfigError.error` deep-equal to the provider's error for
each certificate problem, its message containing `render(...)`'s words, and
no certificate phrase left in `src` (a test reads the source files).

**Load-bearing proof.** For each runtime rule — every admission check, each
classification step, `relayOutcome`'s re-mint, the guard's catch, the
broker's relay — the plan names the deliberate break (delete the check,
return the target's object, read `message`), the test that goes red, and the
revert; the PR records each run (CLAUDE.md "Testing"; memory "mutate each
half").

### 11.2 Type tests

`src/__typechecks__/*.ts`, part of `test:check` (compiled, never run). Each
static rule is a line that must fail, under `@ts-expect-error` — an unused
directive fails `test:check`, so each line is load-bearing by construction:

- an object literal assigned to `IAuthProviderError`, `IAuthRefusal`, and as
  `refusal` of `AuthOutcome` (interfaces-auth);
- a fact of another kind (`authError.tls({ problem: 'expired' })`), a fact of
  the wrong type (`status: 500`, `code: 'EWHATEVER'`, `rule: 'audience-not-us'`
  with `check: 'issuer'`);
- **the correlation of facts and diagnostics** — the probe below, compiled
  on 2026-10-05 with TypeScript 5.9.3 (the version installed in this
  repository) under auth-providers' flags (`strict`,
  `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`,
  `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noImplicitOverride`),
  against a model of §4.1 / §5.2 with three rules, three SNC problems, two
  configuration cases and one plain kind. Result: **0 errors with the 14
  directives in place** (every one used); **14 errors with them removed**,
  each the expected one (TS2322 "not assignable to type 'undefined'" for a
  forbidden builder field, TS2322 for the fixed `check`, TS2322 "… to type
  'never'" for a union discriminant, TS2554 "Expected 1 arguments" for a
  diagnostics argument on a plain kind, TS2339 "Property 'id' does not exist
  on type '{ readonly issuer?: DocumentValue; }'" after narrowing, TS2339
  "… on type 'never'" for a variant without diagnostics, TS2322 "has no
  properties in common" for the mismatched pairing without the brand). The
  type tests in `auth-errors` and `interfaces-auth` are this probe on the full
  types:

```ts
// builders — exact public signatures
authError['saml-assertion']({ rule: 'untrusted-issuer', check: 'issuer' }, { issuer: v }); // ok
authError['saml-assertion']({ rule: 'duplicate-id', check: 'duplicateId' }, { id: v });    // ok
authError.snc({ problem: 'no-credential' }, { library: v });                               // ok
authError.configuration({ case: 'saml-acs-mismatch', fields: ['acsUrl'] },
                        { configuredUri: v, strategyUri: v });                             // ok
const a = authError['saml-assertion']({ rule: 'untrusted-issuer', check: 'issuer' }, { issuer: v });
const i: string | undefined = a.diagnostics?.issuer;                                       // ok: the result keeps its variant
// @ts-expect-error duplicate-id carries no issuer
authError['saml-assertion']({ rule: 'duplicate-id', check: 'duplicateId' }, { issuer: v });
// @ts-expect-error logon-refused carries no library
authError.snc({ problem: 'logon-refused' }, { library: v });
// @ts-expect-error a non-mismatch case carries no configuredUri
authError.configuration({ case: 'required-fields-missing', fields: ['clientId'] }, { configuredUri: v });
// @ts-expect-error the rule's check is fixed
authError['saml-assertion']({ rule: 'duplicate-id', check: 'issuer' });
declare const anyRule: AssertionRule;
// @ts-expect-error a discriminant typed as the whole union
authError['saml-assertion']({ rule: anyRule, check: 'issuer' }, { issuer: v });
// @ts-expect-error no diagnostics parameter on a kind without diagnostics
authError['client-certificate']({ problem: 'expired' }, { library: v });

// consumers — narrowing by kind + variant
declare const e: IAuthProviderError;
if (e.kind === 'saml-assertion' && e.variant === 'untrusted-issuer') {
  use(e.diagnostics?.issuer);                       // ok
  const r: 'untrusted-issuer' = e.facts.rule;       // ok: facts narrowed too
  // @ts-expect-error id is not a field of this variant
  use(e.diagnostics?.id);
}
if (e.kind === 'saml-assertion' && e.variant === 'expired') {
  // @ts-expect-error this variant has no diagnostics
  use(e.diagnostics?.issuer);
}
if (e.kind === 'snc' && e.variant === 'no-credential') {
  use(e.diagnostics?.library);                      // ok
  // @ts-expect-error candidatePaths belongs to library-not-found
  use(e.diagnostics?.candidatePaths);
}
if (e.kind === 'configuration' && e.variant === 'required-fields-missing') {
  // @ts-expect-error no diagnostics for this case
  use(e.diagnostics?.configuredUri);
}
if (e.kind === 'client-certificate') {
  // @ts-expect-error no diagnostics on this kind
  use(e.diagnostics?.library);
}
// facts.rule alone does not narrow the union (why `variant` is top-level):
if (e.kind === 'saml-assertion' && e.facts.rule === 'untrusted-issuer') {
  // @ts-expect-error issuer is not known to be permitted here
  use(e.diagnostics?.issuer);
}
// a mismatched pairing — with the brand missing, and with the brand set aside
const forged = { kind: 'saml-assertion', variant: 'duplicate-id',
  facts: { rule: 'duplicate-id', check: 'duplicateId' }, diagnostics: { issuer: 'x' }, reason: '' } as const;
// @ts-expect-error brand missing, and the pairing matches no variant
const f2: IAuthProviderError = forged;
type Unbranded<T> = T extends unknown ? { [K in keyof T as K extends string ? K : never]: T[K] } : never;
// @ts-expect-error duplicate-id with an issuer matches no variant
const f3: Unbranded<IAuthProviderError> = forged;
```

- `WORDS` without one kind (a local copy with a key removed does not satisfy
  the mapped type); a discriminant switch missing one member;
- `matchKind` with one handler missing; a `switch` over all but one kind with
  `unreachableKind(error)` in `default`;
- each allowlist union equal to `(typeof ARRAY)[number]`, and each runtime
  set's element type equal to the union (an `Equal<>` both ways);
- `keyof AuthProviderErrorFacts` equal to `AuthProviderErrorKind`;
- `AuthProviderFailure` constructed from an unminted object.

Positive lines beside each (the same call made valid) prove the failure is
the rule's, not an unrelated error.

### 11.3 The shape check's own tests

Fixtures under `tools/__fixtures__/` — one file per rule of §8.2 breaking it,
and one obeying all — run by a Jest test that expects exactly the right rule
reported per file.

### 11.4 Generated documentation

The README tables of refusals (auth-providers' "What `rejected()` answers",
"Refusals", "Refusal messages", auth-errors' kinds table) are produced by a
script from `WORDS` and the allowlists, and a test fails when the committed
README differs from the generated table.

### 11.5 Release gates

1. Every row of Appendix A implemented as mapped, and every loss of Appendix
   C approved by the user (goal Open 5).
2. In each repository: `build`, `test:check` (type tests included),
   `lint:check` (shape check included), `test`; the provider stand
   (`test:stand`) for auth-providers.
3. README, guides, CLAUDE.md and migration notes updated (global
   CLAUDE.md "Releasing"; goal Open 5), the generated tables current.
4. Dependencies only from the registry, in order: interfaces (auth 5.0.0,
   auth-sap 3.1.0) → auth-errors 1.0.0 → connection 12.0.0 → auth-providers
   6.0.0 → auth-stores 4.0.0 → auth-broker 5.0.0 + CLI 3.0.0; each consumer
   built against the published versions, the lockfile checked for
   `"link": true` and non-registry resolutions; after publishing, a clean
   install of each from the registry outside the repositories.
5. `docs/superpowers/` emptied of this work's documents before the
   auth-providers release.

## 12. Out of scope, and what is not measured

**Out of scope.** Localised words (the renderer makes them possible; none
ships). The broker's own `DestinationConfigError` language and the stores'
`StoreErrors`, which describe configuration and storage, not authentication
refusals. connection's `WireLogonError` (`authErrors.ts:43-53`), which copies
the wire error's message by design and travels as `IAuthRejection.error`, not
as a refusal. connection's `AuthRefusedError.cause` (the wire's error, its own
policy). Moving connection to `interfaces-adt-connection` 2.0.0. The server
`mcp-abap-adt`, which reads only `AuthRefusedError.message`
(`src/lib/auth/errors.ts:110`) and moves in its own task.

**Not measured; to be checked during implementation:**

- That the TypeScript compiler API script can decide rule 3 of §8.2
  (structural `IAuthProvider` satisfaction of an object literal) without
  false positives — Inference; if it cannot, rule 3 narrows to "an object
  literal with all four methods" and the spec is amended in review.
- That two installed copies of `auth-errors` re-mint each other's errors as
  §5.4 step 3 says — designed, to be proven by the test of §11.1.
- That `pino`'s error serializer, which copies enumerable own properties,
  logs `AuthProviderFailure.error` (with diagnostics) and nothing else of the
  original — no original is attached, so nothing else exists; the
  serialization itself is not measured.
- The completeness of `SAML_STATUS_CODES` against the identity providers in
  use (Keycloak, UAA, XSUAA's IAS): a status outside it still reaches a
  person as the `statusCode` diagnostic.
- Whether any consumer outside the chain matches today's words (the server
  reads the message only, measured by search 2026-10-05; consumers outside
  these repositories are unknown).

## 13. Goal invariants: how each is honoured

1. **Separate contracts** — `IAuthProvider` and the token interfaces name
   `IAuthRefusal` / `IAuthProviderFailure` only; the kinds live in
   `src/error/` (§4).
2. **No exception crosses `IAuthProvider`** — §8: the guard owns the four
   methods. *Held by a check, not the compiler:* TypeScript has no `final`
   and does not type throws; the shape check (§8.2) and the runtime suite
   (§8.3) are what prevent a subclass from overriding a method. This is the
   goal's own statement of the limit (invariant 4, fifth bullet).
3. **No free text in facts; diagnostics admitted** — facts are allowlist
   unions and branded ranges (§4.3); `reason` / `hint` come from `WORDS` only
   (§5.6); diagnostics have one source each and are admitted at the builder
   (§3.3, §5.3), and kept only when minted by this copy's builder at an
   approved site — a structural rebuild drops them (§5.4, L13); every
   exception message and free value quoted today outside that list is dropped
   (Appendix C, L7–L8). *Hard to honour fully:* the
   compiler cannot stop `{ ...minted, reason: '…' }` — a spread keeps the
   brand. It is refused by the shape check (§8.2 rule 5), frozen at run time
   (a mutation fails), and every relay boundary re-mints or passes the
   original object (§7), so a forged copy does not survive a hop; within one
   producer, the check is what holds it.
4. **Runtime checking only at the boundaries** — classification (§5.4) and
   admission (§5.3) are the only runtime checks of an error's content; the
   branded-integer makers are the builder's input checks. The static rules are
   listed with their type tests (§11.2). *Hard:* the brand is type-only and an
   explicit `as` forges it; the compiler allows that, the shape check (rule
   4) refuses it everywhere but `mint`.
5. **Closed union; a new kind is a major** — §4.3 "What a later release may
   change", §9.
6. **The consumer composes** — `render` is a default; `matchKind` lets a
   consumer render its own words; no provider forces text beyond the stored
   default `reason` / `hint`, which a consumer may ignore.

---

## Appendix A — Diagnostic compatibility matrix

Columns: **#** · **Source** (today) · **Today's text** (shape; `<…>` marks a
value, never a secret) · **Kind** · **Facts** · **Diagnostics** · **New words /
information lost**. *Verbatim* means the rendered `reason` (and `hint`) equal
today's string exactly, pinned by a test; "→ Cn" points to Appendix C.

### A.1 Refusals — `refusalFrom` and its constants (auth-providers)

| # | Source | Today's text | Kind | Facts | Diag. | New words / lost |
|---|---|---|---|---|---|---|
| A1 | `refusal.ts:247` | `<what> failed (unknown error)` (a value whose reading threw) | `unknown` | `operation` | — | verbatim with the operation's words; the free `what` → closed operation (L10) |
| A2 | `refusal.ts:252-253` | `showing the device code failed` | `interactive-login` | `outcome: device-code-not-shown` | — | verbatim |
| A3 | `refusal.ts:255-262` | `the SAML assertion was refused (<check>)` | `saml-assertion` | `check`, `rule`, rule facts | per rule (App. B) | reason gains the rule's words: `the SAML assertion was refused (<check>): <rule words>` — more information, not less |
| A4 | `refusal.ts:266-268`, `CertificateMaterialError.ts:9-27` | the three certificate reason/hint pairs | `client-certificate` | `problem` | — | verbatim |
| A5 | `refusal.ts:270-274`, `ClientAuthenticationError.ts:26-29` | `the client authentication returned a request that cannot be sent` / `check the client authentication strategy` | `client-authentication` | `problem: result-unsendable` | — | verbatim |
| A6 | `refusal.ts:276-278`, `ClientAuthenticationError.ts:5-8` | `the client signing key could not be used` / hint | `client-authentication` | `problem: signing-key-unusable` | — | verbatim |
| A7 | `refusal.ts:279-281`, `ClientAuthenticationError.ts:50-53` | `the client id contains ':', which raw Basic cannot carry` / hint | `client-authentication` | `problem: basic-client-id-colon` | — | verbatim |
| A8 | `refusal.ts:282-291` | `the identity provider refused the login (<code>)` / `check the identity provider: the user, the client and the scopes it allows` | `interactive-login` | `outcome: identity-provider-refused`, `oauthError?` | — | verbatim |
| A9 | `refusal.ts:292-295` | `the interactive login did not complete` / `complete the login within the strategy's time` | `interactive-login` | `outcome` (A.3), its facts | — | reason names the outcome (`the interactive login timed out after <n> s`, …); the old sentence stays for `outcome: failed` — more information |
| A10 | `refusal.ts:297-298` | `the refresh token was refused` / `log in again` | `credential-refused` | `credential: refresh-token` | — | verbatim |
| A11 | `refusal.ts:300-305` | `the provider configuration is incomplete or invalid[: <fields>]` / `check the provider configuration` | `configuration` | `case`, `fields`, `allowed?` | mismatch URIs | per-case words (A.5); fields kept |
| A12 | `refusal.ts:306-311` | `the service key or session data is incomplete[: <fields>]` | — | — | — | no producer in this package (README `:2062`); removed with the classes |
| A13 | `refusal.ts:312-314` | `<what> failed (<OwnClassLabel>)` | `unknown` | `operation` | — | `<operation> failed (unknown error)`; class label lost (L11) |
| A14 | `refusal.ts:315-320` | `<what> failed (HTTP <n>[, <oauth>][, <code>])` / `(the token endpoint gave no reason)` | `request-failed` | `operation`, `grant?`, `problem`, `status?`, `oauthError?`, `code?` | — | verbatim |
| A15 | `refusal.ts:321-325`, `knownCodes.ts:438-497` | `<what> failed: <tls words> (<code>)` / TLS hint | `tls` | `operation`, `grant?`, `code` | — | verbatim |
| A16 | `refusal.ts:326-334` | `<what> failed (HTTP <n>, …)` or `(unknown error[, <facts>])` for a foreign value | `unknown` | `operation`, `status?`, `oauthError?`, `code?` | — | verbatim |
| A17 | `refusal.ts:63-67`, `BaseTokenProvider.ts:795-797` | `the token is bound to a client certificate this provider does not present` / hint | `token-binding` | `problem: bound-to-unpinned` | — | verbatim |
| A18 | `refusal.ts:74-78`, `BaseTokenProvider.ts:800-805` | `the new token is bound to a client certificate this provider does not present` / hint | `token-binding` | `problem: renewed-bound-elsewhere` | — | verbatim |
| A19 | `refusal.ts:347-353` | `refusalWords(error, what)` — the words of A1–A16 for a consumer | (any) | — | — | removed; `classify(error, operation)` (L10) |

### A.2 Refusals — rejection reading and the credentials

| # | Source | Today's text | Kind | Facts | Diag. | New words / lost |
|---|---|---|---|---|---|---|
| B1 | `rejection.ts:40-43` | `the credential was accepted, but the user is not authorized (403)` / hint | `system-refused` | `verdict: not-authorized`, `status`, `at` | — | verbatim |
| B2 | `rejection.ts:46-49` | `the system redirected instead of accepting the credential (<n>)` / hint | `system-refused` | `verdict: redirected`, `status`, `at` | — | verbatim |
| B3 | `rejection.ts:52-55` | `the system failed (<n>), not the credential` / `try again later` | `system-refused` | `verdict: system-failed`, `status`, `at` | — | verbatim |
| B4 | `rejection.ts:57-59` | `the system answered <n>, which is not a credential refusal` | `system-refused` | `verdict: other-status`, `status`, `at` | — | verbatim |
| B5 | `rejection.ts:78-80` | `the RFC <call\|logon> failed (<KEY>), not as a credential refusal` | `system-refused` | `verdict: rfc-failure`, `rfcKey`, `at` | — | verbatim |
| B6 | `rejection.ts:89-94` | `the request was refused (unknown error)` / `the logon failed (unknown error)` | `system-refused` | `verdict: unknown`, `at` | — | verbatim |
| B7 | `BasicAuthProvider.ts:45-48` | `the user or password was refused` / `check the user and password` | `credential-refused` | `credential: user-password`, `at` | — | verbatim |
| B8 | `CertificateAuthProvider.ts:55-59` | `the certificate is not loaded` / `connect() prepares it first` | `not-prepared` | `provider: certificate` | — | verbatim |
| B9 | `CertificateAuthProvider.ts:89-92` | `the client certificate was refused` / `check that it is mapped to a user (CERTRULE / USREXTID)` | `credential-refused` | `credential: client-certificate`, `at` | — | verbatim |
| B10 | `SamlAuthProvider.ts:35-38` | `the SAML session was refused or has expired` / `obtain a new SAML session` | `credential-refused` | `credential: saml-session`, `at` | — | verbatim |
| B11 | `TokenAuthProvider.ts:65` | `the token was refused` / `obtain a new token` | `credential-refused` | `credential: token`, `at` | — | verbatim |
| B12 | `TokenAuthProvider.ts:70-73` | `the renewal returned the credential that was refused` / `the token source must issue a new token` | `renewal-unchanged` | `source: token-source` | — | verbatim |
| B13 | `BaseTokenProvider.ts:779-782` | same reason / `the token source must issue a new token; log in again` | `renewal-unchanged` | `source: token-provider` | — | verbatim |
| B14 | `certificateMaterial.ts:59-70` | `checkCertificateMaterial`'s Oops: A4's words | `client-certificate` | `problem` | — | verbatim |
| B15 | operations of `safely(...)` in the credentials (`BasicAuthProvider.ts:26,33,44`, `CertificateAuthProvider.ts:41,60,88`, `SamlAuthProvider.ts:26,34`, `TokenAuthProvider.ts:47,57`) | `<what> failed (…)` via A1/A13/A16 | `unknown` / `tls` | `operation` from A.8 | — | verbatim with the operation's words |

### A.3 Interactive login — thrown messages and their refusals

| # | Source | Today's text | Kind | Facts | Diag. | New words / lost |
|---|---|---|---|---|---|---|
| K1 | `BrowserCallbackStrategy.ts:101-103` | `Port <n> is already in use. Please specify a different port or free the port.` | `interactive-login` | `outcome: port-in-use`, `port` | — | verbatim (the phrase "already in use" kept, `CallbackScopeError` doc) |
| K2 | `BrowserCallbackStrategy.ts:122` | `BrowserCallbackStrategy has been disposed` | `interactive-login` | `outcome: disposed` | — | `the browser login strategy has been disposed` |
| K3 | `BrowserCallbackStrategy.ts:125-127` | `BrowserCallbackStrategy is already authorizing; it holds a single port` | `interactive-login` | `outcome: busy` | — | verbatim |
| K4 | `BrowserCallbackStrategy.ts:152-154`, `callbackServer.ts:86`, `:159` | `Authorization aborted before the callback server bound` / `Callback server aborted before it started` / `Callback server aborted` | `interactive-login` | `outcome: aborted` | — | one sentence, `the browser login was aborted`; which of three moments lost (minor) |
| K5 | `BrowserCallbackStrategy.ts:195-197` | `Browser opening failed. Open manually: <authorization URL>` | `interactive-login` | `outcome: browser-launch-failed`, `code?` | — | URL leaves the thrown message; stays in the strategy's log line (H7) → L4 |
| K6 | `callbackServer.ts:56-58` | `Invalid callback server port: <value>. Must be an integer in 0..65535.` | `configuration` | `case: callback-port-invalid`, `fields: [port]` | — | value lost → L5 |
| K7 | `callbackServer.ts:65-68` | `Invalid callback server timeoutMs: <value>. Must be finite and within 1..<max>.` | `configuration` | `case: callback-timeout-invalid`, `fields: [timeoutMs]` | — | value lost → L5 |
| K8 | `callbackServer.ts:148-150`, `:273` | `Callback server closed before a result arrived` / `Callback server scope has ended` | `interactive-login` | `outcome: callback-closed` | — | one sentence |
| K9 | `callbackServer.ts:258-260` | `Authentication timeout after <s> seconds. Please try again.[ <k> incomplete request(s) reached /callback and were ignored.]` | `interactive-login` | `outcome: timeout`, `timeoutSeconds`, `ignoredCallbacks?` | — | verbatim |
| K10 | `callbackScopeError.ts:139-151` | `the identity provider refused the login (<code>\|an unregistered error code)` | `interactive-login` | `outcome: identity-provider-refused`, `oauthError?` | — | verbatim |
| K11 | `BrowserCallbackStrategy.ts:77-82`, `:224-230` | `BrowserAuthError` with `the browser login failed (unknown error[, <code>])[ (HTTP <n>)]`, original as `cause` | `interactive-login` | `outcome: failed`, `code?`, `status?` | — | verbatim; `cause` lost → L2 |
| K12 | `manualStrategies.ts:50-52` | `the manual input was abandoned before it began` | `interactive-login` | `outcome: input-abandoned` | — | verbatim |
| K13 | `manualStrategies.ts:55-57` | `Manual input needs an interactive terminal. Supply \`read\` to source the value elsewhere.` | `interactive-login` | `outcome: no-terminal` | — | verbatim |
| K14 | `manualStrategies.ts:69`, `:172`, `:193`, `codeStrategies.ts:42` | `No input received` / `No SAMLResponse was provided` / `No passcode was provided` / `Authorization code provider returned an empty value` | `interactive-login` | `outcome: no-input` | — | `no input was received`; which input lost (minor) |
| K15 | `manualStrategies.ts:100`, `:111-113` | `the manual strategy was disposed` / `the manual input did not arrive in time, or the strategy was disposed` | `interactive-login` | `outcome: disposed` / `input-timeout` | — | verbatim |
| K16 | `manualStrategies.ts:154` | `Could not read an authorization code from that input` | `interactive-login` | `outcome: unreadable-input` | — | verbatim |
| K17 | `DeviceCodePresenter.ts:26-31` | `showing the device code failed` | `interactive-login` | `outcome: device-code-not-shown` | — | verbatim |

### A.4 Token requests — thrown messages

| # | Source | Today's text | Kind | Facts | Diag. | New words / lost |
|---|---|---|---|---|---|---|
| D1 | `tokenRequest.ts:375-390` via `passcodeAuth.ts:98`, `oidcToken.ts:232`, `:341`, `clientCredentialsAuth.ts:82-86`, `tokenRefresher.ts:86` | `TokenEndpointError`: `<label> (<status>): <redacted OAuth summary>`, `status`, `oauthError`, original as `cause` | `request-failed` | `operation` (label → A.8), `grant?`, `problem: refused`, `status`, `oauthError?` | — | `<operation> failed (HTTP <n>[, <oauth>])`; redacted `error_description` lost → L1; `cause` → L2 |
| D2 | `tokenRequest.ts:391-396` | `<label>: <loggedError words>`, `code?` | `request-failed` / `tls` | `problem: no-response`, `code?` | — | verbatim words of A14/A15 |
| D3 | `tokenRequest.ts:293-341` (`sendTokenRequest`, the non-wrapping sites: code exchange `browserAuth.ts`, OIDC token and device poll `oidcToken.ts`, SAML exchange and refresh `saml2TokenExchange.ts`) | reduced `AxiosError`: `Request failed with status code <n>` / `the token request failed (<code>)`; `response.data` = `{error, error_description, error_uri}` redacted | `request-failed` / `tls` | as D1/D2 | — | words as A14; reduced body lost → L1; `AxiosError` identity lost → L3 |
| D4 | `browserAuth.ts:158`, `saml2TokenExchange.ts:110`, `:167`, `passcodeAuth.ts:108`, `clientCredentialsAuth.ts:95-97`, `oidcToken.ts:109`, `tokenRefresher.ts:96-98` | `… missing access_token` / `… returned no access_token` / `… does not contain access_token` | `request-failed` | `operation`, `problem: no-access-token` | — | `<operation> returned no access_token` |
| D5 | `oidcToken.ts:240` | `Device authorization response missing required fields` | `request-failed` | `operation: device-authorization`, `problem: incomplete-response` | — | verbatim meaning |
| D6 | `oidcDiscovery.ts:65` | `OIDC discovery document missing token_endpoint` | `request-failed` | `operation: oidc-discovery`, `problem: incomplete-response` | — | verbatim meaning |
| D7 | `BaseTokenProvider.ts:388` | `Authorization token is missing.` (unreachable guard) | `unknown` | `operation: token-request` | — | fixed words |
| D8 | `RefreshError` at `Saml2PureProvider.ts:130`, `ClientCredentialsProvider.ts:97`, `OidcTokenExchangeProvider.ts:117`, `OidcPasswordProvider.ts:108`, `OidcBrowserProvider.ts:167`, `OidcDeviceFlowProvider.ts:173`; plain `Error` at `UaaPasscodeProvider.ts:125`, `Saml2BearerProvider.ts:148`, `AuthorizationCodeProvider.ts:225` | `… has no refresh grant` / `Refresh token is required for refresh` — caught by `renewOnce` (`BaseTokenProvider.ts:475-487`), never escape | `credential-refused` | `credential: refresh-token` | — | internal; A10's words if it ever escaped |

### A.5 Configuration — thrown messages

`case` values are the `CONFIG_CASES` array; each gets its own words, keeping
today's sentence minus any interpolated value.

| # | Source | Today's text | `case` | `fields` | Diag. | Lost |
|---|---|---|---|---|---|---|
| E1 | `ClientCredentialsProvider.ts:58-61`, `AuthorizationCodeProvider.ts:96-99` | `Missing required fields: <names>` (plain `Error`, `code`, `missingFields`) | `required-fields-missing` | the names | — | — |
| E2 | `BaseTokenProvider.ts:162-165` | `clientSecret cannot be given beside clientAuthentication` | `client-secret-beside-client-authentication` | `clientSecret` | — | — |
| E3 | `saml2Utils.ts:70-73` | `acsUrl is required when authorizationUrl is set: …` | `saml-acs-required-with-authorization-url` | `acsUrl` | — | — |
| E4 | `saml2Utils.ts:79-82` | `SAML idpInitiated is true and authnRequestId is set: … Remove one of them.` | `saml-idp-initiated-with-request-id` | `idpInitiated`, `authnRequestId` | — | — |
| E5 | `saml2Utils.ts:108-111` | `The supplied assertionValidator is a shipped one … missing idpEntityId` | `saml-shipped-validator-without-issuer` | `idpEntityId` | — | — |
| E6 | `saml2Utils.ts:126` | `Missing tokenUrl or uaaUrl for SAML bearer exchange` | `saml-token-endpoint-missing` | `tokenUrl`, `uaaUrl` | — | — |
| E7 | `saml2Utils.ts:155-158` | `SAML idpInitiated is true and no authorizationUrl is configured, but the authorization strategy asked for an authorization URL …` | `saml-idp-initiated-without-authorization-url` | `idpInitiated`, `authorizationUrl` | — | — |
| E8 | `saml2Utils.ts:168-171`, `:193-196` | `SAML acsUrl is <acs>, but the authorization strategy is listening on / used <uri>. They must match.` | `saml-acs-mismatch` | `acsUrl` | `configuredUri`, `strategyUri` | URIs move from message to diagnostics → L9 |
| E9 | `saml2Utils.ts:224-227` | `SAML idpInitiated is true, but a request ID was also minted or configured …` | `saml-idp-initiated-with-request-id` | `idpInitiated` | — | — |
| E10 | `saml2Utils.ts:237-240` | `Cannot validate InResponseTo: … authnRequestId must be configured — or … idpInitiated: true …` | `saml-in-response-to-undeclared` | `authnRequestId`, `idpInitiated` | — | — |
| E11 | `saml2TokenExchange.ts:37-40` | `clientId is required with a client authentication` | `client-id-required-with-client-authentication` | `clientId` | — | — |
| E12 | `AuthorizationCodeProvider.ts:163-166`, `:177-179`, `:198-200` | `Pre-built authorizationUrl declares redirect_uri <a>, but the authorization strategy used <b> … An ephemeral port cannot be used with a pre-built URL.` | `redirect-mismatch` | `authorizationUrl` | `configuredUri`, `strategyUri` | → L9 |
| E13 | `OidcBrowserProvider.ts:91`, `:173`; `OidcDeviceFlowProvider.ts:95`, `:176`, `:182`; `OidcPasswordProvider.ts:64`, `:70`, `:112`, `:118`; `OidcTokenExchangeProvider.ts:67`, `:73` | `OIDC issuerUrl is required when discovery is used` | `oidc-discovery-needs-issuer` | `issuerUrl` | — | — |
| E14 | `OidcBrowserProvider.ts:113-116` | `OIDC authorization endpoint is required (authorizationEndpoint or discovery)` | `oidc-endpoint-missing` | `authorizationEndpoint` | — | — |
| E15 | `OidcBrowserProvider.ts:139-141`, `:183-185`; `OidcDeviceFlowProvider.ts:111-113`, `:189-191`; `OidcPasswordProvider.ts:77-79`, `:125-127`; `OidcTokenExchangeProvider.ts:80-82` | `OIDC token endpoint is required (tokenEndpoint or discovery)` | `oidc-endpoint-missing` | `tokenEndpoint` | — | — |
| E16 | `OidcDeviceFlowProvider.ts:106-108` | `OIDC device authorization endpoint is required (…)` | `oidc-endpoint-missing` | `deviceAuthorizationEndpoint` | — | — |
| E17 | `FileCertificateMaterialLoader.ts:17-20` | `Certificate auth: provide either PEM (certPath+certKeyPath) OR certPfxPath, not both.` | `certificate-pem-and-pfx` | `certPath`, `certPfxPath` | — | — |
| E18 | `FileCertificateMaterialLoader.ts:35-38` | `Certificate auth requires certPfxPath OR (certPath AND certKeyPath).` | `certificate-files-missing` | `certPfxPath`, `certPath`, `certKeyPath` | — | — |
| E19 | `clientSecret.ts:44-47` | `clientSecretBasic needs encoding: 'raw' or 'form'` | `basic-encoding-missing` | `encoding` | — | — (`allowed: basic-encoding`) |
| E20 | `SncLogonProvider.ts:82-85` | `SncLogonProvider needs partnerName — the system's SNC name.` | `snc-partner-name-missing` | `partnerName` | — | — |
| E21 | `SncLogonProvider.ts:89-92` | `SncLogonProvider: qop must be one of 1, 2, 3, 8, 9, got '<value>'.` | `snc-qop-invalid` | `qop` | — | value lost → L5 (`allowed: snc-qop` keeps the list) |
| E22 | `browserAuth.ts:72` | `Authorization config missing UAA URL or client ID` | `required-fields-missing` | `uaaUrl`, `clientId` | — | — |
| E23 | `SsoProviderFactory.ts:42-44` | `Unsupported SSO provider config: no provider for this protocol and flow` | `unsupported-sso-flow` | — | — | — |
| E24 | `assertionValidator.ts:133-135` | `clockSkewMs must be a finite non-negative integer, got <value>` | `validator-clock-skew-invalid` | `clockSkewMs` | — | value lost → L5 |
| E25 | `assertionValidator.ts:138-140` | `idpCertificates must not be empty: nothing could be verified` | `validator-no-certificates` | `idpCertificates` | — | — |
| E26 | `signedNode.ts:44-46`, `:57-62` | `a configured certificate is neither PEM nor base64 DER` / `… is not a valid X.509 certificate` (OpenSSL's error as `cause`) | `idp-certificate-invalid` | `idpCertificates` | — | `cause` → L2 |
| E27 | `codeStrategies.ts:55` | `staticCodeStrategy requires a payload` | `static-code-without-payload` | `payload` | — | — |
| E28 | `saml2Utils.ts` provider construction without `assertionValidator` and without `idpCertificates` / `idpEntityId` (`validateSamlConfig`) | `ValidationError` naming the missing fields | `required-fields-missing` | the names | — | — |

### A.6 SAML — thrown messages

Every `AssertionValidationError` message (README `:1372-1468`) is one rule
of Appendix B, kind `saml-assertion`. Outside the validators:

| # | Source | Today's text | Rule | Diag. | Lost |
|---|---|---|---|---|---|
| F1 | `samlBearerAssertion.ts:35` | `SAML bearer payload is not base64-encoded XML` | `payload-not-base64-xml` | — | — |
| F2 | `samlBearerAssertion.ts:44-46` | `SAML bearer payload is not well-formed XML: "<parser message>"` | `payload-not-well-formed` | — | parser message → L7 |
| F3 | `samlBearerAssertion.ts:53-55` | `… neither a SAML Response nor an Assertion` | `payload-not-saml` | — | — |
| F4 | `samlBearerAssertion.ts:69-71` | `… carries only an EncryptedAssertion …` | `only-encrypted-assertion` | — | — |
| F5 | `samlBearerAssertion.ts:73` | `SAML Response carries no Assertion` | `no-assertion` | — | — |
| F6 | `samlBearerAssertion.ts:76-78` | `SAML Response carries <n> Assertions; a bearer grant takes one` | `several-assertions` (`count`) | — | — |
| F7 | `strictXml.ts:17` | `XML <level>: <parser message>` — caught by the validator (`assertionValidator.ts:168-170`) | `not-xml` | — | never surfaced today except through F2 |
| F8 | `assertionValidator.ts:206`, `signedNode.ts:142-144` | `fail('signature', error.message)`; `the signature element is malformed: "<xml-crypto message>"` | `signature-malformed` | — | xml-crypto message → L7 |

### A.7 SNC

| # | Source | Today's text | Kind | Facts | Diag. | New words / lost |
|---|---|---|---|---|---|---|
| G1 | `sncRefusal.ts:44-50` | `the SNC library has no credential to present (A2200019)` / `log on in the Secure Login Client, to the profile used for SAP applications` \| `make sure the SNC product behind <library path (archs)> is logged on` | `snc` | `problem: no-credential`, `secureLoginClient`, `libraryArchs?` | `library` | reason verbatim; second hint becomes `make sure the SNC product behind the SNC library is logged on` — path moves to diagnostics → L9 |
| G2 | `sncRefusal.ts:52-56` | `the RFC SDK could not initialise <library path (archs)> as its SNC library (SNCERR_INIT)` | `snc` | `problem: library-init-failed`, `libraryArchs?` | `library` | `the RFC SDK could not initialise the SNC library (<archs>) as its SNC library (SNCERR_INIT)` → L9 |
| G3 | `sncRefusal.ts:65` | `SNC logon refused[ (<KEY>)]` | `snc` | `problem: logon-refused`, `rfcKey?` | — | verbatim |
| G4 | `sncRefusal.ts:77-79` | `no usable SNC library was found` / `set sncLib to the SNC (GSS) library of your SNC product` (a locator's foreign error) | `snc` | `problem: library-not-found` | — | verbatim |
| G5 | `sncRefusal.ts:87-90` | `no usable SNC library was found: <source> <path> (<reason>); …` / same hint | `snc` | `problem: library-not-found`, `searched: true`, `candidates` (source, reason, archs) , `processArch?` | `candidatePaths` | `no usable SNC library was found: <source> (<reason>); …` — paths → diagnostics → L9 |
| G6 | `sncRefusal.ts:89` | `…: no candidate (SNC_LIB_64 and SNC_LIB are unset and no Secure Login Client installation was found)` | `snc` | `problem: library-not-found`, `searched: true`, `candidates: []` | — | verbatim |
| G7 | `DefaultSncLibraryLocator.ts:89-92`, `:109-115` (`SncLibraryNotFoundError` message, multi-line, with each detail incl. `built for <archs>, this process is <arch>`) | thrown by `locate()`, logged by the provider as `refusal.reason` | `snc` | as G5, `candidates[i].archs`, `processArch` | `candidatePaths` | rendered from facts + diagnostics; architectures kept as facts |
| G8 | `SncLogonProvider.ts:135-138` | `no usable SNC library was found: the locator returned no path` / hint | `snc` | `problem: locator-returned-no-path` | — | verbatim |
| G9 | `SncLogonProvider.ts:176-179` | `the SNC provider is not prepared` / `connect() prepares it first` | `not-prepared` | `provider: snc` | — | verbatim |
| G10 | `SncLogonProvider.ts:63` | `the SNC provider failed while <moment> (unknown error)` | `unknown` | `operation` (an SNC operation, A.8) | — | verbatim |

### A.8 Operations, and the `loggedError` lines

`OPERATIONS` — each with its words — replaces every `what`:

| Operation | Today's `what` (source) |
|---|---|
| `token-request` (+ `grant`) | `` `${kind} token request` `` (`BaseTokenProvider.ts:651-653`) |
| `refresh` | `'the refresh'` (`BaseTokenProvider.ts:481`) |
| `on-tokens-hook` | `'onTokens'` (`:638`) |
| `presenting-token` | `'presenting the token'` (`:732`) |
| `presenting-certificate` | `'presenting the certificate'` (`:690`, `CertificateAuthProvider.ts:60`) |
| `loading-certificate` | `'loading the certificate'` (`CertificateAuthProvider.ts:41`) |
| `writing-authorization-header` | `BasicAuthProvider.ts:33` |
| `offering-logon-parameters` | `BasicAuthProvider.ts:26` |
| `writing-session-cookies` | `SamlAuthProvider.ts:26` |
| `reading-rejection` | `BasicAuthProvider.ts:44`, `CertificateAuthProvider.ts:88`, `SamlAuthProvider.ts:34` |
| `token-source` | `TokenAuthProvider.ts:47`, `:57` |
| `resolving-snc-library`, `handing-over-snc-parameters`, `authorizing-snc-request`, `explaining-snc-refusal` | `SncLogonProvider.ts:123`, `:173`, `:192`, `:201` |
| `probing-snc-product` | `'the probe'` (`SncLogonProvider.ts:155`) |
| `presenting-device-code` | `'the presenter'` (`OidcDeviceFlowProvider.ts:143`) |
| `saml-token-exchange`, `saml-token-refresh` | `saml2TokenExchange.ts:103`, `:160` |
| `browser-login`, `opening-browser` | `BrowserCallbackStrategy.ts:78`, `:186`; `browserAuth.ts:219`, `:299` |
| `passcode-exchange`, `device-authorization`, `password-grant`, `client-credentials`, `token-refresh` | the `tokenEndpointError` labels (`passcodeAuth.ts:98`, `oidcToken.ts:232`, `:341`, `clientCredentialsAuth.ts:83`, `tokenRefresher.ts:86`) |
| `oidc-discovery`, `code-exchange`, `device-poll`, `oidc-token-request` | the non-wrapping sites (D3, D6) |
| `validating-assertion` | a custom `IAssertionValidator`'s throw |
| `client-authentication-strategy` | the broker's `resolveClientAuthentication` |
| `unfamiliar-error` | new: `matchKind` / `unreachableKind` normalising a value this build does not know (§9) |
| `preparing`, `establishing`, `authorizing` (and `reading-rejection`) | new: `AuthProviderBase`'s fixed fallbacks when a configured operation cannot be read (§8.1) |

The log lines (each now `logFields(error)`: `{ error: reason, kind, status?,
diagnostics? }`):

| # | Source | Today | Change |
|---|---|---|---|
| H1 | `BaseTokenProvider.ts:479-482` | `Refresh failed` + `{ error, status? }` | `logFields`; same words |
| H2 | `BaseTokenProvider.ts:636-639` | `onTokens failed; the token stands` + words | same |
| H3 | `OidcDeviceFlowProvider.ts:141-144` | `presenter failed` + words | same |
| H4 | `SncLogonProvider.ts:130` | `SNC library not found: <reason with paths>` | `SNC library not found: <reason>` with `diagnostics` as a field — paths kept in the log, out of the reason |
| H5 | `SncLogonProvider.ts:153-156` | `an SNC product probe failed: <words>` | same |
| H6 | `saml2TokenExchange.ts:101-104`, `:158-161` | `[SAML] Token exchange/refresh failed` + words | same |
| H7 | `BrowserCallbackStrategy.ts:186-193` | `Failed to open browser: <words>. Open manually: <url>` + `{ error, url }` | unchanged: the URL is the strategy's own announcement, not an error's text |
| H8 | `browserAuth.ts:217-220`, `:298-302` | `Could not open browser automatically: <words>` / `Failed to open browser: <words>. Please open manually: <url>` | same as H7 |
| H9 | `tokenRequest.ts:393` | words inside `TokenEndpointError`'s message | gone with the class (D2) |
| H10 | each wrapping token site | (new) | one `debug` line with the redacted OAuth summary, if L1 is approved as proposed |

### A.9 connection

| # | Source | Today's text | Kind | Facts | New words / lost |
|---|---|---|---|---|---|
| I1 | `RfcTransport.ts:479-482` | `this wire carries no TLS material (RFC)` | `logon-target` | `wire: rfc`, `refused: tls-material` | verbatim |
| I2 | `HttpTransport.ts:524-527` | `this wire takes no logon parameters (HTTP)` | `logon-target` | `wire: http`, `refused: logon-parameters` | verbatim |
| I3 | `authErrors.ts:56-58`, used at `:96` | `the credential provider failed` | `connection` | `problem: provider-threw`, `at` | verbatim |
| I4 | `authErrors.ts:64-66`, used at `AbstractAbapConnection.ts:1612` | `the credential was refused again after the provider renewed it` | `connection` | `problem: refused-after-renewal`, `at` | verbatim |
| I5 | `authErrors.ts:69-71`, used at `AbstractAbapConnection.ts:975` | `this connection has no credential to renew` | `connection` | `problem: no-credential` | verbatim |
| I6 | `authErrors.ts:25-28` | `AuthRefusedError` message `reason — hint` | (relays any) | — | format unchanged; reason/hint from the error |
| I7 | (new) a target answering something that is not a minted outcome | — | `logon-target` | `wire: unknown`, `refused` | `the logon target did not take the <material\|parameters>` |

### A.10 The broker and the CLI

| # | Source | Today's text | Change |
|---|---|---|---|
| J1 | `clientAuthentication.ts:78-80`, `:220-226` | `the clientAuthentication strategy refused: the client certificate is incomplete \| has expired \| could not be used` — phrases copied from auth-providers | deleted; `DestinationConfigError.error` carries the provider's `client-certificate` error, the reason renders it: same words |
| J2 | `clientAuthentication.ts:62-63`, `:214-218` | `the clientAuthentication strategy refused: the destination has no client certificate \| secret` | broker's own words, stay; no `error` |
| J3 | `clientAuthentication.ts:202`, `:230` | `the clientAuthentication strategy failed` | words stay; `error` carries `classify(error, 'client-authentication-strategy')` |
| J4 | `clientAuthentication.ts:259-264`, `:300-304`; `destinations.ts:146-174` | broker configuration words | stay |
| J5 | `destinations.ts:247-255` | `the SNC provider refused the destination's SNC settings (<fields>)` from `ValidationError.missingFields` | reads `kind: configuration`, `facts.fields`; words stay |
| J6 | CLI `generateEnv.ts:262-264`, `mcp-auth.ts:587-591` | `❌ Login failed: <error.message>` | `<reason — hint>`, then the diagnostics line when there is one |

## Appendix B — SAML rules

`rule` → `check` is fixed (`ASSERTION_RULE_CHECK`, a `const` object
`satisfies Record<AssertionRule, AssertionCheck>`); the words are today's
message with each quoted value removed (the value is the diagnostic, rendered
apart). Rule ids, in the README table's order:

| `check` | `rule` | Today's message (README `:1384-1433`) | Facts beyond rule/check | Diagnostic |
|---|---|---|---|---|
| document | `doctype` | `the SAMLResponse carries a DOCTYPE declaration, …` | — | — |
| document | `not-xml` | `the SAMLResponse did not parse as XML` | — | — |
| document | `root-not-response-or-assertion` | `expected a samlp:Response or a saml:Assertion, got "…"` | — | `rootElement` |
| document | `root-not-response` | `expected the document element to be a samlp:Response, got "…"` | — | `rootElement` |
| duplicateId | `duplicate-id` | `the document uses the ID "…" more than once, …` | — | `id` |
| signature | `no-signature` | `the document carries no signature` | — | — |
| signature | `signature-malformed` | `the signature element is malformed: "…"` | — | — (L7) |
| signature | `signature-not-verified` | `the signature does not verify against any configured certificate` | — | — |
| signature | `no-reference` | `the signature carries no ds:Reference` | — | — |
| signature | `several-references` | `the signature carries <n> ds:Reference; …` | `count` | — |
| signature | `reference-not-same-document` | `the signature reference is not a same-document URI: "…"` | — | `referenceUri` |
| signature | `reference-not-found` | `the signature references "…", which is not in the document` | — | `referenceUri` |
| signature | `signature-not-enveloped` | `the signature is not inside the element it references, …` | — | — |
| signedNode | `no-direct-assertion` | `the response carries no direct-child saml:Assertion` | — | — |
| signedNode | `several-direct-assertions` | `the response carries <n> direct-child saml:Assertion; …` | `count` | — |
| signedNode | `response-not-signed` | `the signature does not cover the samlp:Response this validator requires` | — | — |
| signedNode | `assertion-not-signed` | `the signature does not cover the saml:Assertion this validator requires` | — | — |
| signedNode | `assertion-outside-signed` | `the document carries an Assertion or EncryptedAssertion, SAML 2.0 or 1.x, outside the one the signature covers` | — | — |
| signedNode | `assertion-inside-signature` | `the document carries an Assertion or EncryptedAssertion inside a ds:Signature, …` | — | — |
| status | `no-status` / `several-status` | `the response carries no samlp:Status` / `<n> samlp:Status; …` | `count` (several) | — |
| status | `no-status-code` / `several-status-codes` | `the samlp:Status carries no samlp:StatusCode` / `<n> …` | `count` (several) | — |
| status | `status-code-no-value` | `the samlp:StatusCode carries no Value` | — | — |
| status | `declined` | `the identity provider declined the login: "…"` | `statusCode?` (registered) | `statusCode` (unregistered) |
| assertionId | `no-assertion-id` | `the assertion carries no ID` | — | — |
| issuer | `no-issuer` / `several-issuers` | `the assertion carries no saml:Issuer` / `<n> saml:Issuer; …` | `count` (several) | — |
| issuer | `empty-issuer` | `the assertion's saml:Issuer is empty` | — | — |
| issuer | `no-expected-issuer` | `no expectedIssuer was configured, …` | — | — |
| issuer | `untrusted-issuer` | `the assertion was issued by "…", not the trusted issuer` | — | `issuer` |
| issuer | `several-response-issuers` | `the response must carry at most one saml:Issuer` | — | — |
| issuer | `issuers-differ` | `the response and the assertion name different issuers` | — | — |
| conditions | `no-conditions` / `several-conditions` | `the assertion carries no saml:Conditions` / `<n> …` | `count` (several) | — |
| notBefore | `not-before-invalid` | `Conditions NotBefore is not a valid xsd:dateTime: "…"` | — | `notBefore` |
| notBefore | `not-yet-valid` | `the assertion is not valid yet` | — | — |
| notOnOrAfter | `no-not-on-or-after` | `Conditions carries no NotOnOrAfter, …` | — | — |
| notOnOrAfter | `not-on-or-after-invalid` | `Conditions NotOnOrAfter is not a valid xsd:dateTime: "…"` | — | `notOnOrAfter` |
| notOnOrAfter | `expired` | `the assertion has expired` | — | — |
| audience | `no-audience-restriction` | `the assertion restricts no audience` | — | — |
| audience | `audience-restriction-empty` | `an AudienceRestriction names no audience` | — | — |
| audience | `audience-not-us` | `an AudienceRestriction on this assertion does not name us` | — | — |
| bearerConfirmation | `no-subject` / `several-subjects` | `the assertion carries no saml:Subject` / `<n> …` | `count` (several) | — |
| bearerConfirmation | `no-subject-confirmation` | `the saml:Subject holds no SubjectConfirmation` | — | — |
| bearerConfirmation | `no-bearer-qualifies` | `no bearer confirmation qualifies: #1 <reason> \| …[ \| and N more]` | `candidates` (≤ 5), `moreCandidates?` | — |
| destination | `no-destination` | `the response carries no Destination` | — | — |
| destination | `destination-not-us` | `the response is addressed to "…", not to us` | — | `destination` |
| replay | `replayed` | `this assertion has been presented before` | — | — |
| document | the six bearer-payload rules of A.6 (F1–F6) | | `count` (`several-assertions`) | — |

That is 50 validator rules (the README's 50 rows; the paired rows above are
two rules each) and 6 payload rules: 56 in `ASSERTION_RULES`.

`BEARER_CANDIDATE_REASONS`, in test order (README `:1443-1453`):
`method-not-bearer`, `no-confirmation-data`, `several-confirmation-data`
(`count`), `in-response-to-unexpected`, `in-response-to-mismatch`,
`recipient-not-acs`, `no-not-on-or-after`, `not-on-or-after-invalid`,
`not-before-invalid`, `not-on-or-after-passed`, `not-before-not-arrived` —
each with today's words verbatim.

## Appendix C — Information lost, for the user's approval

Each item is something a person or a program can see today and will not see
in the same place after this change. Nothing else is lost: every other row
of Appendix A keeps its information as facts, as diagnostics, or verbatim.

- **L1 — A token endpoint's `error_description` and `error_uri`.** Today in
  `TokenEndpointError.message` (redacted) and in the reduced `AxiosError`'s
  `response.data` (D1, D3). Server free text: never in an error. *Proposed:*
  each wrapping site logs it once at `debug`, redacted as today (H10).
  *Alternative:* drop it everywhere. The registered `error` code stays a fact.
- **L2 — `cause`.** `TokenEndpointError`, `BrowserAuthError`,
  `RefreshError`, the IdP-certificate `Error` (E26) keep the original as
  `cause` today. `AuthProviderFailure` carries no original — the goal's "no
  cause of any thrown value reaches an error".
- **L3 — The identity of a thrown value.** `getTokens()` rethrows a
  consumer's strategy, loader or presenter error as itself today, and the
  non-wrapping sites throw an `AxiosError` (`axios.isAxiosError` holds). After:
  always an `AuthProviderFailure`; the consumer's own error object, and its
  message, are not returned to it.
- **L4 — The authorization URL in a failed browser launch's error.**
  "Browser opening failed. Open manually: <url>" (K5). The URL stays in the
  strategy's log line and announcement (H7, H8); the error does not carry it.
- **L5 — A rejected configuration value.** The callback `port` and
  `timeoutMs` (K6, K7), the SNC `qop` (E21), the validator's `clockSkewMs`
  (E24): the field name stays, and for `qop` the allowed values; the value
  given does not.
- **L6 — Explanatory sentences of configuration errors.** Each configuration
  sentence (A.5) becomes its `case`'s fixed words; the meaning stays, the
  wording may shorten (each case's words are reviewed in the plan's words
  table).
- **L7 — Exception text inside SAML refusals.** xml-crypto's `loadSignature`
  message (F8), the XML parser's message (F2, F7).
- **L8 — Document values that fail admission.** An Issuer, Destination,
  StatusCode, reference URI, ID, element name or time carrying a control,
  bidirectional or line-separator character, or the wrong shape: quoted and
  escaped today, dropped after (§5.3). An unregistered `StatusCode` value of
  the right shape is kept as a diagnostic.
- **L9 — Values moved from words to diagnostics.** The SNC library path in
  A2200019's hint and in SNCERR_INIT's reason (G1, G2), each candidate's path
  in "no usable SNC library was found" (G5, G7), the two URIs of a SAML ACS or
  redirect mismatch (E8, E12). A consumer that shows only `reason` / `hint`
  no longer sees them; one that also renders diagnostics does.
- **L10 — A consumer's own `what`.** `refusalWords(error, what)` named the
  consumer's activity in free text; `classify(error, operation)` takes an
  operation from the closed list.
- **L11 — The class label in "`<what>` failed (`<Class>`)"** (A13), and which
  of three abort moments (K4) or four empty inputs (K14) occurred.
- **L12 — API surface, information kept.** `error.code` strings
  (`TOKEN_PROVIDER_ERROR_CODES`, `ASSERTION_ERROR_CODES`), `missingFields`,
  `check` as a class property, `CertificateMaterialError.incomplete` /
  `.expired` / `.words`, `TokenEndpointError.status` / `.oauthError` /
  `.code`: each is now a fact of `error`.
- **L13 — Diagnostics of an error that crosses a copy of `auth-errors`, or
  that was not minted by a builder.** An error rebuilt structurally — from
  another installed copy of `auth-errors` (bare, or inside that copy's
  `AuthProviderFailure`), or from any object shaped like one — keeps its kind
  and facts and loses its diagnostics (§5.4): no provenance mark crosses a
  copy. With one copy installed (the release gate's clean install, deduplicated
  by npm), nothing is lost; with two, an SNC path or a SAML issuer seen
  through the other copy is not shown.
