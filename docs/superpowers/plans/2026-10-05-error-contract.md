# Error contract — Implementation Plan

> **For agentic workers:** execute with superpowers:subagent-driven-development, one task per subagent, a review after each task (spec compliance first, then code quality). Steps use checkbox (`- [ ]`) syntax. This plan contains no implementation code by design: types and signatures are named from the spec, the code is written at implementation, test first.

**Goal:** what goes wrong in authentication has its own contract. Every refusal and every thrown token error of `@mcp-abap-adt/auth-providers`, and every refusal a logon target returns, is an `IAuthProviderError` — a closed union discriminated by `kind`, with allowlisted `facts`, words rendered from `kind` and `facts` alone, and admitted `diagnostics` beside them; the broker relays it without copied phrases (goal, "Goal" and "Success").

**Architecture:** the types and the `as const` allowlists live in `@mcp-abap-adt/interfaces-auth` 5.0.0 (the two optional fields of §4.3a land in 6.0.0, the contract major every later repository uses) (no logic). The runtime half — builders, `mint` and its brand, the renderer, diagnostics admission, classification, `AuthProviderFailure`, `guard`, `relayOutcome`, `matchKind` — lives in the new `@mcp-abap-adt/auth-errors` 1.0.0. connection 12.0.0's logon targets and its own refusals mint through `auth-errors`; auth-providers 6.0.0 puts every provider behind `AuthProviderBase` (the four methods run inside `guard`), converts every refusal and thrown error, and deletes its error classes; auth-stores 4.0.0 and auth-broker 5.0.0 + CLI 3.0.0 move to the new majors and relay the error.

**Anchors (binding):**
- Goal: `docs/superpowers/2026-10-05-error-contract-goal.md` (approved 2026-10-05) — its "Holds throughout" invariants bind this plan.
- Spec: `docs/superpowers/specs/2026-10-05-error-contract-design.md` (approved 2026-10-05; L1–L13 approved, L1 as amended by `authDebug` — commit `b0dc813`, amended again 2026-10-06: no redactor, a secret preparer, no server text ever logged; no built-in login timeouts, §6a and L14 — commit `b7e4587`; cancelling a login, §6b). Section numbers below (§n, A/B/C rows) are the spec's.

Where this plan has to decide something the spec leaves open, it says so under **Decision** and lists it in "Decisions this plan takes" at the end, for review with the plan.

---

## Global Constraints

Copied from the goal and the spec; every task is bound by all of them.

**Versions and order (spec §11.5 gate 4).** "interfaces (auth 5.0.0, auth-sap 3.1.0) → interfaces (auth 6.0.0, auth-sap 3.2.0; PR #125, spec §4.3a) → auth-errors 1.0.0 → connection 12.0.0 → auth-providers 6.0.0 → auth-stores 4.0.0 → auth-broker 5.0.0 + CLI 3.0.0; each consumer built against the published versions, the lockfile checked for `"link": true` and non-registry resolutions; after publishing, a clean install of each from the registry outside the repositories." `interfaces-auth-broker` gets no release (§4.6: "3.1.0 is inside `^3.0.0`").

**Dependencies only from the registry** (global CLAUDE.md). A consumer step starts only after what it builds against is published. No `file:`, `link:`, `npm link`, no cross-repository workspace link. The broker repository's own workspace link (CLI → auth-broker) is the standing same-repository exception and must be gone from what is released. After every install: no `"link": true` in the lockfile except same-repo workspace siblings, nothing resolved from outside the registry.

**Compiler flags** (spec §5.1, verbatim): "`strict`, `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noImplicitOverride`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`". Type tests are part of `test:check`; `lint:check` fails on a warning.

**Engines:** `^22 || ^24 || ^26` (spec §5.1).

**Goal invariants ("Holds throughout"), verbatim headings:**
1. "Normal course and failure are separate contracts." `IAuthProvider` and `IRefreshableTokenProvider` reference the error contract; they do not list kinds.
2. "No exception crosses `IAuthProvider`" (providers' rule 1): the error is a value in the outcome, never thrown across the contract.
3. "No free text in an error's facts." `reason` / `hint` are a function of `kind` and `facts` only; "No `message`, `cause` or body of any thrown value reaches an error"; diagnostics are admitted only from the one approved extraction source per field (§3.3), checked at the builder, rendered by their own function, never into `reason` / `hint`.
4. "Runtime checking only at the boundaries; the compiler guarantees the rest." Two boundaries: classification and diagnostics admission. Type tests (`@ts-expect-error`, part of `test:check`) prove each static rule load-bearing.
5. "The union is closed; a new kind is a major of `interfaces-auth`."
6. "The consumer composes." The shipped renderer is a default a consumer may replace.

**Spec decisions every task assumes (§0):** `reason` / `hint` stay required fields, rendered at minting; sixteen kinds (§3.1); one thrown class `AuthProviderFailure` holding `error`; `type IAuthRefusal = IAuthProviderError`; a logon target builds its refusal with `authError['logon-target']`; a provider relays a target through `relayOutcome`, which re-mints and never passes a target's object through.

**Nothing mutable is exported** from `auth-errors` (§5.5): no `Set`, `Map` or array; allowlist arrays in `interfaces-auth` are `Object.freeze([...] as const)`.

**The only type assertions on the contract's types** are `mint` and the three integer makers in `auth-errors` (§4.3, `tools/assertion-sites.json`); every other repository's list is empty.

**Provider rules** (auth-providers CLAUDE.md, rules 1–8) keep their behaviour; only the words' source and the error shape change. No retry is added, no renewal step runs twice, rule 5's blame does not change (`blamesCredential` is the table of §3.1).

**Repository process** (user rules): each repository step is one PR in that repository, one open PR per repository at a time; auth-providers' work is this PR (#68). The user merges and tags on their word and publishes; tasks stop at those gates. Nothing writes to `process.stdout`. No time estimates. Chat Ukrainian, artifacts English.

**Gates of every auth-providers task from 21 on:** every auth-providers task from 21 on runs `npm run test:stand` (Docker) as part of its gates.

**The 5.4.2 patch** (user-approved exception, in progress separately on `fix/basic-credential-redaction`): 6.0.0 must carry the same `legacyBasic` fix and its header-echo tests (`400` and `200` without `access_token`), and auth-providers' code tasks start from a `master` that includes 5.4.2 (Task 17).

---

## Review Focus

Inputs most likely to reach a user that no task's spec-listed tests exercise; each gets a test in the owning task (named there as **RF1–RF6**).

- **RF1 — An interactive login with no `signal`, and one the consumer aborts** (spec §6a: 6.0.0 has no built-in login timeout). A consumer upgrading from 5.x that never passed `timeoutMs` relied on the 30 s / 300 s defaults; now its login waits until a result, the IdP's refusal or an abort — and an abort must still release the callback port. Tests in Task 23: a browser, an OIDC and a SAML login and each manual strategy without a signal stay open with fake timers advanced well past 30 s and 300 s (the scope observed still open, the port still held); then the test's own `AbortController` aborts and the login ends `aborted`, the port is bound by the test afterwards, nothing is left reading stdin; an abort before the bind, during it and while waiting each end the same way; two empty `/callback` requests before the abort appear as `ignoredCallbacks` in the `aborted` words. In Task 34: the CLI has no bound at all — a login without Ctrl+C keeps waiting past the old five minutes, and `SIGINT` / `SIGTERM` abort it with the port released.
- **RF2 — A token endpoint answering with a status outside 100–599, or a response without a status** (a proxy's `0`, an appliance's `999`, a mock returning `undefined`). `httpStatus()` answers `undefined`; the spec says `problem: 'refused'` is "a response with a status". Test in Task 20: such a response yields `request-failed` with `problem: 'no-response'`, no `status` key, the safe-facts debug line written in both modes (`status` absent or `undefined` as 5.4.2 writes it; with `authDebug: true` also the reduced, previewed body), and no exception from the conversion.
- **RF3 — A refusal a consumer copied or mutated.** 4.x consumers may `structuredClone` a refusal, round-trip it through JSON (a session file, a worker message), spread it in JavaScript, or assign `refusal.hint = …`. A minted error is frozen (assignment throws in strict mode) and a copy is not in the `WeakSet`. Tests: in Task 9 — `structuredClone` and `JSON.parse(JSON.stringify(e))` of each kind classify back to the same kind and facts (rebuilt, no diagnostics); in Task 10 — `new AuthProviderFailure(clone)` documents its result (`unknown`, per §6) and the README warns; in Task 7 — assignment to a minted error throws `TypeError` in strict mode and is silently ignored in sloppy mode, stated in the migration note; in Task 14 — connection's `AuthRefusedError` built from a cloned refusal still has a `reason — hint` message.
- **RF4 — SNC library paths as they occur on users' machines:** a Windows profile with non-ASCII letters (`C:\Users\Олексій\…`), spaces and parentheses (`C:\Program Files (x86)\SAP\…`), a UNC path (`\\server\share\sapcrypto.dll`), and a registry value read by `reg.exe` that ends in `\r\n` or trailing spaces. `LocalPath` refuses C0 controls, so an untrimmed `\r` would drop the whole path to `null`. Tests in Task 25 (through the shipped locator and `nodeSncSystem`'s fake) and Task 6 (admission): each path is admitted unchanged and rendered JSON-quoted by `renderDiagnostics`; a registry value with trailing CR/LF reaches `candidatePaths` trimmed, not `null`.
- **RF5 — Two installed copies of `auth-errors` in one consumer tree** (connection and auth-providers resolving different `auth-errors` minors under a lockfile, or a nested copy). `instanceof AuthProviderFailure` is false across copies and diagnostics are dropped (L13). Tests: in Task 34 — the broker relaying a failure thrown by a second copy loaded from another path: `isAuthProviderFailure` true, `readFailure` gives the same kind and facts, the CLI prints `reason — hint`; in Task 36 — `npm ls @mcp-abap-adt/auth-errors` in a clean registry install of the broker plus connection shows exactly one deduplicated copy. The auth-errors and auth-providers READMEs say "use `isAuthProviderFailure` / `readFailure`, never `instanceof`".
- **RF6 — Two sessions sharing one provider, one of them closing while a login runs** (spec §6b). The server hands one cached provider to several sessions; a login started by one session's `rejected()` must survive another session's close, and end only when the last session has gone. The spec's tests cover two `getTokens` callers and two attached parties separately; the mixed case is not covered. Test in Task 22a: a login started by `rejected()` (attached parties A and B) joined by a `getTokens({ signal: C })` call; A aborts → nothing ends; C aborts → `getTokens` rejects `aborted`, the login continues for B; B aborts → the strategy's signal aborts and the port is bound by the test afterwards. In Task 34 the same through the broker: two `getProvider(…, { signal })` sessions and one `getToken(…, { signal })`.

---

## User gates (outside any task)

- **U0** — this plan approved (separately from the spec's approval). **Given by the user 2026-10-05.**
- **U1** — 5.4.2 merged, tagged and published by the user; Task 17 starts only after.
- **U2** — the GitHub repository `fr0ster/mcp-abap-adt-auth-errors` created and the npm name `@mcp-abap-adt/auth-errors` available to the user's npm account (the user publishes 1.0.0; a placeholder publish is the user's choice, not a task). Task 4 starts only after.
- **G1–G6** — merge, tag and publish of each repository's release, listed at the end of each repository's tasks. Every agent stops there and reports.

## Task overview

| # | Repository | Task | Nature |
|---|---|---|---|
| 1 | interfaces | Error contract types and frozen allowlists | judgement |
| 2 | interfaces | Outcome/refusal/failure, removals, JSDoc, type tests, surface tools | judgement |
| 3 | interfaces | interfaces-auth-sap 3.1.0, READMEs, CHANGELOGs, migration notes | mechanical |
| 3a | interfaces | interfaces-auth 6.0.0: `aborted.strategy?`, `failed.oauthError?` (spec §4.3a) | mechanical |
| 4 | auth-errors | Repository scaffold, CI, strict flags, lint | mechanical |
| 5 | auth-errors | Branded integer makers, private sets, membership guards | mechanical |
| 6 | auth-errors | Diagnostics admission | judgement |
| 7 | auth-errors | `mint`, builders, `WORDS`, `render`, `blamesCredential` | judgement |
| 8 | auth-errors | `renderDiagnostics`, `logFields` | mechanical |
| 9 | auth-errors | `classify`, `classifyOutcome` | judgement |
| 10 | auth-errors | `AuthProviderFailure`, `readFailure`, `isAuthProviderFailure`, `OK` | mechanical |
| 11 | auth-errors | `guard`, `relayOutcome`, `matchKind`, `unreachableKind` | judgement |
| 11a | auth-errors | `sharedAttempt` — the waiter rules, public (spec §6b) | judgement |
| 12 | auth-errors | The shape check (canonical script), fixtures, site lists | judgement |
| 13 | auth-errors | Exports sweep, generated kinds table, README/CHANGELOG/CLAUDE.md | mechanical |
| 14 | connection | Flip to the contract: minted constants, `guarded`, targets, legacy adapter and table, test migration | judgement |
| 15 | connection | Shape check | mechanical |
| 16 | connection | README/CHANGELOG/migration | mechanical |
| 17 | auth-providers | Start from 5.4.2; `auth-errors`; transition types | mechanical |
| 18 | auth-providers | Refusal core: `refusal.ts`, `rejection.ts`, `knownCodes.ts` | judgement |
| 19 | auth-providers | `AuthProviderBase` (with `legacyBridge`) for the credentials and token providers | judgement |
| 20 | auth-providers | `sendTokenRequest` site, `authDebug` debug line `{ status, error?, code?, sent }` with `prepareSecret`, `rejectMissingToken`, `legacyBasic` | judgement |
| 21 | auth-providers | Every token site and device polling on the new conversion | judgement |
| 22 | auth-providers | `getTokens` / `refreshTokens` failures, `remembered`, renewal on `kind` | judgement |
| 22a | auth-providers | Cancellable shared attempts: waiters, `attach`, per-call `signal` (§6b) | judgement |
| 23 | auth-providers | Interactive login (`interactive-login`) | mixed |
| 24 | auth-providers | SAML (`saml-assertion`, rule ids, diagnostics) | judgement |
| 25 | auth-providers | SNC onto `AuthProviderBase` (`snc`, `candidatePaths`, `library`) | judgement |
| 26 | auth-providers | Configuration throws (`configuration`, every case) | mechanical |
| 27 | auth-providers | Flip to interfaces-auth 6.0.0; delete every transition piece, the classes, `asContract` | mechanical |
| 28 | auth-providers | Shape check rules 1–8 and the site lists | judgement |
| 29 | auth-providers | Matrix audit, rule-1 suite, log/thrown-message suites | judgement |
| 30 | auth-providers | README (generated tables), CLAUDE.md, CHANGELOG, migration | mixed |
| 31 | auth-providers | Release preparation, PR description, `docs/superpowers/` deleted | mechanical |
| 32 | connection | Gate 7: suites against published 6.0.0, adapter deleted | mechanical |
| 33 | auth-stores | 4.0.0 on the new interface majors | mechanical |
| 34 | auth-broker | auth-broker 5.0.0 + CLI 3.0.0 relay the error | judgement |
| 35 | (all) | Final cross-repository checks | mechanical |

Every task ends with the **standard gates** of its repository — `build`, `test:check`, `lint:check`, `test` — green, then the two-stage review. "Load-bearing" items are run as deliberate breaks: break, watch the named test go red, revert; the PR records each run (spec §11.1 "Load-bearing proof").

---

## Repository 1 — `mcp-abap-adt-interfaces` (one PR)

Publish dependency: none (first in the chain). Branch from `master` in a worktree.

### Task 1: Error contract types and frozen allowlists

**Files:** `packages/interfaces-auth/src/error/` — `kinds.ts`, `facts.ts`, `diagnostics.ts`, `numbers.ts`, `IAuthProviderError.ts` (spec §10.1).

**Produces (names from §3, §4.1, §4.3):** `AUTH_PROVIDER_ERROR_KINDS` / `AuthProviderErrorKind`, `PlainKind`; every array of the §4.3 table with its union (`CONFIG_FIELDS`, `CONFIG_CASES`, `ALLOWED_VALUE_SETS`, `SNC_QOP_VALUES`, `BASIC_ENCODINGS`, `OPERATIONS`, `REQUEST_PROBLEMS`, `SYSTEM_CODES`, `TLS_FAILURE_CODES`, `OAUTH_ERROR_CODES`, `RFC_KEYS`, `ASSERTION_CHECKS`, `ASSERTION_RULES`, `BEARER_CANDIDATE_REASONS`, `SAML_STATUS_CODES`, `SNC_PROBLEMS`, `SNC_CANDIDATE_SOURCES`, `SNC_UNUSABLE_REASONS`, `SNC_ARCHS`, `INTERACTIVE_OUTCOMES`, `CREDENTIAL_KINDS`) and the per-kind `<KIND>_PROBLEMS` / `_VERDICTS` arrays (§4.3 last paragraph); `AuthProviderErrorFacts` (§3.2, `SamlFactsOf`, `SncFactsOf`, `ConfigFactsOf` — **narrowed per variant**: each `snc` problem and each `configuration` case carries only its own facts per §3.2's two tables, `allowed` only on `snc-qop-invalid` / `basic-encoding-missing` and typed to that set; no flat optional facts —, `BearerCandidate`, `SncCandidate`); the diagnostics maps `SAML_RULE_DIAGNOSTIC`, `SNC_PROBLEM_DIAGNOSTICS`, `CONFIG_CASE_DIAGNOSTICS` (each `satisfies Record<…>`) and `SamlDiagnosticOf` / `SncDiagnosticOf` / `ConfigDiagnosticOf`, the diagnostic value types (`LocalPath`, `DocumentValue`, `DocumentTime`, `XmlName`, `XmlId`, `ConfigUri`); branded `HttpStatus`, `Count`, `Port` with unexported brand symbols (no `Seconds`: spec §4.3, §6a); `IAuthProviderError`, `AuthProviderErrorOf<K>`, `SamlAssertionError`, `SncError`, `ConfigurationError`, the unexported `minted` symbol.

**Steps:**
- [ ] Build each array's members from the spec's named source today (§4.3 "Source today" column; Appendix A §A.8 for `OPERATIONS`, including `unfamiliar-error`, `preparing`, `establishing`, `authorizing`; Appendix B for the 56 `ASSERTION_RULES` and 11 `BEARER_CANDIDATE_REASONS`; §A.5 for `CONFIG_CASES`, `CONFIG_FIELDS` = the 47 of `KNOWN_CONFIG_FIELDS` plus `port`, `payload`, `read` — not `timeoutMs`, removed by §6a). `interactive-login` facts are discriminated by `outcome` (§3.2: `port-in-use` → `port`; `aborted` → `ignoredCallbacks?`; `disposed` → `strategy: 'browser' | 'manual'`; `identity-provider-refused` → `oauthError?`; `browser-launch-failed` → `code?`; `failed` → `code?`, `status?`; others none); `INTERACTIVE_OUTCOMES` has no timeout member. Read the auth-providers sources at the spec's line references; copy, do not retype from memory.
- [ ] Every array `Object.freeze([...] as const)` at its definition (§5.5).
- [ ] The rule → check correlation is a type here (**Decision D1**: `AssertionRuleCheck`, read by `SamlFactsOf<R>`); the runtime `ASSERTION_RULE_CHECK` lives in auth-errors (§5.5 bullet 4) and `satisfies` it.

**Tests to write first** (`src/__typechecks__/errorContract.ts`, compiled by `test:check`, §11.2): the full probe of §11.2 on the real types, including the per-variant fact lines (`logon-refused` with `candidates` / `libraryArchs`, `library-not-found` with `rfcKey`, `snc-qop-invalid` with `allowed: 'basic-encoding'`, `required-fields-missing` with `allowed`) — every positive line and every `@ts-expect-error` line of the consumer half (narrowing by `kind` + `variant`, facts narrowed, forbidden diagnostics, `facts.rule` not narrowing, the forged pairing with and without the brand); object literal not assignable to `IAuthProviderError`; `status: 500` not a `HttpStatus`; each union `Equal<>` to `(typeof ARRAY)[number]` both ways; `keyof AuthProviderErrorFacts` `Equal<>` `AuthProviderErrorKind`.

**Load-bearing:** remove one kind's facts entry → the `keyof` equality fails; move `variant` into `facts` in a scratch copy → the narrowing lines fail (record, revert).

**Gate:** standard; `check:surface`, `check:graph` accept the frozen arrays (if a check refuses `Object.freeze`, the check is amended in this PR — §5.5).

### Task 2: Outcome, refusal, failure; removals; JSDoc; surface tools

**Files:** `src/auth/AuthOutcome.ts` (§4.2), `src/error/IAuthProviderFailure.ts`, JSDoc of `IAuthProvider`, `IAuthTargets` (`ILogonTarget`), `IAssertionValidator`, `ITokenProvider`, `IRefreshableTokenProvider`; `src/auth/ICallbackServer.ts` — `ICallbackServerOptions.timeoutMs` removed, `signal` documented as the only way a scope ends without a result, the `withBrowserCallbackServer` example on `signal` (§4.4, §6a); `IAuthorizationStrategy`'s JSDoc no longer names a timeout; **§6b:** `ITokenResult.refreshTokenDisposition?: 'keep' | 'replace' | 'clear' | undefined` with `REFRESH_TOKEN_DISPOSITIONS` (frozen `as const`); `AuthorizationRequest.signal?: AbortSignal | undefined` (a strategy must honour it), `ITokenRequestOptions { signal? }`, `ITokenProvider.getTokens(options?)` and `IRefreshableTokenProvider.refreshTokens(options?)`; delete `src/token/TokenProviderErrorCodes.ts`, `src/auth/AssertionErrorCodes.ts`; `src/index.ts`; `tools/package-map.json`.

**Consumes:** Task 1. **Produces:** `IAuthRefusal = IAuthProviderError`, `AuthOutcome` (readonly), `IAuthProviderFailure`.

**Steps:**
- [ ] Normal-course files import only `IAuthProviderError` / `IAuthRefusal` / `IAuthProviderFailure` (goal invariant 1) — a type test or grep test asserts no kind name appears in them.
- [ ] JSDoc texts per §4.2 (Oops's refusal is an `IAuthProviderError`; a method never throws; `getTokens` / `refreshTokens` reject with an `IAuthProviderFailure`, read it with `readFailure`; a target's Oops is built through `auth-errors`; shipped validators reject with `saml-assertion`). The `IAuthProviderError` JSDoc states the exhaustiveness requirement (§9).
- [ ] `STORE_ERROR_CODES` stays (§4.4).
- [ ] Every new symbol mapped in `tools/package-map.json`.

**Tests first:** `@ts-expect-error` for an object literal as `refusal` of `AuthOutcome` and as `IAuthRefusal`; `@ts-expect-error` on an `ICallbackServerOptions` literal with `timeoutMs` (positive line: the same literal with `signal`); positive lines: a class with `getTokens()` (no parameter) still satisfies `ITokenProvider`, one with `getTokens(options?: ITokenRequestOptions)` too; `@ts-expect-error` on `getTokens({ signal: 'x' })`; positive line: a value typed `IAuthProviderError` is an `IAuthRefusal`.

**Gate:** standard + `check:surface`, `check:graph`; `surface-removed.txt` lists the two removed code constants and `ICallbackServerOptions.timeoutMs`.

### Task 3: interfaces-auth-sap 3.1.0, docs

**Files:** `packages/interfaces-auth-sap/package.json` (range `^4.0.0 || ^5.0.0`, widened to include `^6.0.0` in the interfaces PR #125 (spec §4.3a)), `__typechecks__/certificateLoaderCompatibility.ts` (the 5.x assertion both ways, §4.6), both CHANGELOGs, interfaces-auth README (error contract section, exhaustiveness requirement, "Migrating to 5.0.0" with the §4.5 table), auth-sap migration note "nothing to do". Versions: interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0; interfaces-auth-broker untouched.

**Gate:** standard; `npm pack --dry-run` of both shows only `dist`, README, CHANGELOG, licences.

**G1 (user):** merge, tag, publish interfaces-auth 5.0.0 and interfaces-auth-sap 3.1.0. Verify with `npm view` before Task 4.

---

### Task 3a: interfaces-auth 6.0.0 (spec §4.3a; new PR in the interfaces repository after G1)

**Files:** `packages/interfaces-auth/src/error/facts.ts` — `interactive-login` `aborted` gains `strategy?: 'browser' | 'manual'`, `failed` gains `oauthError?: OAuthErrorCode`; spec §4.3's rule stated in the README's versioning note (any change to the shape of facts or diagnostics is a major: a field added, removed, made required or narrowed); `CHANGELOG.md` 6.0.0 (migration note: the two optional fields); version 6.0.0; sibling ranges widened in the same PR (#125), versions by the PR #123 rule; `tools/package-map.json` unchanged (no new symbol).

**Tests first** (`src/__typechecks__/errorContract.ts`): positive lines — an `aborted` error with `strategy: 'manual'`, a `failed` error with `oauthError: 'access_denied'`; `@ts-expect-error` — `aborted` with `strategy: 'device'`, `failed` with an unregistered `oauthError`, `oauthError` on `aborted`; **the union stays closed**: `keyof AuthProviderErrorFacts` still `Equal<>` `AuthProviderErrorKind`, `INTERACTIVE_OUTCOMES` unchanged (`Equal<>` against 5.0.0's list), and a handler map over every kind still compiles without a new handler — 6.0.0 changes the shape of two kinds' facts, and adds no kind.

**Gate:** standard; `check:surface`, `check:graph`.

**G1a (user):** merge, tag, publish interfaces-auth 6.0.0. Verify with `npm view` before Task 4.

---

## Repository 2 — `mcp-abap-adt-auth-errors` (new; one PR after the initial commit)

Publish dependency: interfaces-auth 6.0.0 on the registry (G1, G1a); repository and npm name ready (U2).

### Task 4: Scaffold

**Files (§5.1):** `package.json` (`main`, `types`, `files`, `license: LGPL-3.0-only`, `engines`, `sideEffects: false`, scripts `clean`, `build`, `build:fast`, `test`, `test:check`, `lint`, `lint:check`, `prepublishOnly`; `dependencies`: `@mcp-abap-adt/interfaces-auth ^6.0.0` only (spec §4.3a); `devDependencies` as auth-stores), `tsconfig.json` (the six flags), `tsconfig.build.json` (excludes tests and `__typechecks__`), `biome.json` (auth-providers'), `jest.config.js`, `.github/workflows/ci.yml` (Node 22, 24, 26: `npm ci`, build, `test:check`, `lint:check`, `test`), `release.yml` (on `v*.*.*`), `CHANGELOG.md`, `README.md`, `CLAUDE.md`, `LICENSE`, `COPYING`, `.npmrc`, `.gitignore`, `src/index.ts`; empty module files of §5.1's `src/` list.

**Steps:** initial scaffold commit on `main` (the user's new repository may need the first push to `main`; everything after goes through one PR, branch `feat/auth-errors-1`). Lockfile check after `npm install`.

**Files (addition, R3):** `src/index.ts` exports `OK` (the frozen `{ ok: true }`, §5.6) from this task on, so the scaffold has one real export.

**Tests first:** the built package (`dist/index.js`, required by path as a consumer would) exports `OK`, deep-equal to `{ ok: true }` and frozen (an assignment throws in strict mode); `test:check` compiles a `__typechecks__` file asserting `OK`'s type is the `{ ok: true }` member of `AuthOutcome`.

**Gate:** standard; CI green on the PR.

### Task 5: Integer makers, private sets, guards

**Files:** `src/numbers.ts` (`httpStatus`, `count`, `port`, private `inRange`; no `seconds`, §4.3), `src/allowlists.ts` (one module-private `Set` per array, `has` captured at load, one exported guard per array: `isSystemCode`, `isTlsFailureCode`, `isOAuthErrorCode`, `isRfcKey`, `isConfigField`, `isAssertionRule`, `isOperation`, … — one per §4.3 array and per `<KIND>_PROBLEMS` array).

**Tests first:** each maker at both bounds, one past each bound, non-integers, `NaN`, `Infinity`, strings, `-0`; each guard true for every member, false for a near miss and a non-string; type tests: each guard's predicate type `Equal<>` the array's union; `const s: HttpStatus = 500` fails, `httpStatus(500)` narrowed compiles.

**Tests first (addition, C5):** patching `Set.prototype.has` after the module has loaded (to answer `true` for everything) changes no guard's answer — a foreign code still refused; restored in `afterEach`.

**Load-bearing:** remove the captured `has` (call `set.has` directly) → the `Set.prototype.has` case red.

### Task 6: Diagnostics admission

**Files:** `src/admission.ts` — the six checks of §5.3 (`LocalPath`, `DocumentValue` incl. the ASCII-only variant for `referenceUri` / `statusCode`, `XmlName`, `XmlId`, `DocumentTime`, `ConfigUri`), each total (guarded read), answering the admitted value or "drop"; the runtime admission table keyed by the three diagnostics maps (one source with the types).

**Tests first (§11.1 "Diagnostics admission"):** each check accepted value; each refused class (C0, DEL, C1, U+2028/2029, each bidi control U+202A–U+202E and U+2066–U+2069, a lone surrogate); length limits both sides (`LocalPath` 1024 never truncated; `DocumentValue` cut to 64 code points at a code-point boundary with `…`, an astral character on the boundary); non-string; throwing getter; `&#10;`-decoded newline in an Issuer; 10 000-character Destination; `xsd:dateTime` with a quote; `referenceUri` with a space; `ConfigUri` with userinfo, a query, a fragment, `javascript:`; admitted `ConfigUri` is `origin + pathname` ≤ 512. **RF4:** `C:\Users\Олексій\AppData\…\sapcrypto.dll`, `C:\Program Files (x86)\SAP\…`, `\\server\share\sapcrypto.dll`, `/Applications/Secure Login Client.app/…` admitted unchanged; a path ending in `\r` dropped (proving the trim in Task 25 is load-bearing).

**Load-bearing:** delete the bidi range from `LocalPath` → its case red; delete the code-point-boundary logic → the astral case red.

### Task 7: `mint`, builders, words, blame

**Files:** `src/mint.ts` (the one assertion, the module-private `WeakSet`, deep freeze, `isMinted` — **exported** as a public guard, spec §5.6, R7), `src/builders.ts` (`authError` per §5.2: generic builders for the three kinds with diagnostics using `One<…>`, `DiagnosticsInputOf<…>`; plain builders; normalisation — omit absent keys, cap and deduplicate arrays per §3.2, freeze nested), `src/words.ts` (`WORDS` `satisfies` the mapped type; one `switch` per discriminant ending in `unreachable(x: never)`; `ASSERTION_RULE_CHECK`; the TLS words), `render`, `blamesCredential` (the §3.1 column, a table `satisfies` a mapped type).

**Words:** Appendix A's "new words" column; *verbatim* rows reproduce today's string exactly (read the auth-providers source at the spec's line references); the words not fixed by the spec are this plan's "Words for review" appendix.

**Tests first:**
- Builders: each kind; `variant` set from the facts' discriminant; absent keys omitted (no `undefined`-valued key); `fields` capped at 8 and deduplicated in order; `candidates` capped at 5 / 8, bearer candidates beyond 5 counted into `moreCandidates` (7 given → 5 kept, `moreCandidates` 2; with a given `moreCandidates` 3 → 5); result frozen deeply; a JavaScript caller passing a forbidden diagnostic gets it dropped; a refused diagnostic dropped and the error still minted.
- Words (§11.1 "Words"): every kind × every discriminant value renders; each *verbatim* row of Appendix A asserts the exact string (A2, A4–A8, A10, A14–A18, B1–B14, K1, K2, K3, K10–K13, K15 (first sentence), K16, K17, G1 reason, G3, G4, G6, G8–G10, I1–I5 — the I rows' words live here because connection mints with them); no rendered string contains a diagnostic value (each built with a marker); `blamesCredential` per row of §3.1 incl. `snc` `logon-refused` with and without `RFC_LOGON_FAILURE`, `connection` `refused-after-renewal`.
- `interactive-login`: `disposed` renders K2's sentence for `strategy: 'browser'` and K15's first for `'manual'`; `aborted` renders `the browser login was aborted` for `strategy: 'browser'` or no strategy, with the tally clause when `ignoredCallbacks` is set, and `the manual login was aborted` for `strategy: 'manual'`, never with the clause; `failed` with `oauthError` renders it where K11 puts the code (`(HTTP <n>, <oauthError>[, <code>])`), verbatim against today's `browserLoginWords` output for the same facts; A9's `failed` hint is `complete the login, or abort it`; no word mentions a timeout or a number of seconds (a test scans every rendered `interactive-login` string).
- **RF3 (part):** assignment to a minted error's `reason` and to a nested `facts` array throws `TypeError` under `'use strict'`.
- Type tests (§11.2): the builder half of the probe verbatim (positive and `@ts-expect-error` lines); `WORDS` with one kind removed does not satisfy; a discriminant switch missing a member fails.

**Load-bearing:** remove the `WeakSet.add` → every "minted" assertion red; drop `Object.freeze` on nested arrays → the mutation test red; make one verbatim word differ by a character → its row test red.

### Task 8: `renderDiagnostics`, `logFields`

**Files:** `src/diagnostics.ts`.

**Tests first:** one line per field, JSON-quoted (`library`, `candidates` joined with each source and reason and `(missing)` for a `null` path, `issuer`, the URIs); `undefined` when none; `render` never calls it (a spy); `logFields` = `{ error: reason, kind, status?, diagnostics? }` with `diagnostics` as a separate field and `status` only when a fact.

### Task 9: `classify`, `classifyOutcome`

**Files:** `src/classify.ts` — the six steps of §5.4 in order, total (own `try`), each property read once through a guarded read; one validator per kind `satisfies` a mapped type over the kinds; re-mint renders words here and never reads the input's `reason`, `hint`, `diagnostics`; `classifyOutcome` per §5.4's last paragraph.

**Tests first (§11.1 "Hostile values", "Carriers from another copy", "Forged diagnostics", "Exception text excluded", "Re-mint across copies"):** all listed hostile values; a forged carrier with a secret `reason` re-minted without it; unknown `kind`; facts out of their sets; primitives, symbols, functions; a second copy of the built package loaded from a temporary path (the test copies `dist/` and requires it) — bare, every kind, same kind and facts, re-rendered, no diagnostics (inside that copy's `AuthProviderFailure`: Task 10, C4); the double-read getter on `error` (only the first read used); a foreign carrier with an invalid `error` falls through to steps 4–6; forged diagnostics (JWT-shaped `library`, exception text in `issuer`) dropped; the same-copy minted error keeps its diagnostics; for each kind an `Error` with a marker in `message`, `cause`, `stack`, `name` — marker absent from `JSON.stringify`, `reason`, `hint`, `renderDiagnostics`, `logFields`. **RF3:** `structuredClone` and a JSON round-trip of a minted error of each kind classify to the same kind and facts, without diagnostics.

**Builders keep only declared facts (controller ruling from Task 7):** once the per-kind validator exists, every builder keeps only the fact keys its kind and variant declare — a JavaScript caller's extra key (`{ problem: 'expired', secret: '<marker>' }`) is dropped before minting; test per kind: the extra key absent from `facts`, the marker in no rendering; load-bearing: copy the facts object as given → red.

**Forged-diagnostics matrix (§11.1, the `classify` and `classifyOutcome` boundaries; `readFailure` in Task 10, `relayOutcome` in Task 11 complete it).** Inputs, each carrying a unique marker: (a) a structurally valid `snc` `no-credential` error, not minted, whose `diagnostics.library` is a JWT-shaped token that passes `LocalPath`; (b) a structurally valid `saml-assertion` `untrusted-issuer` error, not minted, whose `diagnostics.issuer` is an exception message; (c) each of (a) and (b) bare as minted by a second copy loaded from a temporary path; (d) each inside the second copy's `AuthProviderFailure` — **case (d) and the carrier cases of (c) are written in Task 10** (C4), where `AuthProviderFailure` exists; (e) each of (a)/(b) as the `error` of a plain object carrier. Through `classify` and through `classifyOutcome` (cases (a), (b), (c) bare and (e) here) (as `{ ok: false, refusal }`): the result has the input's kind and facts and **no** `diagnostics` key, and the marker is absent from `renderDiagnostics(result)`, `logFields(result)`, `JSON.stringify(result)`, `String(result)` and `util.inspect(result, { depth: null })`. Positive case: the same two errors minted by this copy with the same diagnostics keep them, the same object, through `classify` and `classifyOutcome`.

**Load-bearing:** each step deleted in turn (minted-membership, carrier read-once, structural rebuild, TLS, status/oauth/code) → its named case red; reading `reason` in the rebuild → the forged-carrier case red; copying the input's `diagnostics` into the rebuilt error → the (a), (b), (c) and (e) cases red through `classify`; returning a foreign refusal as it is from `classifyOutcome` → the (c) cases red through `classifyOutcome`.

**Index-signature limit (added 2026-10-05, spec §13 item 3):** a test feeds `classify` / `classifyOutcome` a minted-looking structure whose `diagnostics` and `facts` are index-signature objects carrying another kind's keys (`library`, `credential`) beside the allowed ones: the rebuilt error carries only the declared keys of its variant (and no diagnostics, being a structural rebuild).

### Task 10: `AuthProviderFailure`, `readFailure`, `isAuthProviderFailure`, `OK`

**Files:** `src/failure.ts` (§6): constructor takes a minted error (unminted → `unknown`), `message` = `reason` or `reason — hint`, no `cause`, no diagnostics in the message; `readFailure = classify`; `isAuthProviderFailure` works across copies (structural: `name` + a valid `error` — **Decision D2**: it answers true for another copy's instance whose `error` passes the structural rebuild; it never reads `message`); `OK` frozen.

**Tests first:** message format with and without hint; `JSON.stringify(failure)` and a pino-style enumerable-property copy hold only `name`, `message`, `error` (§12 "not measured" item made measured); **RF3:** `new AuthProviderFailure(structuredClone(minted))` holds the spec's fixed `unknown` error, `operation: 'unfamiliar-error'` (spec §6; the constructor takes no operation, C14) — the test names this as the documented behaviour; **moved from Task 9 (C4):** a second copy's `AuthProviderFailure` of every kind classified by this copy (`classify`, `classifyOutcome` as a refusal carrier) → same kind and facts, re-rendered, no diagnostics, and the forged-diagnostics case (d) through `classify` and `classifyOutcome`; type test: constructing from an unminted object fails to compile. **Forged-diagnostics matrix, the `readFailure` boundary:** Task 9's inputs (a)–(e), each thrown — (d) as the second copy's `AuthProviderFailure`, the rest as thrown objects — read with `readFailure`, and the result wrapped in this copy's `AuthProviderFailure`: kind and facts kept, no `diagnostics`, marker absent from `renderDiagnostics`, `logFields`, `JSON.stringify` of the result and of the new failure, `String(failure)`, `failure.message`, `util.inspect(failure, { depth: null })`; a same-copy failure carrying diagnostics keeps them through `readFailure` (positive case).

**Load-bearing:** let the `AuthProviderFailure` constructor accept an unminted error as it is → the (a)/(b) cases red; make `readFailure` take a foreign carrier's `error` without the rebuild → the (d) case red.

### Task 11: `guard`, `relayOutcome`, `matchKind`, `unreachableKind`

**Files:** `src/guard.ts` (`guard`, `relayOutcome`, `RelayedOutcome` — **Decision D3**: `relayOutcome` lives in `guard.ts`; §5.1 lists no file for it), `src/exhaustive.ts`.

**Tests first:** `guard`: body throws each hostile value → Oops, never rejects; `grant` thunk throws → refusal with the operation and no grant; a grant off the list ignored; the catch reads only the two locals (a body that throws after mutating a provider property still yields the operation given). `relayOutcome`: a target returning a same-copy minted refusal → same object, `thrown: false`; returning a foreign-copy one → rebuilt without diagnostics; returning garbage → `logon-target` fallback with `wire: 'unknown'`, `thrown: false`; throwing → `classify`, `thrown: true`. `matchKind` / `unreachableKind` version-skew cases of §9 verbatim (`future-kind`, `tls` with an unknown `code`, `snc` with an unknown `problem`, through a handler map and through a `switch`). Type tests: `matchKind` with one handler missing; a switch over all but one kind with `unreachableKind(error)`. **Forged-diagnostics matrix, the `relayOutcome` boundary:** Task 9's inputs (a)–(e), each once **returned** by the target call as `{ ok: false, refusal }` and once **thrown** by it: the outcome's refusal has kind and facts, no `diagnostics`, the marker absent from `renderDiagnostics`, `logFields`, `JSON.stringify`, `String`, `util.inspect`; `thrown` is `false` and `true` respectively; positive case: a same-copy minted refusal with diagnostics, returned, comes back as the same object with its diagnostics, and thrown inside this copy's `AuthProviderFailure` comes back with them too.

**Load-bearing:** pass `matchKind`'s argument through unnormalised → `future-kind` case red (`TypeError`); return the target's object from `relayOutcome` → the foreign-copy and the (a)–(e) returned cases red; move the grant read outside the `try` → the throwing-grant case red.

### Task 11a: `sharedAttempt` (spec §6b, R2)

**Files:** `src/sharedAttempt.ts`, exported from `src/index.ts` — the waiter rules, implemented once for the token providers (Task 22a) and the broker (Task 34): a slot holding at most one active attempt; `join(start, signal?)` starts an attempt when the slot is empty or joins the active one, and returns that waiter's promise; an attempt owns an `AbortController` whose signal it hands to `start`; one waiter's abort rejects only that waiter with an `AuthProviderFailure` of `interactive-login` `aborted`; a waiter without a signal never aborts; when the last live waiter aborts, the attempt leaves the slot at once (identity-checked) **before** that waiter is rejected and before the controller aborts; every attempt carries a `drain` (the exclusive local work it reports settled, plus the drain it inherited) and the slot keeps an aborted attempt's drain as `previousDrain`, which a new attempt awaits before its exclusive work — raced only against its own signal; a settled attempt leaves the slot; no timer anywhere. What an attempt commits stays with the caller (`start`'s result is returned, never applied here).

**Tests first:** two waiters, one aborts → only it rejects `aborted`, the other gets the result, `start` called once, its signal not aborted; both abort → the signal aborted, the slot empty before the second waiter's rejection is observed; a waiter without a signal keeps the attempt alive; a new `join` after all aborted, while the old `start` is still pending → a fresh `start` (doomed-join window); `previousDrain` awaited before the new attempt's exclusive work, and the wait ends `aborted` when the new attempt's only waiter aborts; three aborted attempts chain their drains; a settled (resolved or rejected) attempt leaves the slot; a `start` that throws synchronously rejects every waiter with its classified failure (`classify`, no foreign value); the module exports no `Set`/`Map` (Task 13's sweep covers it).

**Load-bearing:** abort the attempt on the first waiter's abort → the two-waiter case red; clear the slot only on settle → the doomed-join case red; drop the inherited drain → the chain case red.

### Task 12: The shape check (canonical script)

**Files:** `tools/check-provider-shape.mjs` (TypeScript compiler API), `tools/assertion-sites.json` (`numbers.ts`: `httpStatus`, `count`, `port`; `mint.ts`: `mint`), `tools/diagnostic-sites.json` (empty: auth-errors calls no builder with diagnostics), `tools/__fixtures__/` (one file per rule 1–8 breaking it, one obeying all), `lint:check` = Biome then the script with the rules this repository runs.

**Decision D4 (script ownership):** this file is the canonical copy, and auth-errors publishes it as a plain file (`tools/check-provider-shape.mjs` in `package.json` `files` — no `bin`, no new dependency: the script needs `typescript`, which every repository running it has as a devDependency). connection, auth-providers and the broker each keep a copy in their `tools/`, **byte-identical** to the one in their installed `@mcp-abap-adt/auth-errors` — no header line, no edit — and each has a test that compares the two files byte for byte, so drift fails that repository's suite (R1). The rules a repository runs are selected by a `--rules` argument in its `lint:check`.

**Decision D5 (rules per repository):** auth-errors runs rule 4 (four allowed sites — `mint` and the three makers, per §4.3 and §8.2 rule 4) and rule 6 (empty list); connection and the broker run rules 4, 5 and 6 (§8.2; §10.3/§10.6 say "4–5", rule 6 with an empty list is strictly stronger and costs nothing); auth-providers runs 1–8.

**Rule 4, overloads (controller ruling from Task 7):** the script also reports an overload signature whose return type is or contains `IAuthProviderError` / `AuthOutcome` outside `builders.ts` and `mint.ts` (an overload hides a cast); a fixture for it, and none reported for the builders' own overloads.

**Tests first (§11.3):** `npm pack --dry-run` lists `tools/check-provider-shape.mjs`; a Jest test runs the script over each fixture and expects exactly that rule reported; the `500 as HttpStatus` fixture reported in any file and not in `numbers.ts`'s makers (§4.3); a spread of an `IAuthProviderError` (rule 5); a builder call with diagnostics outside the site list (rule 6); a `guard` call whose `grant` is not a function expression (rule 7).

**Rule 3 risk (§12 "not measured"):** implement structural satisfaction first; if it gives a false positive on the obeying fixture or on any real source of the four repositories (run it read-only over their trees), narrow to "an object literal with all four methods" and record the spec amendment for review (§12 permits exactly this).

### Task 13: Exports sweep, generated table, docs

**Files:** `src/index.ts` final; `scripts/generate-kinds-table.mjs` and the README table (§11.4); `README.md` (§10.2 list: what an error is, the sixteen kinds with facts and words, diagnostics and admission, the two exhaustiveness patterns, `classify` / `readFailure` and "never `instanceof`" (RF5), `guard` / `relayOutcome` / pointer to `AuthProviderBase`, `sharedAttempt` (Task 11a), `isMinted` as a public guard (R7), the brand and its limit); `package.json` `files` includes `tools/check-provider-shape.mjs` (Decision D4); `CHANGELOG.md` 1.0.0; `CLAUDE.md`.

**Tests first (§11.1 "Exported allowlists cannot be widened"):** every attack listed (push through a cast, index assignment, `defineProperty`, `splice`, `.call` of `Set`/`Map` methods on every export, patching `Set.prototype.has`) then a foreign code is still refused and no word contains it; an `instanceof Set` / `Map` sweep over the module namespace nested one level finds nothing; the README table equals the generated one.

**G2 (user):** merge, tag `v1.0.0`, publish `@mcp-abap-adt/auth-errors` 1.0.0 (depending on `interfaces-auth ^6.0.0`, published at G1a). Verify with `npm view`, and that the published `package.json` declares `^6.0.0`.

---

## Repository 3 — `mcp-abap-connection` 12.0.0 (one PR)

Publish dependency: interfaces-auth 6.0.0, interfaces-auth-sap 3.2.0, auth-errors 1.0.0 on the registry (G1, G2).

**Why one task flips and bridges.** On interfaces-auth 6.0.0 nothing unbranded compiles: connection's own refusal constants, its targets, and every test that hands a 5.x auth-providers provider to connection as an `IAuthProvider` (its devDependency `^5.2.0`, 13 test files). A preparatory adapter cannot be written before the flip either: the adapter translates into `auth-errors` builders, which need interfaces-auth 6.0.0. So the flip, connection's producers, the adapter, its table and the migration of every affected test are one task, Task 14, and it is the first green state of the PR.

### Task 14: Flip to the error contract, with the legacy provider adapter

**Files:**
- `package.json` (`interfaces-auth ^6.0.0`, `interfaces-auth-sap ^3.2.0`, `auth-errors ^1.0.0`; devDependency auth-providers stays `^5.2.0` until Task 32); lockfile check.
- `src/connection/authErrors.ts` (I3–I5 as `authError.connection({ problem, at })`; `guarded` through `classifyOutcome(answer, authError.connection({ problem: 'provider-threw', at }))`; `AuthRefusedError` unchanged in shape and `reason — hint` message), `RfcTransport.ts:477-487`, `HttpTransport.ts:514-528` (I1, I2 via `authError['logon-target']`), `AbstractAbapConnection.ts:975`, `:1612`. Where connection acts on a refusal it reads `kind` (§7).
- `src/__tests__/helpers/legacyProvider.ts` (§10.3: `LegacyRefusal`, `LegacyOutcome`, `LegacyLogonTarget`, `LegacyAuthProvider`, `legacyProvider`), its closed translation table (the exact 5.x words connection's tests produce → the Appendix A builder call), the recorder, and an `afterEach` failing on any untranslated reason.
- Every test file that builds a provider from auth-providers wraps it in `legacyProvider(…)` (`realProviders.test.ts`, `connectorAxes.test.ts`, `connectors/fixtures.ts`, `helpers/onPrem.ts`, … — 13 files, found by import of `@mcp-abap-adt/auth-providers`); every test double that builds a refusal by hand mints it through `auth-errors`.

**Steps (one commit series, gates checked at its end):**
- [ ] On `master`, before any change, run the suites once with a recording-only wrapper (a throwaway branch commit, not pushed) and list every 5.x refusal reason connection's tests produce; this list seeds the table.
- [ ] Flip the dependencies; convert connection's producers; write the adapter and its table; wrap the 13 files; update the hand-built test refusals. No cast anywhere (§10.3); `tsconfig.build.json` keeps `src/__tests__` out of `dist`.

**Tests first:** I1–I5 kind, facts and verbatim words; `guarded` re-mints a forged provider refusal (`{ ok: false, refusal: { reason: '<secret>' } }` from a JavaScript provider → `provider-threw`, the secret in no message) and a provider that throws; a provider returning a refusal minted by the same `auth-errors` passes as the same object; `AuthRefusedError.message` is `reason — hint`. The adapter's own tests: a 5.x refusal in the table becomes its kind; one outside the table yields `provider-threw` and fails the `afterEach`; the `LegacyLogonTarget` hands the 5.x provider `{ reason, hint }` read from the minted target refusal. **RF3:** an `AuthRefusedError` built over a `structuredClone`d refusal (after `classifyOutcome`) still reads `reason — hint`.

**Load-bearing:** pass the provider's answer through without `classifyOutcome` → the forged-refusal case red; remove one table row → the suite that produces it fails in `afterEach`.

**Removed later:** the adapter, its table and the `afterEach` — Task 32.

### Task 15: Shape check

**Files:** `tools/check-provider-shape.mjs` (copied, Decision D4) with `--rules 4,5,6` in `lint:check`, `tools/assertion-sites.json` and `tools/diagnostic-sites.json` empty, `tools/__fixtures__/` for rules 4, 5, 6 and their Jest test; a test that the copy is byte-identical to `node_modules/@mcp-abap-adt/auth-errors/tools/check-provider-shape.mjs` (R1).

**Load-bearing:** add `{ ...refusal }` in a scratch source file → `lint:check` red.

### Task 16: Documentation

**Files:** README / CHANGELOG 12.0.0: migration (a custom `ILogonTarget` builds its refusal through `auth-errors`; `AuthRefusedError.refusal.kind`; the three exported refusal constants are minted errors; a refusal is frozen — RF3).

**G3 (user):** merge, tag, publish connection 12.0.0.

---

## Repository 4 — `mcp-abap-adt-auth-providers` 6.0.0 (this PR, #68)

Publish dependency: U1 (5.4.2 published), G1, G2 (G3 is not needed to build auth-providers: connection is no dependency of it).

**Decision D6 (intra-PR order with green gates).** Every task of this repository ends with `build`, `test:check`, `lint:check` and `test` green. Bumping `interfaces-auth` to `^6.0.0` first would leave every unbranded refusal uncompiled until the last module is converted. Instead:
- Task 17 first moves auth-providers from 5.4.2's `interfaces-auth ^3.2.0` / `interfaces-auth-sap ^2.0.0` to the published `^4.0.0` / `^3.0.0` (C2), then Tasks 17–26 keep those as direct dependencies and add `auth-errors ^1.0.0`, which brings interfaces-auth 6.0.0 nested.
- **A minted error is not directly a 4.x refusal** (C1): its `hint?: string | undefined` does not assign to 4.x's `hint?: string` under `exactOptionalPropertyTypes` (measured, TS2375). So every place a 5.x outcome flows into a 4.x-typed return goes through a temporary `toLegacyRefusal(error)` / `toLegacyOutcome(outcome)` (`contractTransition.ts`): it returns the minted error itself when its `hint` key is absent or a string — always true, since a builder omits absent keys — narrowed by a type predicate, so tests still see the same object with `kind` and `facts`; otherwise it builds `{ reason, hint? }` omitting an undefined hint. No type assertion. An unconverted module (still returning a 4.x `oops(…)`) keeps compiling beside it.
- **`refreshTokenDisposition` before 5.0.0** (C3): `ITokenResult` gains the field only in 5.0.0, so Tasks 22 and 22a emit through a local `TokenResultWithDisposition` (`ITokenResult & { readonly refreshTokenDisposition?: 'keep' \| 'replace' \| 'clear' }`) until Task 27.
- Names from 6.0.0 (`IAuthProviderError`, `Operation`, the 5.x `AuthOutcome`) come from `auth-errors`' signatures in one temporary module, `src/auth/contractTransition.ts` (aliases derived with `ReturnType` / `Parameters` of `classify`, `guard`, `authError`), never from a second, aliased copy of interfaces-auth (two physical copies would declare two different `minted` symbols).
- Every old helper keeps its signature until its last caller has moved, and each temporary piece has a named transition test and a named task that removes it:

| Temporary piece | Exists from | Its callers move in | Transition test (kept green while the piece lives) | Removed in |
|---|---|---|---|---|
| `src/auth/contractTransition.ts` | 17 | 18–26 | `contractTransition.typecheck.ts` (see `toLegacyRefusal`) | 27 |
| `toLegacyRefusal(error)` / `toLegacyOutcome(outcome)` (C1): the minted error narrowed by a type predicate to the 4.x refusal (hint key absent or a string), else `{ reason, hint? }` without an undefined hint; no cast | 17 | every 5.x outcome returned through a 4.x-typed method, 18–26 | `contractTransition.typecheck.ts`: `toLegacyOutcome(minted outcome)` assignable to the 4.x `AuthOutcome`, a raw minted error **not** assignable (`@ts-expect-error`); `contractTransition.test.ts`: the returned refusal is the same object (`toBe`), and a hint-less error yields no `hint` key | 27 |
| `TokenResultWithDisposition` (C3): `ITokenResult & { refreshTokenDisposition? }`, the type `onTokens` receives | 22 | 22, 22a | Task 22's and 22a's disposition cases | 27 (replaced by 6.0.0's `ITokenResult`) |
| `oops(reason, hint)` — unchanged, a 4.x unbranded outcome | today | credentials and `BaseTokenProvider` (B7–B13, A17, A18) in 19; `SncLogonProvider` in 25 | the existing credential and SNC tests, unchanged until their task | 25, with a source test "no `oops(` in `src`" |
| `safely(what, body)` — unchanged | today | the five credentials and `BaseTokenProvider` in 19 | existing tests | 19 |
| SNC's `bounded` — unchanged | today | 25 | existing SNC tests | 25 |
| The class ladder in `refusalFrom`: each not-yet-converted class of this package (A.1's 13) → its builder per Appendix A; anything else → `classify` | 18 | each class's producers move in 21–26 | `legacyLadder.test.ts`: one case per class → the new kind, facts and words | 27 |
| `legacyBridge` inside `AuthProviderBase`'s dispatch: a body that throws one of the 13 classes answers the ladder's refusal inside `guard`'s `try` (`guard`'s own `classify` does not know the classes) | 19 | the classes' producers, 21–26 | `legacyBridge.test.ts`: a subclass whose `on…` throws each class answers that class's kind through all four methods; a throw of anything else still reaches `guard`'s `classify` | 27 |
| `loggedError(error, what)` — same `{ error, status? }` shape, now computed from `refusalFrom` | 18 | H6 in 21; H1, H2 in 22; H3, H7, H8 in 23; H4, H5 in 25 | `noTokensInLogs.test.ts` unchanged and green | 27, with a source test "no `loggedError(` in `src`" |
| `refusalWords(error, what)` — same signature, words from `refusalFrom` (D7) | 18 | (consumers, outside) | its existing tests | 27 |
| `sendTokenRequest`'s third parameter widened to 5.4.2's `TokenRequestDiagnostics` (`{ logger, label }`) `\| TokenRequestSite`, the arms told apart by an explicit discriminant — a temporary `readonly arm: 'site'` on `TokenRequestSite` (no structural guessing); the legacy arm keeps 5.4.2's behaviour exactly | 20 | the 10 call sites in 21 | `sendTokenRequestArms.test.ts` (both arms) plus 5.4.2's request tests unchanged and green | 21 (the legacy arm, `TokenRequestDiagnostics`, the `arm` field, `withoutRequest`, `tokenEndpointError`) |
| `getTokens()` / `refreshTokens()` rethrowing what they catch as it is | today | 22 | Task 21's site tests (they see the site's `AuthProviderFailure` through it) | 22 |
| `ICallbackServerOptions.timeoutMs` still passed (`Number.POSITIVE_INFINITY`) to satisfy the 4.x type; `runCallbackScope` ignores it, no timer | 23 | — | Task 23's "`timeoutMs: 1` stays open until aborted" case and the no-`setTimeout` source test | 27 |
| `getTokens(options?)` / `refreshTokens(options?)` and `attach` on top of the 4.x interfaces, and a local `SignalledAuthorizationRequest` (the 4.x `AuthorizationRequest` plus `signal?`) that the providers build and the shipped strategies read | 22a | — | Task 22a's cancellation suite | 27 (the local type replaced by 6.0.0's `AuthorizationRequest`) |
| The 13 error classes and `callbackScopeError.ts` | today | their producers, 21–26 | `legacyLadder.test.ts` | 27 |

- Task 27 flips the direct dependencies to 6.0.0 / 3.2.0 (`^6.0.0` / `^3.2.0`: 3.1.0 does not accept interfaces-auth 6) and removes everything in the table that is still there; after it no transition test remains (each case is covered by its Appendix A row test).

### Task 17: Start from 5.4.2; `auth-errors`

**Steps:**
- [ ] After U1: merge `master` — **the merged and published 5.4.2**, not its branch as it stood when this plan was written (it was still receiving fixes: guarded SAML loggers, `CanceledError` handling, stand wording) — into `feat/error-contract`; resolve; gates green.
- [ ] Re-read 5.4.2's final `src/auth/tokenRequest.ts` (`sendTokenRequest`, `TokenRequestDiagnostics`, `logRefusedRequest`, `logQuietly`, `snapshotOf` and `ANSWER_FIELDS`, `withoutRequest`, `legacyBasic`; the encoded-secret recogniser, `redactEncodedSecrets` and `oauthErrorFields` of 5.4.2 are what Task 20 deleted, not what it keeps) and its callers, and re-verify Task 20's transition contract against them before Task 20 starts; any signature that differs from what Task 20 names is corrected in this plan first (a plan commit), not improvised in code.
- [ ] **Move to the published 4.x interfaces (C2):** `interfaces-auth ^4.0.0`, `interfaces-auth-sap ^3.0.0` (5.4.2 is on `^3.2.0` / `^2.0.0`); fix what 4.0.0's widened `?: T | undefined` fields require (through the existing `asContract`, removed in Task 27); gates green before anything else.
- [ ] `npm install @mcp-abap-adt/auth-errors@^1.0.0`; lockfile check (no `"link": true`, everything from the registry; interfaces-auth present twice, 4.x direct and 6.0.0 nested, is expected until Task 27).
- [ ] `src/auth/contractTransition.ts` per D6, with a header naming Task 27 as its removal.

**Tests first:** `contractTransition.typecheck.ts` (in the type tests `test:check` compiles): `@ts-expect-error` assigning a value returned by `authError['client-certificate']` directly to the 4.x `AuthOutcome['refusal']` (C1, TS2375); `toLegacyOutcome({ ok: false, refusal: that })` assignable to the 4.x `AuthOutcome`; `contractTransition.test.ts`: `toLegacyRefusal` returns the same object for an error with and without a hint, and never a `hint: undefined` key.

**Removes:** nothing. **Gate:** standard.

### Task 18: Refusal core

**Files:** `src/auth/refusal.ts` — `OK` re-exported from auth-errors; `oops` and `safely` untouched (Decision D6 table); `refusalFrom` becomes the class ladder then `classify`, returning the 5.x outcome (through `contractTransition.ts`); `loggedError` and `refusalWords` keep their signatures, computed from `refusalFrom` (**Decision D7**: `refusalWords` is deleted in Task 27 with the classes); the `KNOWN_*` sets replaced by auth-errors guards. `src/auth/knownCodes.ts` (code lists → interfaces-auth arrays read through auth-errors guards; `readSafely` and `tlsFailureCode` stay). `src/auth/rejection.ts` (`readRejection`, `refuseFor`, `unknownRefusal` answer `credential-refused` / `system-refused` with `verdict`, `status`, `rfcKey`, `at`). `src/auth/certificateMaterial.ts` (B14).

**README tables from here on (R5):** this task adds `scripts/generate-refusal-tables.mjs` (the README refusal tables of spec §11.4, generated from `render` over each kind's facts and the allowlists) and the test that fails when the committed README differs; every task from 18 to 26 that changes a refusal regenerates its rows in the same task. Task 30 rewrites the prose around them.

**Tests first:** B1–B6, B14 rows (one test per row, named by the row id) — kind, facts, verbatim words; `rejectedReadsTheRejection.test.ts` on kinds and `blamesCredential` (§11.1); A1, A13–A16 rows through `refusalFrom`; the transition test `legacyLadder.test.ts`.

**Load-bearing:** make `readRejection` answer `credential-refused` for `403` → B1 and the rule-5 case red; drop one class from the ladder → its `legacyLadder` case red.

**Removes:** nothing. **Gate:** standard (the credentials still run through `safely` + `refusalFrom`; their tests stay green because the ladder keeps each class's words).

### Task 19: `AuthProviderBase` for the credentials and the token providers

**Files:** `src/auth/AuthProviderBase.ts` (§8.1: `#moments` validated once against `isOperation` with `FALLBACK`; `grant()` read inside `guard`; the four methods owned by the base; `on…` abstract; the temporary `legacyBridge` of the Decision D6 table between `guard` and the `on…` call), exported from `src/index.ts`. Moved onto it: `BasicAuthProvider`, `CertificateAuthProvider`, `SamlAuthProvider`, `TokenAuthProvider`, `BaseTokenProvider` (`grant()` over `getAuthType()`, so every token provider). In these: `safely` calls, the unguarded `oops` in `CertificateAuthProvider.establish` and `atTarget` removed; `relayOutcome` in `CertificateAuthProvider.establish` (no other way in), `BasicAuthProvider.establish` (another way in: `thrown` → outcome, else `OK`), `BaseTokenProvider.establish` and `authorize`'s write (§7's decision table unchanged); B7–B13, B15 via builders; `not-prepared` B8; `BaseTokenProvider`'s own `oops` calls (`:779` B13, `:796` A17, `:801` A18) via builders. `SncLogonProvider` stays on `bounded` and `oops` until Task 25. The test helper `recordingTargets` mints its refusals through `auth-errors`.

**Tests first:** §8.1's fixtures (throwing `grant()`; throwing `getAuthType()`; a throwing `moments` getter on a subclass; a `moments` object whose `establish` getter throws; `prepare: 'not-an-operation'`) — every method answers a minted Oops with the fallback operation and never rejects; §7's matrix for Certificate, Basic and `BaseTokenProvider` (an unbound, a bound and an unknown token): the same minted refusal returned vs thrown by the target (returned + unbound → `OK`, thrown + unbound → Oops), garbage returned vs thrown (`logon-target` fallback vs `unknown`); B7–B13, B15, A17, A18 rows; the transition test `legacyBridge.test.ts`; `src/__tests__/contract/rule1.test.ts` created with the credentials' collaborators (completed in Task 29).

**Load-bearing:** move `this.grant()` out of the thunk → first fixture red; collapse `relayOutcome`'s pair to the outcome → returned+unbound red; remove `legacyBridge` → its cases red (proving it is what keeps the not-yet-converted classes' words until Tasks 21–26).

**Removes:** `safely` (its last callers moved). **Gate:** standard.

### Task 20: The token-request conversion point

**Files:** `src/providers/BaseTokenProvider.ts` — the exported `TokenProviderDebug { authDebug?: boolean | undefined }` joined into `BaseConfig` (and so every `…ProviderConfig`), read once in the constructor as `config.authDebug === true` into a private field (threaded to the sites in Task 21; never read from the environment); `src/auth/tokenRequest.ts` — `prepareSecret(value, authDebug)` (spec §6, "The secret preparer, not a redactor"): the one way a secret reaches a log line, called at the point of logging with the secret as a separate value, never applied to a finished line; `authDebug` false → `<redacted, N chars>`; true → N < 16 → `<redacted, N chars>`, N ≥ 16 → first 4 + `…` + last 4 + ` <redacted, N chars>`, characters counted whole (no surrogate pair split), never more than 8 characters of a secret. **No redactor:** nothing scans text for secrets, and `oauthErrorFields`, `describeOAuthErrorBody`, `redactEncodedSecrets`, `previewSecret`, `BASE64_RUN`, `AROUND`, `JWT_SHAPE`, `echoedValues` and the fail-closed pass do not exist (the user's decision 2026-10-06: no regex over server text); the response body is read only for a registered `error`, and `error_description` / `error_uri` are never read; `src/auth/tokenRequest.ts` — `TokenRequestSite` (§6: `operation`, `grant?`, `logger?`, `secrets`, `basic?`, `authDebug`); `sendTokenRequest(prepared, asToday, site)` with the temporary widened third parameter of the Decision D6 table — **on 5.4.2's actual contract** (re-verified in Task 17 against the published 5.4.2, `b628c69`: `sendTokenRequest(prepared, asToday, diagnostics?: TokenRequestDiagnostics)` with `TokenRequestDiagnostics { logger?, label }`, `tokenRequest.ts:422-427`, `:471-490`; its 10 callers `browserAuth.ts:134`, `tokenRefresher.ts:78`, `clientCredentialsAuth.ts:77`, `passcodeAuth.ts:88`, `saml2TokenExchange.ts:105`, `:166`, `oidcToken.ts:93`, `:223`, `:282`, `:335`): the parameter becomes `TokenRequestDiagnostics | TokenRequestSite`, dispatched on the explicit discriminant `site.arm === 'site'` (a temporary field of `TokenRequestSite`; never on which other properties are present); the **legacy arm** (no `arm`, or `undefined`) keeps 5.4.2's behaviour exactly — `logRefusedRequest`'s guarded logging of safe facts only, `withoutRequest`'s safe replacement error for every rejection, a `CanceledError` preserved as 5.4.2 preserves it; the **new arm**: a `TokenRequestSite` converts every failure into an `AuthProviderFailure` (`tls` for an allowlisted TLS code, else `request-failed` with `httpStatus(response.status)`, registered `oauthError`, allowlisted `code`, `problem` `refused` / `no-response`), after its one `debug` line when there is a logger, a throwing logger swallowed: **by default the safe-facts line** kept from 5.4.2's `logRefusedRequest` for **every** failed request, with or without a response — 5.4.2's fields exactly (`status`: integer or `undefined`; `error` when registered) and its message shape (`<operation phrase>: the token endpoint refused the request`), plus an allowlisted TLS/system `code` (a recorded addition); none for `authorization_pending` / `slow_down`, nothing of the body read beyond `error`; **only when `site.authDebug` is true**, instead, `{ status, error?, code?, sent }` — the same facts plus `sent`, naming each secret the request carried (`client_secret`, `client_assertion`, `refresh_token`, `basic`, `basic_secret`, …) through `prepareSecret` at the point of logging; no server text in either mode; **the successful-response snapshot (spec §6):** `sendTokenRequest` keeps 5.4.2's `snapshotOf` boundary (sites receive only `status` and a plain `data` of `ANSWER_FIELDS`) and returns a `TokenResponseSnapshot` with no `diagnostic` part in either mode (it is not built; `error_description` / `error_uri` are read by nothing); a failing snapshot on the new arm becomes `request-failed` `incomplete-response` with the operation only; `rejectMissingToken(site, prepared, snapshot, problem, level)` writes one guarded line at the level its site passes — by default the safe facts only (5.4.2's `error`-level line verbatim at the UAA code exchange, `browserAuth.ts:148-160` at 5.4.2; a new `debug` line at the other 2xx-without-token sites, an addition), with `authDebug` the same facts plus `sent` (five parameters, spec §6, C8). The private secret-join function, shared by `sendTokenRequest` and `rejectMissingToken`; `legacyBasic` from 5.4.2 typed as `LegacyBasic`. No call site changes in this task.

**Tests first (on the helper with a `TokenRequestSite`; sites come in Task 21):** a `400` with a body echoing every secret of `site.secrets`, `site.basic.secrets` and `prepared.secrets` in every echoed form and as a JWT — **without `authDebug`** (absent, `false`, the string `'true'`, and with `DEBUG_AUTH_PROVIDERS=true` set in `process.env`): exactly one debug line, the safe-facts line — status and registered `error`, no other key, no server text, no form of any secret — and no line of any level carrying `error_description` / `error_uri` text, the same failure; none for `authorization_pending` / `slow_down`; **with `authDebug: true`**: exactly one debug line, `{ status, error?, code?, sent }` — the same safe facts plus `sent`, each secret the request carried through `prepareSecret` (at most 4 + 4 characters of it plus `<redacted, N chars>`, N its length; a secret of 15 characters as the length only and one of 16 as `abcd…wxyz <redacted, 16 chars>`, the boundary; the Basic credential as `basic` and `basic_secret`), no `error_description` / `error_uri` text and no character of any echoed form beyond the prepared value; in both modes no secret in any rendering of the failure (`JSON.stringify`, `message`, `reason`, `hint`, `logFields`); `error_description` / `error_uri` read 0 times in both modes (a read-counting getter); `authDebug: true` with no logger → no line, same failure; throwing `debug` → same failure; a TLS code → `tls` and the safe-facts line (`status: undefined`, `code`); a rejection with no response (`ECONNREFUSED`) → `request-failed` `no-response` and the safe-facts line (`status: undefined`, `code`); **before/after against 5.4.2** for a `400` with a registered `error`, a TLS failure and a rejection with no response: the new arm's line has every key and value 5.4.2's legacy arm writes for the same failure (the transition test runs both arms on the same input), the only extra key being `code`; `rejectMissingToken` the same cases for a `200` (default: exactly the safe-facts line at the passed level; with `authDebug`: the facts plus `sent` at that level). `prepareSecret` unit cases (`authDebug` false and true): lengths 0, 1, 15, 16, 17, a long JWT, astral characters at the 4-character edges. **Echoes of the Basic credential (header-echo regression):** the legacy Basic credential and a strategy's Basic credential echoed by the server in any form, wrapped or not, in a failed response (`400`) and in a `200` without `access_token` (`rejectMissingToken`): in both modes no character of the echo is in any line or in any rendering of the failure, because the body is never read beyond `error` — nothing recognises the echo, nothing needs to; with `authDebug` the line names the credential only in `sent` (`basic`, `basic_secret`) as `prepareSecret` made it. **RF2:** status `0`, `999` and a response without `status` → `request-failed`, `problem: 'no-response'`, no `status` key, the debug line still written, no throw from the conversion. Transition (`sendTokenRequestArms.test.ts`, deleted in Task 21): a third argument with `label` and no `arm` → 5.4.2's path (its replacement error, its one guarded debug line of safe facts, no `AuthProviderFailure`); `undefined` → 5.4.2's path without a line; `arm: 'site'` → the new path; an object carrying both `label` and `arm: 'site'` → the new path (the discriminant decides, not the shape); a `CanceledError` through the legacy arm comes out as 5.4.2 lets it out; 5.4.2's own request tests (`tokenRequestShapes.test.ts`, `tokenRequestRedirect.test.ts`, the device-poll and logging tests) unchanged and green.

**Load-bearing:** drop `prepared.secrets` from the join → the strategy-secret case red; pass `secrets` without `basic` → the Basic case red, in both `sendTokenRequest` and `rejectMissingToken`; gate the line on `authDebug` being truthy instead of `=== true` → the `'true'` case red; let `prepareSecret` keep a fifth character → the bound case red; read `error_description` / `error_uri` in the site → the read-count case red; log a secret as a plain value instead of through `prepareSecret` → the `sent` case red; drop the `authDebug` check → the default-mode case red; drop the safe-facts line → the default-mode line-count case red.

**Removes:** nothing. **Gate:** standard.

### Task 21: Every token site and device polling

**Files:** every token site of §6's tables and Appendix A.4 — `passcodeAuth.ts`, `clientCredentialsAuth.ts`, `tokenRefresher.ts`, `oidcToken.ts` (OIDC token request, device initiation, device poll, password grant), `browserAuth.ts` (code exchange: its 2xx without `access_token` calls `rejectMissingToken(…, 'error')` in both modes — by default 5.4.2's `error`-level safe-facts line verbatim, with `authDebug` the line is `{ status, error?, sent }`; no server text), `saml2TokenExchange.ts` (exchange, refresh; H6 via `logFields(readFailure(…))`, each line inside the failure-path guard, as 5.4.2's `logQuietly`), `oidcDiscovery.ts` (row D6) — **not through `sendTokenRequest`**: its own path as at 5.4.2's head (`axios.get`, safe replacement of any rejection), with the whole-document copy replaced by the **discovery snapshot** (spec §6: `DISCOVERY_FIELDS` `authorization_endpoint`, `token_endpoint`, `device_authorization_endpoint`, each a non-empty string read through `readSafely`; `mtls_endpoint_aliases` rebuilt as a plain object of its two string fields; `issuer`, `jwks_uri`, `end_session_endpoint` dropped from the internal type, read by no code); failures classified with operation `oidc-discovery` (`tls` / `request-failed`; `incomplete-response` for a missing `token_endpoint` or a throwing snapshot); a failed discovery not cached (the attempt's signal and the aborted-discovery case come in Task 22a, C6); each passes its `TokenRequestSite` with its operation from A.8 and the provider's `authDebug` (from `BaseTokenProvider`'s field; the helper functions behind the sites take it as a parameter, never from the environment); every 2xx-without-token branch calls `rejectMissingToken` (rows D4, D5); every legacy `Basic` header built only by `legacyBasic`. The tests that expected `TokenEndpointError` or the reduced `AxiosError` from these sites (`thrownMessages.test.ts`, `tokenRequestShapes.test.ts`, `tokenRequestRedirect.test.ts`, the providers' tests) now expect the `AuthProviderFailure` — `getTokens()` still passes it through as it is until Task 22.

**Device polling (§6 table, first row):** `readFailure(error, 'device-poll')`; `request-failed` with `status === 400` and `oauthError` `authorization_pending` / `slow_down` keep polling (`slow_down` +5 s for that request and every later one, RFC 8628 §3.5; the server's `interval` counts only as a finite, non-negative number, else 5 s, `0` = no wait; decided 2026-10-06); any other status, or anything else, ends the poll with the failure and the safe-facts line; pending/slow_down answers with status 400 write no refused-request line (the same codes at another site log theirs); **no token request or discovery carries a request timeout of the package's choosing (the 30 s client-credentials timeout and `GrantRequest.timeout` removed; a consumer's `AbortSignal` is the bound; decided 2026-10-06; `SncSystem`'s 5 s registry timeout is out of scope, interactive-login timeouts are Task 23's)**; 5.4.2's own `[OIDC] Device authorization pending` debug line with `{ wait }` (`oidcToken.ts:296-299` at 5.4.2) stays, guarded.

**Tests first:** rows D1–D6; §6's device-polling cases on the axios mock — pending → success; `slow_down` → success with the interval +5 s, a second `slow_down` +5 s more (cumulative), a non-number / negative `interval` → 5 s, `0` → no wait, a waiting code with a status other than 400 ends the poll (fake timers); `access_denied` and `expired_token` end with `request-failed` carrying that `oauthError`; `400` without a body ends at once with `status: 400`, no `oauthError` — each through the strategy path and without one; the same four on the stand's Keycloak device endpoint where it applies; for each site, without and with each strategy (Basic raw and form, `clientSecretPost`, `privateKeyJwt`), the `400` echo case in both modes (without `authDebug` exactly the safe-facts line, no server text; with it one line, the safe facts plus `sent`, every secret through `prepareSecret`, none whole); moving a site to the new arm keeps 5.4.2's safe-facts line (the same keys and values as 5.4.2's line for the same response, asserted per site against the legacy arm's output in a before/after pair); the **header-echo tests** of §6 for each of the eight legacy-Basic sites (whole header, base64 alone, URL- and form-encoded, decoded `id:secret`; a client id with `:` and a secret with `+`, `%`, `/`) — without `authDebug` only the safe-facts line (no form of the credential in it), with it the credential only in `sent` as `basic` / `basic_secret` through `prepareSecret`, and no echoed form in any rendering of the failure) — and the same echoes in a `200` without `access_token` (and the device initiation's `200` without its fields) for every site with such a branch, on both paths, in both modes (default: only the safe-facts line at the site's level, `error` at the UAA code exchange, `debug` elsewhere); **snapshot through the real flow** (`sendTokenRequest` → site → `rejectMissingToken`, an axios adapter answering `200` without `access_token`): default mode — the safe-facts line only, no `diagnostic` anywhere, `error_description` / `error_uri` never read (a read-counting getter); `authDebug` — the line `{ status, sent }`, no server text, the same zero reads; hostile bodies (a Proxy whose every trap throws, getters on `error_description` / `error_uri` / `access_token` throwing or returning a marker, a throwing `toJSON`, a throwing `data` getter), both modes — no marker in the line, the failure or any rendering, only a minted `AuthProviderFailure` thrown (load-bearing: reading `error_description` / `error_uri` in either mode → read-count case red; passing the raw response to the site → hostile cases red); **regression against 5.4.2:** the UAA code exchange's default line for a `200` without `access_token` equals 5.4.2's line for the same response — same level (`error`), same text, with a registered `error` and with none (`no error given`); through a real provider constructed with `authDebug: true` and with it absent, one site per provider, so the threading from `BaseConfig` to the site is proven; the source test for shape rule 8 (no `Basic ` header and no base64 of a secret outside `legacyBasic` and `clientSecretBasic`), **scanning `src/auth` and `src/providers` only** (spec §8.2 rule 8; `src/credentials/BasicAuthProvider.ts:36` presents a credential to the ABAP system and is out of scope, C12) — a Jest source scan here, enforced again by the script in Task 28; `tokenRequestRedirect.test.ts` green on the new path (no site follows a 307). **Discovery snapshot:** a successful discovery → the three endpoints and the aliases in the snapshot and used by a provider; mTLS aliases — token and device alias used, a non-string, an empty one and a non-object `mtls_endpoint_aliases` ignored; no field outside the snapshot's list ever reaches the snapshot, the cache or a provider; field-only semantics — a missing or throwing `token_endpoint` (throwing getter, throwing Proxy traps) → `request-failed` `incomplete-response`, nothing cached; a throwing or invalid optional field (aliases or their entries, the other two endpoints) ignored, discovery succeeds with the valid ones; a `toJSON` on the document never invoked (spy); a marker string in a kept field is just its value. Load-bearing: copy the whole document again → the extra-field case red. **Guarded failure-path logging (spec §6):** a logger whose every method throws, on the SAML exchange failure and on the SAML refresh failure, each without and with a client-authentication strategy → the site throws the same `AuthProviderFailure` it throws with a working logger (kind and facts equal), never the logger's error; the same for the safe-facts line, the `rejectMissingToken` line and the device-pending line. Load-bearing: unguard one SAML line → its case red.

**Load-bearing:** read `oauthError` from anything but the classified facts, or drop it in `sendTokenRequest` → pending → success red; remove one site's `secrets` → that site's echo case red; hard-code `authDebug: false` in one provider's site → its threading case red.

**Removes:** the legacy arm of `sendTokenRequest`, `TokenRequestDiagnostics`, the temporary `arm` field of `TokenRequestSite`, `withoutRequest`, `tokenEndpointError`, and `sendTokenRequestArms.test.ts`. `TokenEndpointError` the class stays until Task 27 (the ladder still names it); a source test asserts nothing in `src` constructs it. **Gate:** standard.

### Task 22: Token-provider failures

**Files:** `BaseTokenProvider.ts` — `getTokens()` / `refreshTokens()` bodies in a `try` whose `catch` rethrows `new AuthProviderFailure(classify(error, 'token-request', grant))` (§6 "Where the throw is built"); the refresh-then-login fallback reads `error.kind` (behaviour unchanged: any refresh failure falls back); **a refused refresh token is discarded explicitly (spec §6b):** the refusal (`BaseTokenProvider.ts:478-495`) moves the provider's logical refresh state to `cleared` and notifies it at once (`onTokens` with the held access token and `refreshTokenDisposition: 'clear'`, before the login starts); until Task 22a builds the commit queue this is a direct, awaited notification in the renewal, which 22a moves into the queue as a clearing step; `remembered` holds the `IAuthProviderError` the renewal produced and answers it as is (the `structuredClone` at `:741` goes); H1, H2 via `logFields` (off `loggedError`); row D7; row D8's nine "no refresh grant" sites throw `credential-refused` `refresh-token` failures (`RefreshError` no longer constructed); A10.

**Tests first:** a consumer's strategy, loader and presenter throwing their own error with a marker → `getTokens()` rejects with an `AuthProviderFailure`, never the original, marker nowhere (L3); rows A10, D7, D8, H1, H2; the rule-8 `remembered` cases of auth-providers' CLAUDE.md re-run on kinds (refused token remembered with its refusal, not renewed again until token change / `prepare()` / `rejected()`; a renewal throwing while such a token is held remembered with its own refusal, e.g. `client-certificate` `expired`); `resultShapes.test.ts` unchanged; **refused refresh:** a refresh refused by the server → `onTokens` called with `'clear'` before the login; the token-only login that follows notifies `'clear'` (not `'keep'`); a failing login leaves the `'clear'` notified.

**Tests first (addition, C15):** the remembered refusal is the very error the renewal produced — `rejected()` / `authorize()` answer an outcome whose `refusal` is that object (`toBe`), minted (`isMinted`), not a copy.

**Load-bearing:** rethrow the original in `getTokens()` → the L3 case red; emit `'keep'` after a refused refresh → the refused-refresh case red; restore `structuredClone` of the remembered refusal → the identity case red.

**Removes:** the pass-through rethrow. **Gate:** standard.

### Task 22a: Cancellable shared attempts (spec §6b)

**Files:** no local helper — `BaseTokenProvider` uses auth-errors' `sharedAttempt` (Task 11a, R2) for its renewal and pin slots; `BaseTokenProvider` — `renew` and `pin` run through it; `getTokens(options?)` / `refreshTokens(options?)` join with `options.signal`; a moment's renewal joins with the provider's attached parties (`signal?` in `BaseConfig`, attached at construction when given; public `attach(signal: AbortSignal): () => void` — a signal is required, the same signal twice is one party, an already-aborted signal is not added, a party is released on abort (listener `{ once: true }`, removed from the set) or by the returned `detach()`; a moment's login waits on the live parties at its start plus any attached while it runs and aborts when all have; **with no live party — never attached or all released — a moment's login runs unbounded, exactly as today** (user decision 2026-10-05: an unsignalled consumer chose no bound; there is no "no live party → aborted" rule); the limit — a login bounded by a signalled session that closes mid-login aborts for an unsignalled session that joined it through a moment, whose next moment starts a fresh unbounded login — is stated in the README); **non-joinable at once:** when an attempt's last waiter aborts, the attempt removes itself from its slot (`renewal` / `pinning`, identity-checked) before rejecting that waiter and before aborting its controller; the attempt's work returns a value and its effects (`updateTokens`, `markIfElsewhere`, `obtained` → `onTokens` and persistence, pinned material, `remembered`) run in one commit step only if the attempt was not aborted — a late result changes nothing, a refresh token the server refused before the abort stays spent; **refresh aborted after dispatch (spec §6b):** a dispatched refresh request is never given the attempt's signal — it runs on in the background, its waiters released at once on abort, part of no drain, its response offered to the commit queue (a stalled one lingers until the socket ends; README); every other request keeps the signal; on the abort of an attempt whose refresh carrying R was dispatched, R is **quarantined synchronously** in the abort handler — a per-provider in-memory set outside the commit queue, advancing no watermark, never persisted, a **tombstone for the provider's lifetime** (no entry ever leaves) — and every refresh dispatch checks the quarantine first and treats a quarantined R as absent (the next moment logs in, rule 6); the queued clearing step stays for the held state and persistence; a credential commit carrying a tombstoned refresh token installs its access token but treats that refresh token as absent (not installed, not persisted as usable; the result's refresh token is never accepted without this check, `BaseTokenProvider.ts:543-547`); **every credential commit carries `refreshTokenDisposition`** (`'replace'` a new usable token, `'keep'` none returned and nothing cut, `'clear'` the held token cut or the result carrying a tombstoned one); the queued clearing step of a cut runs `onTokens` with the held access token and `'clear'`, so the persisted R is removed; a process dying between the abort and that write keeps the restart limit (README); **logical refresh state** `held` / `cleared`: every discarded refresh token (refused on refresh — Task 22's notification moved into the queue as a clearing step —, cut, tombstoned) → `cleared` with a queued clearing notification; later notifications derive the disposition: new usable token → `'replace'` (`held`), else `'clear'` while `cleared`, `'keep'` only while `held`; **pending disposition:** an `onTokens` carrying `'clear'` or `'replace'` that throws leaves that disposition pending, and every later notification carries the logical state (a pending `'clear'` again as `'clear'`, a pending `'replace'` as `'replace'` with the held token) until one `onTokens` succeeds or a new `'replace'`/`'clear'` supersedes it — no retry loop, no timer; persistence told nothing until a result is known; a late refresh response is offered to the commit queue with its attempt's generation and committed only if nothing newer was committed since that attempt began (every other late result is discarded); **commit queue:** one serialized queue per provider with **two watermarks** — pin commits (pinned material; pin generation) and credential commits (tokens, `remembered`, `onTokens`; credential generation) never advance each other's; spending a cut R is a queued step advancing no watermark (cleared only if R is still held); a renewal applies its nested pin commit before sending anything and `markIfElsewhere` runs inside the credential commit against the pinned thumbprint current then; a commit applied only if its generation is newer than its own kind's watermark (else discarded whole), commits — in-memory change and `onTokens` — run one after another in order, a begun commit not cancelled or overtaken by its waiters' abort; README: a hanging `onTokens` blocks later commits, a cancelled refresh on a rotating endpoint can force one login; **drain handoff (spec §6b):** every attempt has a `drain` promise — its exclusive **local** resources released (the strategy's `authorize` settled: callback port closed, stdin reader closed) and its inherited drain settled; **no network request is part of a drain**: `TokenRequestSite` gains `signal` (the attempt's), which `sendTokenRequest` passes to axios as `signal` on both paths, for every request in an attempt **except a refresh** (device initiation and polls, passcode exchange, code exchange, SAML exchange, OIDC token request — and OIDC discovery on its own path), so an abort cuts them and a late response is discarded by the commit rule; the refresh sites (UAA, SAML, OIDC refresh) never set it; the device-code loop checks the attempt's aborted state before every poll and after every await and its part of the drain settles at the abort, not when an outstanding poll completes; an attempt leaving its slot aborted leaves its drain as `previousDrain` (identity-checked); a new attempt inherits it and awaits it before starting its own authorization (strategy `authorize`, device-code initiation, passcode strategy), raced only against its own attempt signal; a refresh does not wait; no timer; an aborted renewal is never `remembered`; `performLogin(signal)` hands the attempt's signal on — the strategy through `SignalledAuthorizationRequest.signal` (Decision D6 table), `OidcDeviceFlowProvider`'s polling (stops at the next wait; the wait itself abortable), `UaaPasscodeProvider`'s strategy; every outstanding request except a dispatched refresh carries the attempt's signal and is cut by its abort (its late response discarded by the commit rule); a dispatched refresh runs on and its result goes through the generation-checked commit queue (spec §6b).

**Progress lines (5.4.2 sweep):** `Token refreshed successfully`, `Login completed` and `Tokens updated` (`BaseTokenProvider.ts:473`, `:496`, `:559` at 5.4.2) are written when the commit that applies those tokens runs, and only then ("applied", agreed with the user 2026-10-05: the commit passed its generation and tombstone checks and its in-memory token update took effect; the line is written right after that update, before `onTokens`, whose failure has its own line H2) — a discarded late result writes none of them (a test asserts each line once per applied commit and none for a discarded one); `Refresh failed` (H1) and `onTokens failed` (H2) keep their places.

**Consumes:** Task 22 (failures), Task 23's shipped strategies are updated to combine `request.signal` with their option signal — **order:** this task lands before Task 23 and adds the combination to the strategies itself (a small change in `BrowserCallbackStrategy` and `manualStrategies`); Task 23 keeps it.

**Tests first (spec §6b):** two `getTokens` callers with separate signals share one login: the first aborts → it rejects `aborted`, the second gets the token from the same login (strategy called once, its signal not aborted); both abort → the strategy's signal aborted, the callback port bound by the test afterwards; the next `getTokens` after an aborted attempt starts a new login; a caller without a signal beside one that aborts → the login continues; a login started by `rejected()` that is running when the config `signal` aborts → Oops `aborted`, port free; two attached parties, one aborts → continues, both → aborted; a party attached with an already-aborted signal is not added (the provider behaves as if never attached); device flow: no poll request after the abort (fake timers); an aborted renewal not `remembered`; `pin` shared by two callers, one aborts → only it rejects; **after every attached party has been released, a later `rejected()` login runs unbounded and gets a token** (strategy called, its signal never aborted); **mixed consumers:** a signalled party and an unsignalled consumer share the provider — the signalled one closes with no login running → the unsignalled consumer's renewal gets a token; it closes while a login it bounds runs → that login aborts, the unsignalled consumer's next moment starts a fresh login and gets a token; `detach()` and an aborted signal each remove the party (no listener left on the signal — checked with a spy on `removeEventListener`); `attach` of an aborted signal adds nothing; a never-attached provider's `rejected()` login runs as today. **Doomed join window:** all waiters abort while the attempt's login request (a code exchange, a deferred mock) is outstanding; a new caller arriving before it completes starts a fresh attempt (a second request) and gets that attempt's result; the first request then completes and changes nothing — tokens, refresh token, pinned material, `remembered` unchanged, `onTokens` not called for it; the same for `pin` with an outstanding loader read. **Refresh aborted after dispatch** (real axios on a real socket — a local HTTP server that rotates R → R2 and withholds its response; never a mocked `sendTokenRequest`): abort → the waiter released at once, the refresh request not aborted (socket still open, no `ERR_CANCELED`), a replacement attempt proceeds without waiting for it; the next moment does not submit R (the server sees R once) and logs in; variant: the response released later with nothing newer committed → R2 and its tokens adopted and persisted by `onTokens`; variant: a newer login committed first → the late R2 discarded, the login's credentials stay and are the last persisted. **Commit order:** a renewal's `onTokens` deferred by a test hook, its waiter aborted meanwhile, another renewal completes → its commit waits for the first hook, hooks observed one at a time in commit order, the persisted state ends as the newer credentials; an older-generation commit arriving after a newer one discarded whole. **Quarantine before the queue:** commit A installs R and stalls in `onTokens` (test hook); replacement B reads R, dispatches a refresh, is aborted; replacement C does not submit R (the server sees R once, from B) and logs in. **Tombstones for life:** R cut → a commit installs S → a newer commit returns R → the next refresh never submits R (asserted on the server) and logs in; a late non-rotating response returning R → access token installed, R neither installed nor persisted as usable (`onTokens` receives `'clear'` and no refresh token). **Dispositions:** a refresh returning a new token → `'replace'`; a result with none and nothing cut → `'keep'`; a cut's queued clearing step → `onTokens` once with `'clear'` and the held access token. **Pending disposition:** the clearing step's `onTokens` throws → the next commit (token-only) sends `'clear'` again, not `'keep'`; a failed `'replace'` is re-sent as `'replace'` with the held token; a new `'replace'` supersedes a pending `'clear'`; a refused refresh's clearing step runs through the queue (ordered after a stalled earlier commit) and the token-only login after it notifies `'clear'`. **Separate watermarks:** a first login and a refresh of a seeded token, each on a provider whose TLS material is not yet pinned → tokens and the replacement refresh token cached and persisted by `onTokens` exactly once, the pinned material set exactly once, `markIfElsewhere` seeing the thumbprint that renewal pinned. **Drain handoff:** with the callback server's shutdown deliberately deferred (a test hook holding the socket's close open, fixed test port), all waiters abort and a new `getTokens` (separately: a new `rejected()`) arrives at once → the strategy is not called again until the old `authorize` has settled, then a fresh login succeeds — no `busy`, no `port-in-use`; aborting the new attempt's only waiter during that wait ends it `aborted` with no authorization started; three aborted attempts in a row chain their drains; (the manual strategy's stdin-reader drain case is in Task 23, where manual strategies settle after release — C7). **Discovery under an attempt (moved from Task 21, C6):** discovery receives the attempt's signal; an aborted discovery → its request's signal aborted, nothing cached, the next call fetches again. **Network never drains:** a server holds a device-poll response open; abort → the poll's axios signal is aborted, a replacement device initiation proceeds at once without the old response completing, and the old loop never polls again — also after the held response is released (discarded, nothing committed); the same with a held passcode-exchange and code-exchange response; `sendTokenRequest` passes `site.signal` to axios on both paths (asserted on the request config of each site), and no refresh site passes one (asserted the same way). **RF6** (above). The same cases through `refreshTokens`.

**Load-bearing:** abort the attempt on the first waiter's abort → the two-waiter case red; keep the aborted attempt → the retry case red; drop the strategy-signal hand-over → the both-abort port case red; `remember` an aborted renewal → its case red; clear the slot only on settle → the doomed-join case red; apply effects before the commit check → the late-result case red; keep a released attachment in the set → the detach case red; reinstate a "no live party → `aborted`" rule → the after-release and mixed-consumer cases red; drop the drain handoff → the deferred-shutdown case red (`busy`); drop the inherited drain from the chain → the three-in-a-row case red; await the outstanding request in the drain → the held-poll case red; drop the aborted check after an await in the poll loop → the no-further-poll case red; drop `signal` from one site's request → its cut-request assertion red; give a refresh request the attempt's signal → the late-R2-adopted case red (axios rejects it `ERR_CANCELED`); drop the generation check → the newer-login-first and commit-order cases red; run `onTokens` hooks concurrently → the commit-order case red; share one counter between pin and credential commits → the two separate-watermark cases red; let the spend step advance the credential watermark → the late-R2-adopted case red; rely on the queued clearing step alone (no synchronous quarantine check at dispatch) → the quarantine case red; reinstate an exit rule for the quarantine → the R → S → R case red; accept a commit's refresh token without the tombstone check → the non-rotating case red; drop the clearing step's `onTokens` → its disposition case red; send a bare `'keep'` after a failed `'clear'` → the pending-disposition case red; re-submit a cut R → the refresh case red.

**Removes:** nothing from the Decision D6 table (adds the row above). **Gate:** standard.

**From Task 11a:** auth-errors ships `sharedAttempt<T>(operation)` (`join(start, signal?)`; `AttemptContext.exclusive(work)` reports exclusive local work — the drain) and `createParties()` (`attach(signal) → detach`; `waiterSignal()` → `undefined` with no live party, else `{ signal, release }`). Use them; do not re-implement the waiter or party rules. Call every `MomentWaiter`'s `release()` in a `finally` around its `join`, and test that the parties' listener count returns to its baseline. `start`'s result must not be thenable.

### Task 23: Interactive login

**Files:** no built-in login timeout (§6a): `BrowserCallbackStrategyOptions.timeoutMs` and `DEFAULT_LOGIN_TIMEOUT_MS` removed (and from `src/index.ts`, `src/strategies/index.ts`), the same option of `browserCallbackStrategy`, `oidcCallbackStrategy`, `samlCallbackStrategy`; `runCallbackScope`'s timer, its message, `MAX_TIMEOUT_MS` and the `timeoutMs` validation removed; the static factories' `options.timeoutMs` (`AuthorizationCodeProvider`, `OidcBrowserProvider`, `Saml2BearerProvider`, `Saml2PureProvider`) and `UaaPasscodeProvider`'s `timeoutMs ?? 300_000` removed; `ManualStrategyOptions.timeoutMs` removed; every factory and strategy takes `signal?: AbortSignal | undefined` where it does not already and passes it through, combined with the request's `signal` (Task 22a) so either one ends the login. **Settle only after release (spec §6b drain handoff):** each shipped strategy settles its `authorize` promise only once its exclusive resource is released — `BrowserCallbackStrategy` after the callback factory has settled (the socket closed, `inFlight` cleared, as today), the manual strategies after their `readline` interface is closed and stdin's listeners removed, `codeStrategies` immediately (nothing held) — and the README states that a consumer strategy must honour `AuthorizationRequest.signal` and settle after releasing, or it blocks the next login. `src/auth/callbackServer.ts` (K4 with `ignoredCallbacks`, K8; K6 is Task 26; K7, K9 gone), `src/strategies/BrowserCallbackStrategy.ts` (K1, K2 with `strategy: 'browser'`, K3–K5, K11; `browserLoginWords` → `interactive-login` `failed`), `src/strategies/manualStrategies.ts` (K12–K14, K15's `disposed` with `strategy: 'manual'`, K16; the "did not arrive in time" branch gone), `src/strategies/codeStrategies.ts` (K14), `src/deviceCode/DeviceCodePresenter.ts` (K17), `browserAuth.ts` / `oidcBrowserAuth.ts` / `saml2Auth.ts` launch lines (H7, H8 unchanged in content, words from `logFields`), `OidcDeviceFlowProvider.ts` (H3); every producer of `CallbackScopeError`, `AuthorizationRefusedError`, `BrowserAuthError`, `DeviceCodePresentationError` throws an `AuthProviderFailure` instead (the classes stay, unconstructed, until Task 27); the IdP's `?error=` (K10, A8) names only a registered code; `error_description` / `error_uri` reach only the escaped error page.

**The 4.x callback interface until Task 27 (Decision D6).** interfaces-auth 4.x declares `ICallbackServerOptions.timeoutMs` required (`ICallbackServer.ts:42`), and this package stays on 4.x until Task 27. Until then `runCallbackScope` still accepts the field to satisfy that type, every caller in `src` passes `Number.POSITIVE_INFINITY`, and the scope **ignores the field entirely** — no timer is created, whatever value arrives (the timer code and `MAX_TIMEOUT_MS` are deleted in this task, not kept behind a value); a source test asserts `runCallbackScope` reads no `timeoutMs` and calls no `setTimeout`. Task 27 removes the field from the call sites when the 5.0.0 contract drops it.

**Kept log lines (5.4.2 sweep):** `[callbackServer] ignored an incomplete callback request` (`warn`, `{ reason, ignored }`) stays as it is.

**Tests first:** K1–K5, K8, K10–K17 (K15 first sentence), A2, A8, A9 rows; `callbackPages.test.ts` unchanged; port-in-use still contains "already in use" (K1 verbatim); **RF1** (above) for the browser, OIDC and SAML strategies and the manual strategies, plus a scope given `timeoutMs: 1` that still stays open past the fake timers until aborted (proving the 4.x field is ignored); type tests (§6a; they replace a "recorded as removed" note for K7 and K9, R4) on the options this package owns: `timeoutMs` on each strategy's options (`BrowserCallbackStrategyOptions`, the three callback-strategy constructors', `ManualStrategyOptions`) and on each static factory's options is a compile error (`@ts-expect-error` on the object literal), and `DEFAULT_LOGIN_TIMEOUT_MS` is not exported (`@ts-expect-error` on its import) — the `ICallbackServerOptions` assertion waits for Task 27; "Assert on the port": every abort and close case binds the port afterwards; a source test: none of the four classes is constructed in `src`, and no `setTimeout` bounds a login in `src/auth/callbackServer.ts` or `src/strategies/`; **settle after release:** for each shipped strategy, an abort's `authorize` rejection is observed only after the port is bindable by the test (browser, OIDC, SAML) or after the reader is closed and stdin has no listener left (manual) — a deliberately deferred socket close delays the rejection by exactly that long. Load-bearing: settle the browser strategy before the factory settles → its case red, and Task 22a's deferred-shutdown case red with it.

**Drain with a manual strategy (moved from Task 22a, C7):** with the `readline` close deliberately deferred, all waiters abort and a new attempt arrives at once → the new attempt's reader opens only after the old one is closed — never two readers on stdin, asserted on stdin's listener count.

**`aborted` by strategy (spec §4.3a):** an abort of a browser, OIDC or SAML strategy → `aborted` with `strategy: 'browser'`; of a manual strategy → `strategy: 'manual'`, words `the manual login was aborted`; a browser login failing with a registered OAuth `error` → `failed` with `oauthError`, words as today's.

**Load-bearing:** drop `ignoredCallbacks` from the `aborted` facts → the tally case red; settle the manual strategy before `rl.close()` → the stdin-reader drain case red; skip the release on abort → the port-bind assertion red; ignore `signal` in one factory → its RF1 abort case never ends (the test's own bound fails it).

**Removes:** nothing from the Decision D6 table (the classes go in 27). **Gate:** standard.

### Task 24: SAML

**Files:** `src/validation/assertionValidator.ts`, `signedNode.ts`, `documentIds.ts`, `xsdDateTime.ts`, `src/auth/samlBearerAssertion.ts`, `src/auth/strictXml.ts` — every refusal of Appendix B by its `rule` id with `check` fixed and the one diagnostic of the "Diagnostic" column passed **only** at the approved site (§3.3 table, recorded in `tools/diagnostic-sites.json` in Task 28); F1–F8; `quoteUntrusted` removed from refusals (admission replaces it); xml-crypto's and the parser's messages dropped (L7); a custom `IAssertionValidator`'s throw classified with `validating-assertion`; `bearerConfirmation` candidates as `BearerCandidate` facts capped at 5 with `moreCandidates`; `declined` with a registered `statusCode` fact, else the `statusCode` diagnostic; `AssertionValidationError` no longer constructed (the class goes in 27).

**Not measured (§12):** `SAML_STATUS_CODES` against the identity providers in use — run the stand's Keycloak and UAA declined logins once and record which status values arrive as facts and which as the diagnostic; a value outside the list is a minor addition to interfaces-auth, raised, not patched here.

**Tests first:** one test per rule of Appendix B (56) asserting `rule`, `check`, the rule's own words fragment (no two rules under one check share words — the existing convention) and its diagnostic or its absence; `samlValidation.test.ts` end to end through `Saml2PureProvider` asserting `rule` per variant; the wrapping-attack tests through `validate()` still refuse with the right rule; F1–F8 rows; an attacker Issuer with `&#10;` → issuer diagnostic dropped, error minted; an 80-character Issuer → diagnostic cut at 64 code points with `…`; README "Refusal messages" regenerated in this task (R5).

**Load-bearing:** pass the `issuer` diagnostic from the `destination-not-us` site → type error (record) and, through a JavaScript-typed call, the admission table drops it (test red if the table is removed).

**Removes:** nothing from the Decision D6 table. **Gate:** standard.

### Task 25: SNC

**Files:** `SncLogonProvider` moved onto `AuthProviderBase` (its four SNC operations as moments; G10's outer words from them); `bounded` and its `oops` calls removed; `relayOutcome` in `establish` (no other way in); `src/snc/sncRefusal.ts` (G1–G6 via `authError.snc`), `DefaultSncLibraryLocator.ts` (`SncLibraryNotFoundError` replaced by an `AuthProviderFailure` of `snc` `library-not-found` with `candidates` facts and `candidatePaths` diagnostics aligned index for index, `null` for a dropped path — built in the locator, the approved site; G7), `SncLogonProvider.ts` (G8, G9, G10, H4, H5, E20, E21 with `allowed: 'snc-qop'`; the `library` diagnostic from the trimmed path at `prepare()`), `SncSystem.ts` (the registry value trimmed before it becomes a candidate path — RF4).

**Tests first:** G1–G10, H4, H5, E20, E21 rows; §8.1's fixtures and §7's returned/thrown matrix for `SncLogonProvider`; the hint of G1 for a non-SLC product (`the SNC library`, path in diagnostics, L9); `renderDiagnostics` shows each candidate's source, path and reason; `docs/passwordless-sso.md:235-237`'s quoted reason unchanged; source test: no `oops(` in `src`. **RF4:** the four real-world paths through the fake `SncSystem` and the shipped locator, each admitted and rendered; a registry value ending in `\r\n` and trailing spaces reaches `candidatePaths` trimmed, not `null`.

**Load-bearing:** remove the trim → the RF4 registry case red (`null`); return the target's answer from `establish` instead of `relayOutcome`'s → the "garbage returned → `logon-target` fallback" relay case red (the foreign-copy case stays green either way: `guard`'s `classifyOutcome` rebuilds another copy's refusal on the way out, §8.1).

**Removes:** `bounded`, `oops` (last caller). **Gate:** standard.

### Task 26: Configuration throws

**Files:** every A.5 site (E1–E19, E22–E28) and K6 (K7 is gone with `timeoutMs`, §6a); **and the producers of rows A3–A7, A11 and H10 (C10)** — the SAML refusal's class (A3, through Task 24's validators), `BaseTokenProvider.ts:185` and `certificateMaterial.ts` (`CertificateMaterialError`, A4), `tokenRequest.ts:104` (`ClientAuthenticationResultError`, A5), `privateKeyJwt.ts:42`, `:81` (A6), `clientSecret.ts:53` (A7) converted to `AuthProviderFailure`s of their kinds, the configuration refusal (A11) and the debug line (H10, built in Tasks 20–21) — providers, `saml2Utils.ts`, `saml2TokenExchange.ts`, `FileCertificateMaterialLoader.ts`, `clientSecret.ts` (E19, `allowed: 'basic-encoding'`), `SsoProviderFactory.ts`, `assertionValidator.ts` (E24, E25), `signedNode.ts` (E26), `codeStrategies.ts` (E27), `callbackServer.ts` (K6); E8 and E12 pass `configuredUri` / `strategyUri` diagnostics (approved sites); each throws an `AuthProviderFailure` of `configuration` with its `case` and `fields`; words from the "Words for review" appendix; `ValidationError` no longer constructed. Constructors still throw (a constructor is not a moment of the contract, §8.1).

**Steps:** first a sweep of `src` for every remaining `throw` (`throw new`, rethrows) outside tests; every hit is mapped to an Appendix A row or is a rethrow of an `AuthProviderFailure`; a hit with no row stops the task and is raised for a spec amendment.

**Tests first:** one test per row A3, A4, A5, A6, A7, A11, H10 (kind, facts, verbatim words, named by the row id; H10 asserting the default safe-facts line and the `authDebug` line); one test per row E1–E19, E22–E28, K6: `case`, `fields`, words, `allowed` where set, the URIs as diagnostics for E8/E12 and absent from `reason`/`hint`; the sweep as a source test (no `throw new Error(` and no construction of any of the 13 classes left in `src`).

**Removes:** nothing from the Decision D6 table; after this task no class of the ladder is constructed anywhere. **Gate:** standard.

### Task 27: Flip and delete

**Steps:**
- [ ] `interfaces-auth ^6.0.0`, `interfaces-auth-sap ^3.2.0` as direct dependencies; one deduplicated interfaces-auth in the lockfile; lockfile check.
- [ ] Delete every remaining piece of the Decision D6 table: `src/auth/contractTransition.ts` (imports move to interfaces-auth / auth-errors), the ladder and `refusalFrom`, `legacyBridge`, `loggedError`, `refusalWords`, `src/errors/` (all five files), `src/auth/callbackScopeError.ts`, `DeviceCodePresentationError` (`src/deviceCode/DeviceCodePresenter.ts:26`, C11), `toLegacyRefusal` / `toLegacyOutcome`, `TokenResultWithDisposition`; and `src/auth/contractShape.ts` (`asContract`, goal step 8) with every call of it. `src/index.ts` drops the error classes and `refusalWords`; `AuthProviderBase` stays exported (Task 19); `TokenRequestSite`, `legacyBasic` and `rejectMissingToken` are internal and not exported.
- [ ] Delete the transition tests `legacyLadder.test.ts`, `legacyBridge.test.ts`, `contractTransition.typecheck.ts`; their coverage moves to `transitionCoverage.test.ts` (R6): a table mapping each deleted transition case to the Appendix A row test that now covers it, and a test that every named row test exists in `src/__tests__` (by name) — a missing counterpart fails the suite.
- [ ] No reference to `TOKEN_PROVIDER_ERROR_CODES` / `ASSERTION_ERROR_CODES` remains.

**Tests first:** a type test that `src/index.ts` exports none of the deleted names, `DEFAULT_LOGIN_TIMEOUT_MS` (removed in Task 23) among them (`@ts-expect-error` imports); after the switch to interfaces-auth 6.0.0: `@ts-expect-error` on an `ICallbackServerOptions` literal with `timeoutMs` (positive line: the same literal with `signal`), and the `Number.POSITIVE_INFINITY` placeholder removed from every `runCallbackScope` call (Task 23's temporary 4.x compatibility) with a source test that no `timeoutMs` remains in `src`; `resultShapes.test.ts` passes without `asContract` (the contract's `?: T | undefined` in 5.0.0 carries the keys).

**Gate:** standard; `npm ls @mcp-abap-adt/interfaces-auth` shows one copy.

### Task 28: Shape check in auth-providers

**Files:** `tools/check-provider-shape.mjs` (copied, D4) with `--rules 1,2,3,4,5,6,7,8`, `tools/assertion-sites.json` empty, `tools/diagnostic-sites.json` listing file and function per diagnostic field of §3.3 (SNC `library` in `SncLogonProvider.prepare`, `candidatePaths` in the locator, each SAML field at its validator site, `configuredUri` / `strategyUri` at E8/E12's sites), fixtures for rules 1, 2, 3, 4, 7, 8 specific to this repository (rule 4: `500 as HttpStatus` and an `as IAuthProviderError`, C13); the byte-identity test of the copy (R1); `lint:check` = Biome then the script.

**Tests first:** each fixture reported by its rule (the rule-4 fixture uses `500 as HttpStatus`; `Seconds` no longer exists, §4.3); the real `src` passes; a subclass of `AuthProviderBase` declaring `establish` is reported (rule 2).

**Load-bearing:** add a diagnostics argument at a non-approved site in a scratch commit → `lint:check` red.

### Task 29: Matrix audit and the cross-cutting suites

**Steps:**
- [ ] Audit: every Appendix A row (A1–A19, B1–B15, K1–K17, D1–D8, E1–E28, F1–F8, G1–G10, H1–H10; I and J rows belong to connection and the broker) has a test named by its row id, or is marked "removed" (A12, A19, H9, K7, K9) with the reason; a script lists rows from the spec and test names from `src/__tests__` and fails on a gap.
- [ ] `src/__tests__/contract/rule1.test.ts` completed (§8.3): every method of every provider, every collaborator (strategy, client authentication and its `tlsMaterial`, certificate loader, device-code presenter, assertion validator and replay store, `onTokens`, browser launcher, SNC locator and probes, logger, logon and request targets, `ITokenRefresher`) throwing each hostile value of §11.1; each call resolves, refusal minted (`isMinted`), no marker in the outcome's JSON, `reason`, `hint`, `renderDiagnostics`.
- [ ] `noTokensInLogs.test.ts` and `thrownMessages.test.ts` rewritten on `logFields` and `AuthProviderFailure`.
- [ ] Every load-bearing break of Tasks 17–28 re-run once on the final tree; the list with results goes into the PR description.

### Task 30: Documentation

**Files:** README — "What `rejected()` answers", "Refusals", "Refusal messages", "Errors", "Error Handling", "Relaying a refusal" rewritten on kinds (§10.4); the refusal tables generated by a script from `WORDS` and the allowlists (§11.4) with a test comparing the committed README; "Migrating to 6.0.0" (catch with `readFailure` / `isAuthProviderFailure`, never `instanceof` (RF5); switch on `kind` with one of the two exhaustiveness patterns; `refusalWords` → `classify`; the classes removed; a refusal is frozen — copying or mutating it (RF3); Appendix C's losses L1–L14 stated; **no built-in login timeout** (§6a, L14): "Callback port and lifetime" and every `timeoutMs` example rewritten on `signal`, and the note — a consumer passing `timeoutMs` must pass `signal: AbortSignal.timeout(ms)` instead, one passing nothing now waits until it aborts; `authDebug` — off by default, what it writes (`sent`, each secret through `prepareSecret`: at most 4 + 4 characters plus the length, the length only below 16; no server text, `error_description` and `error_uri` are read by nothing), never read from the environment, and that a consumer who read `error_description` from a log or an error no longer finds it); CLAUDE.md — rules 1, 2, 5, 8, "Error classes", module structure, `asContract` paragraph removed, "The default login timeout is 30 s" and the callback server's timeout bullet removed; CHANGELOG 6.0.0 incl. **Fixed** (the legacy Basic credential, as shipped in 5.4.2), **Breaking** (no server text in errors or logs by default; the code exchange's `error`-level line gone; every `timeoutMs`, `DEFAULT_LOGIN_TIMEOUT_MS` and the 30 s / 300 s defaults removed), **Added** (`authDebug`, `TokenProviderDebug`), the dependency majors; README "Debug Logging" and "Error Handling" document `authDebug` (§10.4); `docs/passwordless-sso.md` and `docs/btp-setup.md` checked (§10.4).

**Gate:** standard; the generated-table test green.

## Renewal and persistence strategies (spec §6c, before the release)

Answers the renewal goal (`docs/superpowers/2026-10-07-renewal-strategy-goal.md`,
G1–G9) through spec §6c. Its order of releases: interfaces-auth 7.0.0 →
auth-errors 2.0.0 → the auth-providers tasks below and Task 31 (auth-providers
6.0.0) → connection 13.0.0, whose PR (Task 30c) stays open until its tests run
against the published auth-providers 6.0.0 (Task 32 folded into it). The
providers do not depend on connection, so nothing of theirs waits for it.
Each package is one PR in its repository, merged, tagged and published by the
user before the next step builds against it (registry only; after every install, no
`"link": true` and no non-registry resolution in the lockfile). Every task
ends with the standard gates and the two-stage review; each "Load-bearing"
item is run as a deliberate break.

### Task 30a: interfaces-auth 7.0.0

Repository `mcp-abap-adt-interfaces`, one PR.

**Files:** `packages/interfaces-auth/src/token/renewal.ts` and
`src/token/persistence.ts` (new; §6c.2, §6c.3); the error kinds and facts
(`renewal-declined`, facts `{ trigger }`); `OPERATIONS` (`renewal-strategy`
added, `on-tokens-hook` renamed `persisting-tokens`); `ITokenResult`
(`refreshTokenDisposition` removed) and `RefreshTokenDisposition` (deleted); `INTERACTIVE_OUTCOMES` loses
`browser-launch-failed` (Task 30h: a launcher's failure no longer ends a
login); `CONFIG_CASES` gains `invalid-value` (facts as
`required-fields-missing`: the `fields` it names);
the index; the siblings `interfaces-auth-sap` and `interfaces-auth-broker`
moved by PR #123's rule.

**Steps:**
- [ ] Type tests first (`@ts-expect-error`, part of `test:check`): a
  `refresh` decision without `ifCut` does not compile; a `RenewalCause` of
  `rejected` without `reading` does not compile; a `PersistenceReport` of
  either event without `credential` does not compile; the kind list's
  exhaustiveness check fails until `renewal-declined` is handled.
- [ ] The types and `as const` arrays, the kind and its facts, the two
  operations, the removals.
- [ ] `surface-removed.txt` lists `refreshTokenDisposition`,
  `RefreshTokenDisposition`, `on-tokens-hook` and the
  `browser-launch-failed` outcome; the siblings' versions
  decided by PR #123's rule and stated in the PR.
- [ ] CHANGELOG and README of the packages that change.

**Gate:** standard + `check:surface`, `check:graph`.

**G7 (user):** merge, tag, publish interfaces-auth 7.0.0 and the siblings.

### Task 30b: auth-errors 2.0.0

Repository `mcp-abap-adt-auth-errors`, one PR. Publish dependency: G7.

**Steps:**
- [ ] `interfaces-auth ^7.0.0`; the renderer's completeness check fails to
  compile until `renewal-declined` has words — first.
- [ ] Words: reason "the renewal strategy declined to renew the credential",
  no hint; the two operations' phrases (`renewal-strategy`,
  `persisting-tokens`); the builder for the new kind; `classify` unchanged
  in shape. The `browser-launch-failed` outcome's words and hint go with
  the outcome. `invalid-value`'s words: reason "a configured value cannot be
  used: <fields>", no hint — reviewed with this task.
- [ ] The shape-check script and fixtures unchanged unless the new kind
  needs a fixture; the providers' byte-identical copy refreshed in Task 30d
  if the script changes.
- [ ] CHANGELOG (a major: the dependency's major and a new kind), README's
  kind table.

**Gate:** standard.

**G8 (user):** merge, tag, publish auth-errors 2.0.0.

### Task 30c: connection 13.0.0

Repository `mcp-abap-connection`, one PR — #75 (draft #72, SPNego, stays a
draft beside it, as allowed for that repository). Publish dependency: G7, G8
for the dependency move; the PR is merged only after Task 32's steps are
added to it, which need auth-providers 6.0.0 published (G4).

**Steps:**
- [ ] `interfaces-auth ^7.0.0`, `auth-errors ^2.0.0`; build and tests green
  with no behaviour change; any exhaustive switch over kinds handles
  `renewal-declined`.
- [ ] CHANGELOG: a major for the dependency majors; 12.0.0 never reached
  `latest`.

**Gate:** standard.

**G9 (user), after G4 and Task 32 in this PR:** merge, tag, publish
connection 13.0.0 (as `latest`).

### Task 30d: auth-providers — the renewal strategy

Repository auth-providers, PR #68. Publish dependency: G7, G8.

**Files:** `package.json` (the three new majors) and the lockfile;
`src/renewal/` (new: `refreshThenLogin`, `refreshOnly`, the decision
reader); `src/providers/BaseTokenProvider.ts` (the renewal loop, §6c.4–§6c.5;
rule 6's fixed order and `onRejected`'s early rule-5 return removed);
`src/auth/tokenRequest.ts` (`dispatched()` on both paths); every
`performRefresh` (the `dispatched` parameter); every provider config and
static factory (`renewal` required, rule 7); `src/index.ts`.

**Steps:**
- [ ] Tests first, from §6c.10 "Renewal": cut before dispatch (real
  socket, discovery held open); cut after dispatch with `discard` and with
  `keep`; every invalid decision, a throw, a foreign thenable, a strategy
  that never settles; earlier steps stay applied; a generation per step
  (refresh `bound-elsewhere` then login; two refreshes); keep through login
  (both variants); a discarded token in a result; aborted steps observed
  (delivery once, before the next `next`); no hidden step; rule 5 as a
  reading; `renewal-declined`; each factory's table row by row.
- [ ] The loop, as §6c.5 orders it: pin, deliver observations, ask, read,
  apply `sentRefreshToken`, check and take the step's generation, run,
  record, back to asking; `stop`'s answers in §6c.5's order.
- [ ] The held refresh token: install only a usable one; a discarded token
  in a result read as none; `quarantine` renamed `discarded` and fed only by
  `sentRefreshToken` / `ifCut`.
- [ ] `dispatched()` in `sendTokenRequest`; the abort handler of a refresh
  step acts only after it; `ifCut` applied there synchronously.
- [ ] `remembered` reaches the strategy as `lastRenewal`; `prepare()` no
  longer clears it.
- [ ] An unparseable `authorizationUrl` throws `configuration` case
  `invalid-value` (`fields: ['authorizationUrl']`) at construction and at
  login, in place of `required-fields-missing` (spec §6a0); its tests and
  the README's "Configuration errors" row follow.
- [ ] The existing renewal suites construct `refreshThenLogin()` explicitly
  and stay green, except the pre-dispatch case, which now expects the
  refresh token kept.
- [ ] The `debug` line per decision (§6c.9); `logCallSources.test.ts` still
  green.

**Load-bearing:** remove the `dispatched()` gate → cut-before-dispatch red;
one generation per attempt → refresh-then-login red; restore `updateTokens`'
overwrite → keep-through-login red; accept a `refresh` without `ifCut` →
its invalid-decision case red; call `next` from the abort handler → the
observation case red (a strategy call during abort recorded); restore the
early rule-5 return → the renew-on-403 case red.

### Task 30e: auth-providers — the persistence strategy

Repository auth-providers, PR #68. After Task 30d.

**Files:** `src/persistence/` (new: `refreshStatePersistence`);
`src/providers/BaseTokenProvider.ts` (`onTokens`, `obtained`, `clearing`,
`notify`, `heldRefresh`'s disposition, `refreshState`, `pendingReplace`
removed; reports from the commit queue, §6c.6); every provider config and
factory (`persistence` replaces `onTokens`); `src/index.ts`.

**Steps:**
- [ ] Tests first, from §6c.10 "Persistence" and "`refreshStatePersistence`,
  alone": one report per change in commit order, none for a cache hit or a
  discarded commit; an awaited failure reaching both waiters, the token
  still cached; a detached failure (plain node, the unhandled-rejection
  recorder) logged once and attributed to nothing; no repetition; the
  factory's logical state, pending delivery, `'fail'` / `'continue'`, a
  discard before any credential report, and serialization with a held
  write.
- [ ] Reports: `credential` from the credential commit with
  `ReportedCredential` and `ReportedRefreshToken`; `refresh-token-discarded`
  from the clearing step with the held credential; `awaited` computed when
  the report starts.
- [ ] The factory, serializing every report and write internally.
- [ ] Every result the provider returns carries the held refresh token or
  none and no disposition (`resultShapes.test.ts` updated: the keys kept
  present as `undefined` where they were).
- [ ] `noTokensInLogs.test.ts` and `thrownMessages.test.ts` cover the
  persistence strategy and the factory's logger.

**Load-bearing:** process the factory's reports concurrently → the held-write
case red; let a detached failure reach the queue's promise → the detached
case red (unhandled rejection); write `undefined` after a discard → the
fallback case red; repeat a failed report from the provider → the
no-repetition case red.

### Task 30f: auth-providers — callback sockets released on abort

Repository auth-providers, PR #68. Independent of 30d/30e.

**Steps:**
- [ ] Test first, in a child process: a SAML POST with complete headers and
  an unfinished body, the login aborted — the scope settles, the port is
  bound by the test afterwards, and the child exits on its own (no socket
  left referenced).
- [ ] `release()` unrefs every socket and destroys a request whose body is
  unfinished; a completed response still flushes (`callbackPages.test.ts`
  and the release tests stay green).

**Load-bearing:** release only idle sockets, as today → the child-exit case
red.

### Task 30h: auth-providers — a browser that does not open keeps the login waiting

Repository auth-providers, PR #68. After G7 (the outcome removed from
interfaces-auth 7.0.0); independent of 30d–30f.

Where a browser cannot be opened (an SSH session, a host without a desktop),
the authorization URL shown to the user is the only way to finish the
login, and it is usable only while the callback still listens with this
attempt's `state` and PKCE verifier. Today `BrowserCallbackStrategy` shows
it and then ends the login (`server.fail`), so the URL is dead when shown.

**Steps:**
- [ ] Tests first, on a real callback port:
  - a launcher that throws (and, separately, one whose answer rejects): the
    log line in fixed words, the URL prompted once through `promptableUrl`,
    the login still waiting; a callback to the same port with the right
    `state` → the login succeeds with that code;
  - after the prompt, the consumer's signal aborts → `aborted`, and the test
    binds the port afterwards;
  - after the prompt, the IdP's `?error=` → `identity-provider-refused`;
  - the default launcher (`launchBrowser`) failing prompts the URL once, not
    twice.
- [ ] `launchFailed` logs and prompts, and no longer calls `server.fail`;
  `browserLaunchFailed` and its outcome are deleted
  (`interactiveLogin.ts`); no timer is added — the login ends on its
  result, the IdP's refusal or the consumer's signal.
- [ ] README: the browser-launch paragraph and the `interactive-login`
  outcome list (no `browser-launch-failed`); "Migrating to 6.0.0": a launch
  failure is no longer an error, bound the login with a signal.

**Load-bearing:** restore `server.fail` after the prompt → the
callback-after-prompt case red; drop the prompt → its case red.

### Task 30i: auth-providers — `state` on every redirect, PKCE for UAA

Repository auth-providers, PR #68. After 30h. Spec §6a1. Publish
dependency: interfaces-auth 7.3.0 (`ICallbackServerOptions.gated?`,
`ICallbackServerHandle.expectState?(state | null)`, `CONFIG_FIELDS` +
`callbackServer`), released first, one PR in the
interfaces repository, merged/tagged/published by the user.

**Steps:**
- [ ] Tests first, from §6a1: forged callbacks (missing / different
  `state`) answered `400`, counted, ignored, the login then completing with
  the right one, on a real port; a forged `?error=` ignored; a fresh `state`
  per attempt; the manual paste of a URL with a wrong `state` refused and
  asked again, a bare code accepted; the UAA URL and exchange shapes
  (`tokenRequestShapes.test.ts`); the stand: UAA accepts the PKCE login and
  refuses a code exchanged with a wrong verifier.
- [ ] Providers mint `state` (and, for UAA, the PKCE pair) per attempt,
  only for a URL they build; a configured `authorizationUrl` and a static /
  external code stay unbound, as today. The shipped transports implement
  `gated` (closed from the bind on) and `expectState`, gating every callback
  (code and `?error=`) before settling; `BrowserCallbackStrategy` opens them
  gated, arms them after building the URL and before opening the browser,
  or refuses a transport without `expectState`; the UAA transport's
  `/submit` paste route is bound by a per-attempt form token from its served
  form (and a pasted URL's `state`); `manualPasteStrategy` compares a
  pasted URL's `state`. Constant time; nothing logs it.
- [ ] README: the strategy contract (a consumer's redirect strategy must
  check `state`), the login CSRF note; CHANGELOG `Security`.

**Load-bearing:** accept any `state` → the forged-callback cases red; drop
the UAA PKCE → the stand's wrong-verifier case red; reuse one `state`
across attempts → the per-attempt case red.

### Task 30g: auth-providers — documentation of §6c

Repository auth-providers, PR #68. After 30d–30f, 30h and 30i.

**Steps:**
- [ ] CLAUDE.md rules 5 and 6 as §6c.13 words them; the "Cancellable shared
  attempts" and token-provider paragraphs rewritten for the two strategies;
  `onTokens` and `refreshTokenDisposition` gone from it.
- [ ] README: "Renewal strategy" and "Persistence strategy" sections (the
  types, the defaults and their decision table, writing one's own, the
  write-failure choice); §6b's cancellation text rewritten for `ifCut`.
- [ ] "Migrating to 6.0.0": `renewal` required (`refreshThenLogin()` is
  the old behaviour), `onTokens` → `persistence`
  (`refreshStatePersistence(write, { onWriteFailure })` is the old
  behaviour; the choice is required), `refreshTokenDisposition` gone,
  `renewal-declined` added, the three dependency majors.
- [ ] CHANGELOG `[Unreleased]`: the surface diff against 5.4.2 regenerated;
  the generated refusal tables regenerated (`npm run docs:tables`).

**Gate:** standard; the generated-table test green.

### Changes to the tasks after it

- **Task 31:** a Codex adversarial pass on PR #68 at the head after 30g;
  the PR description also carries the renewal goal's and §6c's decisions
  and the 30d–30f load-bearing runs.
- **Global Constraints, versions and order:** interfaces-auth 7.0.0 (and
  siblings) and auth-errors 2.0.0 enter the chain before auth-providers
  6.0.0; connection 13.0.0 follows auth-providers 6.0.0.
- **Task 32 (connection gate 7)** is done inside PR #75 (Task 30c), before
  connection 13.0.0 is released: devDependency `auth-providers ^6.0.0`, the
  legacy adapter deleted, every suite against the real 6.0.0 providers;
  any difference is fixed in the same PR. No separate PR and no 13.0.1.
  Then G9; Tasks 33–34 follow it.
- **Task 33 (auth-stores 4.0.0):** dependencies on interfaces-auth 7 and its
  siblings; no `refreshTokenDisposition` to accept — `''` stays the clearing
  operation, documented and pinned by a test per session store.
- **Task 34 (auth-broker 5.0.0):** its dependency ranges and publish
  prerequisites are replaced, for both workspace packages: interfaces-auth
  `^7.0.0` and the siblings Task 30a released, auth-errors `^2.0.0` (the
  CLI's `renderDiagnostics` dependency included), auth-providers `^6.0.0`,
  auth-stores `^4.0.0`, connection `^13.0.0` where used; before G6,
  `npm ls @mcp-abap-adt/interfaces-auth` and `npm ls @mcp-abap-adt/auth-errors`
  show one deduplicated copy each, and an exhaustive kind switch in the
  broker or CLI handles `renewal-declined`. Then the `renewal` option, default
  `refreshThenLogin()`; persistence through
  `refreshStatePersistence(write, { onWriteFailure: 'fail' })` over
  `SessionWriter` (`null` → `refreshToken: ''`, `undefined` → the stored
  one carried); `failedWrites` keyed by result removed for the providers it
  builds and kept, with `throwFailedWrite`, for `obtainFromConsumer`; tests:
  a failed session write fails the initiating `getToken()` on both paths
  (cache hits of a consumer's provider included) while retries continue and
  `flush()` reports it.
- **Task 35:** gate 4 installs the new majors; RF5 checks one deduplicated
  copy of interfaces-auth 7 and auth-errors 2.

**Decision (this plan):** the broker's write-failure mapping (its own error
in place of `persisting-tokens` for the token API) is decided in Task 34
from the broker's existing error types, not here.


### Task 31: Release preparation

**Steps:**
- [ ] `npm run test:stand` green; standard gates; version 6.0.0.
- [ ] PR #68 description: what the deleted documents still owe — Tasks 32–35 of this plan with their order and gates, the D-decisions, the load-bearing record (Task 29), the L1 decision as amended 2026-10-06 (no server text in any line or error, `authDebug` adds only `sent`, each secret through `prepareSecret`; no redactor) and the 5.4.2 record (§11.5 gate 6); for the server task (`mcp-abap-adt`), that it must choose its own bound for an interactive login it triggers, or document that it waits until the user finishes or the request is cancelled (§6a, §10.6); and that it ties each MCP request's cancellation to the token API's per-call `signal` and each session's close to the `signal` it passes to `getProvider` (§6b).
- [ ] **Measured on a Windows host before the providers release** (the Linux stand cannot): the SNC `reg.exe` abort kill (an aborted signal ends the child and the moment answers `aborted`), `parseRegQuery` on real `reg` output including a localised one, a live SNC logon (G1/G2), and the browser launch through `rundll32` and through PowerShell `Start-Process` (Task 26). Record each result; a Pending stays Pending in the docs until run.
- [ ] Delete `docs/superpowers/` documents of this work (goal, spec, plan) — CLAUDE.md "Plans and specs"; gate 5.

**G4 (user):** merge #68, tag, publish auth-providers 6.0.0. Before saying "publish": the main checkout on the tag, built (memory "verify a release where it is published").

---

## After auth-providers 6.0.0 (carried in PR #68's description once this file is deleted)

### Task 32: connection gate 7

Repository connection, new PR. Publish dependency: auth-providers 6.0.0 (G4).

**Steps:** devDependency `@mcp-abap-adt/auth-providers ^6.0.0`; delete `legacyProvider.ts`, its table and the `afterEach`; unwrap every test file; run every suite against the real 6.0.0 providers. Green → gate 7 met, PR merged without a release (test-only change) — **Decision D8**: a test-only change is released only if the user wants it; any difference (a word, a kind, a disposition) is fixed in this same PR as connection 12.0.1 (G5, user) before Tasks 33–34 start.

### Task 33: auth-stores 4.0.0

Repository auth-stores, one PR. Publish dependency: interfaces-auth 6.0.0, interfaces-auth-sap 3.2.0 (interfaces-auth-broker 1.3.0 already published).

**Steps:** dependencies `interfaces-auth ^6.0.0`, `interfaces-auth-sap ^3.2.0`, `interfaces-auth-broker ^1.3.0`; delete its `asContract`; released with its unreleased strict-compiler change (already breaking: engines) as 4.0.0; **refresh-token clearing (spec §10.5, §6b):** `saveSession` with `refreshToken: ''` (already removing it, `sessionSecret.ts:168-170`) documented as the clearing operation (`''` clears, `undefined` keeps) in README and the store notes, pinned by a test per session store (file, in-memory): saved R, then a save with `refreshToken: ''` and a new access token → reload has the access token and no refresh token; a save with `refreshToken` omitted keeps R (break: treat `''` as omitted → red); CHANGELOG / README migration: the versions and that statement. Standard gates; lockfile check.

**G5 (user):** merge, tag, publish auth-stores 4.0.0.

### Task 34: auth-broker 5.0.0 and auth-broker-cli 3.0.0

Repository auth-broker (workspace), one PR. Publish dependency: interfaces-auth 6.0.0, interfaces-auth-sap 3.2.0, auth-errors 1.0.0, auth-providers 6.0.0, auth-stores 4.0.0 (G1, G2, G4, G5) and gate 7 met (Task 32).

**Files:** both `package.json`s (§10.6; the CLI also takes `auth-errors ^1.0.0` for `renderDiagnostics`); `clientAuthentication.ts` (J1: copied phrases at `:77-80` and `:220-226` deleted; `resolveClientAuthentication` catches with `readFailure(error, 'client-authentication-strategy')`; `DestinationConfigError` gains `readonly error?: IAuthProviderError`; reason `the clientAuthentication strategy refused: ${error.reason}` for `client-certificate`, else `the clientAuthentication strategy failed` — rendered, not copied; J2, J3, J4 stay); `destinations.ts:247-255` (J5 on `kind === 'configuration'` and `facts.fields`); `getTokens` / `refreshTokens` relay the provider's failure unchanged; **cancelling (spec §6b, §10.6):** `getProvider(destination, { signal })`, `getToken(destination, { signal })`, `refreshToken(destination, { signal })`; `getProvider` callers are waiters of the destination's shared build (the build-cache rule of §6b, through auth-errors' `sharedAttempt` — no second implementation of the waiter rules, R2: one caller's abort rejects only its promise `aborted`; when all have aborted the build is removed from `built` at once, identity-checked, and its late completion is neither cached nor written; a failed or aborted build retried on the next call), and only a given signal is attached (`attach`) to the token provider returned, built or cached — `getProvider` without a signal attaches nothing; the token API reaches the provider only through a new private, non-attaching `providerFor(destination, signal?)` (replacing `obtainShared`'s call of `getProvider`, `AuthBroker.ts:621`) and passes the call's signal to `getTokens` / `refreshTokens`; the broker adds no bound and no signal of its own; **refresh-token disposition (spec §6b, §10.6):** the broker keeps a **logical refresh state** per destination (`stored` initially, `cleared`, `token(X)`; `'replace'` → `token(X)`, `'clear'` → `cleared`, `'keep'` → unchanged) and builds every session write and every retry of a pending write from it (`AuthBroker.ts:1282-1295`, `SessionWriter.ts:80-84`, which keeps only the latest pending result): `token(X)` writes X, `cleared` writes `refreshToken: ''` with no stored-token fallback (sticky until a `'replace'`), only `stored` keeps today's fallback; an access token written only when non-empty; **login bound (§6a):** the broker sets and adds none — its consumer composes a strategy or factory with a `signal`; the CLI keeps no bound either (user decision 2026-10-05): `INTERACTIVE_LOGIN_TIMEOUT_MS` (`mcp-auth.ts:40`, `:580`; `generate-env-from-service-key.ts:44`, `:54`; `mcpSsoConfig.ts:40`, `:700`, `:717`, `:758`) is removed, not turned into `AbortSignal.timeout`; each command that starts a login creates one `AbortController`, wires `SIGINT` and `SIGTERM` to its `abort()` for the duration of the login (handlers removed afterwards) and passes its `signal` to the strategy or factory; an aborted login prints the `aborted` words and exits non-zero without a stack trace; no `timeoutMs` is passed anywhere; `AuthBroker.ts:660`, `SessionWriter.ts:40-46` log `AuthProviderFailure`; CLI `generateEnv.ts:262-264`, `mcp-auth.ts:587-591` (J6: `reason — hint`, then `renderDiagnostics` on its own line); `AuthBrokerConfig.authDebug?: boolean | undefined` passed as `authDebug` to every token provider the broker builds from a destination (`destinations.ts`'s provider construction), `=== true` only, never read from the environment; a consumer-supplied provider instance or factory result keeps its own setting; the CLI (`mcp-auth`, `generate-env`) gains `--auth-debug`, which sets it and nothing else; `tools/check-provider-shape.mjs` copied with `--rules 4,5,6`, with the byte-identity test (R1); READMEs (the option and the flag: off by default, what they write), CHANGELOGs, migration notes of both packages (incl.: a consumer that relied on the providers' 30 s / 300 s defaults must now bound the login itself; the CLI's five-minute limit is gone — interrupt with Ctrl+C).

**Tests first:** `DestinationConfigError.error` deep-equal to the provider's error for each certificate problem, message containing `render(…)`'s words; a source test: no certificate phrase left in `src` (§11.1); J5 with an SNC configuration failure; the CLI's output for a failure with and without diagnostics. **RF5:** a failure thrown by a second copy of `auth-errors` loaded from another path is relayed: `isAuthProviderFailure` true, `readFailure` same kind and facts, the CLI prints `reason — hint`. **`authDebug` pass-through:** a destination-built provider receives `authDebug: true` only when `AuthBrokerConfig.authDebug === true` (absent, `false`, `'true'` → off); a consumer-supplied provider keeps its own setting; `mcp-auth` and `generate-env` with `--auth-debug` hand `authDebug: true` to the broker, without it they do not; with `DEBUG_AUTH_PROVIDERS=true` (and any other variable of the chain) set and no flag or option, nothing changes; without the flag the CLI's output carries no server text for a token endpoint answering `400` with an `error_description` marker. **Refresh-token disposition (§10.6), end to end with the published auth-stores 4.0.0 session store:** a persisted R, a refresh cut after dispatch, then a result carrying the tombstoned R → reload from the store: R absent; a persisted R and only the cut → the clearing step's write removed R, and a fresh broker on the same store (a restart) finds no refresh token and logs in; `'keep'` keeps a stored R; `'replace'` writes the new one; **refused refresh, end to end:** a persisted R → refresh refused by the server → token-only login → a restarted broker on the same store finds no R; the same with the `'clear'` write failing once then succeeding; the same with the fallback login itself failing (R still cleared in the store); **composition:** a persisted R → a cut → the `'clear'` save fails once → a token-only `'keep'` result → the retried write succeeds → a fresh broker on the same store (restart) finds no R; a `'replace'` after a pending `'clear'` wins. **Cancelling (§10.6):** two `getProvider` callers, one aborts → the other gets the provider; both abort → nothing cached, the next call builds again; a provider from `getProvider(…, { signal })` whose `rejected()` starts a login is cancelled by that signal (strategy signal aborted, port bound by the test afterwards) and not while another caller's signal is live; `getToken(…, { signal })` aborted → rejects `aborted` while a concurrent `getToken` without a signal still gets the token; **RF6** through the broker (two sessions via `getProvider`, one `getToken` call); **immortal-party regression:** a `getToken` without a signal, then two sessions via `getProvider(…, { signal })`, a `rejected()`-started login, both sessions close → the login aborts and the port is bound by the test afterwards; `getProvider` without a signal attaches nothing; **after all sessions closed:** every session's signal aborted, then a later `getProvider(destination)` without a signal (a cache hit, the same provider) handed to a connection whose renewal (`rejected()`) logs in → gets a token; **mixed connections:** a signalled and an unsignalled connection share the provider, the signalled one closes → the unsignalled one's next renewal gets a token; a source test: nothing in the token API calls `getProvider`; **doomed build window:** all `getProvider` callers abort while the build's store read is outstanding → a new caller arriving before it completes builds afresh and gets its own provider; the first build's late completion is not cached and writes no session secret; **session-secret write order:** writes for one destination serialized and generation-tagged — a deferred older write (a retried failed write) completing after a newer one does not overwrite it (break: drop the tag → red). **RF1 (CLI, no bound):** a source test finds no timer bounding a login anywhere in the CLI — no `INTERACTIVE_LOGIN_TIMEOUT_MS`, no `AbortSignal.timeout`, no `setTimeout` on a login path — and no `timeoutMs` passed to any auth-providers factory or strategy in either package; for `mcp-auth` and `generate-env`, a login that receives no signal keeps waiting past the old five minutes (fake timers advanced well past 300 s, the callback port observed still held), the test then ending it with its own abort; `SIGINT` delivered while the login waits (and separately `SIGTERM`) aborts it — the `aborted` words printed, a non-zero exit without a stack trace, and the callback port **bound by the test afterwards** (asserted on the port, not on a log line); after the login the CLI's signal handlers are removed (`process.listenerCount('SIGINT')` back to its value before).

**Load-bearing:** re-add one copied phrase → the source test red; relay through `instanceof` instead of `readFailure` → the RF5 case red; read the option from the environment as a fallback → the env-ignored case red; drop the flag's wiring in one CLI command → its pass-through case red; leave `SIGINT` unwired in one command → its port case red; re-add a five-minute `AbortSignal.timeout` → the source test and the keeps-waiting case red; cache an aborted build → the build-retry case red; skip `attach` on a cache hit → the second-session case red; route the token API through `getProvider` again → the immortal-party case red; fall back to the stored refresh token on `'clear'` → the end-to-end tombstone case red; write each result on its own (no composition) → the composition case red; a provider emitting `'keep'` after a refused refresh → the refused-refresh end-to-end case red; reinstate a "no live party → `aborted`" rule in the provider → the after-all-sessions and mixed-connections cases red; remove the abandoned build only on settle → the doomed-build case red.

**Release:** the CLI's workspace link to auth-broker is gone from what is released (both ranges semver; auth-broker published first, then the CLI) — global CLAUDE.md standing exception.

**G6 (user):** merge, tag, publish auth-broker 5.0.0, then auth-broker-cli 3.0.0.

**From Task 11a:** auth-errors ships `sharedAttempt<T>(operation)` (`join(start, signal?)`; `AttemptContext.exclusive(work)` reports exclusive local work — the drain) and `createParties()` (`attach(signal) → detach`; `waiterSignal()` → `undefined` with no live party, else `{ signal, release }`). Use them; do not re-implement the waiter or party rules. Call every `MomentWaiter`'s `release()` in a `finally` around its `join`, and test that the parties' listener count returns to its baseline. `start`'s result must not be thenable.

### Task 35: Final cross-repository checks (spec §11.5)

**Steps (each recorded with its output):**
- [ ] Gate 1: every Appendix A row implemented as mapped (Task 29's audit, connection's I rows, the broker's J rows); L1–L13 approved (spec Appendix C header).
- [ ] Gate 2: each repository's standard gates on its released tag; `test:stand` for auth-providers.
- [ ] Gate 3: READMEs, guides, CLAUDE.md, migration notes, generated tables current in all six packages.
- [ ] Gate 4: in an empty directory outside every repository, `npm install` of interfaces-auth 6.0.0, interfaces-auth-sap 3.2.0, auth-errors 1.0.0, connection 12.0.x, auth-providers 6.0.0, auth-stores 4.0.0, auth-broker 5.0.0, auth-broker-cli 3.0.0 from the registry; lockfile: no `"link": true`, every resolution from the registry. **RF5:** `npm ls @mcp-abap-adt/auth-errors` and `npm ls @mcp-abap-adt/interfaces-auth` show one deduplicated copy each; a smoke script there builds a provider, runs `prepare()` / a refused `rejected()` and prints `reason`, `kind`.
- [ ] Gate 5: `docs/superpowers/` holds none of this work's documents on auth-providers' master.
- [ ] Gate 6: the CHANGELOG **Fixed** entry for the legacy Basic credential; the `authDebug` tests green in auth-providers — only the safe-facts line without it (every failed request, with or without a response; the code exchange's 2xx line verbatim at `error`), the `prepareSecret` bounds (15/16), a short secret as its length only, `error_description` / `error_uri` read 0 times — and the header-echo tests for every token site on both paths in both modes (each proving that no echoed form reaches a line or the failure); the broker and CLI pass-through tests green (Task 34); L1 as amended and the 5.4.2 record in #68.
- [ ] Gate 7: Task 32 green before Tasks 33–34 moved.
- [ ] Gate 8: the Windows measurements of Task 31 (SNC `reg.exe` abort kill, `parseRegQuery` on real and localised output, a live SNC logon G1/G2, browser launch via `rundll32` and PowerShell `Start-Process`) recorded before auth-providers 6.0.0 is published.
- [ ] §12 "not measured", last item: search the chain's consumers known to the user (the server `mcp-abap-adt`, the proxy, calm) for matches on today's refusal words; record each hit for the server's own task.

**After:** the server `mcp-abap-adt` reads `kind` where it acts on a refusal and chooses its own bound for an interactive login (§6a), tying MCP request cancellation and session close to the broker's signals (§6b) — its own task (goal "After"), out of this plan.

---

## Words for review (spec L6: "each case's words are reviewed in the plan's words table")

Words the spec does not fix. `<…>` is a fact; a hint `—` means none. Each is today's sentence with interpolated values removed, unless noted.

**Configuration cases** (default hint: `check the provider configuration`):

| `case` | reason | hint (if not default) |
|---|---|---|
| `required-fields-missing` | `required configuration is missing: <fields>` | |
| `client-secret-beside-client-authentication` | `clientSecret cannot be given beside clientAuthentication` | `give the secret to the clientAuthentication strategy, or drop the strategy` |
| `saml-acs-required-with-authorization-url` | `acsUrl is required when authorizationUrl is set: the ACS inside a pre-built SAML request cannot be read, so it must be declared` | |
| `saml-idp-initiated-with-request-id` | `SAML idpInitiated is true, but a request ID was also configured or minted: an IdP-initiated login sends no request` | `remove one of them` |
| `saml-shipped-validator-without-issuer` | `the supplied assertionValidator is a shipped one, which refuses every assertion without an expected issuer: idpEntityId is missing` | |
| `saml-token-endpoint-missing` | `the SAML bearer exchange needs tokenUrl or uaaUrl` | |
| `saml-idp-initiated-without-authorization-url` | `SAML idpInitiated is true and no authorizationUrl is configured, but the authorization strategy asked for an authorization URL` | `configure the IdP-initiated SSO URL as authorizationUrl, or use a strategy that does not call buildAuthorizationUrl` |
| `saml-acs-mismatch` | `SAML acsUrl and the address the authorization strategy used do not match` | `they must match; the two addresses are in the diagnostics` |
| `saml-in-response-to-undeclared` | `cannot validate InResponseTo: this login did not build its own AuthnRequest` | `configure authnRequestId, or idpInitiated: true if the identity provider starts this login itself` |
| `client-id-required-with-client-authentication` | `clientId is required with a client authentication` | |
| `redirect-mismatch` | `the pre-built authorizationUrl declares a redirect_uri the authorization strategy did not use` | `an ephemeral port cannot be used with a pre-built URL` |
| `oidc-discovery-needs-issuer` | `OIDC issuerUrl is required when discovery is used` | |
| `oidc-endpoint-missing` | `OIDC <fields> is required (configure it, or use discovery)` | |
| `certificate-pem-and-pfx` | `certificate auth: provide either PEM (certPath + certKeyPath) or certPfxPath, not both` | |
| `certificate-files-missing` | `certificate auth requires certPfxPath, or certPath and certKeyPath` | |
| `basic-encoding-missing` | `clientSecretBasic needs encoding: 'raw' or 'form'` (from `allowed`) | |
| `snc-partner-name-missing` | `SncLogonProvider needs partnerName — the system's SNC name` | |
| `snc-qop-invalid` | `SncLogonProvider: qop must be one of 1, 2, 3, 8, 9` (from `allowed`) | |
| `unsupported-sso-flow` | `unsupported SSO provider config: no provider for this protocol and flow` | |
| `validator-clock-skew-invalid` | `clockSkewMs must be a finite non-negative integer` | |
| `validator-no-certificates` | `idpCertificates must not be empty: nothing could be verified` | |
| `idp-certificate-invalid` | `a configured IdP certificate is not a valid X.509 certificate in PEM or base64 DER` (E26's two sentences become one) | |
| `static-code-without-payload` | `staticCodeStrategy requires a payload` | |
| `callback-port-invalid` | `invalid callback server port: it must be an integer in 0..65535` | |

**Interactive-login outcomes not fixed verbatim:** `aborted` — `the browser login was aborted[; <k> incomplete request(s) reached /callback and were ignored]` (spec K4); `disposed` — K2's and K15's sentences by `strategy` (spec, verbatim); `browser-launch-failed` — `the browser could not be opened[ (<code>)]` / `open the authorization URL from the log by hand`; `callback-closed` — `the callback server closed before a result arrived`; `no-input` — `no input was received` (spec K14); `failed` — K11's reason verbatim (`the browser login failed (HTTP <n>[, <code>])`, or `(unknown error[, <code>])` without a status) with A9's new hint `complete the login, or abort it` (spec); `identity-provider-refused` without a registered code — K10's `… (an unregistered error code)`. No outcome renders a timeout.

**Operation phrases** (in `<phrase> failed (…)`; today's `what` where one exists, so A1/A13–A16/B15 stay verbatim): `token-request` `<grant> token request`; `refresh` `the refresh`; `on-tokens-hook` `onTokens`; `presenting-token` `presenting the token`; `presenting-certificate` `presenting the certificate`; `loading-certificate` `loading the certificate`; `writing-authorization-header` `writing the Authorization header`; `offering-logon-parameters` `offering the logon parameters`; `writing-session-cookies` `writing the session cookies`; `reading-rejection` `reading the rejection`; `token-source` `the token source`; the four SNC moments render `the SNC provider failed while <resolving the SNC library | handing over the SNC logon parameters | authorizing a request | explaining the SNC refusal> (unknown error)` (G10 verbatim); `probing-snc-product` `the probe`; `presenting-device-code` `the presenter`; `saml-token-exchange` `the SAML token exchange`; `saml-token-refresh` `the SAML token refresh`; `browser-login` `the browser login`; `opening-browser` `opening the browser`; `passcode-exchange` `the passcode exchange`; `device-authorization` `the OIDC device authorization`; `password-grant` `the OIDC password grant`; `client-credentials` `the client credentials request`; `token-refresh` `the token refresh`; `oidc-discovery` `OIDC discovery`; `code-exchange` `the code exchange`; `device-poll` `the device poll`; `oidc-token-request` `the OIDC token request`; `validating-assertion` `validating the SAML assertion`; `client-authentication-strategy` `the clientAuthentication strategy`; `preparing` `preparing`; `establishing` `establishing the logon`; `authorizing` `authorizing the request`; `unfamiliar-error` renders its own sentence, `an authentication error of a kind this version does not know` (§9). `request-failed` `no-access-token`: `<phrase> returned no access_token`; `incomplete-response`: `<phrase> returned an incomplete response`.

---

## Decisions this plan takes (for review with the plan)

- **Decision D1** — The rule → check correlation is a type in interfaces-auth; auth-errors' runtime `ASSERTION_RULE_CHECK` `satisfies` it (Task 1).
- **Decision D2** — `isAuthProviderFailure` is structural across copies (`name` + an `error` passing the structural rebuild), never reading `message` (Task 10).
- **Decision D3** — `relayOutcome` lives in `guard.ts` (Task 11).
- **Decision D4** — The shape-check script is authored in auth-errors, published as a plain file in its package, and copied byte-identically (a byte-comparison test per repository, R1) into the other repositories with its source commit; not published (Task 12).
- **Decision D5** — Rules per repository: auth-errors 4 (four sites) + 6 (empty); connection and broker 4, 5, 6; auth-providers 1–8 (Task 12).
- **Decision D6** — Intra-PR order in auth-providers: stay on interfaces-auth 4.x direct with auth-errors (6.0.0 nested), derive 5.x names from auth-errors' signatures, keep every old helper's signature until its last caller moves, bridge legacy throws inside guarded bodies, flip in Task 27; each temporary piece has a transition test and a removal task (the Decision D6 table) — so every task's gates are green.
- **Decision D12** — connection's flip, its producers, the legacy adapter, its table and the 13 test files' migration are one task (Task 14): nothing unbranded compiles after the flip, and the adapter cannot exist before it.
- **Decision D7** — `refusalWords` survives until Task 27 (implemented on `classify`), then is deleted with the classes.
- **Decision D8** — connection's gate-7 PR releases only if it changes shipped code (a 12.0.x patch); a test-only change is merged without a release unless the user asks.
- **Decisions D9–D11** — *Closed by the spec (b7e4587, §6a, L14):* no built-in login timeout, so no `Seconds`, no `timeout` outcome and no timeout words; `disposed` carries `strategy: 'browser' | 'manual'` and keeps both sentences.
