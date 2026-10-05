# Error contract — Implementation Plan

> **For agentic workers:** execute with superpowers:subagent-driven-development, one task per subagent, a review after each task (spec compliance first, then code quality). Steps use checkbox (`- [ ]`) syntax. This plan contains no implementation code by design: types and signatures are named from the spec, the code is written at implementation, test first.

**Goal:** what goes wrong in authentication has its own contract. Every refusal and every thrown token error of `@mcp-abap-adt/auth-providers`, and every refusal a logon target returns, is an `IAuthProviderError` — a closed union discriminated by `kind`, with allowlisted `facts`, words rendered from `kind` and `facts` alone, and admitted `diagnostics` beside them; the broker relays it without copied phrases (goal, "Goal" and "Success").

**Architecture:** the types and the `as const` allowlists live in `@mcp-abap-adt/interfaces-auth` 5.0.0 (no logic). The runtime half — builders, `mint` and its brand, the renderer, diagnostics admission, classification, `AuthProviderFailure`, `guard`, `relayOutcome`, `matchKind` — lives in the new `@mcp-abap-adt/auth-errors` 1.0.0. connection 12.0.0's logon targets and its own refusals mint through `auth-errors`; auth-providers 6.0.0 puts every provider behind `AuthProviderBase` (the four methods run inside `guard`), converts every refusal and thrown error, and deletes its error classes; auth-stores 4.0.0 and auth-broker 5.0.0 + CLI 3.0.0 move to the new majors and relay the error.

**Anchors (binding):**
- Goal: `docs/superpowers/2026-10-05-error-contract-goal.md` (approved 2026-10-05) — its "Holds throughout" invariants bind this plan.
- Spec: `docs/superpowers/specs/2026-10-05-error-contract-design.md` (approved 2026-10-05; L1–L13 and the SAML debug line approved). Section numbers below (§n, A/B/C rows) are the spec's.

Where this plan has to decide something the spec leaves open, it says so under **Decision** and lists it in "Decisions this plan takes" at the end, for review with the plan.

---

## Global Constraints

Copied from the goal and the spec; every task is bound by all of them.

**Versions and order (spec §11.5 gate 4).** "interfaces (auth 5.0.0, auth-sap 3.1.0) → auth-errors 1.0.0 → connection 12.0.0 → auth-providers 6.0.0 → auth-stores 4.0.0 → auth-broker 5.0.0 + CLI 3.0.0; each consumer built against the published versions, the lockfile checked for `"link": true` and non-registry resolutions; after publishing, a clean install of each from the registry outside the repositories." `interfaces-auth-broker` gets no release (§4.6: "3.1.0 is inside `^3.0.0`").

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

**The only type assertions on the contract's types** are `mint` and the four integer makers in `auth-errors` (§4.3, `tools/assertion-sites.json`); every other repository's list is empty.

**Provider rules** (auth-providers CLAUDE.md, rules 1–8) keep their behaviour; only the words' source and the error shape change. No retry is added, no renewal step runs twice, rule 5's blame does not change (`blamesCredential` is the table of §3.1).

**Repository process** (user rules): each repository step is one PR in that repository, one open PR per repository at a time; auth-providers' work is this PR (#68). The user merges and tags on their word and publishes; tasks stop at those gates. Nothing writes to `process.stdout`. No time estimates. Chat Ukrainian, artifacts English.

**The 5.4.2 patch** (user-approved exception, in progress separately on `fix/basic-credential-redaction`): 6.0.0 must carry the same `legacyBasic` fix and its header-echo tests (`400` and `200` without `access_token`), and auth-providers' code tasks start from a `master` that includes 5.4.2 (Task 17).

---

## Review Focus

Five inputs most likely to reach a user that no task's spec-listed tests exercise; each gets a test in the owning task (named there as **RF1–RF5**).

- **RF1 — A callback timeout that is not a whole number of seconds** (`timeoutMs: 1500`, `timeoutMs: 500`, the maximum `2147483647`). Today the message prints `timeoutMs / 1000` (`callbackServer.ts:259`: "after 1.5 seconds"); the spec's `timeoutSeconds` is a branded integer (`Seconds`), so `seconds(1.5)` answers `undefined` and the fact — and the number in the words — would silently vanish. Test in Task 23 (and the words in Task 7): each of the three values renders a timeout sentence that states a duration and never "undefined"/"NaN", per the decision taken at plan review (see "Decisions", D9).
- **RF2 — A token endpoint answering with a status outside 100–599, or a response without a status** (a proxy's `0`, an appliance's `999`, a mock returning `undefined`). `httpStatus()` answers `undefined`; the spec says `problem: 'refused'` is "a response with a status". Test in Task 20: such a response yields `request-failed` with `problem: 'no-response'`, no `status` key, the debug line still written with the reduced body, and no exception from the conversion.
- **RF3 — A refusal a consumer copied or mutated.** 4.x consumers may `structuredClone` a refusal, round-trip it through JSON (a session file, a worker message), spread it in JavaScript, or assign `refusal.hint = …`. A minted error is frozen (assignment throws in strict mode) and a copy is not in the `WeakSet`. Tests: in Task 9 — `structuredClone` and `JSON.parse(JSON.stringify(e))` of each kind classify back to the same kind and facts (rebuilt, no diagnostics); in Task 10 — `new AuthProviderFailure(clone)` documents its result (`unknown`, per §6) and the README warns; in Task 7 — assignment to a minted error throws `TypeError` in strict mode and is silently ignored in sloppy mode, stated in the migration note; in Task 14 — connection's `AuthRefusedError` built from a cloned refusal still has a `reason — hint` message.
- **RF4 — SNC library paths as they occur on users' machines:** a Windows profile with non-ASCII letters (`C:\Users\Олексій\…`), spaces and parentheses (`C:\Program Files (x86)\SAP\…`), a UNC path (`\\server\share\sapcrypto.dll`), and a registry value read by `reg.exe` that ends in `\r\n` or trailing spaces. `LocalPath` refuses C0 controls, so an untrimmed `\r` would drop the whole path to `null`. Tests in Task 25 (through the shipped locator and `nodeSncSystem`'s fake) and Task 6 (admission): each path is admitted unchanged and rendered JSON-quoted by `renderDiagnostics`; a registry value with trailing CR/LF reaches `candidatePaths` trimmed, not `null`.
- **RF5 — Two installed copies of `auth-errors` in one consumer tree** (connection and auth-providers resolving different `auth-errors` minors under a lockfile, or a nested copy). `instanceof AuthProviderFailure` is false across copies and diagnostics are dropped (L13). Tests: in Task 34 — the broker relaying a failure thrown by a second copy loaded from another path: `isAuthProviderFailure` true, `readFailure` gives the same kind and facts, the CLI prints `reason — hint`; in Task 36 — `npm ls @mcp-abap-adt/auth-errors` in a clean registry install of the broker plus connection shows exactly one deduplicated copy. The auth-errors and auth-providers READMEs say "use `isAuthProviderFailure` / `readFailure`, never `instanceof`".

---

## User gates (outside any task)

- **U0** — this plan approved (separately from the spec's approval).
- **U1** — 5.4.2 merged, tagged and published by the user; Task 17 starts only after.
- **U2** — the GitHub repository `fr0ster/mcp-abap-adt-auth-errors` created and the npm name `@mcp-abap-adt/auth-errors` available to the user's npm account (the user publishes 1.0.0; a placeholder publish is the user's choice, not a task). Task 4 starts only after.
- **G1–G6** — merge, tag and publish of each repository's release, listed at the end of each repository's tasks. Every agent stops there and reports.

## Task overview

| # | Repository | Task | Nature |
|---|---|---|---|
| 1 | interfaces | Error contract types and frozen allowlists | judgement |
| 2 | interfaces | Outcome/refusal/failure, removals, JSDoc, type tests, surface tools | judgement |
| 3 | interfaces | interfaces-auth-sap 3.1.0, READMEs, CHANGELOGs, migration notes | mechanical |
| 4 | auth-errors | Repository scaffold, CI, strict flags, lint | mechanical |
| 5 | auth-errors | Branded integer makers, private sets, membership guards | mechanical |
| 6 | auth-errors | Diagnostics admission | judgement |
| 7 | auth-errors | `mint`, builders, `WORDS`, `render`, `blamesCredential` | judgement |
| 8 | auth-errors | `renderDiagnostics`, `logFields` | mechanical |
| 9 | auth-errors | `classify`, `classifyOutcome` | judgement |
| 10 | auth-errors | `AuthProviderFailure`, `readFailure`, `isAuthProviderFailure`, `OK` | mechanical |
| 11 | auth-errors | `guard`, `relayOutcome`, `matchKind`, `unreachableKind` | judgement |
| 12 | auth-errors | The shape check (canonical script), fixtures, site lists | judgement |
| 13 | auth-errors | Exports sweep, generated kinds table, README/CHANGELOG/CLAUDE.md | mechanical |
| 14 | connection | Dependencies, minted constants, `guarded`, the two targets | judgement |
| 15 | connection | Test-only legacy provider adapter and its closed table | judgement |
| 16 | connection | Shape check, README/CHANGELOG/migration | mechanical |
| 17 | auth-providers | Start from 5.4.2; `auth-errors`; transition types | mechanical |
| 18 | auth-providers | Refusal core: `refusal.ts`, `rejection.ts`, `knownCodes.ts` | judgement |
| 19 | auth-providers | `AuthProviderBase`, `guard`, `relayOutcome` in every provider | judgement |
| 20 | auth-providers | `sendTokenRequest` site, debug line, `rejectMissingToken`, `legacyBasic` | judgement |
| 21 | auth-providers | Every token site and device polling on the new conversion | judgement |
| 22 | auth-providers | `getTokens` / `refreshTokens` failures, `remembered`, renewal on `kind` | judgement |
| 23 | auth-providers | Interactive login (`interactive-login`) | mixed |
| 24 | auth-providers | SAML (`saml-assertion`, rule ids, diagnostics) | judgement |
| 25 | auth-providers | SNC (`snc`, `candidatePaths`, `library`) | judgement |
| 26 | auth-providers | Configuration throws (`configuration`, every case) | mechanical |
| 27 | auth-providers | Flip to interfaces-auth 5.0.0; delete classes, ladder, `asContract` | mechanical |
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

**Produces (names from §3, §4.1, §4.3):** `AUTH_PROVIDER_ERROR_KINDS` / `AuthProviderErrorKind`, `PlainKind`; every array of the §4.3 table with its union (`CONFIG_FIELDS`, `CONFIG_CASES`, `ALLOWED_VALUE_SETS`, `SNC_QOP_VALUES`, `BASIC_ENCODINGS`, `OPERATIONS`, `REQUEST_PROBLEMS`, `SYSTEM_CODES`, `TLS_FAILURE_CODES`, `OAUTH_ERROR_CODES`, `RFC_KEYS`, `ASSERTION_CHECKS`, `ASSERTION_RULES`, `BEARER_CANDIDATE_REASONS`, `SAML_STATUS_CODES`, `SNC_PROBLEMS`, `SNC_CANDIDATE_SOURCES`, `SNC_UNUSABLE_REASONS`, `SNC_ARCHS`, `INTERACTIVE_OUTCOMES`, `CREDENTIAL_KINDS`) and the per-kind `<KIND>_PROBLEMS` / `_VERDICTS` arrays (§4.3 last paragraph); `AuthProviderErrorFacts` (§3.2, `SamlFactsOf`, `SncFactsOf`, `ConfigFactsOf`, `BearerCandidate`, `SncCandidate`); the diagnostics maps `SAML_RULE_DIAGNOSTIC`, `SNC_PROBLEM_DIAGNOSTICS`, `CONFIG_CASE_DIAGNOSTICS` (each `satisfies Record<…>`) and `SamlDiagnosticOf` / `SncDiagnosticOf` / `ConfigDiagnosticOf`, the diagnostic value types (`LocalPath`, `DocumentValue`, `DocumentTime`, `XmlName`, `XmlId`, `ConfigUri`); branded `HttpStatus`, `Count`, `Port`, `Seconds` with unexported brand symbols; `IAuthProviderError`, `AuthProviderErrorOf<K>`, `SamlAssertionError`, `SncError`, `ConfigurationError`, the unexported `minted` symbol.

**Steps:**
- [ ] Build each array's members from the spec's named source today (§4.3 "Source today" column; Appendix A §A.8 for `OPERATIONS`, including `unfamiliar-error`, `preparing`, `establishing`, `authorizing`; Appendix B for the 56 `ASSERTION_RULES` and 11 `BEARER_CANDIDATE_REASONS`; §A.5 for `CONFIG_CASES`, `CONFIG_FIELDS` = the 47 of `KNOWN_CONFIG_FIELDS` plus `port`, `timeoutMs`, `payload`, `read`). Read the auth-providers sources at the spec's line references; copy, do not retype from memory.
- [ ] Every array `Object.freeze([...] as const)` at its definition (§5.5).
- [ ] The rule → check correlation is a type here (**Decision D1**: `AssertionRuleCheck`, read by `SamlFactsOf<R>`); the runtime `ASSERTION_RULE_CHECK` lives in auth-errors (§5.5 bullet 4) and `satisfies` it.

**Tests to write first** (`src/__typechecks__/errorContract.ts`, compiled by `test:check`, §11.2): the full probe of §11.2 on the real types — every positive line and every `@ts-expect-error` line of the consumer half (narrowing by `kind` + `variant`, facts narrowed, forbidden diagnostics, `facts.rule` not narrowing, the forged pairing with and without the brand); object literal not assignable to `IAuthProviderError`; `status: 500` not a `HttpStatus`; each union `Equal<>` to `(typeof ARRAY)[number]` both ways; `keyof AuthProviderErrorFacts` `Equal<>` `AuthProviderErrorKind`.

**Load-bearing:** remove one kind's facts entry → the `keyof` equality fails; move `variant` into `facts` in a scratch copy → the narrowing lines fail (record, revert).

**Gate:** standard; `check:surface`, `check:graph` accept the frozen arrays (if a check refuses `Object.freeze`, the check is amended in this PR — §5.5).

### Task 2: Outcome, refusal, failure; removals; JSDoc; surface tools

**Files:** `src/auth/AuthOutcome.ts` (§4.2), `src/error/IAuthProviderFailure.ts`, JSDoc of `IAuthProvider`, `IAuthTargets` (`ILogonTarget`), `IAssertionValidator`, `ITokenProvider`, `IRefreshableTokenProvider`; delete `src/token/TokenProviderErrorCodes.ts`, `src/auth/AssertionErrorCodes.ts`; `src/index.ts`; `tools/package-map.json`.

**Consumes:** Task 1. **Produces:** `IAuthRefusal = IAuthProviderError`, `AuthOutcome` (readonly), `IAuthProviderFailure`.

**Steps:**
- [ ] Normal-course files import only `IAuthProviderError` / `IAuthRefusal` / `IAuthProviderFailure` (goal invariant 1) — a type test or grep test asserts no kind name appears in them.
- [ ] JSDoc texts per §4.2 (Oops's refusal is an `IAuthProviderError`; a method never throws; `getTokens` / `refreshTokens` reject with an `IAuthProviderFailure`, read it with `readFailure`; a target's Oops is built through `auth-errors`; shipped validators reject with `saml-assertion`). The `IAuthProviderError` JSDoc states the exhaustiveness requirement (§9).
- [ ] `STORE_ERROR_CODES` stays (§4.4).
- [ ] Every new symbol mapped in `tools/package-map.json`.

**Tests first:** `@ts-expect-error` for an object literal as `refusal` of `AuthOutcome` and as `IAuthRefusal`; positive line: a value typed `IAuthProviderError` is an `IAuthRefusal`.

**Gate:** standard + `check:surface`, `check:graph`; `surface-removed.txt` lists the two removed code constants.

### Task 3: interfaces-auth-sap 3.1.0, docs

**Files:** `packages/interfaces-auth-sap/package.json` (range `^4.0.0 || ^5.0.0`), `__typechecks__/certificateLoaderCompatibility.ts` (the 5.x assertion both ways, §4.6), both CHANGELOGs, interfaces-auth README (error contract section, exhaustiveness requirement, "Migrating to 5.0.0" with the §4.5 table), auth-sap migration note "nothing to do". Versions: interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0; interfaces-auth-broker untouched.

**Gate:** standard; `npm pack --dry-run` of both shows only `dist`, README, CHANGELOG, licences.

**G1 (user):** merge, tag, publish interfaces-auth 5.0.0 and interfaces-auth-sap 3.1.0. Verify with `npm view` before Task 4.

---

## Repository 2 — `mcp-abap-adt-auth-errors` (new; one PR after the initial commit)

Publish dependency: interfaces-auth 5.0.0 on the registry (G1); repository and npm name ready (U2).

### Task 4: Scaffold

**Files (§5.1):** `package.json` (`main`, `types`, `files`, `license: LGPL-3.0-only`, `engines`, `sideEffects: false`, scripts `clean`, `build`, `build:fast`, `test`, `test:check`, `lint`, `lint:check`, `prepublishOnly`; `dependencies`: `@mcp-abap-adt/interfaces-auth ^5.0.0` only; `devDependencies` as auth-stores), `tsconfig.json` (the six flags), `tsconfig.build.json` (excludes tests and `__typechecks__`), `biome.json` (auth-providers'), `jest.config.js`, `.github/workflows/ci.yml` (Node 22, 24, 26: `npm ci`, build, `test:check`, `lint:check`, `test`), `release.yml` (on `v*.*.*`), `CHANGELOG.md`, `README.md`, `CLAUDE.md`, `LICENSE`, `COPYING`, `.npmrc`, `.gitignore`, `src/index.ts`; empty module files of §5.1's `src/` list.

**Steps:** initial scaffold commit on `main` (the user's new repository may need the first push to `main`; everything after goes through one PR, branch `feat/auth-errors-1`). Lockfile check after `npm install`.

**Tests first:** a smoke test that the package imports; `test:check` compiles an empty `__typechecks__`.

**Gate:** standard; CI green on the PR.

### Task 5: Integer makers, private sets, guards

**Files:** `src/numbers.ts` (`httpStatus`, `count`, `port`, `seconds`, private `inRange`), `src/allowlists.ts` (one module-private `Set` per array, `has` captured at load, one exported guard per array: `isSystemCode`, `isTlsFailureCode`, `isOAuthErrorCode`, `isRfcKey`, `isConfigField`, `isAssertionRule`, `isOperation`, … — one per §4.3 array and per `<KIND>_PROBLEMS` array).

**Tests first:** each maker at both bounds, one past each bound, non-integers, `NaN`, `Infinity`, strings, `-0`; each guard true for every member, false for a near miss and a non-string; type tests: each guard's predicate type `Equal<>` the array's union; `const s: HttpStatus = 500` fails, `httpStatus(500)` narrowed compiles.

**Load-bearing:** patch `Set.prototype.has` after load → guards unchanged (test exists in Task 13; here: remove the captured `has` → that test red).

### Task 6: Diagnostics admission

**Files:** `src/admission.ts` — the six checks of §5.3 (`LocalPath`, `DocumentValue` incl. the ASCII-only variant for `referenceUri` / `statusCode`, `XmlName`, `XmlId`, `DocumentTime`, `ConfigUri`), each total (guarded read), answering the admitted value or "drop"; the runtime admission table keyed by the three diagnostics maps (one source with the types).

**Tests first (§11.1 "Diagnostics admission"):** each check accepted value; each refused class (C0, DEL, C1, U+2028/2029, each bidi control U+202A–U+202E and U+2066–U+2069, a lone surrogate); length limits both sides (`LocalPath` 1024 never truncated; `DocumentValue` cut to 64 code points at a code-point boundary with `…`, an astral character on the boundary); non-string; throwing getter; `&#10;`-decoded newline in an Issuer; 10 000-character Destination; `xsd:dateTime` with a quote; `referenceUri` with a space; `ConfigUri` with userinfo, a query, a fragment, `javascript:`; admitted `ConfigUri` is `origin + pathname` ≤ 512. **RF4:** `C:\Users\Олексій\AppData\…\sapcrypto.dll`, `C:\Program Files (x86)\SAP\…`, `\\server\share\sapcrypto.dll`, `/Applications/Secure Login Client.app/…` admitted unchanged; a path ending in `\r` dropped (proving the trim in Task 25 is load-bearing).

**Load-bearing:** delete the bidi range from `LocalPath` → its case red; delete the code-point-boundary logic → the astral case red.

### Task 7: `mint`, builders, words, blame

**Files:** `src/mint.ts` (the one assertion, the module-private `WeakSet`, deep freeze, `isMinted`), `src/builders.ts` (`authError` per §5.2: generic builders for the three kinds with diagnostics using `One<…>`, `DiagnosticsInputOf<…>`; plain builders; normalisation — omit absent keys, cap and deduplicate arrays per §3.2, freeze nested), `src/words.ts` (`WORDS` `satisfies` the mapped type; one `switch` per discriminant ending in `unreachable(x: never)`; `ASSERTION_RULE_CHECK`; the TLS words), `render`, `blamesCredential` (the §3.1 column, a table `satisfies` a mapped type).

**Words:** Appendix A's "new words" column; *verbatim* rows reproduce today's string exactly (read the auth-providers source at the spec's line references); the words not fixed by the spec are this plan's "Words for review" appendix.

**Tests first:**
- Builders: each kind; `variant` set from the facts' discriminant; absent keys omitted (no `undefined`-valued key); `fields` capped at 8 and deduplicated in order; `candidates` capped at 5 / 8; result frozen deeply; a JavaScript caller passing a forbidden diagnostic gets it dropped; a refused diagnostic dropped and the error still minted.
- Words (§11.1 "Words"): every kind × every discriminant value renders; each *verbatim* row of Appendix A asserts the exact string (A2, A4–A8, A10, A14–A18, B1–B14, K1, K3, K9, K10–K13, K15–K17, G1 reason, G3, G4, G6, G8–G10, I1–I5 — the I rows' words live here because connection mints with them); no rendered string contains a diagnostic value (each built with a marker); `blamesCredential` per row of §3.1 incl. `snc` `logon-refused` with and without `RFC_LOGON_FAILURE`, `connection` `refused-after-renewal`.
- **RF1:** `interactive-login` `timeout` rendered for the facts produced by `timeoutMs` 1500, 500 and 2147483647 per decision D9 — never `undefined`, `NaN` or an empty number.
- **RF3 (part):** assignment to a minted error's `reason` and to a nested `facts` array throws `TypeError` under `'use strict'`.
- Type tests (§11.2): the builder half of the probe verbatim (positive and `@ts-expect-error` lines); `WORDS` with one kind removed does not satisfy; a discriminant switch missing a member fails.

**Load-bearing:** remove the `WeakSet.add` → every "minted" assertion red; drop `Object.freeze` on nested arrays → the mutation test red; make one verbatim word differ by a character → its row test red.

### Task 8: `renderDiagnostics`, `logFields`

**Files:** `src/diagnostics.ts`.

**Tests first:** one line per field, JSON-quoted (`library`, `candidates` joined with each source and reason and `(missing)` for a `null` path, `issuer`, the URIs); `undefined` when none; `render` never calls it (a spy); `logFields` = `{ error: reason, kind, status?, diagnostics? }` with `diagnostics` as a separate field and `status` only when a fact.

### Task 9: `classify`, `classifyOutcome`

**Files:** `src/classify.ts` — the six steps of §5.4 in order, total (own `try`), each property read once through a guarded read; one validator per kind `satisfies` a mapped type over the kinds; re-mint renders words here and never reads the input's `reason`, `hint`, `diagnostics`; `classifyOutcome` per §5.4's last paragraph.

**Tests first (§11.1 "Hostile values", "Carriers from another copy", "Forged diagnostics", "Exception text excluded", "Re-mint across copies"):** all listed hostile values; a forged carrier with a secret `reason` re-minted without it; unknown `kind`; facts out of their sets; primitives, symbols, functions; a second copy of the built package loaded from a temporary path (the test copies `dist/` and requires it) — bare and inside its `AuthProviderFailure`, every kind, same kind and facts, re-rendered, no diagnostics; the double-read getter on `error` (only the first read used); a foreign carrier with an invalid `error` falls through to steps 4–6; forged diagnostics (JWT-shaped `library`, exception text in `issuer`) dropped; the same-copy minted error keeps its diagnostics; for each kind an `Error` with a marker in `message`, `cause`, `stack`, `name` — marker absent from `JSON.stringify`, `reason`, `hint`, `renderDiagnostics`, `logFields`. **RF3:** `structuredClone` and a JSON round-trip of a minted error of each kind classify to the same kind and facts, without diagnostics.

**Load-bearing:** each step deleted in turn (minted-membership, carrier read-once, structural rebuild, TLS, status/oauth/code) → its named case red; reading `reason` in the rebuild → the forged-carrier case red.

### Task 10: `AuthProviderFailure`, `readFailure`, `isAuthProviderFailure`, `OK`

**Files:** `src/failure.ts` (§6): constructor takes a minted error (unminted → `unknown`), `message` = `reason` or `reason — hint`, no `cause`, no diagnostics in the message; `readFailure = classify`; `isAuthProviderFailure` works across copies (structural: `name` + a valid `error` — **Decision D2**: it answers true for another copy's instance whose `error` passes the structural rebuild; it never reads `message`); `OK` frozen.

**Tests first:** message format with and without hint; `JSON.stringify(failure)` and a pino-style enumerable-property copy hold only `name`, `message`, `error` (§12 "not measured" item made measured); **RF3:** `new AuthProviderFailure(structuredClone(minted))` answers `unknown` with the operation it was given, as §6 says — the test names that this is the documented behaviour; type test: constructing from an unminted object fails to compile.

### Task 11: `guard`, `relayOutcome`, `matchKind`, `unreachableKind`

**Files:** `src/guard.ts` (`guard`, `relayOutcome`, `RelayedOutcome` — **Decision D3**: `relayOutcome` lives in `guard.ts`; §5.1 lists no file for it), `src/exhaustive.ts`.

**Tests first:** `guard`: body throws each hostile value → Oops, never rejects; `grant` thunk throws → refusal with the operation and no grant; a grant off the list ignored; the catch reads only the two locals (a body that throws after mutating a provider property still yields the operation given). `relayOutcome`: a target returning a same-copy minted refusal → same object, `thrown: false`; returning a foreign-copy one → rebuilt without diagnostics; returning garbage → `logon-target` fallback with `wire: 'unknown'`, `thrown: false`; throwing → `classify`, `thrown: true`. `matchKind` / `unreachableKind` version-skew cases of §9 verbatim (`future-kind`, `tls` with an unknown `code`, `snc` with an unknown `problem`, through a handler map and through a `switch`). Type tests: `matchKind` with one handler missing; a switch over all but one kind with `unreachableKind(error)`.

**Load-bearing:** pass `matchKind`'s argument through unnormalised → `future-kind` case red (`TypeError`); return the target's object from `relayOutcome` → the foreign-copy case red; move the grant read outside the `try` → the throwing-grant case red.

### Task 12: The shape check (canonical script)

**Files:** `tools/check-provider-shape.mjs` (TypeScript compiler API), `tools/assertion-sites.json` (`numbers.ts`: `httpStatus`, `count`, `port`, `seconds`; `mint.ts`: `mint`), `tools/diagnostic-sites.json` (empty: auth-errors calls no builder with diagnostics), `tools/__fixtures__/` (one file per rule 1–8 breaking it, one obeying all), `lint:check` = Biome then the script with the rules this repository runs.

**Decision D4 (script ownership):** this file is the canonical copy. connection, auth-providers and the broker each copy it verbatim into their `tools/`, with a header line naming the auth-errors commit it was copied from; the rules a repository runs are selected by a `--rules` argument in its `lint:check`. It is not published as a package bin: auth-errors stays dependency-free (§5.1), and the script needs `typescript`.

**Decision D5 (rules per repository):** auth-errors runs rule 4 (five allowed sites, per §4.3 — §8.2's "one allowed site, `mint`" predates the measured makers) and rule 6 (empty list); connection and the broker run rules 4, 5 and 6 (§8.2; §10.3/§10.6 say "4–5", rule 6 with an empty list is strictly stronger and costs nothing); auth-providers runs 1–8.

**Tests first (§11.3):** a Jest test runs the script over each fixture and expects exactly that rule reported; the `500 as HttpStatus` fixture reported in any file and not in `numbers.ts`'s makers (§4.3); a spread of an `IAuthProviderError` (rule 5); a builder call with diagnostics outside the site list (rule 6); a `guard` call whose `grant` is not a function expression (rule 7).

**Rule 3 risk (§12 "not measured"):** implement structural satisfaction first; if it gives a false positive on the obeying fixture or on any real source of the four repositories (run it read-only over their trees), narrow to "an object literal with all four methods" and record the spec amendment for review (§12 permits exactly this).

### Task 13: Exports sweep, generated table, docs

**Files:** `src/index.ts` final; `scripts/generate-kinds-table.mjs` and the README table (§11.4); `README.md` (§10.2 list: what an error is, the sixteen kinds with facts and words, diagnostics and admission, the two exhaustiveness patterns, `classify` / `readFailure` and "never `instanceof`" (RF5), `guard` / `relayOutcome` / pointer to `AuthProviderBase`, the brand and its limit); `CHANGELOG.md` 1.0.0; `CLAUDE.md`.

**Tests first (§11.1 "Exported allowlists cannot be widened"):** every attack listed (push through a cast, index assignment, `defineProperty`, `splice`, `.call` of `Set`/`Map` methods on every export, patching `Set.prototype.has`) then a foreign code is still refused and no word contains it; an `instanceof Set` / `Map` sweep over the module namespace nested one level finds nothing; the README table equals the generated one.

**G2 (user):** merge, tag `v1.0.0`, publish `@mcp-abap-adt/auth-errors` 1.0.0. Verify with `npm view`.

---

## Repository 3 — `mcp-abap-connection` 12.0.0 (one PR)

Publish dependency: interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0, auth-errors 1.0.0 on the registry (G1, G2).

### Task 14: Dependencies, minted constants, `guarded`, targets

**Files:** `package.json` (`interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0`, `auth-errors ^1.0.0`; devDependency auth-providers stays `^5.2.0` until Task 32), `src/connection/authErrors.ts` (I3–I5 as `authError.connection({ problem, at })`; `guarded` through `classifyOutcome(answer, authError.connection({ problem: 'provider-threw', at }))`; `AuthRefusedError` unchanged in shape and `reason — hint` message), `RfcTransport.ts:477-487`, `HttpTransport.ts:514-528` (I1, I2 via `authError['logon-target']`), `AbstractAbapConnection.ts:975`, `:1612`. Where connection acts on a refusal it reads `kind` (§7).

**Tests first:** I1–I5 kind, facts and verbatim words; `guarded` re-mints a forged provider refusal (`{ ok: false, refusal: { reason: '<secret>' } }` from a JavaScript provider → `provider-threw`, the secret in no message) and a provider that throws; a provider returning a refusal minted by the same `auth-errors` passes as the same object; `AuthRefusedError.message` is `reason — hint`. **RF3:** an `AuthRefusedError` built over a `structuredClone`d refusal (after `classifyOutcome`) still reads `reason — hint`.

**Load-bearing:** pass the provider's answer through without `classifyOutcome` → the forged-refusal case red.

### Task 15: Test-only legacy provider adapter

**Files:** `src/__tests__/helpers/legacyProvider.ts` (§10.3: `LegacyRefusal`, `LegacyOutcome`, `LegacyLogonTarget`, `LegacyAuthProvider`, `legacyProvider`), its closed translation table (the exact 5.x words connection's tests produce → the Appendix A builder call), the recorder and an `afterEach` failing on any untranslated reason; every test file building a provider from auth-providers wraps it (`realProviders.test.ts`, `connectorAxes.test.ts`, `connectors/fixtures.ts`, `helpers/onPrem.ts`, … — 13 files; find them by import of `@mcp-abap-adt/auth-providers`).

**Steps:** build the table by running the suites once with a recorder that only logs, then make each recorded 5.x reason a row; no cast anywhere (§10.3); `tsconfig.build.json` keeps `src/__tests__` out of `dist`.

**Tests first:** the adapter's own tests: a 5.x refusal in the table becomes its kind; one outside the table yields `provider-threw` and fails the `afterEach`; the `LegacyLogonTarget` hands the 5.x provider `{ reason, hint }` read from the minted target refusal.

**Load-bearing:** remove one table row → the suite that produces it fails in `afterEach`.

### Task 16: Shape check, docs

**Files:** `tools/check-provider-shape.mjs` (copied, D4) with `--rules 4,5,6` in `lint:check`, `tools/assertion-sites.json` and `tools/diagnostic-sites.json` empty, `tools/__fixtures__/` for rules 4, 5, 6; README / CHANGELOG 12.0.0: migration (a custom `ILogonTarget` builds its refusal through `auth-errors`; `AuthRefusedError.refusal.kind`; the three exported refusal constants are minted errors).

**G3 (user):** merge, tag, publish connection 12.0.0.

---

## Repository 4 — `mcp-abap-adt-auth-providers` 6.0.0 (this PR, #68)

Publish dependency: U1 (5.4.2 published), G1, G2 (G3 is not needed to build auth-providers: connection is no dependency of it).

**Decision D6 (intra-PR order with green gates).** Bumping `interfaces-auth` to `^5.0.0` first would leave every `oops(…)` and every unbranded refusal uncompiled until the last module is converted, so no task in between could pass its gates. Instead:
- Tasks 17–26 keep `interfaces-auth ^4.0.0` / `interfaces-auth-sap ^3.0.0` as direct dependencies and add `auth-errors ^1.0.0`, which brings interfaces-auth 5.0.0 nested. A minted error has `reason: string` and `hint?: string | undefined`, so it is assignable to 4.x `IAuthRefusal`: each converted module compiles against the 4.x contract.
- Names from 5.0.0 (`IAuthProviderError`, `Operation`, `AuthOutcome` of 5.x) are taken from `auth-errors`' signatures in one temporary module, `src/auth/contractTransition.ts` (type aliases derived with `ReturnType` / `Parameters` of `classify`, `guard`, `authError`), never from a second, aliased copy of interfaces-auth (two physical copies would declare two different `minted` symbols).
- Until Task 27, `refusalFrom` keeps a temporary ladder that maps this package's not-yet-converted classes to their builder per Appendix A.1, so a module that still throws an old class refuses with its new kind.
- Task 27 flips the direct dependencies to 5.0.0 / 3.1.0, deletes `contractTransition.ts` and the ladder, and the classes go.

### Task 17: Start from 5.4.2; `auth-errors`

**Steps:**
- [ ] After U1: merge `master` (with 5.4.2's `legacyBasic` and header-echo tests) into `feat/error-contract`; resolve; gates green.
- [ ] `npm install @mcp-abap-adt/auth-errors@^1.0.0`; lockfile check (no `"link": true`, everything from the registry; interfaces-auth present twice, 4.x direct and 5.0.0 nested, is expected until Task 27).
- [ ] `src/auth/contractTransition.ts` per D6, with a header saying it is deleted in Task 27.

**Tests first:** a type test that a value returned by `authError['client-certificate']` is assignable to 4.x `AuthOutcome['refusal']`.

### Task 18: Refusal core

**Files:** `src/auth/refusal.ts` (`OK` from auth-errors; `oops` removed; `refusalFrom` = temporary ladder (D6) then `classify`; `loggedError` → `logFields`; `KNOWN_*` sets removed in favour of auth-errors guards; `refusalWords` kept until Task 27 and implemented as `classify(…)`'s words — **Decision D7**: it is deleted in Task 27 with the classes, so a consumer's `refusalWords` call still compiles on the commits between), `src/auth/knownCodes.ts` (code lists → interfaces-auth arrays and auth-errors guards; `readSafely`, `tlsFailureCode` reading through the guards), `src/auth/rejection.ts` (`readRejection`, `refuseFor`, `unknownRefusal` answer `credential-refused` / `system-refused` with `verdict`, `status`, `rfcKey`, `at`), `src/auth/certificateMaterial.ts` (B14).

**Tests first:** B1–B6, B14 rows (one test per row named by the row id) — kind, facts, verbatim words; `rejectedReadsTheRejection.test.ts` on kinds and `blamesCredential` (§11.1); each A1, A13–A16 row through the ladder/classify.

**Load-bearing:** make `readRejection` answer `credential-refused` for `403` → B1 and the rule-5 case red.

### Task 19: `AuthProviderBase` and `relayOutcome` in every provider

**Files:** `src/auth/AuthProviderBase.ts` (§8.1: `#moments` validated once against `isOperation` with `FALLBACK`, `grant()` read inside `guard`, the four methods final by convention, `on…` abstract), the five credentials, `SncLogonProvider` (moments and its outer words, G10), `BaseTokenProvider` (`grant()` over `getAuthType()`); `safely`, SNC's `bounded`, the unguarded `oops` in `CertificateAuthProvider.establish`, and `atTarget` removed; `relayOutcome` in `CertificateAuthProvider.establish`, `SncLogonProvider.establish` (no other way in), `BasicAuthProvider.establish` (another way in: `thrown` → outcome, else `OK`), `BaseTokenProvider.establish` and `authorize`'s write (§7's decision table unchanged); B7–B13, B15 via builders; `not-prepared` B8, G9. Export `AuthProviderBase` from `src/index.ts`.

**Tests first:** §8.1's fixtures (throwing `grant()`; throwing `getAuthType()`; a throwing `moments` getter on a subclass; a `moments` object whose `establish` getter throws; `prepare: 'not-an-operation'`) — every method answers a minted Oops with the fallback operation and never rejects; §7's matrix: the same minted refusal returned vs thrown by the target for Certificate, SNC, Basic and `BaseTokenProvider` with an unbound, a bound and an unknown token (returned + unbound → `OK`, thrown + unbound → Oops); garbage returned vs thrown (`logon-target` fallback vs `unknown`); B7–B13, B15 rows; `src/__tests__/contract/rule1.test.ts` created with the credentials' collaborators (completed in Task 29).

**Load-bearing:** move `this.grant()` out of the thunk → first fixture red; collapse `relayOutcome`'s pair to the outcome → returned+unbound red.

### Task 20: The token-request conversion point

**Files:** `src/auth/tokenRequest.ts` — `TokenRequestSite` (§6: `operation`, `grant?`, `logger?`, `secrets`, `basic?`), `sendTokenRequest(prepared, asToday, site)` converting every failure into an `AuthProviderFailure` (`tls` for an allowlisted TLS code, else `request-failed` with `httpStatus(response.status)`, registered `oauthError`, allowlisted `code`, `problem` `refused` / `no-response`), the private secret-join function, the one `debug` line before conversion (reduced by `oauthErrorFields`, a throwing logger swallowed, no line without a logger), `rejectMissingToken(site, prepared, response, problem)` through the same join, `legacyBasic` from 5.4.2 kept and typed as `LegacyBasic`; the reduced `AxiosError` and `tokenEndpointError` removed.

**Tests first (on the helper, sites come in Task 21):** a `400` with a body echoing every secret of `site.secrets`, `site.basic.secrets` and `prepared.secrets` in every echoed form and as a JWT → one debug line with the redacted summary, no secret in it or in any rendering of the failure (`JSON.stringify`, `message`, `reason`, `hint`, `logFields`); no logger → no line, same failure; throwing `debug` → same failure; a TLS code → `tls` with no line; `rejectMissingToken` the same three cases for a `200`. **RF2:** status `0`, `999` and a response without `status` → `request-failed`, `problem: 'no-response'`, no `status` key, the debug line still written, no throw from the conversion.

**Load-bearing:** drop `prepared.secrets` from the join → the strategy-secret case red; pass `secrets` without `basic` → the Basic case red, in both `sendTokenRequest` and `rejectMissingToken`.

### Task 21: Every token site and device polling

**Files:** every token site of §6's tables and Appendix A.4 — `passcodeAuth.ts`, `clientCredentialsAuth.ts`, `tokenRefresher.ts`, `oidcToken.ts` (OIDC token request, device initiation, device poll, password grant), `browserAuth.ts` (code exchange; its 2xx line moves from `error` to `debug`), `saml2TokenExchange.ts` (exchange, refresh; H6 via `logFields(readFailure(…))`), `oidcDiscovery.ts` (D6); each passes its `TokenRequestSite` with its operation from A.8; every 2xx-without-token branch calls `rejectMissingToken` (D4, D5); every legacy `Basic` header built only by `legacyBasic`.

**Device polling (§6 table, first row):** `readFailure(error, 'device-poll')`; `request-failed` with `status === 400` and `oauthError` `authorization_pending` / `slow_down` keep polling (`slow_down` +5 s); anything else rethrows the failure; pending/slow_down answers write no debug line.

**Tests first:** D1–D6 rows; §6's device-polling cases on the axios mock — pending → success; `slow_down` → success with the interval +5 s (fake timers); `access_denied` and `expired_token` end with `request-failed` carrying that `oauthError`; `400` without a body ends at once with `status: 400`, no `oauthError` — each through the strategy path and without one; the same four on the stand's Keycloak device endpoint where it applies; `oauthErrorBodies.test.ts` / `tokenRequestShapes.test.ts`: for each site, without and with each strategy (Basic raw and form, `clientSecretPost`, `privateKeyJwt`), the `400` echo case; the **header-echo tests** of §6 for each of the eight legacy-Basic sites (whole header, base64 alone, URL- and form-encoded, decoded `id:secret`; a client id with `:` and a secret with `+`, `%`, `/`), and the same echoes in a `200` without `access_token` (and the device initiation's `200` without its fields) for every site with such a branch, on both paths; the source test for shape rule 8 (no `Basic ` header and no base64 of a secret outside `legacyBasic` and `clientSecretBasic`) — written here as a Jest source scan, enforced again by the script in Task 28; `tokenRequestRedirect.test.ts` still green (no site follows a 307).

**Load-bearing:** read `oauthError` from anything but the classified facts, or drop it in `sendTokenRequest` → pending → success red; remove one site's `secrets` → that site's echo case red.

### Task 22: Token-provider failures

**Files:** `BaseTokenProvider.ts` — `getTokens()` / `refreshTokens()` bodies in a `try` whose `catch` rethrows `new AuthProviderFailure(classify(error, 'token-request', grant))` (§6 "Where the throw is built"); the refresh-then-login fallback reads `error.kind` (behaviour unchanged: any refresh failure falls back); `remembered` holds the `IAuthProviderError` the renewal produced and answers it as is (the `structuredClone` at `:741` goes); H1, H2 via `logFields`; D7; D8's nine "no refresh grant" sites throw `credential-refused` `refresh-token` failures; A17, A18 via `token-binding`.

**Tests first:** a consumer's strategy, loader and presenter throwing their own error with a marker → `getTokens()` rejects with an `AuthProviderFailure`, never the original, marker nowhere (L3); A10, A17, A18, D7, D8, H1, H2 rows; the rule-8 `remembered` cases of auth-providers' CLAUDE.md re-run on kinds (refused token remembered with its refusal, not renewed again until token change / `prepare()` / `rejected()`; a renewal throwing while such a token is held remembered with its own refusal, e.g. `client-certificate` `expired`); `resultShapes.test.ts` unchanged.

**Load-bearing:** rethrow the original in `getTokens()` → the L3 case red; restore `structuredClone` of the remembered refusal → its identity assertion red.

### Task 23: Interactive login

**Files:** `src/auth/callbackServer.ts` (K4, K6, K7, K8, K9), `src/strategies/BrowserCallbackStrategy.ts` (K1–K5, K11; `browserLoginWords` → `interactive-login` `failed`), `src/strategies/manualStrategies.ts` (K12–K16), `src/strategies/codeStrategies.ts` (K14, E27), `src/deviceCode/DeviceCodePresenter.ts` (K17; `DeviceCodePresentationError` removed), `browserAuth.ts` / `oidcBrowserAuth.ts` / `saml2Auth.ts` launch lines (H7, H8 unchanged in content, words from `logFields`), `OidcDeviceFlowProvider.ts` (H3); `callbackScopeError.ts`'s classes replaced by `AuthProviderFailure`s; the IdP's `?error=` (K10, A8) names only a registered code; `error_description` / `error_uri` reach only the escaped error page.

**Tests first:** K1–K17, A2, A8, A9 rows; `callbackPages.test.ts` unchanged; port-in-use still contains "already in use" (K1 verbatim); **RF1:** `timeoutMs` 1500, 500, 2147483647 through a real `runCallbackScope` (fake timers) → `timeout` facts and words per D9; "Assert on the port": every abort/timeout/close case binds the port afterwards.

**Load-bearing:** drop `ignoredCallbacks` from the facts → the tally case red.

### Task 24: SAML

**Files:** `src/validation/assertionValidator.ts`, `signedNode.ts`, `documentIds.ts`, `xsdDateTime.ts`, `src/auth/samlBearerAssertion.ts`, `src/auth/strictXml.ts` — every refusal of Appendix B by its `rule` id with `check` fixed and the one diagnostic of the "Diagnostic" column passed **only** at the approved site (§3.3 table, recorded in `tools/diagnostic-sites.json` in Task 28); F1–F8; `quoteUntrusted` removed from refusals (admission replaces it); xml-crypto's and the parser's messages dropped (L7); a custom `IAssertionValidator`'s throw classified with `validating-assertion`; `bearerConfirmation` candidates as `BearerCandidate` facts capped at 5 with `moreCandidates`; `declined` with a registered `statusCode` fact, else the `statusCode` diagnostic.

**Not measured (§12):** `SAML_STATUS_CODES` against the identity providers in use — run the stand's Keycloak and UAA declined logins once and record which status values arrive as facts and which as the diagnostic; a value outside the list is a minor addition to interfaces-auth, raised, not patched here.

**Tests first:** one test per rule of Appendix B (56) asserting `rule`, `check`, the rule's own words fragment (no two rules under one check share words — the existing convention) and its diagnostic or its absence; `samlValidation.test.ts` end to end through `Saml2PureProvider` asserting `rule` per variant; the wrapping-attack tests through `validate()` still refuse with the right rule; F1–F8 rows; an attacker Issuer with `&#10;` → issuer diagnostic dropped, error minted; an 80-character Issuer → diagnostic cut at 64 code points with `…`.

**Load-bearing:** pass the `issuer` diagnostic from the `destination-not-us` site → type error (record) and, through a JavaScript-typed call, the admission table drops it (test red if the table is removed).

### Task 25: SNC

**Files:** `src/snc/sncRefusal.ts` (G1–G6 via `authError.snc`), `DefaultSncLibraryLocator.ts` (`SncLibraryNotFoundError` replaced by an `AuthProviderFailure` of `snc` `library-not-found` with `candidates` facts and `candidatePaths` diagnostics aligned index for index, `null` for a dropped path — built in the locator, the approved site; G7), `SncLogonProvider.ts` (G8, G9, G10, H4, H5, E20, E21 with `allowed: 'snc-qop'`; the `library` diagnostic from the trimmed path at `prepare()`), `SncSystem.ts` (the registry value trimmed before it becomes a candidate path — RF4).

**Tests first:** G1–G10, H4, H5 rows; the hint of G1 for a non-SLC product (`the SNC library`, path in diagnostics, L9); `renderDiagnostics` shows each candidate's source, path and reason; `docs/passwordless-sso.md:235-237`'s quoted reason unchanged. **RF4:** the four real-world paths through the fake `SncSystem` and the shipped locator, each admitted and rendered; a registry value ending in `\r\n` and trailing spaces reaches `candidatePaths` trimmed, not `null`.

**Load-bearing:** remove the trim → the RF4 registry case red (`null`).

### Task 26: Configuration throws

**Files:** every A.5 site (E1–E28) and K6, K7 — providers, `saml2Utils.ts`, `saml2TokenExchange.ts`, `FileCertificateMaterialLoader.ts`, `clientSecret.ts` (E19, `allowed: 'basic-encoding'`), `SncLogonProvider.ts` (E20, E21 if not done in Task 25), `SsoProviderFactory.ts`, `assertionValidator.ts` (E24, E25), `signedNode.ts` (E26), `codeStrategies.ts` (E27), `callbackServer.ts` (K6, K7); E8 and E12 pass `configuredUri` / `strategyUri` diagnostics (approved sites); each throws an `AuthProviderFailure` of `configuration` with its `case` and `fields`; words from the "Words for review" appendix.

**Steps:** first a sweep of `src` for every remaining `throw` (`throw new`, `throw tokenEndpointError`, rethrows) outside tests; every hit is mapped to an Appendix A row or is a rethrow of an `AuthProviderFailure`; a hit with no row stops the task and is raised for a spec amendment.

**Tests first:** one test per row E1–E28, K6, K7: `case`, `fields`, words, `allowed` where set, the URIs as diagnostics for E8/E12 and absent from `reason`/`hint`; the sweep as a source test (no `throw new Error(` / `throw new ValidationError(` left in `src`).

### Task 27: Flip and delete

**Steps:**
- [ ] `interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0` as direct dependencies; one deduplicated interfaces-auth in the lockfile; lockfile check.
- [ ] Delete `src/auth/contractTransition.ts` (imports move to interfaces-auth / auth-errors), the ladder in `refusalFrom` and `refusalFrom` itself, `refusalWords`, `src/errors/` (all five files), `src/auth/callbackScopeError.ts`, `src/auth/contractShape.ts` (`asContract`, goal step 8) and every call of it; `src/index.ts` drops the error classes and `refusalWords`; `AuthProviderBase` stays exported (Task 19); `TokenRequestSite`, `legacyBasic` and `rejectMissingToken` are internal and not exported.
- [ ] No reference to `TOKEN_PROVIDER_ERROR_CODES` / `ASSERTION_ERROR_CODES` remains.

**Tests first:** a type test that `src/index.ts` exports none of the deleted names (`@ts-expect-error` imports); `resultShapes.test.ts` passes without `asContract` (the contract's `?: T | undefined` in 5.0.0 carries the keys).

**Gate:** standard; `npm ls @mcp-abap-adt/interfaces-auth` shows one copy.

### Task 28: Shape check in auth-providers

**Files:** `tools/check-provider-shape.mjs` (copied, D4) with `--rules 1,2,3,4,5,6,7,8`, `tools/assertion-sites.json` empty, `tools/diagnostic-sites.json` listing file and function per diagnostic field of §3.3 (SNC `library` in `SncLogonProvider.prepare`, `candidatePaths` in the locator, each SAML field at its validator site, `configuredUri` / `strategyUri` at E8/E12's sites), fixtures for rules 1, 2, 3, 7, 8 specific to this repository; `lint:check` = Biome then the script.

**Tests first:** each fixture reported by its rule; the real `src` passes; a subclass of `AuthProviderBase` declaring `establish` is reported (rule 2).

**Load-bearing:** add a diagnostics argument at a non-approved site in a scratch commit → `lint:check` red.

### Task 29: Matrix audit and the cross-cutting suites

**Steps:**
- [ ] Audit: every Appendix A row (A1–A19, B1–B15, K1–K17, D1–D8, E1–E28, F1–F8, G1–G10, H1–H10; I and J rows belong to connection and the broker) has a test named by its row id, or is marked "removed" (A12, A19, H9) with the reason; a script lists rows from the spec and test names from `src/__tests__` and fails on a gap.
- [ ] `src/__tests__/contract/rule1.test.ts` completed (§8.3): every method of every provider, every collaborator (strategy, client authentication and its `tlsMaterial`, certificate loader, device-code presenter, assertion validator and replay store, `onTokens`, browser launcher, SNC locator and probes, logger, logon and request targets, `ITokenRefresher`) throwing each hostile value of §11.1; each call resolves, refusal minted (`isMinted`), no marker in the outcome's JSON, `reason`, `hint`, `renderDiagnostics`.
- [ ] `noTokensInLogs.test.ts` and `thrownMessages.test.ts` rewritten on `logFields` and `AuthProviderFailure`.
- [ ] Every load-bearing break of Tasks 17–28 re-run once on the final tree; the list with results goes into the PR description.

### Task 30: Documentation

**Files:** README — "What `rejected()` answers", "Refusals", "Refusal messages", "Errors", "Error Handling", "Relaying a refusal" rewritten on kinds (§10.4); the refusal tables generated by a script from `WORDS` and the allowlists (§11.4) with a test comparing the committed README; "Migrating to 6.0.0" (catch with `readFailure` / `isAuthProviderFailure`, never `instanceof` (RF5); switch on `kind` with one of the two exhaustiveness patterns; `refusalWords` → `classify`; the classes removed; a refusal is frozen — copying or mutating it (RF3); Appendix C's losses L1–L13 stated); CLAUDE.md — rules 1, 2, 5, 8, "Error classes", module structure, `asContract` paragraph removed; CHANGELOG 6.0.0 incl. **Fixed** (the legacy Basic credential, as shipped in 5.4.2), **Breaking**, the dependency majors; `docs/passwordless-sso.md` and `docs/btp-setup.md` checked (§10.4).

**Gate:** standard; the generated-table test green.

### Task 31: Release preparation

**Steps:**
- [ ] `npm run test:stand` green; standard gates; version 6.0.0.
- [ ] PR #68 description: what the deleted documents still owe — Tasks 32–35 of this plan with their order and gates, the D-decisions, the load-bearing record (Task 29), the L1 decision (debug line kept) and the 5.4.2 record (§11.5 gate 6).
- [ ] Delete `docs/superpowers/` documents of this work (goal, spec, plan) — CLAUDE.md "Plans and specs"; gate 5.

**G4 (user):** merge #68, tag, publish auth-providers 6.0.0. Before saying "publish": the main checkout on the tag, built (memory "verify a release where it is published").

---

## After auth-providers 6.0.0 (carried in PR #68's description once this file is deleted)

### Task 32: connection gate 7

Repository connection, new PR. Publish dependency: auth-providers 6.0.0 (G4).

**Steps:** devDependency `@mcp-abap-adt/auth-providers ^6.0.0`; delete `legacyProvider.ts`, its table and the `afterEach`; unwrap every test file; run every suite against the real 6.0.0 providers. Green → gate 7 met, PR merged without a release (test-only change) — **Decision D8**: a test-only change is released only if the user wants it; any difference (a word, a kind, a disposition) is fixed in this same PR as connection 12.0.1 (G5, user) before Tasks 33–34 start.

### Task 33: auth-stores 4.0.0

Repository auth-stores, one PR. Publish dependency: interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0 (interfaces-auth-broker 1.3.0 already published).

**Steps:** dependencies `interfaces-auth ^5.0.0`, `interfaces-auth-sap ^3.1.0`, `interfaces-auth-broker ^1.3.0`; delete its `asContract`; released with its unreleased strict-compiler change (already breaking: engines) as 4.0.0; CHANGELOG / README migration "none beyond the versions" (§10.5). Standard gates; lockfile check.

**G5 (user):** merge, tag, publish auth-stores 4.0.0.

### Task 34: auth-broker 5.0.0 and auth-broker-cli 3.0.0

Repository auth-broker (workspace), one PR. Publish dependency: interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0, auth-errors 1.0.0, auth-providers 6.0.0, auth-stores 4.0.0 (G1, G2, G4, G5) and gate 7 met (Task 32).

**Files:** both `package.json`s (§10.6; the CLI also takes `auth-errors ^1.0.0` for `renderDiagnostics`); `clientAuthentication.ts` (J1: copied phrases at `:77-80` and `:220-226` deleted; `resolveClientAuthentication` catches with `readFailure(error, 'client-authentication-strategy')`; `DestinationConfigError` gains `readonly error?: IAuthProviderError`; reason `the clientAuthentication strategy refused: ${error.reason}` for `client-certificate`, else `the clientAuthentication strategy failed` — rendered, not copied; J2, J3, J4 stay); `destinations.ts:247-255` (J5 on `kind === 'configuration'` and `facts.fields`); `getTokens` / `refreshTokens` relay the provider's failure unchanged; `AuthBroker.ts:660`, `SessionWriter.ts:40-46` log `AuthProviderFailure`; CLI `generateEnv.ts:262-264`, `mcp-auth.ts:587-591` (J6: `reason — hint`, then `renderDiagnostics` on its own line); `tools/check-provider-shape.mjs` copied with `--rules 4,5,6`; READMEs, CHANGELOGs, migration notes of both packages.

**Tests first:** `DestinationConfigError.error` deep-equal to the provider's error for each certificate problem, message containing `render(…)`'s words; a source test: no certificate phrase left in `src` (§11.1); J5 with an SNC configuration failure; the CLI's output for a failure with and without diagnostics. **RF5:** a failure thrown by a second copy of `auth-errors` loaded from another path is relayed: `isAuthProviderFailure` true, `readFailure` same kind and facts, the CLI prints `reason — hint`.

**Load-bearing:** re-add one copied phrase → the source test red; relay through `instanceof` instead of `readFailure` → the RF5 case red.

**Release:** the CLI's workspace link to auth-broker is gone from what is released (both ranges semver; auth-broker published first, then the CLI) — global CLAUDE.md standing exception.

**G6 (user):** merge, tag, publish auth-broker 5.0.0, then auth-broker-cli 3.0.0.

### Task 35: Final cross-repository checks (spec §11.5)

**Steps (each recorded with its output):**
- [ ] Gate 1: every Appendix A row implemented as mapped (Task 29's audit, connection's I rows, the broker's J rows); L1–L13 approved (spec Appendix C header).
- [ ] Gate 2: each repository's standard gates on its released tag; `test:stand` for auth-providers.
- [ ] Gate 3: READMEs, guides, CLAUDE.md, migration notes, generated tables current in all six packages.
- [ ] Gate 4: in an empty directory outside every repository, `npm install` of interfaces-auth 5.0.0, interfaces-auth-sap 3.1.0, auth-errors 1.0.0, connection 12.0.x, auth-providers 6.0.0, auth-stores 4.0.0, auth-broker 5.0.0, auth-broker-cli 3.0.0 from the registry; lockfile: no `"link": true`, every resolution from the registry. **RF5:** `npm ls @mcp-abap-adt/auth-errors` and `npm ls @mcp-abap-adt/interfaces-auth` show one deduplicated copy each; a smoke script there builds a provider, runs `prepare()` / a refused `rejected()` and prints `reason`, `kind`.
- [ ] Gate 5: `docs/superpowers/` holds none of this work's documents on auth-providers' master.
- [ ] Gate 6: debug-line and header-echo tests green for every token site on both paths; the CHANGELOG **Fixed** entry; L1 and 5.4.2 decisions recorded in #68.
- [ ] Gate 7: Task 32 green before Tasks 33–34 moved.
- [ ] §12 "not measured", last item: search the chain's consumers known to the user (the server `mcp-abap-adt`, the proxy, calm) for matches on today's refusal words; record each hit for the server's own task.

**After:** the server `mcp-abap-adt` reads `kind` where it acts on a refusal — its own task (goal "After"), out of this plan.

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
| `callback-timeout-invalid` | `invalid callback server timeoutMs: it must be finite and within 1..2147483647` | |

**Interactive-login outcomes not fixed verbatim:** `aborted` — `the browser login was aborted` (spec K4); `disposed` — see D10; `browser-launch-failed` — `the browser could not be opened[ (<code>)]` / `open the authorization URL from the log by hand`; `callback-closed` — `the callback server closed before a result arrived`; `no-input` — `no input was received` (spec K14); `timeout` — see D9.

**Operation phrases** (in `<phrase> failed (…)`; today's `what` where one exists, so A1/A13–A16/B15 stay verbatim): `token-request` `<grant> token request`; `refresh` `the refresh`; `on-tokens-hook` `onTokens`; `presenting-token` `presenting the token`; `presenting-certificate` `presenting the certificate`; `loading-certificate` `loading the certificate`; `writing-authorization-header` `writing the Authorization header`; `offering-logon-parameters` `offering the logon parameters`; `writing-session-cookies` `writing the session cookies`; `reading-rejection` `reading the rejection`; `token-source` `the token source`; the four SNC moments render `the SNC provider failed while <resolving the SNC library | handing over the SNC logon parameters | authorizing a request | explaining the SNC refusal> (unknown error)` (G10 verbatim); `probing-snc-product` `the probe`; `presenting-device-code` `the presenter`; `saml-token-exchange` `the SAML token exchange`; `saml-token-refresh` `the SAML token refresh`; `browser-login` `the browser login`; `opening-browser` `opening the browser`; `passcode-exchange` `the passcode exchange`; `device-authorization` `the OIDC device authorization`; `password-grant` `the OIDC password grant`; `client-credentials` `the client credentials request`; `token-refresh` `the token refresh`; `oidc-discovery` `OIDC discovery`; `code-exchange` `the code exchange`; `device-poll` `the device poll`; `oidc-token-request` `the OIDC token request`; `validating-assertion` `validating the SAML assertion`; `client-authentication-strategy` `the clientAuthentication strategy`; `preparing` `preparing`; `establishing` `establishing the logon`; `authorizing` `authorizing the request`; `unfamiliar-error` renders its own sentence, `an authentication error of a kind this version does not know` (§9). `request-failed` `no-access-token`: `<phrase> returned no access_token`; `incomplete-response`: `<phrase> returned an incomplete response`.

---

## Decisions this plan takes (for review with the plan)

- **D1** — The rule → check correlation is a type in interfaces-auth; auth-errors' runtime `ASSERTION_RULE_CHECK` `satisfies` it (Task 1).
- **D2** — `isAuthProviderFailure` is structural across copies (`name` + an `error` passing the structural rebuild), never reading `message` (Task 10).
- **D3** — `relayOutcome` lives in `guard.ts` (Task 11).
- **D4** — The shape-check script is authored in auth-errors and copied verbatim into the other repositories with its source commit; not published (Task 12).
- **D5** — Rules per repository: auth-errors 4 (five sites) + 6 (empty); connection and broker 4, 5, 6; auth-providers 1–8 (Task 12).
- **D6** — Intra-PR order in auth-providers: stay on interfaces-auth 4.x direct with auth-errors (5.0.0 nested), derive 5.x names from auth-errors' signatures, a temporary class ladder, flip in Task 27 — so every task's gates are green.
- **D7** — `refusalWords` survives until Task 27 (implemented on `classify`), then is deleted with the classes.
- **D8** — connection's gate-7 PR releases only if it changes shipped code (a 12.0.x patch); a test-only change is merged without a release unless the user asks.
- **D9** — *Open, needs the user:* `timeoutSeconds` for a non-whole-second `timeoutMs`. Proposal: round up to whole seconds, at least 1 (`1500` → "after 2 seconds", `500` → "after 1 seconds" kept verbatim as today's grammar), so K9 stays verbatim for whole seconds and loses the fraction otherwise — a new minor loss to approve. Alternative: `Seconds` is read as milliseconds (its range, 0–86 400 000, is one day in milliseconds) and renamed `timeoutMs`, keeping K9 verbatim for every value — a spec amendment.
- **D10** — *Open, needs the user:* `interactive-login` `disposed` has two verbatim sources (K2 `the browser login strategy has been disposed`, K15 `the manual strategy was disposed`), but words are a function of kind and facts. Proposal: one sentence, `the login strategy has been disposed`, both losing verbatim (a minor loss like K4/K14). Alternative: split the outcome into `strategy-disposed` / `input-disposed` (a spec amendment adding a member to `INTERACTIVE_OUTCOMES`).
- **D11** — *Open, needs the user:* timeout words. A9 says the reason names the outcome as "`the interactive login timed out after <n> s`"; K9 says the thrown message is kept verbatim. Proposal: K9's sentence (the one users have seen), with A9's hint `complete the login within the strategy's time`.
