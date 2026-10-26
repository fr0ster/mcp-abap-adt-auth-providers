# Static types first — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `@mcp-abap-adt/auth-providers` 8.0.0 checks at runtime only what
the compiler cannot see. Checks the contract types already prove are
removed, and every throw stays handled.

**Architecture:** The change proceeds one mechanism at a time:
- promise adoption;
- options;
- collaborator calls and the reads of their answers;
- the renewal decision;
- configuration refusals;
- `void` answers;
- the package's own invariants.

Each task first tightens a type or deletes a helper, then lets the
compiler (`npm run test:check`) list what breaks, then fixes those sites.
Each removed check is removed together with its test, and every new test is
proved load-bearing.

**Tech Stack:**
- TypeScript (strict, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`);
- Jest through `npm test` (`--experimental-vm-modules`);
- Biome;
- auth-errors 3 and interfaces-auth 8.

**Spec:** `docs/superpowers/specs/2026-10-26-static-types-first-design.md`.
**Goal doc:** `docs/superpowers/2026-10-26-static-types-first-goal.md`.

Paths are relative to `packages/auth-providers/`. The inventory with
file:line for every site is in the spec's sources; each task names its
sites by function and file. The implementer finds the exact lines with the
compiler and `grep`, never from line numbers in this plan.

## Global Constraints

- The runtime-check boundary is spec §1. Thrown values, network answers,
  JWT, SAML/XML, files, env, registry output, terminal input, callback
  requests, GSS bytes and contract fields typed `unknown` stay checked.
  Value rules stay.
- **A throw is not a type question.** A collaborator's call and every read
  of its answer share one failure boundary (spec §3). A throw while reading
  takes the same classification, settling and release as a throw from the
  call.
- Adoption is always `new Promise((resolve) => resolve(x))`, never
  `Promise.resolve(x)` (spec §6).
- There is no new refusal, kind, case or operation. Every refusal the
  package still produces keeps its words, facts and kind.
- Rule 1 (every moment inside `guard`), rules 2–8 and `relayOutcome` on
  logon-target answers are unchanged.
- No regex over input. No timer. No `exec`. No `npx`. npm scripts only.
  Lockfiles change only through npm.
- A removed check is removed with its test. A test that turns red when its
  check is removed and protects behaviour still promised is rewritten, not
  deleted.
- Every new test is load-bearing: it fails on the code before the task, or,
  for a guard test, the implementer breaks the guard, watches the test go
  red, and restores the guard.
- Artifacts are in English. Commits end with the repository's attribution
  lines.
- CLAUDE.md changes only with text the owner approved (Task 8).

## Review Focus

1. **A typed answer whose getter throws on an asynchronous callback path.**
   The login must end through its failure path, with the port, reader or
   scope released, not hang (Task 3).
2. **A detached answer that rejects, or whose `then` getter throws.** This
   covers the persistence report, `IBrowser.open()` and `present()`. It must
   raise no `unhandledRejection` (Task 1).
3. **Options changed after creation.** The provider must not see the change
   (Task 2).
4. **A renewal decision whose fields throw on read.** The answer must still
   be `unknown` `renewal-strategy`, with no step taken (Task 4).
5. **A logger that throws on a failure path.** It must not replace the
   site's own failure (Task 6).

---

### Task 1: Adoption without `isPlainPromise`, and the detached-answer handler

**Files:**
- Modify: `src/auth/attempt.ts` (`untilAborted`; a new `whenRejected`)
- Modify: `src/providers/BaseTokenProvider.ts` (the detached persistence report)
- Modify: `src/authorization/compose.ts` (`present()`)
- Modify: `src/authorization/presentation/openInBrowser.ts` (`IBrowser.open()`)
- Test: `src/__tests__/auth/untilAborted.test.ts`, `src/__tests__/auth/handled.test.ts`, and the owning tests of the three detached paths

**Interfaces:**
- Produces: `whenRejected(answer: unknown, handler: (error: unknown) => void): void`
  in `src/auth/attempt.ts`. It adopts `answer` through
  `new Promise((resolve) => resolve(answer))` and attaches `handler`. A
  throw from the handler is contained, and nothing raises
  `unhandledRejection`. It replaces `onAnswerRejection` at the three
  detached paths.
- Produces: `untilAborted<T>(work: T | PromiseLike<T>, signal)`. Its
  signature is unchanged, and it adopts through a fresh native promise for
  every value.

- [ ] **Step 1:** Move the `onAnswerRejection` cases of
  `auth/handled.test.ts` to the three detached paths. These are the
  rejecting answer, the `then` getter that throws, the Proxy whose trap
  throws, and the handler that throws. For each path, assert through the
  path's public behaviour, using the existing unhandled-rejection recorder
  in `helpers/plainNode.ts` or the file's own recorder:
  - persistence report detached: the fixed log line once;
  - `open`: the URL prompted once;
  - `present`: the fixed failure line.

  In every case, assert that no `unhandledRejection` is raised. Keep the
  existing `untilAborted` tests for adoption through an own `then`.
- [ ] **Step 2:** Run the moved tests against the current code. Expected:
  PASS, since the behaviour is unchanged. Then temporarily replace each
  path's handler with nothing and confirm the test goes red. Restore the
  handler.
- [ ] **Step 3:** Implement `whenRejected`. Switch the three paths to it.
  Make `untilAborted` adopt every value through a fresh native promise, and
  drop its `isPlainPromise` import.
- [ ] **Step 4:** Delete the `isPlainPromise` cases of
  `auth/untilAborted.test.ts`. Keep the case "a native promise with its own
  `then` is adopted through that `then`".
- [ ] **Step 5:** Run `npm run test:check`, then
  `npm test -- src/__tests__/auth src/__tests__/authorization src/__tests__/persistence src/__tests__/providers/persistenceReports.test.ts src/__tests__/providers/renewalStrategy.test.ts`.
  Expected: both clean.
- [ ] **Step 6:** Commit: `refactor: adopt every answer through a fresh native promise; whenRejected for detached answers`.

### Task 2: Options are a typed copy

**Files:**
- Modify: `src/auth/configuration.ts` (delete `ownOptions`)
- Modify: every caller. The compiler lists them once `ownOptions` is gone.
  Today they are the 29 files under `src/` that import it, plus
  `SncLogonProvider`'s `ownData` and `saml2Utils`' `samlTrustOf`.
- Test: `src/__tests__/errors/hostileOptions.test.ts`, and the owning test files its kept cases move to

**Interfaces:**
- Consumes: nothing new.
- Produces: every exported constructor and factory starts with
  `const own = { ...options }`, typed by its options type. The casts
  `own.x as T` go.

- [ ] **Step 1:** Write the failing test `options getter runs once, at
  creation` in `errors/optionsCopy.test.ts`. It builds `ClientCredentialsProvider`,
  `composeAuthorization`, `privateKeyJwt` and `SpnegoAuthProvider` with an
  options object whose `clientId` (or an equivalent field) is a counting
  getter. It asserts the count is exactly 1 after construction and still 1
  after a moment runs.
- [ ] **Step 2:** Run it. Expected: FAIL, because `ownOptions` never runs a
  getter, so the count is 0.
- [ ] **Step 3:** Classify `hostileOptions.test.ts`:
  - **Moves to the owning file:** cases whose subject is a value rule, and
    cases where a collaborator throws once called or read inside a moment.
  - **Deleted with `ownOptions`:** cases of a hostile options object at
    construction (Proxy, getter, revoked Proxy, primitive).

  Move the kept cases before touching `src`.
- [ ] **Step 4:** Delete `ownOptions`. Run `npm run test:check`. At each
  site the compiler lists, replace the call with the typed spread, and drop
  the casts that followed it. Read the package's own internal objects
  (`AnswerTransportOptions`, `openOptions`, the SAML trust) as typed, with
  no copy. In `SncLogonProvider`, drop `ownData`'s accessor defense and
  keep its value checks.
- [ ] **Step 5:** Delete the construction-time hostile cases of
  `hostileOptions.test.ts`. Delete the file if nothing is left.
- [ ] **Step 6:** Run `npm run test:check` and `npm test`. Expected: clean.
  The snapshot test (a later change to options changes nothing) and the
  new getter test pass.
- [ ] **Step 7:** Commit: `refactor!: options are a typed copy; ownOptions removed`.

### Task 3: Collaborators called as typed, one failure boundary

**Files:**
- Modify:
  - `src/authorization/compose.ts`;
  - `src/authorization/transport/httpListener.ts` (`judged`, `readOptions`, `methodsOf`, `pasteWordsOf`);
  - `src/authorization/transport/terminalPaste.ts`;
  - `src/authorization/transport/consumerAnswer.ts`;
  - `src/authorization/presentation/prompt.ts`;
  - `src/authorization/presentation/openInBrowser.ts`;
  - `src/strategies/callbackStrategies.ts`, `manualStrategies.ts`, `codeStrategies.ts`, `asOidcResult.ts`;
  - `src/auth/browserLaunch.ts` (`usableSignal`);
  - `src/spnego/SpnegoAuthProvider.ts` (`ask`, `read`);
  - `src/snc/SncLogonProvider.ts` and `src/snc/sncRefusal.ts` (the locator answer);
  - `src/auth/tokenRequest.ts` (the client-authentication result, `rejectMissingToken`'s snapshot);
  - `src/auth/oidcDiscovery.ts` (`mtlsAlias`);
  - `src/auth/rejection.ts` (`at` / `status`);
  - `src/providers/BaseTokenProvider.ts` (`tlsMaterial()` answer, `aborted`, `report` call).
- Delete: `src/auth/signalledRequest.ts`.
- Test: a new `src/__tests__/authorization/throwingAnswers.test.ts`; existing owners.

**Interfaces:**
- Consumes: `untilAborted`, `whenRejected` (Task 1).
- Produces: no new exports. `signalOf`, `asAbortSignal` and `usableSignal`
  are gone, and signals are read as `request.signal` / `options.signal`.

- [ ] **Step 1:** Write the failing tests in
  `authorization/throwingAnswers.test.ts`, one per asynchronous callback
  path. In each, a typed answer has one field as a getter that throws
  `new Error('SECRET')`:
  The composer's latching judge reads a protocol's verdict first and hands
  the transport a fresh frozen one. So a transport's own boundary is
  reachable only by a judge given to that transport directly. The tests
  are therefore split.

  **Transport level.** Call `transport.open(options, use)`. Inside `use`,
  arm the channel with a judge that returns a typed verdict whose `verdict`
  getter throws, deliver one answer, and await `channel.answer()`:
  - **`loopback`**: deliver with an HTTP request to the bound callback.
    Assert that `answer()` settles (rejects or resolves with no payload,
    whatever the transport's failure path is today for a judge that
    throws), that `open` settles, that `'SECRET'` appears in no response
    body, and that the port is free (bind it);
  - **`terminalPaste`**, through a reader fixture (the transport's
    `read` option) that records the abort of the signal it is given.
    Deliver one line. Assert two things:
    - `answer()` / `open` end with exactly the failure that a judge
      throwing itself produces on this transport (same kind, same outcome),
      and the original error, `'SECRET'`, is in no rendering of it;
    - the reader's signal was aborted before `open` settled.
  - **`consumerAnswer`**, delivering through `receive`. Assert the same
    failure-equality and no-`'SECRET'` points. It holds no scope, so it has
    no release mutation; its one break is the verdict read.
  - **`consumerHandoff`**, delivering through `provide`. Assert the same
    failure-equality and no-`'SECRET'` points. Then, after `open` has
    settled, invoke its presentation once more and assert that `provide` is
    not called again, which proves the scope was cleared.

  For `loopback`, the failure-equality and no-`'SECRET'` points apply too.

  **Composer level** (`composeAuthorization` with a recording transport,
  and a protocol whose judge returns the throwing verdict). Assert three
  things:
  - `authorize` settles `interactive-login` `failed`;
  - the transport's `open` settled before `authorize` did;
  - a second `authorize` on the same strategy is not `busy`.
  - **a strategy outcome with a throwing `payload` getter, through a token
    provider**: `getTokens()` throws a classified failure, with no token
    request;
  - **a SPNego source answer with a throwing `ok` getter**: `prepare()`
    answers `unknown` `obtaining-negotiate-token`;
  - **an SNC locator answer with a throwing `path` getter**: `prepare()`
    answers its fixed SNC refusal.

  Before the change, the transport and composer tests pass, because
  `readSafely` covers them. So this step makes them load-bearing: run them
  now (PASS). Then, after Step 3, break each site twice and watch the
  test for that site, and no other, go red:
  - move that site's `verdict` read back outside its `try`;
  - skip that site's release (the scope, reader or socket cleanup on that
    path).

  Restore both.
- [ ] **Step 2:** Audit every site in the Files list. For each `readSafely`,
  `typeof … === 'function'`, `Reflect.apply`, `Array.isArray` or
  allowlist re-check on a typed collaborator or answer:
  - note whether the read sits inside the call's failure boundary;
  - where it does not, widen the `try` so the call and every read of its
    answer share it, with the same catch path as today's call failure.

  Record the audit (site → in / widened) in the commit message body.
- [ ] **Step 3:** Remove the checks the types prove:
  - `readSafely` on typed collaborators, their answers and the package's
    own objects;
  - `typeof … === 'function'` before typed methods (use `?.()` for
    optional methods);
  - `Reflect.apply`;
  - the type part of the client-authentication result check. Its value
    rules stay: CR/LF, name collisions, the `https:` endpoint;
  - the "is an object" check on `tlsMaterial()`'s answer. Completeness
    stays;
  - `signalledRequest.ts` and `usableSignal`.

  `readSafely` stays on thrown values, network answers and
  `IAuthRejection.error`.
- [ ] **Step 4:** Delete the tests that fail only because they fed a value
  of the wrong type. Examples: the rows of `contract/rule1Scenario.ts`
  holding a wrong-typed value, the bad-signal cases of
  `auth/attemptSignals.test.ts`, the `Reflect.apply`/`readSafely` shape
  rows of the SPNego and SNC tests. Keep every row whose answer throws.
- [ ] **Step 5:** Run `npm run test:check` and `npm test`. Expected: clean,
  with `throwingAnswers.test.ts` green.
- [ ] **Step 6:** Commit: `refactor!: collaborators are called as typed; a call and the reads of its answer share one failure boundary`.

### Task 4: The renewal decision

**Files:**
- Modify: `src/renewal/decision.ts` (`readDecision` becomes `checkDecision`)
- Modify: `src/providers/BaseTokenProvider.ts` (`decide`)
- Test: `src/__tests__/providers/renewalStrategy.test.ts`

**Interfaces:**
- Produces: `checkDecision(decision: RenewalDecision, context: { canRefresh: boolean; sentRequired: boolean }): RenewalDecision | undefined`.
  It returns a fresh frozen copy, or `undefined` when a rule is broken.
  `needsSentDecision` is unchanged.

- [ ] **Step 1:** Rewrite the getter and Proxy rows of the "invalid
  decisions" table as typed `RenewalDecision` answers whose field reads
  throw. Expected outcome: `unknown` `renewal-strategy`, no refresh, no
  login, and `R` still held. Delete the null, string and number rows.
- [ ] **Step 2:** Run the file. Expected: PASS, since `readSafely` covers
  the throwing reads today.
- [ ] **Step 3:** Implement `checkDecision`. It drops the non-object check,
  the field-by-field `readSafely`, the unknown-`next` check and the
  `ifCut` membership check. It keeps three rules:
  - `refresh` needs `canRefresh`;
  - `sentRefreshToken` is required iff `sentRequired`, and absent
    otherwise;
  - the copy-and-freeze.

  In `decide`, move the `checkDecision` call and the
  discard-what-you-send rule inside the strategy-failure `try`.
- [ ] **Step 4:** Make the tests load-bearing: temporarily move the
  `checkDecision` call outside the `try` and confirm the rewritten getter
  and Proxy rows go red. Restore the call.
- [ ] **Step 5:** Run `npm run test:check` and
  `npm test -- src/__tests__/providers src/__tests__/renewal`. Expected:
  clean.
- [ ] **Step 6:** Commit: `refactor!: checkDecision keeps only the rules RenewalDecision cannot express`.

### Task 5: Configuration refusals for typed fields

**Files:**
- Modify:
  - `src/providers/BaseTokenProvider.ts` (renewal, persistence);
  - `src/spnego/SpnegoAuthProvider.ts`;
  - `src/authorization/compose.ts`;
  - `src/authorization/presentation/openInBrowser.ts`, `consumerPresentation.ts`;
  - `src/authorization/transport/consumerAnswer.ts`, `terminalPaste.ts`;
  - `src/strategies/callbackStrategies.ts`, `codeStrategies.ts`, `manualStrategies.ts`;
  - `src/persistence/refreshStatePersistence.ts`;
  - `src/clientAuthentication/clientSecret.ts`;
  - `src/providers/saml2Utils.ts`;
  - `src/validation/assertionValidator.ts`;
  - `src/providers/ClientCredentialsProvider.ts`, `AuthorizationCodeProvider.ts`;
  - `src/auth/browserAuth.ts`;
  - `src/sso/SsoProviderFactory.ts`.
- Modify: `src/__tests__/helpers/refusalTables.ts` (the configuration rows' "Thrown" cells) and `README.md` (through `npm run docs:tables`)
- Delete: `src/__tests__/errors/renewalRequired.test.ts`, `src/__tests__/errors/persistenceInvalid.test.ts`
- Test: `src/__tests__/errors/configurationRows.test.ts`, `readmeRefusalTables.test.ts`, owners

**Interfaces:**
- Produces: no new exports. `SsoProviderFactory.create` ends its switch with
  a `never` default and no refusal.

- [ ] **Step 1:** For each site, decide whether to remove or keep its
  refusal under spec §4:
  - **Remove:** the field is required in its type, or the check asks the
    value's type or union membership.
  - **Keep:** the refusal checks an empty string, a parse, a range,
    "one of several optional fields", or a cross-field rule.

  Record the list in the commit body.
- [ ] **Step 2:** Remove the refusals in the "Remove" set. Leave the
  `undefined` check on a field only where its type is optional.
- [ ] **Step 3:** Delete the tests that construct with a missing required
  field or a wrong-typed value. These are `renewalRequired.test.ts`,
  `persistenceInvalid.test.ts`, and the `undefined`-collaborator cases in
  the SPNego, composer, `openInBrowser`, SNC and `AuthProviderBase` tests.
  Keep every empty-string, parse and range case.
- [ ] **Step 4:** In `refusalTables.ts`, remove the removed situations from
  the configuration rows' hand-written "Thrown" cells. Drop
  `basic-encoding-missing` and `unsupported-sso-flow` from the rows the
  package produces. Run `npm run docs:tables` and check the README diff
  touches only that table.
- [ ] **Step 5:** Run `npm run test:check` and `npm test`. Expected: clean,
  including `readmeRefusalTables.test.ts` and `configurationRows.test.ts`.
- [ ] **Step 6:** Commit: `refactor!: no configuration refusal for what the types already require`.

### Task 6: Answers typed `void`

**Files:**
- Modify:
  - `src/providers/BaseTokenProvider.ts` (`header` / `cookies` application, `aborted`);
  - `src/spnego/SpnegoAuthProvider.ts`;
  - `src/credentials/TokenAuthProvider.ts`, `SamlAuthProvider.ts`, `BasicAuthProvider.ts`;
  - `src/providers/Saml2PureProvider.ts`;
  - `src/auth/tokenRequest.ts` (`logQuietly`);
  - `src/auth/announce.ts`.
- Test: `src/__tests__/auth/voidAnswers.test.ts` (new); `asyncLogger.test.ts`, `announce.test.ts`, `snc/sncRows.test.ts`, rule1 and the target tests

**Interfaces:**
- Produces: `logQuietly(call: () => void): void` keeps only its
  `try/catch`. `announce` falls back to stderr only when the logger throws.

- [ ] **Step 1:** Write `auth/voidAnswers.test.ts`, with one case each for
  a request target's `header()` and `cookies()`, a renewal strategy's
  `aborted()` and a logger's `info()`. Each answers a never-settling
  thenable whose `then` counts its calls. Assert the moment's outcome is
  unchanged and the `then` count is 0, since the returned value is
  ignored. Add one case where a logger throws on a token-site failure
  path, asserting the site's own failure is thrown.
- [ ] **Step 2:** Run it. Expected: FAIL for the logger case (today
  `logQuietly` adopts the answer and calls `then`). The other cases
  already pass, because `markHandled` never calls a foreign `then`.
  Mark them as guard tests to prove in Step 4.
- [ ] **Step 3:** Remove `markHandled` from the target, `aborted` and
  logger calls. Reduce `logQuietly` and `announce` to their `try/catch`.
- [ ] **Step 4:** Delete the cases that assert a rejecting target, logger or
  `aborted()` promise is handled: `asyncLogger.test.ts`, the async-logger
  rows of `announce.test.ts` and `sncRows.test.ts`, and the
  rejecting-target rows. Keep the throwing-logger and throwing-target cases
  and confirm they still pass.
- [ ] **Step 5:** Run `npm run test:check` and `npm test`. Expected: clean.
- [ ] **Step 6:** Commit: `refactor!: answers typed void are ignored, not handled as promises`.

### Task 7: The package's own invariants; `handled.ts` deleted

**Files:**
- Modify: `src/auth/AuthProviderBase.ts` (`validatedMoments`)
- Modify: `src/auth/configuration.ts` (`misconfigured`'s `isMinted`) and `src/validation/samlRefusal.ts` (`refuse`'s `isMinted`)
- Modify: `src/providers/BaseTokenProvider.ts` (`readGrant`, `isGrant(result.authType)`, `heldGrant`'s failure path, the unreachable `refreshStep` guard, `markHandled(this.commit(…))`)
- Modify: `src/authorization/transport/terminalPaste.ts`, `httpListener.ts` (the `ANSWER_WORDS` / `REFUSALS` membership re-checks)
- Delete: `src/auth/handled.ts`, `src/__tests__/auth/handled.test.ts`
- Test: `src/__tests__/auth/AuthProviderBase.test.ts`, `providers/tokenProviderFailures.test.ts`

**Interfaces:**
- Produces: no exports change. The `AuthProviderBase` constructor keeps its
  `protected` signature, typed `MomentOperations`.

- [ ] **Step 1:** Remove the listed checks. Replace
  `markHandled(this.commit(…))` with a plain `.catch` on the package's own
  promise.
- [ ] **Step 2:** Delete `handled.ts` and `handled.test.ts`. Its
  adoption cases already moved in Task 1. Run `npm run test:check`.
  Expected: no remaining importer.
- [ ] **Step 3:** Delete the tests that fed `AuthProviderBase` invalid
  moment operations, or `getAuthType()` a non-grant or a thenable. Keep the
  cases where `getAuthType()` throws.
- [ ] **Step 4:** Run `npm test` and `npm run test:shape`. Expected: clean.
- [ ] **Step 5:** Commit: `refactor!: the package's own invariants are proven by its types; handled.ts removed`.

### Task 8: Docs, CHANGELOG, version

**Files:**
- Modify: `../../CLAUDE.md`, `docs/architecture.md`, `README.md`, `CHANGELOG.md`, `package.json` (through `npm version`)
- Delete before release: `../../docs/superpowers/2026-10-26-static-types-first-goal.md`, `../../docs/superpowers/specs/2026-10-26-static-types-first-design.md`, this plan

- [ ] **Step 1:** Draft the CLAUDE.md texts of spec §10 and bring them to
  the owner. They cover:
  - rule 1's `markHandled` reference;
  - "Options are a typed copy" in place of "Options are read as own data";
  - the narrowed `readSafely` sentence;
  - the module-tree entries for `decision.ts`, `handled.ts`,
    `knownCodes.ts` and `signalledRequest.ts`.

  Apply them only as approved.
- [ ] **Step 2:** Rewrite `docs/architecture.md`'s "Options are read as own
  data" principle and the "Collaborator answers are awaited as given"
  decision to the boundary of spec §1, and drop `markHandled`.
- [ ] **Step 3:** Update the README passages:
  - "Options are read as own data";
  - the renewal invalid-answer list;
  - the logger passage;
  - the SPNego options table;
  - the composer parts;
  - the persistence `invalid-value` mentions;
  - "Configuration errors";
  - "Your collaborators are awaited like any `await`" (drop "trust
    boundary" wording where it named `markHandled`).

  Then add "Migrating to 8.0.0":
  - options and collaborators are trusted to match their types;
  - the configuration refusals no longer produced, with their cases;
  - a request target, a logger or `aborted()` answering a rejecting
    promise despite its `void` type now raises `unhandledRejection`.

  Run `grep -n` for `ownOptions`, `readSafely`, `markHandled`,
  `isPlainPromise`, `signalOf`, `readDecision`, `hostileOptions` across
  README, docs and CLAUDE.md. Expected: only intended mentions remain.
- [ ] **Step 4:** Write the CHANGELOG `[8.0.0] - <release day>` with
  Removed / Changed sections naming each removed mechanism and each case
  no longer produced. Run `npm version 8.0.0 --no-git-tag-version`.
- [ ] **Step 5:** Run CI's own step list locally: `npm run build`,
  `npm run lint:check`, `npm run test:check`, `npm test`,
  `npm run test:shape`. Expected: all clean.
- [ ] **Step 6:** Commit the docs. After the final review approves, delete
  the goal, spec and plan in their own commit before the tag.
