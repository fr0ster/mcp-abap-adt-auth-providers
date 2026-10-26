# Goal: static types first in auth-providers

## The target

`@mcp-abap-adt/auth-providers` checks at runtime only what the compiler
cannot see. A value whose type is already proven by a contract — a
consumer's options, a collaborator, a collaborator's answer — is used as
typed. It is not re-read through defensive helpers, not re-validated field
by field, and not refused with a configuration error that only an untyped
caller could ever trigger.

## Why

The rule is "Types: static checking first": whatever static type checking
can verify is verified statically. A runtime check either lets through
what it was meant to catch, or spends resources and slows the work. The
native-promise check on collaborator answers (dropped in 7.1.0) was the
first example: an async wrapper passed it.

The package today defends against a consumer who bypasses the types (plain
JavaScript, `as any`). It reads every option through `ownOptions`, reads
every collaborator property through `readSafely`, checks `typeof … ===
'function'` before calling a typed method, and refuses missing typed
fields with `configuration` errors. An inventory found about 120 such
sites, plus the four larger mechanisms listed under "What changes". All of
this runs on every construction or call and proves nothing the compiler
has not already proved.

## What changes

- **Checks the type already proves are removed.** These are:
  - `readSafely` on the package's own objects and on typed collaborators
    and their answers;
  - `typeof m === 'function'` before a call to a typed method;
  - `asAbortSignal` / `signalOf` / `usableSignal`;
  - `typeof` / `Array.isArray` / allowlist re-checks of typed answers;
  - grant re-validation of the abstract `getAuthType()` and of the
    package's own results;
  - `validatedMoments`;
  - `isMinted` on the package's own builder output;
  - `isPlainPromise` in `untilAborted`, and `markHandled` on the package's
    own promises;
  - the type part of configuration checks (the value part stays);
  - the guard the code itself marks unreachable.
- **`ownOptions` goes.** Options are a plain copy (`{ ...options }`) made
  at creation, so a later change to the consumer's object still changes
  nothing. Accessors and Proxies are no longer defended against, and the
  copy is typed by the options type, not `Partial<Record<…, unknown>>`.
- **Constructor refusals for typed fields go.** These are the
  `required-fields-missing`, `invalid-value` and `basic-encoding-missing`
  cases that only fire when a typed field is absent or of the wrong type,
  for example `renewal`, `persistence`, `tokenSource`, the composition's
  parts, the browser, `show`, `receive` / `provide`, `encoding`,
  `assertionValidator` and `replayStore`. `unsupported-sso-flow` becomes
  an exhaustive `never`. The README's generated configuration table
  changes with them.
- **`readDecision` keeps only the rules the type cannot express.** Those
  rules are: `refresh` needs `canRefresh`; `sentRefreshToken` is required
  after a refresh that failed once sent, and forbidden elsewhere; a
  refresh may not discard the token it sends. Its shape checks go.
- **Answers typed `void` are not handled as promises.** This covers a
  target's `header()` / `cookies()`, the renewal strategy's `aborted()`,
  and every `ILogger` method (`logQuietly`, `announce`). The try/catch
  around those calls stays, because a throw is not something types can
  rule out.
- **Docs:**
  - CLAUDE.md: rule 1's wording, "Options are read as own data", the
    `decision.ts` / `handled.ts` / `knownCodes.ts` descriptions;
  - `docs/architecture.md`: the principle and the decision;
  - the README passages that promise these defenses, with a migration
    note;
  - the CHANGELOG.
- **A major release, 8.0.0.** A caller that bypasses the types loses
  refusals and defenses it has today.

## Holds throughout

- **Everything outside the type system is still checked at runtime.**
  That means:
  - thrown values (`catch` is `unknown`; `classify` / `readFailure` read
    them);
  - token endpoint and discovery answers, JWT payloads, SAML / XML;
  - files, the environment, registry output, terminal input;
  - callback HTTP requests and GSS token bytes;
  - `IAuthRejection.error`, which the contract types `unknown`.
- **Value checks the type cannot express stay.** These include URL and
  path shapes, port and integer ranges, non-empty strings, printable text,
  CR/LF in headers, the presence of fields the type leaves optional, and
  the provenance brands (the shipped locator's failures, the shipped
  validators).
- **Rule 1 holds for typed callers.** No exception crosses a moment.
  Every moment still runs inside `guard`, so a collaborator's throw is
  still classified. What leaves is only the defense against values that
  break their declared types.
- **Rules 2–8 hold.** A refusal carries no secret and no error's message,
  and the refusals the package still produces are unchanged.
- **The contracts in other packages are not changed here.** `relayOutcome`
  on logon-target answers stays, because interfaces-auth requires it.
  `present(): unknown` stays as declared.
- **Every removal is found by the compiler where possible.** Types are
  tightened first, and the code that no longer type-checks shows what
  goes. Removing a check that a test protected turns that test red. The
  test is deleted with the check, or rewritten when the behaviour it
  protects remains.

## Scope

In scope:
- `packages/auth-providers/src`;
- its tests and docs;
- CLAUDE.md;
- `docs/architecture.md`.

Out of scope:
- `relayOutcome` and other contract-level changes in interfaces-auth;
- `isMinted` on verdict errors from another auth-errors copy;
- turning value rules into union types (`qop`, `clientSecret` beside
  `clientAuthentication`, the SAML `idpInitiated` combinations);
- `packages/auth-spnego-gssapi`.

Open questions for the spec:
- The constructor of a caller that passes an object whose getter throws
  now throws that error itself, not a `configuration` failure. Is that
  stated as the contract of an untyped caller, or left unsaid?
- A target or logger that breaks its `void` type and answers a rejecting
  promise now raises `unhandledRejection`. Does the README say so in the
  migration note?
