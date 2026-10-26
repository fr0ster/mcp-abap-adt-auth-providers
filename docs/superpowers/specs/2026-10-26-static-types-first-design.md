# Static types first in auth-providers: design

Answers `docs/superpowers/2026-10-26-static-types-first-goal.md`. Paths are
relative to `packages/auth-providers/`.

## 1. The boundary

A value is checked at runtime only when it comes from outside the type
system:
- a thrown value (a `catch` binding is `unknown`);
- a network answer (the token endpoint, OIDC discovery);
- a JWT payload;
- a SAML or XML document;
- a file, the environment, registry output or terminal input;
- a callback HTTP request;
- GSS token bytes;
- any field a contract itself types `unknown` (`IAuthRejection.error`,
  `IAuthorizationPresentation.present()`).

A value is used as typed when its type comes from a contract or from this
package's own declarations:
- an options object;
- a collaborator and the methods it is called through;
- a collaborator's answer;
- the package's own objects.

A **value rule** is a rule about a typed value that the type cannot
express:
- the shape of a URL or path;
- a port, integer or time range;
- a non-empty or printable string;
- CR/LF in a header;
- presence where the type leaves a field optional but the configuration
  needs one of several (`issuer` or the endpoints, `tokenUrl` or `uaaUrl`,
  PEM or PFX);
- a cross-field rule (`clientSecret` beside `clientAuthentication`, the
  SAML `idpInitiated` combinations, the renewal decision rules in §5).

Value rules stay, with their refusals unchanged. A **type check** asks what
the type already answers:
- `typeof`;
- `Array.isArray`;
- `=== true` on a `boolean`;
- `!== undefined` on a required field;
- a method's existence;
- membership in the union the field is declared as.

Type checks go.

## 2. Options: a typed copy

`ownOptions` is deleted. Every exported constructor and factory takes its
options typed and copies them once with a spread
(`const own = { ...options }`). Nothing is read through a descriptor, and
the copy has the options type, not `Partial<Record<…, unknown>>`. The casts
that followed the snapshot (`own.x as T`) go with it.

What stays:
- **The snapshot.** A change to the consumer's object after creation
  changes nothing, as today. The copy is shallow, as `ownOptions` was.
- **Configuration that is already a copy.** Configuration copied for later
  use (`privateKeyJwt`'s key, `tlsClientCertificate`'s material or loader,
  the SAML trust) is read from the copy, not from the consumer's object.

What goes:
- the defense against accessors, Proxies, revoked Proxies and primitives
  in the options position. A getter now runs, once, during the spread;
- `ownData`'s accessor defense in `SncLogonProvider`;
- the `ownOptions` calls on the package's own internal objects
  (`AnswerTransportOptions` built by the composer, `openOptions`,
  `samlTrustOf`). Those are read as typed.

How a caller that breaks the types behaves is not stated anywhere.

## 3. Collaborators: called as typed

A collaborator is called directly through its typed method:
`this.renewal.next(situation)`, `strategy.dispose?.()`,
`browser.open(url, signal)`, `source.token(principal, { signal })`, and so
on.

These go:
- `readSafely` before the call;
- `typeof … === 'function'`;
- `Reflect.apply`.

An optional method is called with `?.()`.

**A throw is not a type question, so every throw stays handled.** A typed
value can still throw. A getter is a valid implementation of a typed field,
and a method may throw whatever it likes. `readSafely` used to make a read
total wherever it sat, so some reads of a collaborator's answer sit outside
any `try` today. One example is `httpListener`'s `judged()`, which catches
only `judge(answer)` and reads the verdict's fields after its `try`. The
composer's judge path in `compose.ts` has the same split.

The rule is therefore: **the collaborator's call and every read of its
answer share one failure boundary.** That boundary is the site's existing
`try`, widened where needed, or the moment's `guard`. A throw while reading
an answer takes the same path as a throw from the call:
- the same classification, refusal or end;
- the same settling of the attempt;
- the same release of a socket, reader or scope.

Every site where `readSafely` is removed is audited for this before its
removal. The asynchronous callback paths come first: the listener's and the
terminal's and the consumer transports' `judged`, the composer's judge, a
strategy outcome, a token source's answer and a locator's answer. Rule 1
holds unchanged.

A collaborator's answer is used as its contract types it:
- **Strategy answers.** A strategy outcome's `payload` and `redirectUri`,
  a channel's `redirectUri` / `callbackMethods` / `paste`, a judge's
  verdict and its `reason`, and `buildAuthorizationUrl()`'s string are read
  as typed.
- **SNC answers.** A locator's `path` / `archs` are read as typed.
- **Typed text answers.** `ReceiveAnswer` / `TerminalRead` text is used as
  typed.
- **The token source's answer.** `NegotiateTokenAnswer`, a union on `ok`,
  is narrowed by `ok`. The value rules on the token itself stay: Kerberos
  vs NTLM vs unreadable.
- **Client authentication.** The client-authentication result's
  `parameters` / `headers` are typed `Readonly<Record<string, string>>`.
  Their type check goes. The value rules stay: CR/LF in a header, the site's
  own names not replaced, the endpoint being an absolute `https:` URL.
- **TLS material.** `tlsMaterial()`'s answer is an `ICertificateMaterial`.
  Every field of that type is optional, so the completeness rule stays
  (`client-certificate` `incomplete`). Only the check "is it an object"
  goes.

These go too:
- **`signalOf` / `asAbortSignal` / `usableSignal`.** `request.signal`,
  `options.signal` and the like are typed `AbortSignal | undefined` and are
  read directly. `signalledRequest.ts` is deleted.
- **`readSafely` on the package's own objects.** That means the token
  response snapshot, the discovery document, `PresentationContext` and
  `IAuthRejection.at` / `status`. The status range rule stays.

`readSafely` (`src/auth/knownCodes.ts`) stays for what §1 keeps:
- thrown values (`failedLogin`, `readRequestFailure`, `tlsFailureCode`,
  `systemCodeOf`);
- the network answers (`answerData`, the discovery snapshot);
- `IAuthRejection.error`.

## 4. Configuration refusals

A constructor or factory no longer refuses a field whose type already
rules out what is being refused. Concretely, these no longer produce a
refusal:
- `required-fields-missing` for a field required in the type, such as
  `renewal`, `tokenSource`, `servicePrincipal`'s presence, the
  composition's `presentation` / `transport` / `protocol` / `endpoint` /
  `label`, `browser`, `show`, `receive`, `provide`, `read`,
  `assertionValidator`, a strategy's `redirectUri` where the type requires
  it, `clientId` / `clientSecret` where the type requires them;
- `invalid-value` for a value of the wrong type: a `persistence` without a
  callable `report`, `refreshStatePersistence`'s `write` or a non-member
  `onWriteFailure`, a part that is not an object with its methods, a
  browser name where an `IBrowser` belongs, `remoteHint` not a function,
  certificates not an array, a replay store without its method;
- `basic-encoding-missing`. `encoding` is a required `'raw' | 'form'`.

`SsoProviderFactory.create` switches exhaustively over its typed flow, with
a `never` default. `unsupported-sso-flow` is no longer produced.

Every other refusal stays as it is:
- an empty string where the type says `string`;
- a URL that does not parse;
- a port out of range;
- `oidc-issuer-required` / `oidc-endpoint-missing`;
- `saml-token-endpoint-missing`;
- the SAML and client-secret cross-field cases;
- `saml-shipped-validator-without-issuer`, whose brand cannot be typed;
- `callback-port-invalid`;
- `locator-returned-no-path`;
- the SNC `partnerName` and `qop` value rules;
- everything a moment refuses.

The README's generated configuration table loses the removed rows and
cells. The words come from auth-errors and are unchanged. interfaces-auth
keeps the cases on its allowlist, since other producers may still use
them.

## 5. The renewal decision

`readDecision` becomes `checkDecision(decision: RenewalDecision, context)`.
The shape checks go: not an object, a field read through `readSafely`, an
unknown `next`, an `ifCut` outside `SentRefreshToken`. The type proves all
of these.

The rules the type cannot express stay, each still `unknown`
`renewal-strategy`:
- `refresh` needs `canRefresh`;
- `sentRefreshToken` is required after a refresh that failed once sent
  (`needsSentDecision`) and absent elsewhere;
- a refresh may not discard the refresh token it would send.

The decision is copied and frozen once, as today, so a strategy that
changes its object after answering changes nothing. `ifCut` is read when
the abort lands, which can be later.

## 6. Promises

- **`untilAborted(work: T | PromiseLike<T>, signal)`.** It adopts `work`
  with `Promise.resolve(work)`. `isPlainPromise` goes from it.
- **Answers typed `void` are not handled as promises.** That covers
  `IRequestTarget.header()` / `cookies()`, `IRenewalStrategy.aborted?()`
  and every `ILogger` method. The call stays inside its `try`, and a throw
  is handled as today. A returned value is ignored. `logQuietly` keeps only
  its `try/catch`. `announce` falls back to stderr when the logger throws,
  and no longer when it answers a rejecting promise.
- **Answers typed as promises keep a rejection handler.** These are
  `ITokenPersistence.report()` (`void | Promise<void>`, detached),
  `IBrowser.open()` and `present()` (typed `unknown` by its contract, so
  it is outside the type system). Each gets its handler through
  `Promise.resolve(answer).then(undefined, handler)`. The handler's own
  throw is contained, as `onAnswerRejection` does today.
- **The package's own promises.** `markHandled(this.commit(…))` becomes a
  plain `.catch`. `getAuthType()` is the provider's own abstract method,
  typed `OAuth2GrantType`, and is read as typed. `readGrant`'s `isGrant`
  and `markHandled` go, and so does `isGrant(result.authType)`.
- **`src/auth/handled.ts` is deleted** (`isPlainPromise`, `markHandled`,
  `onAnswerRejection`). Every user is covered above.

## 7. The package's own invariants

These go, because the type or the construction already proves them:
- `validatedMoments` (the constructor is `protected`, typed
  `MomentOperations`);
- `isMinted` on `misconfigured`'s and `refuse`'s own builder output;
- the `refreshStep` guard that the code marks unreachable;
- the `REFUSALS.has` / `ANSWER_WORDS` membership re-checks of a typed
  `AnswerRefusal`.

`endFailure`'s `isMinted` stays, because it tells another copy of
auth-errors apart, which is out of scope. The provenance brands stay too:
the shipped locator's `WeakSet` and the shipped validators' symbol.

## 8. What does not change

- **Everything §1 keeps.** That means:
  - K1–K18 of the inventory;
  - `classify`, `readFailure`, `logFields` on thrown values;
  - `relayOutcome` on logon-target answers, which interfaces-auth
    requires;
  - every moment inside `guard`;
  - rules 2–8.
- **No new refusal, kind, case or operation.**
- **auth-spnego-gssapi.**

## 9. Tests

- **Tests that prove only removed checks are deleted.** These are:
  - `errors/hostileOptions.test.ts`, except its value-rule cases, which
    move to the owning test files;
  - the rows of `contract/rule1Scenario.ts` whose hostile answer holds a
    value of the wrong type. The rows whose answer throws, whether from a
    getter, a Proxy trap or the method itself, stay: a throw is still
    handled (§3);
  - `auth/handled.test.ts`;
  - the `isPlainPromise` part of `auth/untilAborted.test.ts`;
  - `auth/attemptSignals.test.ts`' bad-signal cases;
  - the shape rows of `providers/renewalStrategy.test.ts` (null, string,
    number, getter, Proxy);
  - `errors/renewalRequired.test.ts` and `errors/persistenceInvalid.test.ts`;
  - the `undefined`-collaborator cases in the SPNego, composer,
    `openInBrowser`, SNC and AuthProviderBase tests;
  - the target, logger and `aborted()` rejecting-promise cases.
- **Tests that state behaviour still promised stay.** These include:
  - the snapshot test ("a later change to the options changes nothing");
  - every value-rule refusal;
  - every throw classification;
  - the decision rules;
  - `collaboratorThenables.test.ts` (adoption);
  - the README table test.
- **A removed check is removed together with its test.** A test that
  still passes after the check's removal was not testing the check, and is
  kept or fixed on its own merit.
- **New tests:**
  - an options getter runs once, at creation (the spread);
  - a `void` target or logger answer is ignored;
  - one per asynchronous callback path (§3), where a typed answer with a
    getter that throws ends the login through its failure path: the attempt
    settles, and the port, reader or scope is released. Each test binds the
    port to prove the release.
- **The type checks have no runtime test.** The compiler is their test:
  `test:check` covers it under `strict` and `exactOptionalPropertyTypes`.

## 10. Docs

- **CLAUDE.md** (texts approved by the owner before they land):
  - rule 1, "collaborators' answers are awaited normally": the
    `markHandled` reference goes;
  - "Options are read as own data" is replaced by "Options are a typed
    copy";
  - "Every property of a foreign value is read through `readSafely`" is
    narrowed to values from outside the type system;
  - the `decision.ts`, `handled.ts`, `knownCodes.ts` and
    `signalledRequest.ts` entries of the module tree.
- **`docs/architecture.md`.** The "Options are read as own data"
  principle and the "Collaborator answers are awaited as given" decision
  are rewritten to the boundary of §1. The `markHandled` reference goes.
- **README:**
  - the passages listed in the inventory's "Docs affected";
  - the generated configuration table;
  - "Options are read as own data";
  - the renewal invalid-answer list;
  - the logger passage (README:4613-4615);
  - a migration note for 8.0.0:
    - options and collaborators are trusted to match their types;
    - the configuration refusals of §4 are no longer produced;
    - a request target, a logger or `aborted()` that answers a rejecting
      promise despite its `void` type now raises `unhandledRejection`.
- **CHANGELOG 8.0.0.** Removed / Changed, with the cases no longer
  produced.
