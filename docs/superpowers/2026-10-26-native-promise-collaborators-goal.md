# Goal: every collaborator answers with a native promise

## The target

Every asynchronous answer `@mcp-abap-adt/auth-providers` receives from a
collaborator the consumer composed must be a plain native promise
(`isPlainPromise`). A foreign thenable, a Promise subclass, a Proxy, or a
promise with its own `then` / `catch` is refused, and its `then` is never
called. Today two collaborators answer under this rule: the renewal
strategy's `next()` and `SpnegoAuthProvider`'s token source. After this
change every collaborator does.

## Why

Adopting a thenable calls its `then`. Promise machinery reads getters
and runs consumer code that the provider never asked for. A throw from
that code is still contained, but the provider no longer knows which
consumer code ran inside its boundary. With a plain native promise, the
only consumer code that runs is the method the provider called.
`docs/architecture.md` ("Collaborator answers are native promises")
records the decision. Its status today is "enforced for two
collaborators". This change makes it hold for all of them.

The decision covers this package only. Whether it suits other packages
has not been assessed.

## What changes

- **Answers the package awaits.** These are:
  - the client-authentication strategy and its TLS material;
  - certificate material loaders;
  - `TokenAuthProvider.from`'s refresher;
  - the SNC locator and probes;
  - the assertion validator and replay store;
  - the cookie provider;
  - the device-code presenter;
  - the persistence strategy and the shipped persistence's `write`;
  - the authorization strategy;
  - the composition's parts and the consumer callbacks of the shipped
    parts (`open`, `answer()`, the consumer transports' callbacks,
    `consumerPresentation`'s `show` / `onFailure`, and `IBrowser.open`).

  Each of these answers is awaited only when it is a plain native
  promise. Any other answer is refused like a failure of that call, at
  that site, with the classification the site already gives a rejection
  there. Nothing new is invented per site.
- **A synchronous answer where the contract declares a promise is
  refused** in the same way. Where the contract declares `T | Promise<T>`
  or leaves the answer open (the renewal strategy's `next()`, the
  persistence `report()`, `aborted()`, the presentation's `present()`),
  a synchronous answer stays legal.
- **Answers the package does not await.** These are logger calls, the
  presentation's answer, the detached persistence report and
  `aborted()`. A plain native promise gets a handler, as it does today
  (`markHandled`). Anything else is left alone, and its `then` is never
  called: a rejection there is not observed. `onAnswerRejection`, which
  adopts thenables, goes. This is the one place where a consumer loses
  something it has today: a Bluebird logger's rejection is no longer
  contained by the package.
- **Documentation:**
  - CLAUDE.md rule 1 in general terms;
  - the `architecture.md` Status;
  - every README passage that promises a thenable works ("a native
    promise, Bluebird, Q or any Promises/A+ thenable works"), plus a
    migration note: wrap a library's promise in a native one
    (`Promise.resolve(x)` does not do it; `new Promise((r, j) =>
    x.then(r, j))` does, in the consumer's own code);
  - the CHANGELOG.
- **A major release, 8.0.0.** A consumer whose collaborator answers a
  thenable today gets a refusal.

## Holds throughout

- Rules 1–8 hold. No exception crosses the contract. Every refusal is
  minted by auth-errors with allowlisted facts only. A refused answer adds
  no new kind, case or operation.
- **No foreign `then` is ever called**, by any path: not by `await`,
  `Promise.resolve`, `new Promise(r => r(x))` or a library helper.
- **The test is one function.** `isPlainPromise` in `src/auth/handled.ts`
  decides at every site. No site has a test of its own.
- **A refused answer looks like that site's failure.** It gets the same
  kind, operation or end as a rejection from that collaborator gets
  today, so a consumer's handling of failures does not change shape.
- **Abort semantics stay.** Wherever the attempt's signal bounds an
  awaited answer today (`untilAborted`), it still does.
- **The shipped collaborators comply.** Every strategy, loader, browser,
  transport and presenter this package ships answers with plain native
  promises, and the tests prove it through the strict sites.
- Each new rule is load-bearing. A test proves it at each site, and
  breaking the rule turns that test red.

## Scope

In scope:
- every site where `src` receives a collaborator's answer;
- the helpers in `src/auth/handled.ts` and `src/auth/attempt.ts`;
- the docs listed above.

Out of scope:
- the request and logon targets, whose answers already go through
  `relayOutcome` / `markHandled`;
- other packages (interfaces-auth's contract types are not changed);
- a collaborator's synchronous return values that are not promises
  (judges, `begin`, `arm`, `remoteHint`).

Open questions for the spec:
- A refused promise that later rejects. A Promise subclass or a promise
  with its own `then` that the package refuses is not subscribed, so its
  rejection may raise `unhandledRejection`. Leave this to the consumer, as
  the "never call a foreign `then`" rule implies, or call the built-in
  `Promise.prototype.then` on any native-branded promise to mark it
  handled (that calls no consumer `then`, but a subclass's species
  constructor would still run)?
- The text of CLAUDE.md rule 1. The fragment approved earlier names "the
  operation of that call". At sites whose failure today is an end, such as
  the composer's `interactive-login` `failed`, the general rule reads
  "refused like a failure of that call". The text is brought for approval
  with the spec.
