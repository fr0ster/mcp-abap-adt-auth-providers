# Error contract — goal and path

**Status:** goal approved by the user 2026-10-05 (after four Codex adversarial passes). The spec and then the plan come
next, in this PR. This file is the anchor: it says what they are for, and what
neither may trade away. If the spec or the plan needs to depart from anything
under *Holds throughout*, this file changes first — explicitly, in review.

## Goal

What goes wrong in authentication has its own contract, separate from the
contracts that describe the normal course. `IAuthProvider` describes the four
moments and their outcome; when a moment fails, its refusal carries an
`IAuthProviderError` defined by the error contract. The same error describes
what `getTokens()` / `refreshTokens()` throw, so a consumer reads one language
of errors from one provider, whichever contract it calls.

An `IAuthProviderError` is a **closed union discriminated by `kind`**: each
kind carries its own `facts`, every fact a value from an allowlist, and
`reason` / `hint` — text derived from `kind` and `facts` alone, by the
renderer in `@mcp-abap-adt/auth-errors`. Beside them, an error may carry
`diagnostics` (see invariant 3), rendered by a separate function and never
part of `reason` / `hint`: a consumer that drops diagnostics drops every
diagnostic-derived character. A consumer may show `reason` / `hint` as they
are, or render its own text from `kind` and `facts`; the renderer is exported
so the same words can be produced anywhere (the broker relays the error whole
and copies no phrase).

**Success:** every refusal and every thrown token error of
`@mcp-abap-adt/auth-providers`, and every refusal a logon target returns, is
an `IAuthProviderError`; the broker relays them without copied phrases; a
consumer that handles kinds exhaustively — a `never` assertion in the
`default`, or a handler map typed over every kind — stops compiling when it
upgrades to a contract with a new kind (a switch without either is not
checked by TypeScript, so the contract's guides require one); nothing about a
refusal is discovered at run time that the compiler could have reported.

## Why

`IAuthRefusal` today is free text, `{ reason, hint? }`. A consumer cannot act
on a refusal without parsing words; the broker keeps copies of the provider's
phrases, which drift; and the one property that matters most — no secret in
a refusal — is held by the provider's discipline, not by a type. The error
codes that already exist (`TOKEN_PROVIDER_ERROR_CODES`, `ASSERTION_ERROR_CODES`)
cover thrown classes only, not refusals.

## What changes, by repository

1. **`@mcp-abap-adt/interfaces-auth`** — the error contract: the kinds, the
   facts of each, the allowlist types (`as const` arrays and the unions they
   give), `IAuthProviderError`; `IAuthRefusal` carries it. Types and constants
   only — no logic (the interfaces package holds none).
2. **`@mcp-abap-adt/auth-errors`** (new package, its own repository; decided
   by the user 2026-10-05) — the runtime half of the contract, which the
   interfaces package cannot hold: the one way to build an
   `IAuthProviderError` (the brand is minted only here), the renderer, and the
   allowlists' runtime sets. Small and dependency-free apart from
   `interfaces-auth`, so every producer — providers, connection's logon
   targets, the broker — depends on it without pulling in a provider.
3. **`@mcp-abap-adt/auth-providers`** — classification (`unknown` →
   `IAuthProviderError`, the one runtime boundary), and every refusal and
   thrown token error built through `auth-errors`. It also moves to the
   error contract's `@mcp-abap-adt/interfaces-auth` major (5.0.0; it carries
   4.0.0's `?: T | undefined` fields too) and deletes `asContract`
   (`src/auth/contractShape.ts`), the one cast 5.4.1 kept for them. Every
   producer and consumer in this release chain moves to that same major.
4. **`@mcp-abap-adt/auth-broker`** — relays the error; its copied certificate
   phrases go.
5. **`@mcp-abap-adt/connection`** — its logon targets (`ILogonTarget`:
   `header`, `cookies`, `logonParameters`, `tlsMaterial`) return an
   `AuthOutcome` too, and a provider with no other way in returns the
   target's Oops as its own (providers' rule 4: `CertificateAuthProvider`,
   `SncLogonProvider`). A target is a producer of refusals, not only a reader:
   its refusals are `IAuthProviderError`s of the same contract, built through
   `auth-errors`, and connection reads `kind` where it acts on one.
6. **Further consumers** (the server `mcp-abap-adt`) — read `kind` where they
   act on a refusal; each in its own change.

## Holds throughout

1. **Normal course and failure are separate contracts.** `IAuthProvider` and
   `IRefreshableTokenProvider` reference the error contract; they do not list
   kinds.
2. **No exception crosses `IAuthProvider`** (providers' rule 1): the error is a
   value in the outcome, never thrown across the contract.
3. **No free text in an error's facts.** `facts` hold only allowlisted
   values; `reason` / `hint` are a function of `kind` and `facts` only,
   produced by the renderer and nothing else. No `message`,
   `cause` or body of any thrown value reaches an error (providers' rule 2).
   **`diagnostics`** (decided by the user 2026-10-05) is a separate, typed
   channel for the values that help a person and cannot be allowlisted —
   today an SNC library's and each candidate's path, and a SAML document's
   values quoted by `quoteUntrusted` — admitted only when the value is one the
   consumer supplied or received in clear (its own configuration and files,
   the assertion it was handed), never a secret, a token, key material, a
   server's free text or any exception's text. Provenance alone does not make
   a value safe — an assertion is attacker-controlled — so the spec
   enumerates each diagnostic field per kind with its one approved extraction
   source (e.g. the configured SNC library path, a candidate path the locator
   built; from an assertion only selected metadata such as an Issuer, an
   InResponseTo, an ID or a time — never arbitrary element content), and
   **admission is checked at the producing boundary**: the builder in
   `auth-errors` validates each diagnostic field (shape, length, the
   escaping `quoteUntrusted` does today) before the error is minted. Values
   quoted today that fall outside this — exception messages quoted inside
   SAML refusals (`signedNode.ts`), any other free text — are dropped, and
   the diagnostic compatibility matrix records each one. Diagnostics are
   rendered by their own function, never into `reason` / `hint`.
4. **Runtime checking only at the boundaries; the compiler guarantees the
   rest.** Two boundaries, both in `auth-errors`'s builder or called by it:
   classification turns a thrown `unknown` into an `IAuthProviderError`, and
   diagnostics admission validates each diagnostic field before minting.
   Everything after them is typed:
   - a fact of the wrong type for its kind does not compile;
   - an allowlist type and its runtime set come from one `as const` array;
   - the renderer is checked complete over the kinds (`satisfies` a mapped
     type), so a kind without words does not compile;
   - an `IAuthProviderError` cannot be assembled by hand where the contract
     expects one minted by the renderer (a type-only brand);
   - rule 1 (no exception crosses the contract) is held structurally, not by
     a type: TypeScript does not track what a function throws, so a brand on
     a result proves only where the result came from. The four methods are
     owned by one place that runs each body inside `safely` (a base or
     wrapper the providers cannot bypass), a lint rule refuses another
     shape, and runtime tests throw from every collaborator;
   - type tests (`@ts-expect-error`, part of `test:check`) prove each static
     rule is load-bearing, as runtime tests do for runtime rules.
5. **The union is closed; a new kind is a major of `interfaces-auth`.**
   With consumers handling kinds exhaustively (see Success), that is what
   turns an upgrade into a build error instead of a runtime surprise; an
   installed consumer is not changed by a release, only by its own upgrade.
6. **The consumer composes.** Text is the consumer's choice: the shipped
   renderer is a default it may replace, never something a provider forces.

## Before this work

Done 2026-10-05: auth-providers 5.4.1 is under the compiler this goal relies
on; interfaces 4.0.0 (auth), 3.0.0 (auth-sap) carry the widened fields;
auth-stores and auth-broker get the same compiler in their own PRs, released
with this work. What that change did: the test files type-checked by
`test:check` (they are excluded from it today, so a type error in a test
surfaces only when Jest runs), and the stricter compiler options
(`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
`noImplicitReturns`, `noFallthroughCasesInSwitch`,
`noPropertyAccessFromIndexSignature` — 147 errors in `src` measured
2026-10-05) fixed or decided one by one.

## Out of scope

- Localised texts: the renderer makes them possible; none ships here.
- Error contracts of packages outside the auth chain.

## Open — for the spec

1. Whether `reason` / `hint` stay required fields of the error, or become
   optional once every consumer renders from `kind`.
2. The list of kinds, built from every refusal the providers produce today
   (configuration, certificate, client authentication, token endpoint, TLS,
   SAML assertion, SNC, rejection reading, bound token, unknown).
3. How `getTokens()` / `refreshTokens()` carry the error: a thrown class that
   holds an `IAuthProviderError`, or the existing classes extended.
4. The transition for consumers reading `IAuthRefusal` today.
5. **A diagnostic compatibility matrix**, a release gate: every message a user
   sees today — each refusal, each `loggedError` line, each thrown message
   (`TokenEndpointError`'s redacted OAuth summary, `CallbackScopeError`'s
   timeout / port in use / abort, each SAML validator sub-rule and its listed
   candidates, each SNC library candidate and GSS classification) and the
   README refusal table — mapped to its kind and facts, with every loss of
   information named and approved, and the README, guides and migration notes
   updated before release.
6. How a logon target (connection) builds its refusals, and how a provider
   relays one under rule 4.

## Path

Order, not dates. Each step is one PR in its repository (one open PR per
repository at a time) and ends with a review; a step starts only when the one
it depends on is merged — and, where a later repository builds against it,
published.

**Groundwork — done**
1. Strict compiler: auth-providers 5.4.1, interfaces (auth 4.0.0, auth-sap
   3.0.0, auth-broker 1.3.0, adt-connection 2.0.0, adt 13.0.0) published;
   auth-stores and auth-broker + CLI merged, unreleased — they ship with
   steps 9 and 10.

**The error contract — this PR, in auth-providers**
2. This goal, reviewed and approved.
3. The spec, reviewed and approved: the kinds, their facts and diagnostics,
   built from every refusal and message the chain produces today (the
   diagnostic compatibility matrix); the builder and renderer; how thrown
   token errors carry the error; how a logon target builds a refusal; the
   transition for readers of `IAuthRefusal`.
4. The plan, reviewed and approved: steps, order, decisions.

**Implementation, in dependency order**
5. Interfaces, one PR in the interfaces repository, released first:
   `@mcp-abap-adt/interfaces-auth` 5.0.0 — the contract's types and constants
   (a major: `IAuthRefusal` changes); and every sibling that depends on it
   (`interfaces-auth-sap`, and through it `interfaces-auth-broker`) moved to
   it — a major where any exported type reaches a changed type, else a range
   widening, by the rule PR #123 established. The spec names each resulting
   version.
6. `@mcp-abap-adt/auth-errors` 1.0.0 — new repository: builder, renderer,
   allowlist sets, type tests. Released.
7. `@mcp-abap-adt/connection` — logon targets build refusals through
   `auth-errors`; moves to interfaces-auth 5.0.0 (and the interface majors of
   step 5 it uses). Released.
8. `@mcp-abap-adt/auth-providers` — in this PR: classification, every refusal
   and thrown token error through `auth-errors`, a target's refusal relayed
   under rule 4, rule 1 held structurally, type tests, `asContract` deleted.
   Released. **The error contract appears for consumers here.**
9. `@mcp-abap-adt/auth-stores` — moves to the step-5 interface versions
   (interfaces-auth, -auth-sap, -auth-broker), deletes its `asContract`;
   released with its unreleased strict-compiler change.
10. `@mcp-abap-adt/auth-broker` + CLI — move to the step-5 interface
    versions, auth-errors, the step-8 auth-providers and the step-9
    auth-stores; relay the error, drop the copied certificate phrases; released with their unreleased strict-compiler
    change. **The contract is used end to end here.**

**After** — its own task: the server `mcp-abap-adt` reads `kind` where it
acts on a refusal; its version bump also takes the x509 and strict-compiler
releases.
