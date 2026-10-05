# Error contract — goal and path

**Status:** draft, 2026-10-05, for review. The spec and then the plan come
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
package's renderer. A consumer may show `reason` / `hint` as they are, or
render its own text from `kind` and `facts`; the provider exports its
renderer so the same words can be produced anywhere (the broker relays the
error whole and copies no phrase).

**Success:** every refusal and every thrown token error of
`@mcp-abap-adt/auth-providers` is an `IAuthProviderError`; the broker relays
them without copied phrases; a consumer that switches on `kind` without a
`default` stops compiling when a kind is added; nothing about a refusal is
discovered at run time that the compiler could have reported.

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
2. **`@mcp-abap-adt/auth-providers`** — classification (`unknown` →
   `IAuthProviderError`, the one runtime boundary), the renderer, every
   refusal and thrown token error built through them. It also moves to
   `@mcp-abap-adt/interfaces-auth` ^4 (optional fields a provider hands out
   are `?: T | undefined`) and deletes `asContract`
   (`src/auth/contractShape.ts`), the one cast 5.4.1 kept for them.
3. **`@mcp-abap-adt/auth-broker`** — relays the error; its copied certificate
   phrases go.
4. **`@mcp-abap-adt/connection` and further consumers** — read `kind` where
   they act on a refusal; each in its own change.

## Holds throughout

1. **Normal course and failure are separate contracts.** `IAuthProvider` and
   `IRefreshableTokenProvider` reference the error contract; they do not list
   kinds.
2. **No exception crosses `IAuthProvider`** (providers' rule 1): the error is a
   value in the outcome, never thrown across the contract.
3. **No free text in an error.** `facts` hold only allowlisted values;
   `reason` / `hint` are a function of `kind` and `facts`, produced by the
   renderer and nothing else. No `message`, `cause` or body of any thrown
   value reaches an error (providers' rule 2).
4. **Runtime checking only at the boundary; the compiler guarantees the
   rest.** One classification function turns a thrown `unknown` into an
   `IAuthProviderError`; everything after it is typed:
   - a fact of the wrong type for its kind does not compile;
   - an allowlist type and its runtime set come from one `as const` array;
   - the renderer is checked complete over the kinds (`satisfies` a mapped
     type), so a kind without words does not compile;
   - an `IAuthProviderError` cannot be assembled by hand where the contract
     expects one minted by the renderer (a type-only brand);
   - a method body outside the `safely` boundary does not compile (an
     internal brand on its result);
   - type tests (`@ts-expect-error`, part of `test:check`) prove each static
     rule is load-bearing, as runtime tests do for runtime rules.
5. **The union is closed; a new kind is a major of `interfaces-auth`.** That
   is what turns an upgrade into a build error instead of a runtime surprise.
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

## Path

Order, not dates. Each step is one PR in its repository (one open PR per
repository at a time) and ends with a review; a step starts only when the one
before it that it depends on is merged — and, where a later repository builds
against it, published.

**Groundwork — done or in review**
1. Strict compiler: auth-providers 5.4.1 (published), interfaces 4.0.0 /
   3.0.0 / 2.0.0 / 13.0.0 (published), auth-stores (PR open, unreleased),
   auth-broker + CLI (next, unreleased).

**The error contract — this PR, in auth-providers**
2. This goal, reviewed and approved.
3. The spec, reviewed and approved: the kinds and their facts, built from
   every refusal the providers produce today; the renderer; how thrown token
   errors carry the error; the transition for readers of `IAuthRefusal`.
4. The plan, reviewed and approved: steps, order, decisions.

**Implementation, in dependency order**
5. `@mcp-abap-adt/interfaces-auth` — the error contract's types and
   constants (a major: `IAuthRefusal` changes). Its own PR, released first.
6. `@mcp-abap-adt/auth-providers` — in this PR, against the published
   interfaces: classification, renderer, every refusal and thrown token error
   through them, type tests for the static rules, `asContract` deleted.
   Released.
7. `@mcp-abap-adt/auth-stores` — moves to the new interfaces majors and
   deletes its `asContract`; released together with its unreleased
   strict-compiler change.
8. `@mcp-abap-adt/auth-broker` + CLI — relay the error, drop the copied
   certificate phrases; released together with their unreleased
   strict-compiler change.

**The error contract appears** for consumers at step 6 (auth-providers
release) and is used end to end at step 8 (broker release).

**After** — each its own task: `@mcp-abap-adt/connection` and the server
`mcp-abap-adt` read `kind` where they act on a refusal; the server's version
bump also takes the x509 and strict-compiler releases.
