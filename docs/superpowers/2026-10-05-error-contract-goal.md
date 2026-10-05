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
   refusal and thrown token error built through them.
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

A separate, earlier change in `@mcp-abap-adt/auth-providers` puts the package
under the compiler this goal relies on: the test files type-checked by
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

1. The compiler change above: its own PR in auth-providers, after PR #66.
2. This goal → spec → plan, each reviewed in this PR.
3. interfaces-auth: its own PR, released first.
4. auth-providers implementation in this PR, against the published
   interfaces; then the broker; merge and release on the user's word.
