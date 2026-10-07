# Renewal and persistence strategies — goal

The renewal part of auth-providers 6.0.0. The error contract's goal
(`2026-10-05-error-contract-goal.md`) binds everything else. The spec and
the plan answer this file; if either needs to depart from anything under
*Holds throughout*, this file changes first.

## Goal

A token provider decides nothing about renewal or persistence that a
consumer might want to decide differently. Two strategies, injected by the
consumer, decide instead:

- a **renewal strategy** — whether to refresh, whether to log in, how many
  times, when to give up, and what becomes of a refresh token whose fate is
  uncertain;
- a **persistence strategy** — what is written, what is cleared, and what
  happens when a write fails. It replaces the `onTokens` hook.

The provider performs the steps it is asked for and reports what happened
as facts. The package ships default strategies that reproduce today's
behaviour, and the consumer may replace either.

**Success:**
- No renewal or persistence policy is left in `BaseTokenProvider`.
- A consumer that wants another behaviour (never log in from a headless
  server, keep a refresh token after a `5xx`, renew on a `403`, persist
  synchronously or not at all) picks or writes a strategy and changes no
  provider.
- A refresh token the server never received is never treated as spent.

## Why

The provider decides today what the consumer should:
- after any failed refresh, it logs in once (rule 6);
- after a cut refresh, it discards the refresh token for good;
- it decides what persistence is told, and re-sends it when the consumer's
  own `onTokens` fails.

This package's rule is that such decisions are the consumer's, made by
injecting a strategy. Its cost already shows. A refresh cut before it was
sent is cleared from storage. Memory and storage drift out of step, because
the persistence rules of one consumer (the broker over auth-stores) live in
every provider. No OAuth document defines those rules: RFC 6749 §6 says only
that a new refresh token replaces the old one and that, when none is issued,
the old one stands.

## What changes, by repository

1. **`@mcp-abap-adt/interfaces-auth`** — the contracts of both strategies,
   types and constants only; released first.
2. **`@mcp-abap-adt/auth-providers` 6.0.0** — the providers take both
   strategies. The policy moves out of `BaseTokenProvider` into the shipped
   default strategies. The docs are rewritten.
3. **`@mcp-abap-adt/auth-broker` 5.0.0** — composes both strategies for the
   providers it builds, over its stores.
4. **`@mcp-abap-adt/auth-stores` 4.0.0** — stores what the broker's
   persistence strategy writes.

Every other package the change reaches moves with it.

## Holds throughout

1. **The consumer composes.** Every decision a consumer might want to make
   differently is a strategy's. The package offers defaults and has no
   implicit ones: the provider never builds a strategy of its own.
2. **Facts, not verdicts.** The provider tells a strategy only what it knows
   for certain. "Not sent" and "sent, outcome unknown" are different facts.
3. **No hidden step.** The provider runs no refresh, login or write that a
   strategy did not ask for, and no retry, backoff or timer of its own.
4. **The provider's own correctness stays the provider's.** These are not
   policy and are not delegated:
   - what it holds and what it returns always agree;
   - a late result never overwrites a newer one;
   - a refresh token discarded is never sent again;
   - certificate pinning and binding (rule 8);
   - releasing what it owns.
5. **The error contract is untouched.** Every failure is a minted
   `IAuthProviderError`, and no exception crosses `IAuthProvider`. A renewal
   strategy never sees a token or any thrown value's text. The persistence
   strategy is the consumer's store, so it alone receives token values.
6. **A strategy is foreign code.** What it throws or answers is classified,
   never relayed as itself; an invalid answer is refused, not guessed at.
7. **A strategy's failure is its own.** When a strategy fails, the call that
   asked it fails, and nothing that happened earlier is undone. A strategy
   that wants to carry on handles its own failure.
8. **Cancellation stays safe.** Cutting a renewal never waits on a strategy
   and never leaves a refresh token in an undecided state.
9. **Rule 5 is a reading, not a guard.** The provider still tells a
   credential refusal from any other. Whether to renew on either is the
   strategy's.

## Out of scope

- Moving the login out of the provider: a strategy decides whether one
  happens, and the provider performs it through the authorization strategy
  it was given.
- Non-token credentials: they have nothing to renew.

## Open — for the spec

1. The shape of each strategy and of the facts it receives.
2. The default strategies: their names and what each decides.
3. How a cut refresh is decided without waiting on a strategy.
4. Whether `refreshTokenDisposition` stays on what `getTokens()` returns.
5. Whether `TokenAuthProvider.from(refresher)` takes a renewal strategy.
6. How the broker composes the strategies, and what its CLI exposes.
7. The versions every package of the change moves to.
