# Renewal strategy — goal and path

**Status:** approved by the user 2026-10-07 (after four Codex adversarial
passes); **revised 2026-10-07 for the user's review** — what persistence is
told becomes a persistence strategy of its own (invariant 8, decided by the
user). Decided by the user
2026-10-07, in 6.0.0 and by the process: goal → spec → plan, each reviewed,
all in PR #68. This file is the anchor for the renewal part of 6.0.0; the
error contract's goal (`2026-10-05-error-contract-goal.md`) still binds
everything else. If the spec or the plan needs to depart from anything under
*Holds throughout*, this file changes first — explicitly, in review.

## Goal

What a token provider does when its credential must be renewed — refresh,
log in, give up, how many times, and what persistence is told about the
refresh token — is decided by a **renewal strategy the consumer injects**,
like every other pluggable decision in this package. What persistence is
told about the tokens — when to write, what to clear, what to do when a
write fails — is decided by a **persistence strategy the consumer injects**
beside it, replacing the `onTokens` hook. The provider performs the steps it
is asked for and reports what happened in facts; it decides nothing a
consumer might reasonably want to decide differently.

**Success:** no renewal policy is left in `BaseTokenProvider`. A consumer
that wants today's behaviour composes it from a shipped, named factory; one
that wants another (never log in from a headless server, log in without
refreshing, keep a refresh token after a `5xx`, discard it after a cut
refresh on a rotating endpoint) writes or picks a strategy and changes no
provider. Codex's finding of 2026-10-07 — a refresh cut during OIDC discovery,
before anything was sent, quarantines the refresh token and tells
persistence to clear it — cannot happen, because the provider no longer
decides that a refresh token is spent.

## Why

Rule 6 (5.0.0 spec, `7138d0d`, from the review of #55) fixed one policy in
the provider: one refresh, then — on any refresh failure — one login. The
error contract's §6b then added more policy on top: a refresh token cut after
dispatch is tombstoned for the provider's lifetime, any discarded refresh
token is cleared from persistence (`refreshTokenDisposition: 'clear'`), a
failed notification is re-sent on the next commit. Each piece answers a real
case, but each is the provider deciding for the consumer — the user's
standing rule is that such decisions are the consumer's, made by injecting a
strategy. The defect Codex found is a symptom: a decision the provider
should not make, made on facts it misread (a cut before dispatch is not a
spent token).

The persistence bookkeeping is the same pattern one level down. The logical
`held` / `cleared` state, `refreshTokenDisposition`, and the re-sending of a
`'clear'` or `'replace'` whose `onTokens` failed exist only because one
consumer — the broker over auth-stores, which falls back to the stored
refresh token on `'keep'` — persists that way. No OAuth document defines
them (RFC 6749 §6 gives only "a new refresh token replaces the old; none
issued, the old stands"; RFC 9700 §4.14.2's reuse detection is the
server's). A consumer without a store needs none of it; one with another
store would want other rules; and a failed `onTokens` is the consumer's own
code failing. Living in `BaseTokenProvider`, it is the place four Codex
passes over the spec kept finding memory and storage out of step.

## What changes, by repository

1. **`@mcp-abap-adt/interfaces-auth`** — the renewal strategy's contract
   (the facts a step reports, the decision a strategy returns, the strategy
   interface) and the persistence strategy's (the events the provider
   reports, the strategy interface). Types and constants only. A major
   (7.0.0, spec §6c.9): a new error kind, and `onTokens` replaced; released
   first.
2. **`@mcp-abap-adt/auth-providers` 6.0.0** — in this PR: every token
   provider takes the strategy (required, rule 7); `BaseTokenProvider`
   performs steps and reports facts; the policy now in it (rule 6's fixed
   order, §6b's quarantine and clearing, the logical refresh state) moves
   into shipped factories or goes; the persistence bookkeeping (logical
   refresh state, dispositions, re-delivery after a failed write) moves into
   a shipped persistence factory; rule 6, §6b, the README and the migration
   notes are rewritten.
3. **`@mcp-abap-adt/auth-broker` 5.0.0** (Task 34, already planned) — composes
   a renewal strategy for each provider it builds (its default the shipped
   factory that reproduces today's behaviour) and a persistence strategy
   over its stores (the shipped persistence factory, writing through the
   broker's session store).
4. **`@mcp-abap-adt/auth-stores` 4.0.0** (Task 33) — accepts what the
   shipped persistence factory writes; whether that is still
   `refreshTokenDisposition` the spec decides.

## Holds throughout

1. **The consumer composes; the provider does not guess.** Every renewal
   decision — whether to refresh, whether and how often to log in, when to
   stop, whether a refresh token whose fate is uncertain (refused, cut after
   dispatch, failed) is kept or discarded — is the strategy's. What is
   certain is not a decision: a result carrying a new usable refresh token
   replaces the held one, and a step that changed nothing keeps it. No
   implicit default: the strategy is a constructor argument; shipped
   factories name common recipes.
2. **The provider reports facts, never a verdict it made up.** After each
   step the strategy learns what the provider knows for certain: whether a
   request was sent at all, what the server answered (an integer status, a
   registered OAuth `error`, an allowlisted code — the error contract's
   facts, nothing else), whether the attempt was aborted before or after
   dispatch. "Not sent" and "sent, outcome unknown" are different facts.
3. **No hidden step.** The provider never runs a refresh or a login the
   strategy did not ask for, and never runs more than it asked for. The
   strategy alone decides how many steps one renewal takes; the provider
   carries no retry, no backoff and no timer of its own (the user's rule:
   no built-in timeouts).
4. **What is the provider's own stays the provider's.** Correctness of its
   own state is not policy and is not delegated: shared attempts and their
   waiters, the serialized commit queue and its generations (a late result
   never overwrites a newer one), certificate pinning and binding (rule 8),
   a renewal that yields the credential that was refused (`renewal-unchanged`),
   and releasing what it owns (sockets, children). These stay as they are
   unless the spec shows one of them is policy.
5. **The error contract is untouched.** Every failure is still a minted
   `IAuthProviderError`; no exception crosses `IAuthProvider` (rule 1); no
   secret and no server text in a fact, a log line or anything a strategy
   receives — a strategy gets facts, never a token, a refresh token's value or
   an error's message.
6. **A strategy is foreign code.** Whatever it throws or answers is read
   like any collaborator's: classified, never relayed as itself; a decision
   that is not one of the contract's is refused, not guessed at.
7. **A decision applies to the attempt and the credential it concerns, and
   to nothing newer.** A renewal can be cut while its refresh is on the wire,
   its slot freed at once and a replacement started (§6b); the cut refresh's
   answer may still arrive. So a strategy's decision is scoped to one attempt
   and to the refresh token that attempt sent, identified without the
   strategy ever seeing its value; a decision about a cut refresh (discard
   the token it sent, or keep it) takes effect before any replacement attempt
   can dispatch that token. **That decision is taken before dispatch, as part
   of the decision to refresh** ("refresh; if cut after dispatch, keep or
   discard what was sent"): at the abort the provider applies an answer it
   already holds, synchronously, calling no foreign code — so a cut never
   waits on a strategy, needs no timer, and has no undecided state. A
   strategy that throws, answers no valid decision or never settles while
   being asked for the **next** step: that step sends nothing and changes no
   credential, and the renewal ends with the strategy's failure (classified,
   invariant 6) or waits for the consumer's signal, like any collaborator.
   What earlier steps of the same renewal already applied through the commit
   queue — an adopted rotated refresh token, a discard — stays applied; and
   a decision that settles late is checked like any step before dispatch
   (the attempt not aborted, its generation still current). And a decision or a late result of an older
   attempt never changes state a newer one committed (the generations of the
   commit queue). Whether one strategy instance serves every attempt, and
   what state it may keep across them, the spec decides; the provider's
   guarantees above hold whatever the strategy keeps.
8. **The provider is coherent in itself; persistence is the persistence
   strategy's** (revised 2026-10-07, decided by the user). Two halves:
   - *The provider's own correctness.* What it holds and what it returns
     from `getTokens()` / `refreshTokens()` never disagree: a kept refresh
     token survives a result that carries none, a discarded one is never
     installed or sent again, a late result never overwrites a newer one.
     It reports every change of its credentials to the persistence strategy
     as facts — a credential committed (the access token, and a new refresh
     token or none), a refresh token discarded — once each, in commit order,
     generation-safe, from the commit queue, and never repeats a report on
     its own. **A report the strategy fails fails the call that caused it:**
     what it throws (or rejects with) is classified, like any collaborator's,
     and is what that `getTokens()` / `refreshTokens()` / moment answers; the
     committed credentials stay committed in memory (they are the server's
     state). Best effort is not the provider's choice: a strategy that wants
     to go on after a failed write catches its own failure. The persistence
     strategy is the one collaborator that receives token values: it is the
     consumer's store.
   - *The persistence strategy's decisions.* What is written, what is
     cleared, how a store that falls back to a stored refresh token is kept
     from restoring a discarded one, and what happens after a failed write
     (retry, re-send with the next report, give up) are its own. The shipped
     factory keeps today's guarantees for the broker's store: best effort
     (it catches a failed write, logs it in fixed words and goes on, as
     `onTokens` failures do today), a discarded refresh token never restored
     by a later write, and a failed `'clear'` or `'replace'` delivered again
     with the next report.
     Without a persistence strategy nothing is persisted.
9. **Rule 5 is a reading, not a guard** (decided by the user 2026-10-07).
   The provider still reads every rejection by rule 5 — a `401` or
   `RFC_LOGON_FAILURE` is the credential's; a `403`, a redirect, a `5xx`,
   any other status or RFC key is not; neither is unknown — and hands that
   reading to the strategy as a fact, beside the status or key it came
   from. Whether to renew on it is the strategy's: the shipped factories
   renew only on the credential's or an unknown rejection and answer the
   rest with rule 5's `system-refused`, as today; a consumer's own strategy
   may renew on a `403` (a system that answers an expired session so). The
   refusal a moment answers when the strategy declines stays rule 5's
   neutral one.

## Out of scope

- Moving the login out of the provider altogether (the consumer calling
  login itself): the strategy decides whether one happens; the provider
  still performs it through the authorization strategy it was given.
- Non-token credentials (`BasicAuthProvider`, `CertificateAuthProvider`,
  `SamlAuthProvider`, `SncLogonProvider`): nothing to renew.
- Codex's second finding of 2026-10-07 (a callback socket with an unfinished
  body kept referenced after an abort): resource release, the provider's own
  (invariant 4); fixed in this PR on its own, not part of this goal.

## Open — for the spec

1. The shape of the strategy: one call per step (facts in, next decision
   out), or one call per renewal returning a plan; how a strategy is told
   which steps are possible for this provider (a refresh grant, a refresh
   token held, an interactive strategy or none).
2. How each trigger is told to the strategy, as a sanitized fact so a
   recipe cannot conflate them: no token yet (`prepare()`, first
   `getTokens()`), an expired token, a held token bound elsewhere (rule 8),
   an explicit `refreshTokens()`, and a rejection.
3. What of §6b's mechanisms goes: the lifetime tombstones become the
   discard decision of invariant 7 and stay in the provider; the logical
   `cleared` state and the pending disposition move into the shipped
   persistence factory (invariant 8).
7. The persistence strategy's shape: the events and their fields, whether
   it is awaited (the commit queue today awaits `onTokens`), and whether
   `ITokenResult.refreshTokenDisposition` stays on what `getTokens()`
   returns or goes with the bookkeeping.
4. The shipped factories, by name and behaviour — at least one reproducing
   5.x (refresh, then on its failure one login) and one that never logs in.
5. `TokenAuthProvider.from(refresher)`: whether its renewal takes the same
   strategy, or stays the refresher's own.
6. How the broker composes it, and what its CLI exposes.

## Path

Order, not dates.

1. This goal, reviewed and approved.
2. The spec — a new section of `specs/2026-10-05-error-contract-design.md`
   replacing §6b's renewal rules and rule 6 — reviewed and approved.
3. The plan — new tasks in `plans/2026-10-05-error-contract.md`, before
   Task 31 (the release) — reviewed and approved.
4. interfaces-auth 7.0.0 (and the cascade of spec §6c.9), released.
5. auth-providers: implementation in this PR, then Task 31 resumes.
6. Tasks 32–35 as planned, the broker composing the strategy in Task 34.
