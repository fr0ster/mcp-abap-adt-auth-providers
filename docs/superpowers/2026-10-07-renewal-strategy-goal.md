# Renewal strategy — goal and path

**Status:** draft for the user's review (2026-10-07). Decided by the user
2026-10-07, in 6.0.0 and by the process: goal → spec → plan, each reviewed,
all in PR #68. This file is the anchor for the renewal part of 6.0.0; the
error contract's goal (`2026-10-05-error-contract-goal.md`) still binds
everything else. If the spec or the plan needs to depart from anything under
*Holds throughout*, this file changes first — explicitly, in review.

## Goal

What a token provider does when its credential must be renewed — refresh,
log in, give up, how many times, and what persistence is told about the
refresh token — is decided by a **renewal strategy the consumer injects**,
like every other pluggable decision in this package. The provider performs
the steps it is asked for and reports what happened in facts; it decides
nothing a consumer might reasonably want to decide differently.

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

## What changes, by repository

1. **`@mcp-abap-adt/interfaces-auth`** — the renewal strategy's contract:
   the facts a step reports, the decision a strategy returns, the strategy
   interface. Types and constants only. Additive, so a minor (6.1.0) unless
   the spec finds an existing type must change; released first.
2. **`@mcp-abap-adt/auth-providers` 6.0.0** — in this PR: every token
   provider takes the strategy (required, rule 7); `BaseTokenProvider`
   performs steps and reports facts; the policy now in it (rule 6's fixed
   order, §6b's quarantine and clearing, the logical refresh state) moves
   into shipped factories or goes; rule 6, §6b, the README and the migration
   notes are rewritten.
3. **`@mcp-abap-adt/auth-broker` 5.0.0** (Task 34, already planned) — composes
   a strategy for each provider it builds; its default is the shipped factory
   that reproduces today's behaviour, unless the spec decides otherwise.
4. **`@mcp-abap-adt/auth-stores` 4.0.0** (Task 33) — unchanged in scope:
   it accepts `refreshTokenDisposition`; what writes `'clear'` changes, not
   the field.

## Holds throughout

1. **The consumer composes; the provider does not guess.** Every renewal
   decision — whether to refresh, whether and how often to log in, when to
   stop, whether a refresh token is kept, replaced or cleared — is the
   strategy's. No implicit default: the strategy is a constructor argument;
   shipped factories name common recipes.
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
2. Which moments it governs — `getTokens()` on an expired token,
   `refreshTokens()`, `authorize()`, `rejected()` — and whether `rejected()`
   tells it the rejection's facts (a `401` against a `403`).
3. Who decides `refreshTokenDisposition`: the strategy for every outcome, or
   the provider for the certain ones (a new refresh token → `'replace'`) and
   the strategy for the uncertain ones (refused, cut, failed).
4. What of §6b goes and what stays: the lifetime tombstones, the logical
   `cleared` state, the pending re-sent disposition after a failed
   `onTokens` — each either a shipped strategy's choice, the provider's own
   correctness (invariant 4), or gone.
5. The shipped factories, by name and behaviour — at least one reproducing
   5.x (refresh, then on its failure one login) and one that never logs in.
6. `TokenAuthProvider.from(refresher)`: whether its renewal takes the same
   strategy, or stays the refresher's own.
7. How the broker composes it, and what its CLI exposes.

## Path

Order, not dates.

1. This goal, reviewed and approved.
2. The spec — a new section of `specs/2026-10-05-error-contract-design.md`
   replacing §6b's renewal rules and rule 6 — reviewed and approved.
3. The plan — new tasks in `plans/2026-10-05-error-contract.md`, before
   Task 31 (the release) — reviewed and approved.
4. interfaces-auth minor, released.
5. auth-providers: implementation in this PR, then Task 31 resumes.
6. Tasks 32–35 as planned, the broker composing the strategy in Task 34.
