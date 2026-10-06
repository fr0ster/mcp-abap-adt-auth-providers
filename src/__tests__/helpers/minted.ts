import { expect } from '@jest/globals';
import { isMinted } from '@mcp-abap-adt/auth-errors';
import type { AuthOutcome, IAuthRefusal } from '@mcp-abap-adt/interfaces-auth';
import type { IAuthProviderError } from '../../auth/contractTransition';

/**
 * The refusal of an outcome as the error auth-errors minted: fails the test
 * when the outcome is Ok or its refusal was not minted (a 4.x `oops`).
 */
export function mintedRefusal(outcome: AuthOutcome): IAuthProviderError {
  if (outcome.ok) throw new Error('expected a refusal, got Ok');
  return minted(outcome.refusal);
}

/** A refusal as the error auth-errors minted, else the test fails. */
export function minted(refusal: IAuthRefusal | undefined): IAuthProviderError {
  expect(isMinted(refusal)).toBe(true);
  if (!isMinted(refusal)) throw new Error('not minted');
  return refusal;
}

/** The keys a refusal may carry: 4.x's words, and a minted error's own. */
const REFUSAL_KEYS: readonly string[] = [
  'kind',
  'variant',
  'facts',
  'reason',
  'hint',
  'diagnostics',
];

/**
 * An outcome as 5.4.2's tests read it: `ok`, and the refusal's `reason` and
 * `hint` (only when it has one) — the words, without the 5.x `kind` and
 * `facts` the row tests assert (TRANSITION, Task 27 restates these tests on
 * kinds). The whole outcome is still checked: the outcome holds no key but
 * `ok` and `refusal`, and the refusal none outside a minted error's keys, so
 * a stray field fails the test as the whole-outcome `toEqual` did.
 */
export function wordsOf(
  outcome: AuthOutcome,
): { ok: true } | { ok: false; refusal: { reason: string; hint?: string } } {
  expect(
    Object.keys(outcome).filter(
      (key) => key !== 'ok' && (outcome.ok || key !== 'refusal'),
    ),
  ).toEqual([]);
  if (outcome.ok) return { ok: true };
  expect(
    Object.keys(outcome.refusal).filter((key) => !REFUSAL_KEYS.includes(key)),
  ).toEqual([]);
  const { reason, hint } = outcome.refusal;
  return {
    ok: false,
    refusal: hint === undefined ? { reason } : { reason, hint },
  };
}
