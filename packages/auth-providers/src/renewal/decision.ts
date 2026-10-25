/**
 * Reading a renewal strategy's answer: the strategy is
 * foreign code, so its answer is read like any collaborator's — every field
 * through `readSafely`, never trusted as it is. An answer that is not a
 * valid decision for the situation is refused (`undefined`), never guessed
 * at.
 */

import type {
  RenewalDecision,
  RenewalStepOutcome,
  SentRefreshToken,
} from '@mcp-abap-adt/interfaces-auth';
import { readSafely } from '../auth/knownCodes';

/** What decides whether a decision is valid, beside the answer itself. */
export interface DecisionContext {
  /** A refresh is possible now (`RenewalSituation.canRefresh`). */
  readonly canRefresh: boolean;
  /**
   * The last step was a refresh that failed after it was sent:
   * `sentRefreshToken` is then required, and absent anywhere else.
   */
  readonly sentRequired: boolean;
}

/** True after a refresh that failed once it was sent (no default). */
export function needsSentDecision(
  steps: readonly RenewalStepOutcome[],
): boolean {
  const last = steps[steps.length - 1];
  return (
    last !== undefined &&
    last.step === 'refresh' &&
    last.outcome === 'failed' &&
    last.sent
  );
}

function isSentRefreshToken(value: unknown): value is SentRefreshToken {
  return value === 'keep' || value === 'discard';
}

/**
 * The decision `answer` states, as a fresh frozen object — or `undefined`
 * for anything else: a non-object, an unknown `next`, a `refresh` without a
 * valid `ifCut` or with no refresh possible, a `sentRefreshToken` where it
 * must be absent, or missing (or not `keep` / `discard`) where it is
 * required. Never throws: a throwing getter or Proxy reads as absent.
 */
export function readDecision(
  answer: unknown,
  context: DecisionContext,
): RenewalDecision | undefined {
  if (answer === null || typeof answer !== 'object') return undefined;
  const next = readSafely(answer, 'next');
  const sent = readSafely(answer, 'sentRefreshToken');
  if (context.sentRequired ? !isSentRefreshToken(sent) : sent !== undefined) {
    return undefined;
  }
  const sentPart = isSentRefreshToken(sent) ? { sentRefreshToken: sent } : {};
  if (next === 'refresh') {
    const ifCut = readSafely(answer, 'ifCut');
    if (!isSentRefreshToken(ifCut) || !context.canRefresh) return undefined;
    return Object.freeze({ next, ifCut, ...sentPart });
  }
  if (next === 'login' || next === 'stop') {
    return Object.freeze({ next, ...sentPart });
  }
  return undefined;
}
