/**
 * Checking a renewal strategy's decision: the type proves its shape, so only
 * the rules the type cannot express are checked, and the decision is copied
 * and frozen. A decision that breaks one is refused (`undefined`), never
 * guessed at.
 */

import type {
  RenewalDecision,
  RenewalStepOutcome,
} from '@mcp-abap-adt/interfaces-auth';

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

/**
 * The decision `decision` states, as a fresh frozen copy — or `undefined`
 * where a rule the type cannot express is broken: a `refresh` with no
 * refresh possible, a `sentRefreshToken` where it must be absent, or missing
 * where it is required. A read of a foreign object may throw: the caller
 * calls this inside the strategy-failure boundary.
 */
export function checkDecision(
  decision: RenewalDecision,
  context: DecisionContext,
): RenewalDecision | undefined {
  const sent = decision.sentRefreshToken;
  if (context.sentRequired ? sent === undefined : sent !== undefined) {
    return undefined;
  }
  const sentPart = sent === undefined ? {} : { sentRefreshToken: sent };
  if (decision.next === 'refresh') {
    if (!context.canRefresh) return undefined;
    return Object.freeze({
      next: decision.next,
      ifCut: decision.ifCut,
      ...sentPart,
    });
  }
  return Object.freeze({ next: decision.next, ...sentPart });
}
