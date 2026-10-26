/**
 * Checking a renewal strategy's decision: the type proves its shape, so only
 * the rules the type cannot express are checked, and the decision is copied
 * and frozen. A decision that breaks one is refused (`undefined`), never
 * guessed at.
 */

import type {
  RenewalDecision,
  RenewalStepOutcome,
  SentRefreshToken,
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
  // `next` is read once, as the switch's discriminant, which narrows
  // `decision` itself; every other field is read at most once, only where it
  // is used, and the copy is built from the values read — a getter answering
  // differently on a second read cannot pass a rule and be copied as another
  // value.
  switch (decision.next) {
    case 'refresh': {
      const sent = checkedSent(decision.sentRefreshToken, context);
      if (sent === false || !context.canRefresh) return undefined;
      const ifCut = decision.ifCut;
      return Object.freeze({ next: 'refresh', ifCut, ...sent });
    }
    case 'login': {
      const sent = checkedSent(decision.sentRefreshToken, context);
      if (sent === false) return undefined;
      return Object.freeze({ next: 'login', ...sent });
    }
    case 'stop': {
      const sent = checkedSent(decision.sentRefreshToken, context);
      if (sent === false) return undefined;
      return Object.freeze({ next: 'stop', ...sent });
    }
    default: {
      // Exhaustive by the compiler; a value no member names is refused, as
      // the dispatch would refuse it, never guessed at.
      const unreachable: never = decision;
      void unreachable;
      return undefined;
    }
  }
}

/**
 * The `sentRefreshToken` part of the copy, or `false` where the rule is
 * broken: required after a refresh that failed once sent, absent elsewhere.
 */
function checkedSent(
  sent: RenewalDecision['sentRefreshToken'],
  context: DecisionContext,
):
  | { readonly sentRefreshToken: SentRefreshToken }
  | Record<never, never>
  | false {
  if (context.sentRequired ? sent === undefined : sent !== undefined) {
    return false;
  }
  return sent === undefined ? {} : { sentRefreshToken: sent };
}
