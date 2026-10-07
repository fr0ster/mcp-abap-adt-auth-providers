/**
 * The shipped renewal strategies (spec §6c.8). The provider builds none of
 * its own (rule 7): the consumer gives one of these, or its own
 * `IRenewalStrategy`. Both are stateless and answer synchronously.
 */

import type {
  IRenewalStrategy,
  RenewalDecision,
  RenewalSituation,
} from '@mcp-abap-adt/interfaces-auth';

const STOP: RenewalDecision = Object.freeze({ next: 'stop' });
const LOGIN: RenewalDecision = Object.freeze({ next: 'login' });
const REFRESH: RenewalDecision = Object.freeze({
  next: 'refresh',
  ifCut: 'discard',
});

/**
 * The table of §6c.8. `login` is what the table answers where a login
 * follows; `refreshOnly()` passes `stop` in its place, with the same
 * `sentRefreshToken`.
 */
function decide(
  situation: RenewalSituation,
  login: 'login' | 'stop',
): RenewalDecision {
  const { cause, moment, canRefresh, steps } = situation;
  const last = steps[steps.length - 1];
  if (last === undefined) {
    // Rule 5's reading: a new credential would be refused the same way.
    if (cause.trigger === 'rejected' && cause.reading === 'not-credential') {
      return STOP;
    }
    // A held token whose last renewal did not make it usable is not renewed
    // again on its own; once per connect (`prepare`) and on a rejection it is.
    if (
      cause.trigger === 'bound-elsewhere' &&
      cause.lastRenewal !== undefined &&
      moment !== 'prepare' &&
      moment !== 'rejected'
    ) {
      return STOP;
    }
    if (canRefresh) return REFRESH;
    return login === 'login' ? LOGIN : STOP;
  }
  if (last.step === 'refresh' && last.outcome === 'failed') {
    // Sent and refused: that refresh token is spent. Not sent: it stands.
    if (last.sent)
      return Object.freeze({ next: login, sentRefreshToken: 'discard' });
    return login === 'login' ? LOGIN : STOP;
  }
  // A refresh that obtained a credential that is not the one wanted, or any
  // login: the renewal ends.
  return STOP;
}

/**
 * One refresh, then — when there is no refresh token, or the refresh
 * failed — one login. A refresh refused after it was sent discards its
 * refresh token; one that failed before it was sent leaves it held. A
 * refresh cut after dispatch discards it (`ifCut: 'discard'`).
 */
export function refreshThenLogin(): IRenewalStrategy {
  return Object.freeze({
    next: (situation: RenewalSituation) => decide(situation, 'login'),
  });
}

/**
 * `refreshThenLogin()` without the login: a renewal that cannot refresh
 * stops — for a consumer with no one to log in (a headless server).
 */
export function refreshOnly(): IRenewalStrategy {
  return Object.freeze({
    next: (situation: RenewalSituation) => decide(situation, 'stop'),
  });
}
