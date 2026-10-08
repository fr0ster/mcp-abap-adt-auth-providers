/**
 * The shipped persistence strategy: the guarantees `onTokens`
 * and the provider's refresh-token disposition gave before 6.0.0, kept here
 * for a store that falls back to its stored refresh token when a write
 * carries none — as the broker's does. The provider builds none of its own
 * (rule 7): the consumer gives this, or its own `ITokenPersistence`.
 */

import { authError, classify, logFields } from '@mcp-abap-adt/auth-errors';
import type {
  ITokenPersistence,
  OAuth2GrantType,
  PersistenceReport,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { misconfigured, ownOptions } from '../auth/configuration';
import { logQuietly } from '../auth/tokenRequest';

/** What one write hands the store. */
export interface PersistedTokens {
  /** `''` when no access token is held. */
  readonly authorizationToken: string;
  readonly tokenType: 'jwt' | 'saml' | 'opaque';
  readonly authType?: OAuth2GrantType | undefined;
  readonly expiresAt?: number | undefined;
  /**
   * A string: write it. `null`: clear the stored one. `undefined`: leave
   * the stored one as it is.
   */
  readonly refreshToken: string | null | undefined;
}

export interface RefreshStatePersistenceOptions {
  /**
   * Required, no default: whether a failed write fails an awaited report —
   * and with it the call that caused it (`'fail'`) — or is only logged
   * (`'continue'`). Either way the write is delivered again by the next
   * report. Missing or any other value: refused at construction,
   * `configuration` `invalid-value` naming `onWriteFailure` (a `write` that
   * is not a function is refused the same way, naming `write`).
   */
  readonly onWriteFailure: 'continue' | 'fail';
  /** Where a failed write is logged, in fixed words. */
  readonly logger?: ILogger | undefined;
}

/** A report, copied when it arrives: the fields the factory reads. */
type Taken =
  | {
      readonly event: 'credential';
      readonly tokens: Omit<PersistedTokens, 'refreshToken'>;
      readonly fresh: string | undefined;
      readonly awaited: boolean;
    }
  | {
      readonly event: 'refresh-token-discarded';
      readonly tokens: Omit<PersistedTokens, 'refreshToken'>;
      readonly awaited: boolean;
    };

function taken(report: PersistenceReport): Taken {
  const { credential } = report;
  const tokens = {
    authorizationToken: credential.authorizationToken,
    tokenType: credential.tokenType,
    authType: credential.authType,
    expiresAt: credential.expiresAt,
  };
  const awaited = report.awaited === true;
  if (report.event === 'refresh-token-discarded') {
    return { event: report.event, tokens, awaited };
  }
  const change = report.refreshToken;
  return {
    event: 'credential',
    tokens,
    fresh: change.change === 'new' ? change.value : undefined,
    awaited,
  };
}

/**
 * Refused at construction, naming each option that cannot be used:
 * `onWriteFailure` when it is missing or not `'continue'` / `'fail'`,
 * `write` when it is not a function — both when both.
 */
function unusable(fields: readonly ('onWriteFailure' | 'write')[]): never {
  throw misconfigured(
    authError.configuration({ case: 'invalid-value', fields: [...fields] }),
  );
}

/**
 * A persistence strategy over `write`:
 *
 * - **One write at a time, in report order.** Every report — a detached one
 *   too, which the provider does not await — is processed only after the
 *   previous report's write has settled, and the state below changes only
 *   inside that sequence, so an older write never lands after a newer one.
 *   An awaited report's promise settles when its own turn ends.
 * - **The logical state**, `held` or — after a `refresh-token-discarded` —
 *   `cleared`. A `credential` report with a new refresh token writes it and
 *   moves to `held`; with none it writes `null` while `cleared`, `undefined`
 *   while `held`. A discard writes the reported credential with `null`. So
 *   a store's fallback to its stored refresh token can never restore a
 *   discarded one, and a discard before any credential report clears the
 *   refresh token without erasing the session.
 * - **Pending delivery.** A failed write is logged in fixed words. A failed
 *   `null` stays in the logical state; a failed new refresh token stays
 *   pending and is written again, with that token, by the next report, until
 *   one write succeeds or a newer new token or a discard supersedes it.
 * - **`onWriteFailure`.** `'continue'`: `report` never throws. `'fail'`: an
 *   awaited report rethrows the write's failure, after recording it as
 *   pending; a detached report never throws.
 *
 * It holds the last new refresh token it could not write: it is part of the
 * consumer's store.
 */
export function refreshStatePersistence(
  write: (tokens: PersistedTokens) => Promise<void>,
  options: RefreshStatePersistenceOptions,
): ITokenPersistence {
  // Read once as own data: an accessor on the options is never run.
  const own = ownOptions<RefreshStatePersistenceOptions>(options);
  const { onWriteFailure, logger } = own;
  const wrong: ('onWriteFailure' | 'write')[] = [];
  if (onWriteFailure !== 'continue' && onWriteFailure !== 'fail') {
    wrong.push('onWriteFailure');
  }
  if (typeof write !== 'function') wrong.push('write');
  if (wrong.length > 0) unusable(wrong);

  let state: 'held' | 'cleared' = 'held';
  let pending: string | undefined;
  let turns: Promise<void> = Promise.resolve();

  /** One report's turn: decide, write, record — never two at once. */
  const process = async (report: Taken): Promise<void> => {
    let refreshToken: string | null | undefined;
    // `pending` is read only while `held` and with no new token; the write
    // below sets or clears it whenever a token is written, so a discard or a
    // new token needs no reset of its own.
    if (report.event === 'refresh-token-discarded') {
      state = 'cleared';
      refreshToken = null;
    } else if (report.fresh !== undefined) {
      state = 'held';
      refreshToken = report.fresh;
    } else if (state === 'cleared') {
      refreshToken = null;
    } else {
      refreshToken = pending;
    }
    try {
      await write({ ...report.tokens, refreshToken });
      if (typeof refreshToken === 'string') pending = undefined;
    } catch (error) {
      if (typeof refreshToken === 'string') pending = refreshToken;
      // Fixed words only: the store's message is foreign text.
      logQuietly(() =>
        logger?.warn(
          '[refreshStatePersistence] Writing the tokens failed',
          logFields(classify(error, 'persisting-tokens')),
        ),
      );
      if (onWriteFailure === 'fail' && report.awaited) throw error;
    }
  };

  return Object.freeze({
    report(report: PersistenceReport): Promise<void> {
      let turn: Promise<void>;
      try {
        const copy = taken(report);
        turn = turns.then(() => process(copy));
      } catch (error) {
        turn = Promise.reject(error);
      }
      turns = turn.then(
        () => undefined,
        () => undefined,
      );
      return turn;
    },
  });
}
