/**
 * Persistence strategies for the suites: one that
 * records every report as the provider made it, and one that records what
 * `refreshStatePersistence` writes — the behaviour `onTokens` had before
 * 6.0.0, read back in its words.
 */

import type {
  ITokenPersistence,
  PersistenceReport,
} from '@mcp-abap-adt/interfaces-auth';
import {
  type PersistedTokens,
  refreshStatePersistence,
} from '../../persistence';

/**
 * What a store was told for one write: the access token, the refresh token
 * written (a string) or none, and what the write does to the stored one —
 * `'replace'` (a string), `'clear'` (`null`) or `'keep'` (`undefined`), the
 * words the 5.x disposition used for the same three cases.
 */
export type Seen = [string, string | undefined, 'replace' | 'clear' | 'keep'];

export function seenOf(tokens: PersistedTokens): Seen {
  const { refreshToken } = tokens;
  if (typeof refreshToken === 'string') {
    return [tokens.authorizationToken, refreshToken, 'replace'];
  }
  return [
    tokens.authorizationToken,
    undefined,
    refreshToken === null ? 'clear' : 'keep',
  ];
}

/**
 * `refreshStatePersistence(write, { onWriteFailure: 'continue' })` whose
 * `write` records each write as a `Seen`, and fails while `failing()` says
 * so (a thrown `Error` holding a secret).
 */
export function stateRecorder(failing: () => boolean = () => false): {
  readonly seen: Seen[];
  readonly writes: PersistedTokens[];
  readonly persistence: ITokenPersistence;
} {
  const seen: Seen[] = [];
  const writes: PersistedTokens[] = [];
  const persistence = refreshStatePersistence(
    async (tokens) => {
      writes.push(tokens);
      seen.push(seenOf(tokens));
      if (failing()) throw new Error('store unavailable: SECRET-STORE-TEXT');
    },
    { onWriteFailure: 'continue' },
  );
  return { seen, writes, persistence };
}

/**
 * A strategy that records every report, a deep copy taken when it arrives,
 * and answers what `answer` returns for it (nothing by default).
 */
export function reportRecorder(
  answer: (report: PersistenceReport, index: number) => unknown = () =>
    undefined,
): {
  readonly reports: PersistenceReport[];
  readonly persistence: ITokenPersistence;
} {
  const reports: PersistenceReport[] = [];
  const persistence: ITokenPersistence = {
    report(report) {
      reports.push(structuredClone(report));
      return answer(report, reports.length - 1) as void | Promise<void>;
    },
  };
  return { reports, persistence };
}
