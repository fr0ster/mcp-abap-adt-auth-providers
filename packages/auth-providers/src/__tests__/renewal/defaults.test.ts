/**
 * The two shipped renewal strategies, each against its table
 * alone, row by row: `refreshThenLogin()` decides what the provider decided
 * before 6.0.0 — except that a refresh which failed before it was sent no
 * longer discards the refresh token — and `refreshOnly()` is the same table
 * with `login` replaced by `stop`. Both are stateless.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { authError, httpStatus } from '@mcp-abap-adt/auth-errors';
import type {
  RenewalCause,
  RenewalMoment,
  RenewalSituation,
  RenewalStepOutcome,
} from '@mcp-abap-adt/interfaces-auth';
import { refreshOnly, refreshThenLogin } from '../../renewal';
import { caseTitle, notMatchObject } from '../helpers/expectations';

const refused = authError['credential-refused']({
  credential: 'refresh-token',
});
const remembered = authError['token-binding']({
  problem: 'renewed-bound-elsewhere',
});
const status = httpStatus(403);
if (status === undefined) throw new Error('403 is an HTTP status');
const systemRefused = authError['system-refused']({
  verdict: 'not-authorized',
  status,
  at: 'request',
});

function situation(partial: Partial<RenewalSituation> = {}): RenewalSituation {
  return {
    cause: { trigger: 'expired' },
    moment: 'get-tokens',
    canRefresh: true,
    steps: [],
    ...partial,
  };
}

const failedSent: RenewalStepOutcome = {
  step: 'refresh',
  outcome: 'failed',
  sent: true,
  error: refused,
};
const failedUnsent: RenewalStepOutcome = {
  step: 'refresh',
  outcome: 'failed',
  sent: false,
  error: refused,
};

/** The table of defaults, with what each factory decides per row. */
const ROWS: ReadonlyArray<{
  readonly row: string;
  readonly situation: RenewalSituation;
  readonly refreshThenLogin: object;
  readonly refreshOnly: object;
}> = [
  {
    row: 'rejected, reading not-credential → stop',
    situation: situation({
      cause: {
        trigger: 'rejected',
        reading: 'not-credential',
        refusal: systemRefused,
        at: 'request',
      },
      moment: 'rejected',
    }),
    refreshThenLogin: { next: 'stop' },
    refreshOnly: { next: 'stop' },
  },
  ...(['get-tokens', 'refresh-tokens', 'authorize'] as RenewalMoment[]).map(
    (moment) => ({
      row: `bound-elsewhere with lastRenewal, moment ${moment} → stop`,
      situation: situation({
        cause: { trigger: 'bound-elsewhere', lastRenewal: remembered },
        moment,
      }),
      refreshThenLogin: { next: 'stop' },
      refreshOnly: { next: 'stop' },
    }),
  ),
  ...(['prepare', 'rejected'] as RenewalMoment[]).map((moment) => ({
    row: `bound-elsewhere with lastRenewal, moment ${moment} → renews`,
    situation: situation({
      cause: { trigger: 'bound-elsewhere', lastRenewal: remembered },
      moment,
    }),
    refreshThenLogin: { next: 'refresh', ifCut: 'discard' },
    refreshOnly: { next: 'refresh', ifCut: 'discard' },
  })),
  ...(
    [
      { trigger: 'no-token' },
      { trigger: 'expired' },
      { trigger: 'explicit' },
      { trigger: 'bound-elsewhere' },
      { trigger: 'rejected', reading: 'credential', at: 'request' },
      { trigger: 'rejected', reading: 'unknown', at: 'logon' },
    ] as RenewalCause[]
  ).flatMap((cause) => [
    {
      row: `${cause.trigger}${'reading' in cause ? ` ${cause.reading}` : ''}, no step yet, canRefresh → refresh, ifCut discard`,
      situation: situation({ cause, canRefresh: true }),
      refreshThenLogin: { next: 'refresh', ifCut: 'discard' },
      refreshOnly: { next: 'refresh', ifCut: 'discard' },
    },
    {
      row: `${cause.trigger}${'reading' in cause ? ` ${cause.reading}` : ''}, no step yet, no refresh → login`,
      situation: situation({ cause, canRefresh: false }),
      refreshThenLogin: { next: 'login' },
      refreshOnly: { next: 'stop' },
    },
  ]),
  {
    row: 'last step a refresh that failed, sent → login, discard',
    situation: situation({ canRefresh: true, steps: [failedSent] }),
    refreshThenLogin: { next: 'login', sentRefreshToken: 'discard' },
    refreshOnly: { next: 'stop', sentRefreshToken: 'discard' },
  },
  {
    row: 'last step a refresh that failed, not sent → login',
    situation: situation({ canRefresh: true, steps: [failedUnsent] }),
    refreshThenLogin: { next: 'login' },
    refreshOnly: { next: 'stop' },
  },
  ...(['unchanged', 'bound-elsewhere'] as const).map((outcome) => ({
    row: `last step a refresh with outcome ${outcome} → stop`,
    situation: situation({
      canRefresh: true,
      steps: [{ step: 'refresh', outcome }],
    }),
    refreshThenLogin: { next: 'stop' },
    refreshOnly: { next: 'stop' },
  })),
  ...(
    [
      { step: 'login', outcome: 'failed', sent: true, error: refused },
      { step: 'login', outcome: 'failed', sent: false, error: refused },
      { step: 'login', outcome: 'unchanged' },
      { step: 'login', outcome: 'bound-elsewhere' },
    ] as RenewalStepOutcome[]
  ).map((last) => ({
    row: `last step a login (${last.outcome}${'sent' in last ? `, sent ${last.sent}` : ''}) → stop`,
    situation: situation({ canRefresh: false, steps: [failedSent, last] }),
    refreshThenLogin: { next: 'stop' },
    refreshOnly: { next: 'stop' },
  })),
];

describe('refreshThenLogin(): the table of defaults, row by row', () => {
  for (const [caseIndex, caseRow] of ROWS.map(
    (r) => [r.row, r] as const,
  ).entries()) {
    const [_row, r] = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), () => {
      assert.deepEqual(
        refreshThenLogin().next(r.situation),
        r.refreshThenLogin,
      );
    });
  }
});

describe('refreshOnly(): the same rows, login replaced by stop', () => {
  for (const [caseIndex, caseRow] of ROWS.map(
    (r) => [r.row, r] as const,
  ).entries()) {
    const [_row, r] = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), () => {
      assert.deepEqual(refreshOnly().next(r.situation), r.refreshOnly);
    });
  }

  it('never answers login, in any row', () => {
    for (const r of ROWS) {
      notMatchObject(refreshOnly().next(r.situation), {
        next: 'login',
      });
    }
  });
});

describe('both are stateless', () => {
  for (const [caseIndex, caseRow] of (
    [
      ['refreshThenLogin', refreshThenLogin],
      ['refreshOnly', refreshOnly],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: one instance answers every row as a fresh one does',
        caseRow,
        caseIndex,
      ),
      () => {
        const shared = make();
        for (const r of [...ROWS, ...ROWS]) {
          assert.deepEqual(shared.next(r.situation), make().next(r.situation));
        }
      },
    );
  }

  for (const [caseIndex, caseRow] of (
    [
      ['refreshThenLogin', refreshThenLogin],
      ['refreshOnly', refreshOnly],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: answers synchronously, with no `aborted` of its own',
        caseRow,
        caseIndex,
      ),
      () => {
        const strategy = make();
        assert.ok(!(strategy.next(situation()) instanceof Promise));
        assert.equal(strategy.aborted, undefined);
      },
    );
  }
});
