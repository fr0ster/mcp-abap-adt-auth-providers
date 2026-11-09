/**
 * The renewal strategy: the provider asks the
 * consumer's strategy before every step, reads its answer as foreign code,
 * and performs only what it was asked for. The grant calls are scripted
 * promises (`ScriptedProvider`); the base class runs as shipped. The cases
 * whose point is what reached the server are in `renewalOnTheWire.test.ts`.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IAuthProviderError,
  IClientAuthentication,
  IRenewalStrategy,
  RenewalAbortObservation,
  RenewalDecision,
  RenewalSituation,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { refreshOnly, refreshThenLogin } from '../../renewal';
import { jwt, quiet, rejectionOf } from '../helpers/attemptHarness';
import {
  certificate,
  otherCertificate,
  thumbprintOf,
} from '../helpers/certificates';
import {
  caseTitle,
  containsEqual,
  matchObject,
  notContains,
  thrown,
} from '../helpers/expectations';
import { reportRecorder, stateRecorder } from '../helpers/persistence';
import { ScriptedProvider, tokens } from '../helpers/scriptedProvider';

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const boundTo = (thumbprint: string, subject: string) =>
  `${b64url({ alg: 'none' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) + 3600,
    sub: subject,
    cnf: { 'x5t#S256': thumbprint },
  })}.sig`;

const pinning: IClientAuthentication = {
  authenticate: async () => ({}),
  tlsMaterial: async () => certificate(),
};

/** The error a failure holds. */
const errorOf = (thrown: unknown): IAuthProviderError =>
  readFailure(thrown, 'unfamiliar-error');

function expectStrategyFailure(thrown: unknown): void {
  const error = errorOf(thrown);
  assert.equal(error.kind, 'unknown');
  matchObject(error.facts, { operation: 'renewal-strategy' });
}

function expectAborted(thrown: unknown): void {
  const error = errorOf(thrown);
  assert.equal(error.kind, 'interactive-login');
  matchObject(error.facts, { outcome: 'aborted' });
}

/**
 * A strategy answering from a script, one answer per `next`, recording every
 * situation, every observation and the order of its calls. With no answer
 * left it stops. `inAbort` is read at each call: a strategy call made while
 * the test is inside `abort()` is recorded.
 */
function scripted(
  answers: ReadonlyArray<(situation: RenewalSituation) => unknown>,
) {
  const queue = [...answers];
  const situations: RenewalSituation[] = [];
  const observed: RenewalAbortObservation[] = [];
  const calls: string[] = [];
  const state = { inAbort: false, callsInAbort: 0 };
  const strategy: IRenewalStrategy = {
    next(situation) {
      if (state.inAbort) state.callsInAbort += 1;
      situations.push(situation);
      calls.push(`next:${observed.length}`);
      const answer = queue.shift();
      return (answer ? answer(situation) : { next: 'stop' }) as RenewalDecision;
    },
    aborted(observation) {
      if (state.inAbort) state.callsInAbort += 1;
      observed.push(observation);
      calls.push('aborted');
    },
  };
  /** Aborts `controller`, noting any strategy call made inside it. */
  const abort = (controller: AbortController) => {
    state.inAbort = true;
    try {
      controller.abort();
    } finally {
      state.inAbort = false;
    }
  };
  return { strategy, situations, observed, calls, state, abort };
}

const refresh =
  (ifCut: 'keep' | 'discard' = 'discard') =>
  () => ({
    next: 'refresh',
    ifCut,
  });
const login = (sentRefreshToken?: 'keep' | 'discard') => () =>
  sentRefreshToken === undefined
    ? { next: 'login' }
    : { next: 'login', sentRefreshToken };

/** A provider holding an expired token and refresh token R. */
function seeded(
  renewal: IRenewalStrategy,
  extra: Partial<ConstructorParameters<typeof ScriptedProvider>[0]> = {},
) {
  return new ScriptedProvider({
    renewal,
    accessToken: jwt('held', -3600),
    refreshToken: 'R',
    ...extra,
  });
}

const refused = () =>
  Object.assign(new Error('refused'), {
    isAxiosError: true,
    response: { status: 400, data: { error: 'invalid_grant' } },
  });

describe('a decision is awaited as given: any thenable is adopted', () => {
  /** A thenable of `decision`, counting the calls of its own `then`. */
  const thenableOf = (decision: unknown) => {
    const calls = { thenCalls: 0 };
    const answer = {
      // biome-ignore lint/suspicious/noThenProperty: a thenable is the answer under test
      then(resolve: (value: unknown) => void) {
        calls.thenCalls += 1;
        resolve(decision);
      },
    };
    return { answer, calls };
  };

  it('a foreign thenable of a refresh: its then called once, the refresh taken', async () => {
    const { answer, calls } = thenableOf({ next: 'refresh', ifCut: 'keep' });
    const { strategy } = scripted([() => answer]);
    const provider = seeded(strategy);
    void rejectionOf(provider.getTokens());
    await provider.refreshes.nth(1);
    assert.equal(calls.thenCalls, 1);
    assert.equal(provider.refreshes.items.length, 1);
    assert.equal(provider.logins.items.length, 0);
  });

  it('a foreign thenable of a stop: read as the stop, not as a strategy failure', async () => {
    const { answer, calls } = thenableOf({ next: 'stop' });
    const { strategy } = scripted([() => answer]);
    const provider = seeded(strategy);
    const thrown = await rejectionOf(provider.getTokens());
    assert.equal(errorOf(thrown).kind, 'renewal-declined');
    assert.equal(calls.thenCalls, 1);
    assert.equal(provider.refreshes.items.length, 0);
  });

  it('a native promise with its own then: adopted through that then', async () => {
    let thenCalls = 0;
    const answer = Promise.resolve({ next: 'refresh', ifCut: 'keep' });
    Object.defineProperty(answer, 'then', {
      value(...args: unknown[]) {
        thenCalls += 1;
        return Promise.prototype.then.apply(answer, args as never);
      },
    });
    const { strategy } = scripted([() => answer]);
    const provider = seeded(strategy);
    void rejectionOf(provider.getTokens());
    await provider.refreshes.nth(1);
    assert.equal(thenCalls, 1);
    assert.equal(provider.refreshes.items.length, 1);
  });
});

describe('invalid decisions end the renewal unknown renewal-strategy, no step taken', () => {
  const INVALID: ReadonlyArray<[string, () => unknown]> = [
    [
      'a sentRefreshToken where it must be absent',
      () => ({ next: 'login', sentRefreshToken: 'keep' }),
    ],
    [
      'a decision whose field read throws',
      () =>
        Object.defineProperty({ next: 'login' }, 'sentRefreshToken', {
          get() {
            throw new Error('SECRET');
          },
        }),
    ],
    [
      'a decision whose next read throws',
      () =>
        Object.defineProperty({}, 'next', {
          get() {
            throw new Error('SECRET');
          },
        }),
    ],
    [
      'a Proxy decision whose reads throw',
      () =>
        new Proxy(
          { next: 'login' },
          {
            get() {
              throw new Error('SECRET');
            },
          },
        ),
    ],
    [
      'a throw',
      () => {
        throw new Error('SECRET');
      },
    ],
    [
      'a thenable whose then throws',
      () => ({
        // biome-ignore lint/suspicious/noThenProperty: a thenable is the answer under test
        then() {
          throw new Error('SECRET');
        },
      }),
    ],
    [
      'a thenable of an invalid answer',
      () => ({
        // biome-ignore lint/suspicious/noThenProperty: a thenable is the answer under test
        then(resolve: (value: unknown) => void) {
          resolve({ next: 'login', sentRefreshToken: 'keep' });
        },
      }),
    ],
    [
      'a native promise of an invalid answer',
      () => Promise.resolve({ next: 'login', sentRefreshToken: 'keep' }),
    ],
    ['a rejecting native promise', () => Promise.reject(new Error('SECRET'))],
  ];

  for (const [caseIndex, caseRow] of INVALID.entries()) {
    const [_name, answer] = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), async () => {
      const { strategy } = scripted([answer]);
      const provider = seeded(strategy);
      const thrown = await rejectionOf(provider.getTokens());
      expectStrategyFailure(thrown);
      notContains(JSON.stringify(errorOf(thrown)), 'SECRET');
      assert.equal(provider.refreshes.items.length, 0);
      assert.equal(provider.logins.items.length, 0);
      assert.equal(provider.held().refresh, 'R');
    });
  }

  it('a refresh while no refresh is possible', async () => {
    const { strategy } = scripted([refresh()]);
    const provider = new ScriptedProvider({ renewal: strategy });
    expectStrategyFailure(await rejectionOf(provider.getTokens()));
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 0);
  });

  for (const [caseIndex, caseRow] of (
    [
      ['missing', login()],
      ['on a stop, missing', () => ({ next: 'stop' })],
    ] as const
  ).entries()) {
    const [_name, second] = caseRow;
    it(
      caseTitle(
        'after a refresh that failed once sent, a sentRefreshToken %s',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { strategy } = scripted([refresh(), second]);
        const provider = seeded(strategy);
        const thrown = rejectionOf(provider.getTokens());
        (await provider.refreshes.nth(1)).result.reject(refused());
        expectStrategyFailure(await thrown);
        // The uncertain refresh token is neither kept nor discarded by default.
        assert.equal(provider.held().refresh, 'R');
        assert.equal(provider.logins.items.length, 0);
        assert.equal(provider.refreshes.items.length, 1);
      },
    );
  }

  it('a decision whose next getter changes its answer is read once: no refresh dispatched where none is possible', async () => {
    const reads = { next: 0, ifCut: 0, sentRefreshToken: 0 };
    const shifting = () => {
      const decision = {};
      Object.defineProperty(decision, 'next', {
        enumerable: true,
        get() {
          reads.next += 1;
          return reads.next === 1 ? 'login' : 'refresh';
        },
      });
      Object.defineProperty(decision, 'ifCut', {
        enumerable: true,
        get() {
          reads.ifCut += 1;
          return 'discard';
        },
      });
      Object.defineProperty(decision, 'sentRefreshToken', {
        enumerable: true,
        get() {
          reads.sentRefreshToken += 1;
          return undefined;
        },
      });
      return decision;
    };
    const { strategy } = scripted([shifting]);
    // No refresh token held: a refresh is not possible.
    const provider = new ScriptedProvider({ renewal: strategy });
    const renewed = provider.getTokens();
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    await renewed;
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 1);
    // A login decision: its ifCut is never read.
    assert.deepEqual(reads, { next: 1, ifCut: 0, sentRefreshToken: 1 });
  });

  it('a type-valid login decision carrying a throwing ifCut getter: ifCut not read, the login taken', async () => {
    let ifCutReads = 0;
    const loginWithIfCut = () =>
      Object.defineProperty({ next: 'login' }, 'ifCut', {
        enumerable: true,
        get() {
          ifCutReads += 1;
          throw new Error('SECRET');
        },
      });
    const { strategy } = scripted([loginWithIfCut]);
    const provider = new ScriptedProvider({ renewal: strategy });
    const renewed = provider.getTokens();
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    await renewed;
    assert.equal(ifCutReads, 0);
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 1);
  });

  it('a refresh of the very token the same decision discards', async () => {
    const { strategy } = scripted([
      refresh(),
      () => ({
        next: 'refresh',
        ifCut: 'discard',
        sentRefreshToken: 'discard',
      }),
    ]);
    const provider = seeded(strategy);
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    expectStrategyFailure(await thrown);
    assert.equal(provider.held().refresh, 'R');
    assert.equal(provider.refreshes.items.length, 1);
  });

  it('a strategy that never settles: the abort ends the renewal aborted at once, no step', async () => {
    const { strategy } = scripted([() => new Promise(() => undefined)]);
    const provider = seeded(strategy);
    const only = new AbortController();
    const thrown = rejectionOf(provider.getTokens({ signal: only.signal }));
    await quiet();
    only.abort();
    expectAborted(await thrown);
    await quiet();
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 0);
    assert.equal(provider.held().refresh, 'R');
  });

  it('a refused decision is logged in fixed words', async () => {
    const lines: unknown[][] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (...args: unknown[]) => {
        lines.push(args);
      },
      error: () => undefined,
    };
    const { strategy } = scripted([
      () => {
        throw new Error('SECRET');
      },
    ]);
    await rejectionOf(seeded(strategy, { logger }).getTokens());
    assert.deepEqual(lines, [
      [
        '[BaseTokenProvider] Renewal strategy refused',
        {
          error: 'the renewal strategy failed (unknown error)',
          kind: 'unknown',
        },
      ],
    ]);
  });
});

describe('earlier steps stay applied', () => {
  it('a refresh commits R2 bound elsewhere, then the strategy throws: R2 is held and was reported', async () => {
    const { seen, persistence } = stateRecorder();
    const { strategy } = scripted([
      refresh(),
      () => {
        throw new Error('the strategy failed');
      },
    ]);
    const provider = seeded(strategy, {
      persistence,
      clientAuthentication: pinning,
    });
    const thrown = rejectionOf(provider.getTokens());
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    expectStrategyFailure(await thrown);
    matchObject(provider.held(), { access: elsewhere, refresh: 'R2' });
    assert.deepEqual(seen, [[elsewhere, 'R2', 'replace']]);
  });
});

describe('a credential generation per step', () => {
  it('a refresh bound elsewhere, then a login: the login is installed and reported', async () => {
    const { seen, persistence } = stateRecorder();
    const { strategy, situations } = scripted([refresh(), login()]);
    const provider = seeded(strategy, {
      persistence,
      clientAuthentication: pinning,
    });
    const renewed = provider.getTokens();
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    const good = boundTo(thumbprintOf(certificate()), 'login');
    (await provider.logins.nth(1)).result.resolve(tokens(good, 'S'));
    matchObject(await renewed, {
      authorizationToken: good,
      refreshToken: 'S',
    });
    matchObject(provider.held(), { access: good, refresh: 'S' });
    assert.deepEqual(seen, [
      [elsewhere, 'R2', 'replace'],
      [good, 'S', 'replace'],
    ]);
    assert.deepEqual(situations[1]?.steps, [
      { step: 'refresh', outcome: 'bound-elsewhere' },
    ]);
  });

  it('two refreshes in one attempt: both committed, in order; the second sends the first one’s refresh token', async () => {
    const { seen, persistence } = stateRecorder();
    const { strategy } = scripted([refresh(), refresh()]);
    const provider = seeded(strategy, {
      persistence,
      clientAuthentication: pinning,
    });
    const renewed = provider.getTokens();
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    const second = await provider.refreshes.nth(2);
    assert.equal(second.refreshToken, 'R2');
    const good = boundTo(thumbprintOf(certificate()), 'r3');
    second.result.resolve(tokens(good, 'R3'));
    matchObject(await renewed, { authorizationToken: good });
    assert.deepEqual(seen, [
      [elsewhere, 'R2', 'replace'],
      [good, 'R3', 'replace'],
    ]);
  });
});

describe('a discarded refresh token in a result is read as none', () => {
  it('R discarded, S installed, then a result carrying R: S stays held, the result reported without a refresh token', async () => {
    const { seen, persistence } = stateRecorder();
    const provider = seeded(refreshThenLogin(), { persistence });
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.reject(refused());
    const T1 = jwt('one', -3600);
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
    await first;
    assert.equal(provider.held().refresh, 'S');

    const again = provider.refreshTokens();
    const refreshS = await provider.refreshes.nth(2);
    assert.equal(refreshS.refreshToken, 'S');
    const T2 = jwt('two');
    refreshS.result.resolve(tokens(T2, 'R'));
    matchObject(await again, {
      authorizationToken: T2,
      refreshToken: 'S',
    });
    assert.equal(provider.held().refresh, 'S');
    assert.deepEqual(seen.at(-1), [T2, undefined, 'keep']);
  });
});

describe('aborted steps observed', () => {
  it('an abort before dispatch: aborted() once with sent false, R untouched, the gate sends nothing; the next next() sees it delivered', async () => {
    const { seen, persistence } = stateRecorder();
    const s = scripted([refresh(), refresh()]);
    const provider = seeded(s.strategy, { persistence });
    provider.holdDispatch = true;
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const held = await provider.refreshes.nth(1);
    s.abort(only);
    expectAborted(await cut);
    // The site's gate: an aborted attempt sends nothing.
    assert.throws(() => held.dispatch(), thrown());
    held.result.reject(new Error('not sent'));
    await quiet();
    assert.equal(s.state.callsInAbort, 0);
    assert.deepEqual(s.observed, [
      {
        cause: { trigger: 'expired' },
        moment: 'get-tokens',
        step: 'refresh',
        sent: false,
      },
    ]);
    assert.equal(provider.held().refresh, 'R');
    assert.deepEqual(seen, []);

    provider.holdDispatch = false;
    const next = provider.getTokens();
    const second = await provider.refreshes.nth(2);
    assert.equal(second.refreshToken, 'R');
    second.result.resolve(tokens(jwt('fresh'), 'R2'));
    await next;
    // Delivered once, before the replacement's first next().
    assert.deepEqual(s.calls, ['next:0', 'aborted', 'next:1']);
  });

  for (const [caseIndex, caseRow] of (
    [
      ['discard', 'discarded', 'login'],
      ['keep', 'kept', 'refresh of R'],
    ] as const
  ).entries()) {
    const [ifCut, refreshToken, then] = caseRow;
    it(
      caseTitle(
        'an abort after dispatch, ifCut %s: sent true, refreshToken %s; the next renewal is a %s',
        caseRow,
        caseIndex,
      ),
      async () => {
        const s = scripted([
          refresh(ifCut),
          // The next renewal: refresh when possible, else log in.
          (situation) =>
            situation.canRefresh
              ? { next: 'refresh', ifCut: 'discard' }
              : { next: 'login' },
        ]);
        const provider = seeded(s.strategy);
        const only = new AbortController();
        const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
        await provider.refreshes.nth(1);
        s.abort(only);
        expectAborted(await cut);
        await quiet();
        assert.equal(s.state.callsInAbort, 0);
        assert.deepEqual(s.observed, [
          {
            cause: { trigger: 'expired' },
            moment: 'get-tokens',
            step: 'refresh',
            sent: true,
            refreshToken,
          },
        ]);
        const next = provider.getTokens();
        if (then === 'login') {
          (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
          assert.equal(provider.refreshes.items.length, 1);
        } else {
          const second = await provider.refreshes.nth(2);
          assert.equal(second.refreshToken, 'R');
          second.result.resolve(tokens(jwt('in'), 'R2'));
          assert.equal(provider.logins.items.length, 0);
        }
        await next;
      },
    );
  }

  it('an abort during a login: aborted() with step login, sent as the sites told', async () => {
    const s = scripted([login()]);
    const provider = new ScriptedProvider({ renewal: s.strategy });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.logins.nth(1);
    s.abort(only);
    expectAborted(await cut);
    await quiet();
    assert.deepEqual(s.observed, [
      {
        cause: { trigger: 'no-token' },
        moment: 'get-tokens',
        step: 'login',
        sent: false,
      },
    ]);
  });

  it('an aborted() that throws changes nothing, and is logged in fixed words', async () => {
    const lines: unknown[][] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (...args: unknown[]) => {
        lines.push(args);
      },
      error: () => undefined,
    };
    const strategy: IRenewalStrategy = {
      next: (situation) => refreshThenLogin().next(situation),
      aborted: () => {
        throw new Error('SECRET');
      },
    };
    const provider = seeded(strategy, { logger });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    expectAborted(await cut);
    await quiet();
    notContains(JSON.stringify(lines), 'SECRET');
    containsEqual(lines, [
      '[BaseTokenProvider] Renewal strategy failed to take an aborted step',
      {
        error: 'the renewal strategy failed (unknown error)',
        kind: 'unknown',
      },
    ]);
    // The renewal goes on as the strategy's next() decides.
    const next = provider.getTokens();
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    matchObject(await next, { refreshToken: 'S' });
  });
});

describe('no hidden step', () => {
  it('every step is preceded by one next(); none after stop', async () => {
    const asked: RenewalSituation[] = [];
    const strategy: IRenewalStrategy = {
      next: (situation) => {
        asked.push(situation);
        return refreshThenLogin().next(situation);
      },
    };
    const provider = seeded(strategy);
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    (await provider.logins.nth(1)).result.reject(new Error('the login failed'));
    await thrown;
    await quiet();
    assert.deepEqual(
      asked.map((s) => s.steps.length),
      [0, 1, 2],
    );
    assert.equal(provider.refreshes.items.length, 1);
    assert.equal(provider.logins.items.length, 1);
  });

  it('refreshOnly(): a refused refresh stops, no login', async () => {
    const provider = seeded(refreshOnly());
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    // The step's own error is what the stop answers (a scripted rejection
    // here, so `unknown` with the operation).
    matchObject(errorOf(await thrown).facts, {
      operation: 'token-request',
    });
    await quiet();
    assert.equal(provider.logins.items.length, 0);
    // Discarded by its decision: sent and refused.
    assert.equal(provider.held().refresh, undefined);
  });
});

describe('rule 5 as a reading', () => {
  const valid = () => jwt('valid');
  async function presented(provider: ScriptedProvider): Promise<void> {
    await provider.authorize({
      header: () => undefined,
      cookies: () => undefined,
    } as never);
  }

  it('a 403 with refreshThenLogin(): system-refused, no step', async () => {
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: valid(),
      refreshToken: 'R',
    });
    await presented(provider);
    const outcome = await provider.rejected({
      at: 'request',
      status: 403,
      error: undefined,
    });
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    assert.equal(outcome.refusal.kind, 'system-refused');
    matchObject(outcome.refusal.facts, {
      verdict: 'not-authorized',
      status: 403,
    });
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 0);
  });

  it('a strategy that renews on not-credential: one refresh sent, the cause as read', async () => {
    const s = scripted([
      (situation) =>
        situation.cause.trigger === 'rejected' &&
        situation.cause.reading === 'not-credential'
          ? { next: 'refresh', ifCut: 'discard' }
          : { next: 'stop' },
    ]);
    const provider = new ScriptedProvider({
      renewal: s.strategy,
      accessToken: valid(),
      refreshToken: 'R',
    });
    await presented(provider);
    const answered = provider.rejected({
      at: 'request',
      status: 403,
      error: undefined,
    });
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('new'), 'R2'));
    assert.deepEqual(await answered, { ok: true });
    assert.equal(provider.refreshes.items.length, 1);
    matchObject(s.situations[0], {
      cause: {
        trigger: 'rejected',
        reading: 'not-credential',
        at: 'request',
        status: 403,
        refusal: { kind: 'system-refused' },
      },
      moment: 'rejected',
      canRefresh: true,
      steps: [],
    });
  });

  it('a 401 renewal that obtains the refused token: renewal-unchanged', async () => {
    const token = valid();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: token,
      refreshToken: 'R',
    });
    await presented(provider);
    const answered = provider.rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    (await provider.refreshes.nth(1)).result.resolve(tokens(token, 'R2'));
    const outcome = await answered;
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    assert.equal(outcome.refusal.kind, 'renewal-unchanged');
    assert.equal(provider.logins.items.length, 0);
  });
});

describe('renewal-declined', () => {
  it('refreshOnly(), an expired token and no refresh token: thrown with trigger expired, nothing sent', async () => {
    const provider = new ScriptedProvider({
      renewal: refreshOnly(),
      accessToken: jwt('held', -3600),
    });
    const error = errorOf(await rejectionOf(provider.getTokens()));
    assert.equal(error.kind, 'renewal-declined');
    assert.deepEqual(error.facts, { trigger: 'expired' });
    assert.equal(
      error.reason,
      'the renewal strategy declined to renew the credential',
    );
    assert.equal(provider.refreshes.items.length, 0);
    assert.equal(provider.logins.items.length, 0);
  });
});

describe('where a renewal starts', () => {
  it('causes and moments: no-token, expired, explicit, and the lastRenewal of a remembered token at get-tokens and at prepare', async () => {
    const s = scripted([]);
    const none = new ScriptedProvider({ renewal: s.strategy });
    await rejectionOf(none.getTokens());
    await rejectionOf(seeded(s.strategy).getTokens());
    await rejectionOf(seeded(s.strategy).refreshTokens());
    assert.deepEqual(
      s.situations.map((x) => [x.cause, x.moment]),
      [
        [{ trigger: 'no-token' }, 'get-tokens'],
        [{ trigger: 'expired' }, 'get-tokens'],
        [{ trigger: 'explicit' }, 'refresh-tokens'],
      ],
    );

    // A held token bound elsewhere, whose renewal failed: remembered.
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'held');
    const b = scripted([login()]);
    const provider = new ScriptedProvider({
      renewal: b.strategy,
      clientAuthentication: pinning,
      accessToken: elsewhere,
    });
    const first = rejectionOf(provider.getTokens());
    (await provider.logins.nth(1)).result.reject(new Error('failed'));
    const remembered = errorOf(await first);
    await rejectionOf(provider.getTokens());
    await provider.prepare();
    // The first ask of each renewal (the failed login's renewal asks again).
    assert.deepEqual(
      b.situations
        .filter((x) => x.steps.length === 0)
        .map((x) => [x.cause, x.moment]),
      [
        [{ trigger: 'bound-elsewhere', lastRenewal: undefined }, 'get-tokens'],
        [{ trigger: 'bound-elsewhere', lastRenewal: remembered }, 'get-tokens'],
        // prepare() no longer clears it: the moment is the strategy's cue.
        [{ trigger: 'bound-elsewhere', lastRenewal: remembered }, 'prepare'],
      ],
    );
  });

  it('a valid cached token asks nothing', async () => {
    const s = scripted([]);
    const provider = new ScriptedProvider({
      renewal: s.strategy,
      accessToken: jwt('valid'),
    });
    await provider.getTokens();
    assert.equal(s.situations.length, 0);
  });
});

describe('logging', () => {
  it('one debug line per decision: trigger, moment and next only', async () => {
    const lines: unknown[][] = [];
    const logger: ILogger = {
      debug: (...args: unknown[]) => {
        if (args[0] === '[BaseTokenProvider] Renewal step') lines.push(args);
      },
      info: () => undefined,
      warn: () => undefined,
      error: () => undefined,
    };
    const provider = seeded(refreshThenLogin(), { logger });
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.reject(refused());
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    await renewed;
    assert.deepEqual(lines, [
      [
        '[BaseTokenProvider] Renewal step',
        { trigger: 'expired', moment: 'get-tokens', next: 'refresh' },
      ],
      [
        '[BaseTokenProvider] Renewal step',
        { trigger: 'expired', moment: 'get-tokens', next: 'login' },
      ],
    ]);
  });
});

describe('a refresh commit that fails: the persistence report of the commit', () => {
  /** A persistence strategy whose every report fails. */
  const failing = () =>
    reportRecorder(() => {
      throw new Error('SECRET store unavailable');
    }).persistence;

  it('a failure after the install — the awaited report — ends the renewal: no login, the credentials stay committed', async () => {
    const provider = seeded(refreshThenLogin(), { persistence: failing() });
    const thrown = rejectionOf(provider.getTokens());
    const T2 = jwt('rotated');
    (await provider.refreshes.nth(1)).result.resolve(tokens(T2, 'R2'));
    const error = errorOf(await thrown);
    matchObject(error, {
      kind: 'unknown',
      facts: { operation: 'persisting-tokens' },
    });
    notContains(JSON.stringify(error), 'SECRET');
    await quiet();
    assert.equal(provider.logins.items.length, 0);
    matchObject(provider.held(), { access: T2, refresh: 'R2' });
    // The committed credentials are the server's state: the cache answers.
    matchObject(await provider.getTokens(), {
      authorizationToken: T2,
    });
    assert.equal(provider.refreshes.items.length, 1);
  });

  it('the same after a login: the renewal fails, nothing more', async () => {
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence: failing(),
    });
    const thrown = rejectionOf(provider.getTokens());
    const T1 = jwt('login');
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
    await thrown;
    await quiet();
    assert.equal(provider.logins.items.length, 1);
    matchObject(provider.held(), { access: T1, refresh: 'S' });
  });
});

describe('the strategy gets frozen copies; the provider reads back nothing it handed out', () => {
  /** Tries `change`; a frozen object refuses it, which the strategy ignores. */
  const attempt = (change: () => void) => {
    try {
      change();
    } catch {
      // Frozen: the strategy carries on.
    }
  };

  it('a strategy rewriting its cause changes nothing a stop answers', async () => {
    const strategy: IRenewalStrategy = {
      next: (situation) => {
        const cause = situation.cause as unknown as Record<string, unknown>;
        attempt(() => {
          cause.trigger = 'rejected';
        });
        attempt(() => {
          cause.refusal = { kind: 'unknown', reason: 'SECRET' };
        });
        return { next: 'stop' };
      },
    };
    const provider = new ScriptedProvider({
      renewal: strategy,
      accessToken: jwt('held', -3600),
    });
    const error = errorOf(await rejectionOf(provider.getTokens()));
    assert.equal(error.kind, 'renewal-declined');
    assert.deepEqual(error.facts, { trigger: 'expired' });
  });

  it('a strategy rewriting the steps cannot bypass a required sentRefreshToken', async () => {
    const strategy: IRenewalStrategy = {
      next: (situation) => {
        if (situation.steps.length === 0) {
          return { next: 'refresh', ifCut: 'discard' };
        }
        const steps = situation.steps as unknown as Record<string, unknown>[];
        attempt(() => {
          (steps[0] as Record<string, unknown>).sent = false;
        });
        attempt(() => {
          steps.length = 0;
        });
        return { next: 'login' };
      },
    };
    const provider = seeded(strategy);
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    expectStrategyFailure(await thrown);
    assert.equal(provider.logins.items.length, 0);
    assert.equal(provider.held().refresh, 'R');
  });

  it('every object handed to next() and aborted() is frozen, deep', async () => {
    const seen: unknown[] = [];
    const strategy: IRenewalStrategy = {
      next: (situation) => {
        seen.push(
          situation,
          situation.cause,
          situation.steps,
          ...situation.steps,
        );
        return refreshThenLogin().next(situation);
      },
      aborted: (observation) => {
        seen.push(observation, observation.cause);
      },
    };
    const provider = seeded(strategy);
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.reject(refused());
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    await first;
    provider.expire();
    const cut = new AbortController();
    const second = rejectionOf(provider.getTokens({ signal: cut.signal }));
    await provider.refreshes.nth(2);
    cut.abort();
    await second;
    await quiet();
    assert.ok(seen.length > 5, `${seen.length} > ${5}`);
    for (const value of seen) assert.equal(Object.isFrozen(value), true);
  });
});

describe('edge cases of a refresh step and of the delivery order', () => {
  function warnings() {
    const lines: unknown[][] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: () => undefined,
      warn: (...args: unknown[]) => {
        lines.push(args);
      },
      error: () => undefined,
    };
    return { lines, logger };
  }

  it('a refresh ended by the abort is not logged as "Refresh failed"', async () => {
    const { lines, logger } = warnings();
    const provider = seeded(refreshThenLogin(), { logger });
    provider.holdDispatch = true;
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const held = await provider.refreshes.nth(1);
    only.abort();
    await cut;
    held.result.reject(new Error('not sent'));
    await quiet();
    notContains(
      lines.map((line) => line[0]),
      '[BaseTokenProvider] Refresh failed',
    );
  });

  it('a discard of a refresh token no longer held reports nothing', async () => {
    const { reports, persistence } = reportRecorder();
    const provider = seeded(refreshThenLogin(), { persistence });
    await (
      provider as unknown as {
        discard(spent: string, attempt: { signal: AbortSignal }): Promise<void>;
      }
    ).discard('replaced-meanwhile', { signal: new AbortController().signal });
    assert.deepEqual(reports, []);
    assert.equal(provider.held().refresh, 'R');
  });
});

describe("stop's answer, in the order of the renewal", () => {
  it("a step's error comes before rule 5's refusal: a 403 renewed, the refresh refused, then stop", async () => {
    const s = scripted([
      refresh(),
      () => ({ next: 'stop', sentRefreshToken: 'keep' }),
    ]);
    const provider = new ScriptedProvider({
      renewal: s.strategy,
      accessToken: jwt('valid'),
      refreshToken: 'R',
    });
    const answered = provider.rejected({
      at: 'request',
      status: 403,
      error: undefined,
    });
    (await provider.refreshes.nth(1)).result.reject(refused());
    const outcome = await answered;
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    // The refresh step's own error, not system-refused.
    assert.equal(outcome.refusal.kind, 'unknown');
    matchObject(outcome.refusal.facts, { operation: 'token-request' });
  });

  it("a step's error comes before the lastRenewal of a token bound elsewhere", async () => {
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'held');
    const first = scripted([login()]);
    const provider = new ScriptedProvider({
      renewal: first.strategy,
      clientAuthentication: pinning,
      accessToken: elsewhere,
      refreshToken: 'R',
    });
    // A first renewal fails: its error is remembered.
    const failing = rejectionOf(provider.getTokens());
    (await provider.logins.nth(1)).result.reject(new Error('failed'));
    const remembered = errorOf(await failing);
    // The next one renews despite lastRenewal; its refresh is refused.
    (provider as unknown as { renewal: IRenewalStrategy }).renewal = scripted([
      refresh(),
      () => ({ next: 'stop', sentRefreshToken: 'keep' }),
    ]).strategy;
    const second = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    const error = errorOf(await second);
    assert.notEqual(error, remembered);
    matchObject(error.facts, { operation: 'token-request' });
  });

  it("an outcome's refusal comes before rule 5's: a 403 renewed into the same token, then stop", async () => {
    const token = jwt('valid');
    const s = scripted([refresh()]);
    const provider = new ScriptedProvider({
      renewal: s.strategy,
      accessToken: token,
      refreshToken: 'R',
    });
    const answered = provider.rejected({
      at: 'request',
      status: 403,
      error: undefined,
    });
    (await provider.refreshes.nth(1)).result.resolve(tokens(token, 'R2'));
    const outcome = await answered;
    assert.equal(outcome.ok, false);
    if (outcome.ok) return;
    assert.equal(outcome.refusal.kind, 'renewal-unchanged');
  });
});

describe('pending observations are delivered before the next next()', () => {
  it('with the queued delivery not yet run, next() delivers first, and only once', async () => {
    // ifCut keep: R stays, so the next renewal can refresh it again.
    const s = scripted([refresh('keep'), refresh()]);
    const provider = seeded(s.strategy);
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    // Hold every microtask queued from here on: the delivery the abort
    // handler queues does not run before the next renewal asks.
    const held: Array<() => void> = [];
    const original = globalThis.queueMicrotask;
    globalThis.queueMicrotask = (task: () => void) => {
      held.push(task);
    };
    let next: Promise<unknown>;
    try {
      only.abort();
      await cut;
      next = provider.getTokens();
      await provider.refreshes.nth(2);
    } finally {
      globalThis.queueMicrotask = original;
    }
    assert.deepEqual(s.calls, ['next:0', 'aborted', 'next:1']);
    for (const task of held) task();
    assert.equal(s.observed.length, 1);
    (await provider.refreshes.nth(2)).result.resolve(tokens(jwt('in'), 'S'));
    await next;
  });
});
