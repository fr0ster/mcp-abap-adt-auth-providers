/**
 * The renewal strategy (spec §6c.5, §6c.10 "Renewal"): the provider asks the
 * consumer's strategy before every step, reads its answer as foreign code,
 * and performs only what it was asked for. The grant calls are scripted
 * promises (`ScriptedProvider`); the base class runs as shipped. The cases
 * whose point is what reached the server are in `renewalOnTheWire.test.ts`.
 */

import { describe, expect, it } from '@jest/globals';
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
import type { BridgedTokenResult } from '../../providers/BaseTokenProvider';
import { refreshOnly, refreshThenLogin } from '../../renewal';
import { jwt, quiet, rejectionOf } from '../helpers/attemptHarness';
import {
  certificate,
  otherCertificate,
  thumbprintOf,
} from '../helpers/certificates';
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
  expect(error.kind).toBe('unknown');
  expect(error.facts).toMatchObject({ operation: 'renewal-strategy' });
}

function expectAborted(thrown: unknown): void {
  const error = errorOf(thrown);
  expect(error.kind).toBe('interactive-login');
  expect(error.facts).toMatchObject({ outcome: 'aborted' });
}

/** What onTokens saw: access token, refresh token, disposition. */
type Seen = [string, string | undefined, string | undefined];
function recorder() {
  const seen: Seen[] = [];
  const onTokens = async (result: BridgedTokenResult) => {
    seen.push([
      result.authorizationToken,
      result.refreshToken,
      result.refreshTokenDisposition,
    ]);
  };
  return { seen, onTokens };
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

describe('invalid decisions end the renewal unknown renewal-strategy, no step taken', () => {
  const foreign = { thenCalls: 0 };
  const INVALID: ReadonlyArray<[string, () => unknown]> = [
    ['null', () => null],
    ['a string', () => 'refresh'],
    ['a number', () => 42],
    ['an object without next', () => ({})],
    ['an unknown next', () => ({ next: 'retry' })],
    ['a refresh without ifCut', () => ({ next: 'refresh' })],
    [
      'a refresh with an invalid ifCut',
      () => ({ next: 'refresh', ifCut: 'maybe' }),
    ],
    [
      'a sentRefreshToken where it must be absent',
      () => ({ next: 'login', sentRefreshToken: 'keep' }),
    ],
    [
      'a getter that throws',
      () =>
        Object.defineProperty({}, 'next', {
          get() {
            throw new Error('SECRET');
          },
        }),
    ],
    [
      'a Proxy that throws',
      () =>
        new Proxy(
          {},
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
      'a foreign thenable',
      () => ({
        then() {
          foreign.thenCalls += 1;
        },
      }),
    ],
    [
      'a native promise of an invalid answer',
      () => Promise.resolve({ next: 'refresh' }),
    ],
    ['a rejecting native promise', () => Promise.reject(new Error('SECRET'))],
  ];

  it.each(INVALID)('%s', async (_name, answer) => {
    foreign.thenCalls = 0;
    const { strategy } = scripted([answer]);
    const provider = seeded(strategy);
    const thrown = await rejectionOf(provider.getTokens());
    expectStrategyFailure(thrown);
    expect(JSON.stringify(errorOf(thrown))).not.toContain('SECRET');
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
    expect(provider.held().refresh).toBe('R');
    expect(foreign.thenCalls).toBe(0);
  });

  it('a refresh while no refresh is possible', async () => {
    const { strategy } = scripted([refresh()]);
    const provider = new ScriptedProvider({ renewal: strategy });
    expectStrategyFailure(await rejectionOf(provider.getTokens()));
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
  });

  it.each([
    ['missing', login()],
    [
      'not keep or discard',
      () => ({ next: 'login', sentRefreshToken: 'drop' }),
    ],
    ['on a stop, missing', () => ({ next: 'stop' })],
  ] as const)(
    'after a refresh that failed once sent, a sentRefreshToken %s',
    async (_name, second) => {
      const { strategy } = scripted([refresh(), second]);
      const provider = seeded(strategy);
      const thrown = rejectionOf(provider.getTokens());
      (await provider.refreshes.nth(1)).result.reject(refused());
      expectStrategyFailure(await thrown);
      // The uncertain refresh token is neither kept nor discarded by default.
      expect(provider.held().refresh).toBe('R');
      expect(provider.logins.items).toHaveLength(0);
      expect(provider.refreshes.items).toHaveLength(1);
    },
  );

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
    expect(provider.held().refresh).toBe('R');
    expect(provider.refreshes.items).toHaveLength(1);
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
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
    expect(provider.held().refresh).toBe('R');
  });

  it('no strategy at all (an untyped consumer): unknown renewal-strategy, nothing built in its place', async () => {
    const provider = seeded(undefined as unknown as IRenewalStrategy);
    expectStrategyFailure(await rejectionOf(provider.getTokens()));
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
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
    expect(lines).toEqual([
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

describe('earlier steps stay applied (G7)', () => {
  it('a refresh commits R2 bound elsewhere, then the strategy throws: R2 is held and was reported', async () => {
    const { seen, onTokens } = recorder();
    const { strategy } = scripted([
      refresh(),
      () => {
        throw new Error('the strategy failed');
      },
    ]);
    const provider = seeded(strategy, {
      onTokens,
      clientAuthentication: pinning,
    });
    const thrown = rejectionOf(provider.getTokens());
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    expectStrategyFailure(await thrown);
    expect(provider.held()).toMatchObject({ access: elsewhere, refresh: 'R2' });
    expect(seen).toEqual([[elsewhere, 'R2', 'replace']]);
  });
});

describe('a credential generation per step', () => {
  it('a refresh bound elsewhere, then a login: the login is installed and reported', async () => {
    const { seen, onTokens } = recorder();
    const { strategy, situations } = scripted([refresh(), login()]);
    const provider = seeded(strategy, {
      onTokens,
      clientAuthentication: pinning,
    });
    const renewed = provider.getTokens();
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    const good = boundTo(thumbprintOf(certificate()), 'login');
    (await provider.logins.nth(1)).result.resolve(tokens(good, 'S'));
    await expect(renewed).resolves.toMatchObject({
      authorizationToken: good,
      refreshToken: 'S',
    });
    expect(provider.held()).toMatchObject({ access: good, refresh: 'S' });
    expect(seen).toEqual([
      [elsewhere, 'R2', 'replace'],
      [good, 'S', 'replace'],
    ]);
    expect(situations[1]?.steps).toEqual([
      { step: 'refresh', outcome: 'bound-elsewhere' },
    ]);
  });

  it('two refreshes in one attempt: both committed, in order; the second sends the first one’s refresh token', async () => {
    const { seen, onTokens } = recorder();
    const { strategy } = scripted([refresh(), refresh()]);
    const provider = seeded(strategy, {
      onTokens,
      clientAuthentication: pinning,
    });
    const renewed = provider.getTokens();
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'r2');
    (await provider.refreshes.nth(1)).result.resolve(tokens(elsewhere, 'R2'));
    const second = await provider.refreshes.nth(2);
    expect(second.refreshToken).toBe('R2');
    const good = boundTo(thumbprintOf(certificate()), 'r3');
    second.result.resolve(tokens(good, 'R3'));
    await expect(renewed).resolves.toMatchObject({ authorizationToken: good });
    expect(seen).toEqual([
      [elsewhere, 'R2', 'replace'],
      [good, 'R3', 'replace'],
    ]);
  });
});

describe('a discarded refresh token in a result is read as none', () => {
  it('R discarded, S installed, then a result carrying R: S stays held, the result reported without a refresh token', async () => {
    const { seen, onTokens } = recorder();
    const provider = seeded(refreshThenLogin(), { onTokens });
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.reject(refused());
    const T1 = jwt('one', -3600);
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
    await first;
    expect(provider.held().refresh).toBe('S');

    const again = provider.refreshTokens();
    const refreshS = await provider.refreshes.nth(2);
    expect(refreshS.refreshToken).toBe('S');
    const T2 = jwt('two');
    refreshS.result.resolve(tokens(T2, 'R'));
    await expect(again).resolves.toMatchObject({
      authorizationToken: T2,
      refreshToken: 'S',
    });
    expect(provider.held().refresh).toBe('S');
    expect(seen.at(-1)).toEqual([T2, undefined, 'keep']);
  });
});

describe('aborted steps observed', () => {
  it('an abort before dispatch: aborted() once with sent false, R untouched, the gate sends nothing; the next next() sees it delivered', async () => {
    const { seen, onTokens } = recorder();
    const s = scripted([refresh(), refresh()]);
    const provider = seeded(s.strategy, { onTokens });
    provider.holdDispatch = true;
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const held = await provider.refreshes.nth(1);
    s.abort(only);
    expectAborted(await cut);
    // The site's gate: an aborted attempt sends nothing.
    expect(() => held.dispatch()).toThrow();
    held.result.reject(new Error('not sent'));
    await quiet();
    expect(s.state.callsInAbort).toBe(0);
    expect(s.observed).toEqual([
      {
        cause: { trigger: 'expired' },
        moment: 'get-tokens',
        step: 'refresh',
        sent: false,
      },
    ]);
    expect(provider.held().refresh).toBe('R');
    expect(seen).toEqual([]);

    provider.holdDispatch = false;
    const next = provider.getTokens();
    const second = await provider.refreshes.nth(2);
    expect(second.refreshToken).toBe('R');
    second.result.resolve(tokens(jwt('fresh'), 'R2'));
    await next;
    // Delivered once, before the replacement's first next().
    expect(s.calls).toEqual(['next:0', 'aborted', 'next:1']);
  });

  it.each([
    ['discard', 'discarded', 'login'],
    ['keep', 'kept', 'refresh of R'],
  ] as const)(
    'an abort after dispatch, ifCut %s: sent true, refreshToken %s; the next renewal is a %s',
    async (ifCut, refreshToken, then) => {
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
      expect(s.state.callsInAbort).toBe(0);
      expect(s.observed).toEqual([
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
        expect(provider.refreshes.items).toHaveLength(1);
      } else {
        const second = await provider.refreshes.nth(2);
        expect(second.refreshToken).toBe('R');
        second.result.resolve(tokens(jwt('in'), 'R2'));
        expect(provider.logins.items).toHaveLength(0);
      }
      await next;
    },
  );

  it('an abort during a login: aborted() with step login, sent as the sites told', async () => {
    const s = scripted([login()]);
    const provider = new ScriptedProvider({ renewal: s.strategy });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.logins.nth(1);
    s.abort(only);
    expectAborted(await cut);
    await quiet();
    expect(s.observed).toEqual([
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
    expect(JSON.stringify(lines)).not.toContain('SECRET');
    expect(lines).toContainEqual([
      '[BaseTokenProvider] Renewal strategy failed to take an aborted step',
      {
        error: 'the renewal strategy failed (unknown error)',
        kind: 'unknown',
      },
    ]);
    // The renewal goes on as the strategy's next() decides.
    const next = provider.getTokens();
    (await provider.logins.nth(1)).result.resolve(tokens(jwt('in'), 'S'));
    await expect(next).resolves.toMatchObject({ refreshToken: 'S' });
  });
});

describe('no hidden step (G3)', () => {
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
    expect(asked.map((s) => s.steps.length)).toEqual([0, 1, 2]);
    expect(provider.refreshes.items).toHaveLength(1);
    expect(provider.logins.items).toHaveLength(1);
  });

  it('refreshOnly(): a refused refresh stops, no login', async () => {
    const provider = seeded(refreshOnly());
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    // The step's own error is what the stop answers (a scripted rejection
    // here, so `unknown` with the operation).
    expect(errorOf(await thrown).facts).toMatchObject({
      operation: 'token-request',
    });
    await quiet();
    expect(provider.logins.items).toHaveLength(0);
    // Discarded by its decision: sent and refused.
    expect(provider.held().refresh).toBeUndefined();
  });
});

describe('rule 5 as a reading (G9)', () => {
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
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.refusal.kind).toBe('system-refused');
    expect(outcome.refusal.facts).toMatchObject({
      verdict: 'not-authorized',
      status: 403,
    });
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
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
    await expect(answered).resolves.toEqual({ ok: true });
    expect(provider.refreshes.items).toHaveLength(1);
    expect(s.situations[0]).toMatchObject({
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
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.refusal.kind).toBe('renewal-unchanged');
    expect(provider.logins.items).toHaveLength(0);
  });
});

describe('renewal-declined', () => {
  it('refreshOnly(), an expired token and no refresh token: thrown with trigger expired, nothing sent', async () => {
    const provider = new ScriptedProvider({
      renewal: refreshOnly(),
      accessToken: jwt('held', -3600),
    });
    const error = errorOf(await rejectionOf(provider.getTokens()));
    expect(error.kind).toBe('renewal-declined');
    expect(error.facts).toEqual({ trigger: 'expired' });
    expect(error.reason).toBe(
      'the renewal strategy declined to renew the credential',
    );
    expect(provider.refreshes.items).toHaveLength(0);
    expect(provider.logins.items).toHaveLength(0);
  });
});

describe('where a renewal starts (spec §6c.4)', () => {
  it('causes and moments: no-token, expired, explicit, and the lastRenewal of a remembered token at get-tokens and at prepare', async () => {
    const s = scripted([]);
    const none = new ScriptedProvider({ renewal: s.strategy });
    await rejectionOf(none.getTokens());
    await rejectionOf(seeded(s.strategy).getTokens());
    await rejectionOf(seeded(s.strategy).refreshTokens());
    expect(s.situations.map((x) => [x.cause, x.moment])).toEqual([
      [{ trigger: 'no-token' }, 'get-tokens'],
      [{ trigger: 'expired' }, 'get-tokens'],
      [{ trigger: 'explicit' }, 'refresh-tokens'],
    ]);

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
    expect(
      b.situations
        .filter((x) => x.steps.length === 0)
        .map((x) => [x.cause, x.moment]),
    ).toEqual([
      [{ trigger: 'bound-elsewhere', lastRenewal: undefined }, 'get-tokens'],
      [{ trigger: 'bound-elsewhere', lastRenewal: remembered }, 'get-tokens'],
      // prepare() no longer clears it: the moment is the strategy's cue.
      [{ trigger: 'bound-elsewhere', lastRenewal: remembered }, 'prepare'],
    ]);
  });

  it('a valid cached token asks nothing', async () => {
    const s = scripted([]);
    const provider = new ScriptedProvider({
      renewal: s.strategy,
      accessToken: jwt('valid'),
    });
    await provider.getTokens();
    expect(s.situations).toHaveLength(0);
  });
});

describe('logging (spec §6c.9)', () => {
  it('one debug line per decision, allowlisted values only', async () => {
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
    expect(lines).toEqual([
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
