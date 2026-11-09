/**
 * What a token provider reports to its persistence strategy: one report per
 * change of its credentials, made from inside the commit queue in commit order;
 * `awaited` decided when the report starts; an awaited failure is the
 * renewal's, a detached one is logged and attributed to nothing; nothing is
 * ever reported twice. The grant calls are scripted (`ScriptedProvider`); the
 * base class runs as shipped. The detached failure under plain node, with the
 * unhandled-rejection recorder, is in `raceScenarios.test.ts`.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  AuthProviderFailure,
  authError,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  IAuthProviderError,
  IRenewalStrategy,
  PersistenceReport,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { refreshThenLogin } from '../../renewal';
import { deferred, jwt, quiet, rejectionOf } from '../helpers/attemptHarness';
import {
  anyOf,
  cases,
  caseTitle,
  deepEqualWith,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { reportRecorder } from '../helpers/persistence';
import { ScriptedProvider, tokens } from '../helpers/scriptedProvider';

const errorOf = (thrown: unknown): IAuthProviderError =>
  readFailure(thrown, 'unfamiliar-error');

function expectPersistingFailure(thrown: unknown): void {
  matchObject(errorOf(thrown), {
    kind: 'unknown',
    facts: { operation: 'persisting-tokens', grant: 'authorization_code' },
  });
}

/** A provider holding an expired token and refresh token R. */
function seeded(
  extra: Partial<ConstructorParameters<typeof ScriptedProvider>[0]> = {},
  renewal: IRenewalStrategy = refreshThenLogin(),
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

function recordingLogger() {
  const lines: { level: string; message: string; meta: unknown }[] = [];
  const at =
    (level: string) =>
    (message: string, meta?: unknown): void => {
      lines.push({ level, message, meta });
    };
  const logger: ILogger = {
    debug: at('debug'),
    info: at('info'),
    warn: at('warn'),
    error: at('error'),
  };
  return { lines, logger };
}

/** The reports' events and refresh-token changes, in order. */
const shapes = (reports: readonly PersistenceReport[]) =>
  reports.map((r) =>
    r.event === 'credential'
      ? [
          r.event,
          r.credential.authorizationToken,
          r.refreshToken.change === 'new' ? r.refreshToken.value : 'none',
          r.awaited,
        ]
      : [r.event, r.credential.authorizationToken, r.awaited],
  );

describe('one report per change, in commit order', () => {
  it('two refreshes: one credential report each, in order, with the credential installed — the second without a new refresh token', async () => {
    const { reports, persistence } = reportRecorder();
    const provider = seeded({ persistence });
    const T1 = jwt('one');
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await first;
    provider.expire();
    const T2 = jwt('two');
    const second = provider.getTokens();
    (await provider.refreshes.nth(2)).result.resolve(tokens(T2));
    await second;
    deepEqualWith(reports, [
      {
        event: 'credential',
        credential: {
          authorizationToken: T1,
          tokenType: 'jwt',
          authType: 'authorization_code',
          expiresAt: anyOf(Number),
        },
        refreshToken: { change: 'new', value: 'R1' },
        awaited: true,
      },
      {
        event: 'credential',
        credential: {
          authorizationToken: T2,
          tokenType: 'jwt',
          authType: 'authorization_code',
          expiresAt: anyOf(Number),
        },
        refreshToken: { change: 'none' },
        awaited: true,
      },
    ]);
  });

  it('a cache hit reports nothing', async () => {
    const { reports, persistence } = reportRecorder();
    const provider = seeded({ persistence });
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('one'), 'R1'));
    await first;
    await provider.getTokens();
    await provider.getTokens();
    assert.equal(reports.length, 1);
  });

  it('a commit discarded by the watermark reports nothing', async () => {
    const { reports, persistence } = reportRecorder();
    const strategy: IRenewalStrategy = {
      next: (situation) =>
        situation.steps.length > 0
          ? { next: 'stop' }
          : situation.canRefresh
            ? { next: 'refresh', ifCut: 'keep' }
            : { next: 'login' },
    };
    const provider = seeded({ persistence }, strategy);
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const late = await provider.refreshes.nth(1);
    only.abort();
    await cut;
    // A newer renewal commits first: R was kept, so it refreshes again.
    const newer = provider.getTokens();
    const T2 = jwt('newer');
    (await provider.refreshes.nth(2)).result.resolve(tokens(T2, 'R2'));
    await newer;
    // The older attempt's late answer is older than what was committed.
    late.result.resolve(tokens(jwt('late'), 'LATE'));
    await quiet();
    assert.deepEqual(shapes(reports), [['credential', T2, 'R2', true]]);
    matchObject(provider.held(), { access: T2, refresh: 'R2' });
  });

  it("a sentRefreshToken 'discard' reports refresh-token-discarded with the credential held, awaited, before the login's report", async () => {
    const { reports, persistence } = reportRecorder();
    const provider = seeded({ persistence });
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.reject(refused());
    const T1 = jwt('login');
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
    await renewed;
    deepEqualWith(reports[0], {
      event: 'refresh-token-discarded',
      credential: {
        authorizationToken: provider.seededToken,
        tokenType: 'jwt',
        authType: 'authorization_code',
        expiresAt: anyOf(Number),
      },
      awaited: true,
    });
    assert.deepEqual(shapes(reports).slice(1), [['credential', T1, 'S', true]]);
  });

  it('a discard before any token is held reports the credential as an empty access token', async () => {
    const { reports, persistence } = reportRecorder();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      refreshToken: 'R',
      persistence,
    });
    const renewed = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    (await provider.logins.nth(1)).result.reject(new Error('login failed'));
    await renewed;
    assert.deepEqual(reports, [
      {
        event: 'refresh-token-discarded',
        credential: {
          authorizationToken: '',
          tokenType: 'jwt',
          authType: 'authorization_code',
          expiresAt: undefined,
        },
        awaited: true,
      },
    ]);
  });

  it('no provider without persistence builds one: nothing is reported, nothing fails', async () => {
    const provider = seeded();
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('one'), 'R1'));
    matchObject(await renewed, { refreshToken: 'R1' });
  });
});

describe('awaited or detached, decided when the report starts', () => {
  it("a refresh cut after dispatch with ifCut 'discard': the discard is reported detached", async () => {
    const { reports, persistence } = reportRecorder();
    const provider = seeded({ persistence });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    await cut;
    await quiet();
    assert.deepEqual(shapes(reports), [
      ['refresh-token-discarded', provider.seededToken, false],
    ]);
  });

  it('a late refresh result committed after its waiters were released is reported detached', async () => {
    const { reports, persistence } = reportRecorder();
    const strategy: IRenewalStrategy = {
      next: (situation) =>
        situation.steps.length > 0
          ? { next: 'stop' }
          : { next: 'refresh', ifCut: 'keep' },
    };
    const provider = seeded({ persistence }, strategy);
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const late = await provider.refreshes.nth(1);
    only.abort();
    await cut;
    const T2 = jwt('late');
    late.result.resolve(tokens(T2, 'R2'));
    await quiet();
    assert.deepEqual(shapes(reports), [['credential', T2, 'R2', false]]);
  });

  it('a report whose waiters all aborted while an earlier report held the queue is detached', async () => {
    const gate = deferred();
    const { reports, persistence } = reportRecorder((_r, index) =>
      index === 0 ? gate.promise : undefined,
    );
    const provider = seeded({ persistence });
    // Attempt A: its refresh commits, and its report holds the queue.
    const a = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: a.signal }));
    const T1 = jwt('one', -3600);
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await quiet();
    assert.equal(reports.length, 1);
    a.abort();
    await first;
    // Attempt B: its refresh answers while A's report still holds the
    // queue; B's only waiter aborts before B's report starts.
    const b = new AbortController();
    const second = rejectionOf(provider.refreshTokens({ signal: b.signal }));
    const T2 = jwt('two');
    const refreshB = await provider.refreshes.nth(2);
    assert.equal(refreshB.refreshToken, 'R1');
    refreshB.result.resolve(tokens(T2, 'R2'));
    await quiet();
    b.abort();
    await second;
    gate.resolve();
    await quiet();
    assert.deepEqual(shapes(reports), [
      ['credential', T1, 'R1', true],
      ['credential', T2, 'R2', false],
    ]);
  });
});

describe('an awaited failure is the renewal’s', () => {
  for (const [caseIndex, caseRow] of cases([
    [
      'a throw',
      () => {
        throw new Error('SECRET-PERSIST-TEXT');
      },
    ],
    ['a rejection', () => Promise.reject(new Error('SECRET-PERSIST-TEXT'))],
  ]).entries()) {
    const [_name, fail] = caseRow;
    it(
      caseTitle(
        '%s: both waiters get persisting-tokens, the token stays cached, nothing is logged in to',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { reports, persistence } = reportRecorder(fail);
        const provider = seeded({ persistence });
        const one = rejectionOf(provider.getTokens());
        const two = rejectionOf(provider.getTokens());
        const T2 = jwt('rotated');
        (await provider.refreshes.nth(1)).result.resolve(tokens(T2, 'R2'));
        const [a, b] = [await one, await two];
        expectPersistingFailure(a);
        expectPersistingFailure(b);
        assert.equal(errorOf(a), errorOf(b));
        notContains(JSON.stringify(errorOf(a)), 'SECRET');
        await quiet();
        assert.equal(provider.logins.items.length, 0);
        // The committed credentials are the server's state: the cache answers.
        matchObject(await provider.getTokens(), {
          authorizationToken: T2,
          refreshToken: 'R2',
        });
        assert.equal(provider.refreshes.items.length, 1);
        // No repetition: the failed report was made once.
        assert.equal(reports.length, 1);
      },
    );
  }

  it('after a login: the renewal fails, nothing more', async () => {
    const { persistence } = reportRecorder(() => {
      throw new Error('SECRET');
    });
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
    });
    const thrown = rejectionOf(provider.getTokens());
    const T1 = jwt('login');
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
    expectPersistingFailure(await thrown);
    await quiet();
    assert.equal(provider.logins.items.length, 1);
    matchObject(provider.held(), { access: T1, refresh: 'S' });
  });

  it("a sentRefreshToken 'discard' whose report fails ends the renewal before the login", async () => {
    const { reports, persistence } = reportRecorder((r) => {
      if (r.event === 'refresh-token-discarded') throw new Error('SECRET');
    });
    const provider = seeded({ persistence });
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.reject(refused());
    expectPersistingFailure(await thrown);
    await quiet();
    assert.equal(provider.logins.items.length, 0);
    assert.equal(provider.held().refresh, undefined);
    assert.equal(reports.length, 1);
  });

  it('a minted failure thrown by the strategy is not relayed as itself', async () => {
    const minted = refusedFailure();
    const { persistence } = reportRecorder(() => {
      throw minted;
    });
    const provider = seeded({ persistence });
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('x'), 'R2'));
    expectPersistingFailure(await thrown);
  });

  it('a strategy whose report is taken away after construction fails the awaited report (defence in depth)', async () => {
    const persistence: { report?: unknown } = { report: () => undefined };
    const provider = seeded({ persistence: persistence as never });
    delete persistence.report;
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('x'), 'R2'));
    expectPersistingFailure(await thrown);
  });
});

describe('a detached failure is logged and attributed to nothing', () => {
  for (const [caseIndex, caseRow] of cases([
    [
      'a throw',
      () => {
        throw new Error('SECRET-PERSIST-TEXT');
      },
    ],
    ['a rejection', () => Promise.reject(new Error('SECRET-PERSIST-TEXT'))],
  ]).entries()) {
    const [_name, fail] = caseRow;
    it(
      caseTitle(
        '%s: one log line, the next report still made, no later call fails',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { lines, logger } = recordingLogger();
        const { reports, persistence } = reportRecorder((r) =>
          r.awaited ? undefined : fail(),
        );
        const provider = seeded({ persistence, logger });
        const only = new AbortController();
        const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
        await provider.refreshes.nth(1);
        only.abort();
        await cut;
        await quiet();
        const failures = lines.filter(
          (l) =>
            l.message === '[BaseTokenProvider] Persisting the tokens failed',
        );
        assert.deepEqual(failures, [
          {
            level: 'warn',
            message: '[BaseTokenProvider] Persisting the tokens failed',
            meta: {
              error: 'persisting the tokens failed (unknown error)',
              kind: 'unknown',
            },
          },
        ]);
        notContains(JSON.stringify(lines), 'SECRET');
        // The next renewal: a login (R was discarded), reported, and it succeeds.
        const T1 = jwt('login');
        const renewed = provider.getTokens();
        (await provider.logins.nth(1)).result.resolve(tokens(T1, 'S'));
        matchObject(await renewed, { authorizationToken: T1 });
        assert.deepEqual(shapes(reports), [
          ['refresh-token-discarded', provider.seededToken, false],
          ['credential', T1, 'S', true],
        ]);
      },
    );
  }
});

describe('an awaited report whose every waiter left while it ran', () => {
  it('fails after the abort: logged as a detached failure, once, in fixed words', async () => {
    const { lines, logger } = recordingLogger();
    const gate = deferred();
    const { persistence } = reportRecorder(async () => {
      await gate.promise;
      throw new Error('SECRET-PERSIST-TEXT');
    });
    const provider = seeded({ persistence, logger });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('one'), 'R1'));
    await quiet();
    only.abort();
    await cut;
    gate.resolve();
    await quiet();
    const failures = lines.filter(
      (l) => l.message === '[BaseTokenProvider] Persisting the tokens failed',
    );
    assert.deepEqual(failures, [
      {
        level: 'warn',
        message: '[BaseTokenProvider] Persisting the tokens failed',
        meta: {
          error: 'persisting the tokens failed (unknown error)',
          kind: 'unknown',
        },
      },
    ]);
    notContains(JSON.stringify(lines), 'SECRET');
  });

  it('a waiter still there gets the failure, and nothing is logged as detached', async () => {
    const { lines, logger } = recordingLogger();
    const { persistence } = reportRecorder(() => {
      throw new Error('SECRET');
    });
    const provider = seeded({ persistence, logger });
    const thrown = rejectionOf(provider.getTokens());
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('one'), 'R1'));
    expectPersistingFailure(await thrown);
    assert.deepEqual(
      lines.filter(
        (l) => l.message === '[BaseTokenProvider] Persisting the tokens failed',
      ),
      [],
    );
  });
});

describe('no repetition', () => {
  it('a report failed once is never made again by the provider', async () => {
    let failures = 1;
    const { reports, persistence } = reportRecorder(() => {
      if (failures-- > 0) throw new Error('SECRET');
    });
    const provider = seeded({ persistence });
    const first = rejectionOf(provider.getTokens());
    const T1 = jwt('one', -3600);
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    expectPersistingFailure(await first);
    // The next renewal reports its own change only: R1 is not said again.
    provider.expire();
    const T2 = jwt('two');
    const second = provider.getTokens();
    (await provider.refreshes.nth(2)).result.resolve(tokens(T2));
    await second;
    assert.deepEqual(shapes(reports), [
      ['credential', T1, 'R1', true],
      ['credential', T2, 'none', true],
    ]);
  });
});

describe('the report is a fresh object', () => {
  it('a strategy changing its report changes nothing held or returned', async () => {
    const persistence = {
      report(report: PersistenceReport) {
        const r = report as unknown as {
          credential: { authorizationToken: string };
          refreshToken: { value: string };
        };
        r.credential.authorizationToken = 'CHANGED';
        r.refreshToken.value = 'CHANGED';
      },
    };
    const provider = seeded({ persistence });
    const T1 = jwt('one');
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    matchObject(await renewed, {
      authorizationToken: T1,
      refreshToken: 'R1',
    });
    matchObject(provider.held(), { access: T1, refresh: 'R1' });
  });
});

describe('what the provider returns', () => {
  it('carries the held refresh token or none, and no disposition', async () => {
    const provider = seeded();
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('one')));
    const renewed = await first;
    assert.equal(renewed.refreshToken, 'R');
    assert.equal('refreshTokenDisposition' in renewed, false);
    const cached = await provider.getTokens();
    assert.equal(cached.refreshToken, 'R');
    assert.equal('refreshTokenDisposition' in cached, false);
  });
});

/** A failure minted by auth-errors, as a strategy might rethrow one. */
function refusedFailure(): AuthProviderFailure {
  return new AuthProviderFailure(
    authError['credential-refused']({ credential: 'refresh-token' }),
  );
}
