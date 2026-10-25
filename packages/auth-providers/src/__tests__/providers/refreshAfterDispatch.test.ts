/**
 * A refresh aborted after dispatch is an uncertain outcome: the
 * server may have consumed R and issued R2. On a real socket through real
 * axios — a local token endpoint that rotates R → R2 and withholds its
 * answer; never a mocked `sendTokenRequest`, since the point is what axios
 * does with a request given a signal. The refresh request runs on; its
 * waiters are released at once; R is quarantined for the provider's
 * lifetime and never submitted again; a late answer is committed only when
 * nothing newer was.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { refreshStatePersistence } from '../../persistence';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { refreshThenLogin } from '../../renewal';
import {
  Arrivals,
  type Deferred,
  deferred,
  type HeldRequest,
  jwt,
  quiet,
  rejectionOf,
  startTokenServer,
  type TokenServer,
  type WaitingStrategy,
  waitingStrategy,
} from '../helpers/attemptHarness';
import { type Seen, seenOf } from '../helpers/persistence';

const silent: ILogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function isAborted(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'interactive-login' &&
    (read.facts as { outcome?: string }).outcome === 'aborted'
  );
}

let server: TokenServer;
/** Refresh requests the server holds, in arrival order. */
let heldRefreshes: Arrivals<HeldRequest>;
/** What each login's code exchange answers, by login number. */
let loginAnswers: Map<number, object>;
let loginCount: number;

beforeEach(async () => {
  heldRefreshes = new Arrivals<HeldRequest>();
  loginAnswers = new Map();
  loginCount = 0;
  server = await startTokenServer((request) => {
    if (request.params.get('grant_type') === 'refresh_token') {
      heldRefreshes.push(request);
      return;
    }
    loginCount += 1;
    request.answer(
      200,
      loginAnswers.get(loginCount) ?? {
        access_token: jwt(`login-${loginCount}`),
        refresh_token: `S-${loginCount}`,
      },
    );
  });
});
afterEach(async () => {
  await server.close();
});

/** The refresh tokens the server received, in order. */
const submitted = () =>
  server.requests
    .filter((r) => r.params.get('grant_type') === 'refresh_token')
    .map((r) => r.params.get('refresh_token'));

function provider(
  strategy: WaitingStrategy,
  seeded: { access?: string; refresh?: string } = {},
  /** Runs inside each write, after it is recorded: may hold it. */
  during?: () => Promise<void>,
): {
  p: AuthorizationCodeProvider;
  seen: Seen[];
  notified: Arrivals<Seen>;
} {
  const seen: Seen[] = [];
  const notified = new Arrivals<Seen>();
  const p = new AuthorizationCodeProvider({
    renewal: refreshThenLogin(),
    uaaUrl: server.url,
    clientId: 'cid',
    clientSecret: 'sec',
    authorization: strategy,
    logger: silent,
    ...(seeded.access ? { accessToken: seeded.access } : {}),
    ...(seeded.refresh ? { refreshToken: seeded.refresh } : {}),
    // The behaviour onTokens had before 6.0.0: the shipped strategy.
    persistence: refreshStatePersistence(
      async (written) => {
        const one = seenOf(written);
        seen.push(one);
        notified.push(one);
        await during?.();
      },
      { onWriteFailure: 'continue' },
    ),
  });
  return { p, seen, notified };
}

/** Starts a refresh of R through `getTokens({ signal })` and cuts it once the server holds it. */
async function cutRefresh(
  p: AuthorizationCodeProvider,
  index: number,
): Promise<HeldRequest> {
  const only = new AbortController();
  const cut = rejectionOf(p.getTokens({ signal: only.signal }));
  const held = await waitForRefresh(index);
  only.abort();
  // The waiter is released at once, the server not having answered.
  expect(isAborted(await cut)).toBe(true);
  return held;
}

async function waitForRefresh(index: number): Promise<HeldRequest> {
  return heldRefreshes.nth(index + 1);
}

const expired = (subject: string) => jwt(subject, -3600);

describe('a refresh aborted after dispatch', () => {
  it('the waiter is released at once; the request is not aborted; the next moment does not submit R and logs in', async () => {
    const strategy = waitingStrategy();
    const { p } = provider(strategy, {
      access: expired('held'),
      refresh: 'R',
    });
    const held = await cutRefresh(p, 0);
    // The socket must stay open: no event exists for a cut that must not come.
    await quiet();
    // Not cut: the socket is still open, the server still holds it.
    expect(held.aborted()).toBe(false);

    // A replacement proceeds without waiting for the held refresh.
    const next = p.getTokens();
    const login = await strategy.nth(1);
    login.answer('code-1');
    await expect(next).resolves.toMatchObject({ refreshToken: 'S-1' });
    expect(submitted()).toEqual(['R']);
    expect(held.aborted()).toBe(false);
    held.answer(200, { access_token: jwt('late'), refresh_token: 'R2' });
  });

  it('the withheld answer released later, nothing newer committed: R2 and its tokens adopted and persisted', async () => {
    const strategy = waitingStrategy();
    const T0 = expired('held');
    const { p, seen, notified } = provider(strategy, {
      access: T0,
      refresh: 'R',
    });
    const held = await cutRefresh(p, 0);
    const T2 = jwt('rotated');
    held.answer(200, { access_token: T2, refresh_token: 'R2' });
    await notified.nth(2);
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [T2, 'R2', 'replace'],
    ]);
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: T2,
      refreshToken: 'R2',
    });
    expect(strategy.calls).toHaveLength(0);
    expect(submitted()).toEqual(['R']);
  });

  it('a newer login committed first: the late R2 is discarded; the login stays, persisted last', async () => {
    const strategy = waitingStrategy();
    const T0 = expired('held');
    const { p, seen, notified } = provider(strategy, {
      access: T0,
      refresh: 'R',
    });
    const held = await cutRefresh(p, 0);
    const next = p.getTokens();
    (await strategy.nth(1)).answer('code-1');
    const login = await next;
    expect(login.refreshToken).toBe('S-1');

    held.answer(200, { access_token: jwt('late'), refresh_token: 'R2' });
    await held.closed;
    // The late answer must change nothing: no event exists for that.
    await quiet();
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [login.authorizationToken, 'S-1', 'replace'],
    ]);
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: login.authorizationToken,
      refreshToken: 'S-1',
    });
  });
});

describe('quarantine before the queue', () => {
  it('a commit installs R and stalls in its report; a replacement reads R, refreshes, is cut; the next does not submit R and logs in', async () => {
    const strategy = waitingStrategy();
    const stall = deferred<void>();
    let stalled = false;
    // Login 1 answers an expired access token: the next need refreshes R.
    loginAnswers.set(1, { access_token: expired('one'), refresh_token: 'R' });
    const { p, seen, notified } = provider(strategy, {}, async () => {
      if (stalled) return;
      stalled = true;
      await stall.promise;
    });
    const a = new AbortController();
    const first = rejectionOf(p.getTokens({ signal: a.signal }));
    (await strategy.nth(1)).answer('code-1');
    await notified.nth(1);
    // Commit A has installed R and is stalled in its report.
    a.abort();
    expect(isAborted(await first)).toBe(true);

    // Replacement B reads R, dispatches its refresh, and is cut.
    await cutRefresh(p, 0);
    expect(submitted()).toEqual(['R']);

    // Replacement C: R is quarantined, so it logs in — while the queue is
    // still held by A's report, before any queued step has run.
    const c = p.getTokens();
    const login = await strategy.nth(2);
    expect(submitted()).toEqual(['R']);
    login.answer('code-2');
    // Nothing may be notified while A holds the queue: no event exists.
    await quiet();
    expect(seen).toHaveLength(1);

    // Release A: the queue drains — the cut's clearing, then C's commit.
    stall.resolve();
    await expect(c).resolves.toMatchObject({ refreshToken: 'S-2' });
    expect(submitted()).toEqual(['R']);
    expect(
      seen.map(([, refresh, disposition]) => [refresh, disposition]),
    ).toEqual([
      ['R', 'replace'],
      [undefined, 'clear'],
      ['S-2', 'replace'],
    ]);
    heldRefreshes.items[0]?.answer(200, { access_token: jwt('late') });
  });
});

describe('tombstones for life', () => {
  // A result carrying a discarded refresh token is read as
  // carrying none, nothing more — S, held before, stays held.
  it('R cut, S installed, a newer commit returns R: R is not installed, never submitted again, and S stays held', async () => {
    const strategy = waitingStrategy();
    const { p, seen } = provider(strategy, {
      access: expired('held'),
      refresh: 'R',
    });
    const held = await cutRefresh(p, 0);

    // A login installs S.
    loginAnswers.set(1, { access_token: expired('one'), refresh_token: 'S' });
    const login = p.getTokens();
    (await strategy.nth(1)).answer('code-1');
    await expect(login).resolves.toMatchObject({ refreshToken: 'S' });

    // A refresh of S whose answer returns R again.
    const refreshS = p.getTokens();
    const second = await waitForRefresh(1);
    expect(second.params.get('refresh_token')).toBe('S');
    const T2 = expired('two');
    second.answer(200, { access_token: T2, refresh_token: 'R' });
    const afterS = await refreshS;
    expect(afterS.refreshToken).toBe('S');
    // Told as a result with no refresh token: the one stored stands.
    expect(seen.at(-1)).toEqual([T2, undefined, 'keep']);

    // The next renewal refreshes S again; R is never submitted again.
    const next = p.getTokens();
    const third = await waitForRefresh(2);
    expect(third.params.get('refresh_token')).toBe('S');
    third.answer(200, { access_token: jwt('three'), refresh_token: 'S3' });
    await expect(next).resolves.toMatchObject({ refreshToken: 'S3' });
    expect(submitted()).toEqual(['R', 'S', 'S']);
    expect(strategy.calls).toHaveLength(1);
    held.answer(200, { access_token: jwt('late') });
  });

  it('a late answer of a non-rotating endpoint returning R: its access token installed, R neither installed nor persisted as usable', async () => {
    const strategy = waitingStrategy();
    const T0 = expired('held');
    const { p, seen, notified } = provider(strategy, {
      access: T0,
      refresh: 'R',
    });
    const held = await cutRefresh(p, 0);
    const T2 = jwt('non-rotating');
    // No refresh_token in the answer: the site keeps the one it sent, R.
    held.answer(200, { access_token: T2 });
    await notified.nth(2);
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [T2, undefined, 'clear'],
    ]);
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: T2,
      refreshToken: undefined,
    });
  });
});

describe('a refresh answered, then cut while its outcome waits in the queue', () => {
  /**
   * Z refreshes R0 → R1, its commit stalls in its report, its waiter aborts.
   * W refreshes R1; the server answers W; W's outcome (a commit, or a
   * clearing step) waits behind Z; then W's waiter aborts. The next renewal
   * must not send R1 again: it is quarantined until W's outcome is applied.
   */
  async function answeredThenCut(answerW: (held: HeldRequest) => void) {
    const strategy = waitingStrategy();
    // Z's report stalls; every later one passes.
    const stall = deferred<void>();
    const stalled = deferred<void>();
    let first = true;
    const { p, seen } = provider(
      strategy,
      { access: expired('old'), refresh: 'R0' },
      async () => {
        if (!first) return;
        first = false;
        stalled.resolve();
        await stall.promise;
      },
    );
    const a = new AbortController();
    const z = rejectionOf(p.getTokens({ signal: a.signal }));
    (await waitForRefresh(0)).answer(200, {
      access_token: jwt('Z', 10),
      refresh_token: 'R1',
    });
    await stalled.promise;
    a.abort();
    expect(isAborted(await z)).toBe(true);

    const s1 = new AbortController();
    const w = rejectionOf(p.refreshTokens({ signal: s1.signal }));
    const held = await waitForRefresh(1);
    expect(held.params.get('refresh_token')).toBe('R1');
    answerW(held);
    // W's answer has reached the client: its socket is done.
    await held.closed;
    // Let the answer reach the provider and queue its outcome behind Z: it
    // happens inside the provider, with no event a test can await.
    await quiet();
    s1.abort();
    expect(isAborted(await w)).toBe(true);

    // X: a new renewal, while the queue is still held by Z's report.
    const x = p.refreshTokens();
    const login = await strategy.nth(1);
    expect(submitted()).toEqual(['R0', 'R1']);
    login.answer('code-1');
    stall.resolve();
    await x;
    expect(submitted()).toEqual(['R0', 'R1']);
    return seen;
  }

  it('answered with R2: R1 is not sent again; R2 is still committed before the login', async () => {
    const seen = await answeredThenCut((held) =>
      held.answer(200, { access_token: jwt('W'), refresh_token: 'R2' }),
    );
    expect(seen.map(([, refresh, how]) => [refresh, how])).toContainEqual([
      'R2',
      'replace',
    ]);
  });

  it('refused (400 invalid_grant): R1 is not sent again', async () => {
    await answeredThenCut((held) =>
      held.answer(400, { error: 'invalid_grant' }),
    );
  });
});

describe('a refresh whose own commit step fails', () => {
  // A commit step that throws after the server answered is a refresh that
  // failed after it was sent: refreshThenLogin() discards R and
  // logs in, within the same renewal.
  it('after the server rotated R → R2, a throwing commit step: R is spent, the renewal logs in and R reaches the server once', async () => {
    class FailingOnce extends AuthorizationCodeProvider {
      fail = 1;
      protected override updateTokens(
        result: Parameters<AuthorizationCodeProvider['updateTokens']>[0],
      ): void {
        if (this.fail > 0) {
          this.fail -= 1;
          throw new Error('subclass update failed');
        }
        super.updateTokens(result);
      }
    }
    const strategy = waitingStrategy();
    const p = new FailingOnce({
      renewal: refreshThenLogin(),
      uaaUrl: server.url,
      clientId: 'cid',
      clientSecret: 'sec',
      authorization: strategy,
      logger: silent,
      accessToken: expired('held'),
      refreshToken: 'R',
    });
    const renewed = p.getTokens();
    (await waitForRefresh(0)).answer(200, {
      access_token: jwt('rotated'),
      refresh_token: 'R2',
    });
    (await strategy.nth(1)).answer('code-1');
    await expect(renewed).resolves.toMatchObject({ refreshToken: 'S-1' });
    await expect(p.getTokens()).resolves.toMatchObject({
      refreshToken: 'S-1',
    });
    expect(submitted()).toEqual(['R']);
    expect(strategy.calls).toHaveLength(1);
  });
});
