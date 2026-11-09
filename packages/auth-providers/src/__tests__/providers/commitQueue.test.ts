/**
 * What an attempt commits: one serialized commit queue per
 * provider, two watermarks (pin, credential), a late result of an aborted
 * attempt changing nothing — but a refresh's answer, which is the server's
 * state, committed when nothing newer was — and what the shipped
 * persistence strategy (`refreshStatePersistence`) writes for the reports
 * the commits make, a failed write kept pending. The grant calls are
 * scripted promises the test settles; the base class runs as shipped.
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  ICertificateMaterial,
  IClientAuthentication,
  ITokenResult,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { refreshStatePersistence } from '../../persistence';
import { refreshThenLogin } from '../../renewal';
import {
  Arrivals,
  type Deferred,
  deferred,
  jwt,
  quiet,
  rejectionOf,
} from '../helpers/attemptHarness';
import {
  certificate,
  otherCertificate,
  thumbprintOf,
} from '../helpers/certificates';
import { matchObject } from '../helpers/expectations';
import { type Seen, seenOf } from '../helpers/persistence';
import { ScriptedProvider, tokens } from '../helpers/scriptedProvider';

/**
 * The `token-binding` `renewed-bound-elsewhere` failure: since 6.0.0 a
 * renewal whose step obtained a token still bound elsewhere stops with it
 * (`refreshThenLogin()`), committed all the same.
 */
function isRenewedBoundElsewhere(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'token-binding' &&
    (read.facts as { problem?: string }).problem === 'renewed-bound-elsewhere'
  );
}

function isAborted(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'interactive-login' &&
    (read.facts as { outcome?: string }).outcome === 'aborted'
  );
}

/**
 * `refreshStatePersistence` over a write that records what it was told
 * (`Seen`), then runs `during` — which may hold the write or fail it.
 */
function recorder(
  during: (one: Seen) => Promise<void> | void = () => undefined,
) {
  const seen: Seen[] = [];
  const notified = new Arrivals<Seen>();
  const persistence = refreshStatePersistence(
    async (written) => {
      const one = seenOf(written);
      seen.push(one);
      notified.push(one);
      await during(one);
    },
    { onWriteFailure: 'continue' },
  );
  return { seen, notified, persistence };
}

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const boundTo = (thumbprint: string, subject: string) =>
  `${b64url({ alg: 'none' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) + 3600,
    sub: subject,
    cnf: { 'x5t#S256': thumbprint },
  })}.sig`;

describe('the doomed-join window', () => {
  it('every waiter aborts while the login is outstanding: a new caller starts afresh; the late result changes nothing', async () => {
    const { seen, persistence } = recorder();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
    });
    const only = new AbortController();
    const doomed = rejectionOf(provider.getTokens({ signal: only.signal }));
    const first = await provider.logins.nth(1);
    only.abort();
    assert.equal(isAborted(await doomed), true);
    assert.equal(first.attempt.signal.aborted, true);

    // Arriving before the first login answers: a fresh attempt.
    const fresh = provider.getTokens();
    const second = await provider.logins.nth(2);
    assert.notEqual(second.attempt, first.attempt);
    const T2 = jwt('second');
    second.result.resolve(tokens(T2, 'R2'));
    matchObject(await fresh, {
      authorizationToken: T2,
      refreshToken: 'R2',
    });

    first.result.resolve(tokens(jwt('first'), 'R1'));
    await quiet();
    assert.deepEqual(provider.held(), {
      access: T2,
      refresh: 'R2',
      pinned: undefined,
    });
    assert.deepEqual(seen, [[T2, 'R2', 'replace']]);
    // Still the second login's: served from the cache, nothing renewed.
    matchObject(await provider.getTokens(), {
      authorizationToken: T2,
    });
    assert.equal(provider.logins.items.length, 2);
  });

  it('the same for pin: a loader read outstanding when its waiters abort changes nothing', async () => {
    const reads: ReturnType<typeof deferred<ICertificateMaterial>>[] = [];
    const clientAuthentication: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: () => {
        const read = deferred<ICertificateMaterial>();
        reads.push(read);
        return read.promise;
      },
    };
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      clientAuthentication,
    });
    const pin = (signal?: AbortSignal) =>
      (
        provider as unknown as {
          pin(signal?: AbortSignal): Promise<{ thumbprint: string }>;
        }
      ).pin(signal);
    const only = new AbortController();
    // The pin attempt starts synchronously: its loader is called at once.
    const doomed = rejectionOf(pin(only.signal));
    assert.equal(reads.length, 1);
    only.abort();
    assert.equal(isAborted(await doomed), true);

    const fresh = pin();
    assert.equal(reads.length, 2);
    reads[1]?.resolve(otherCertificate());
    matchObject(await fresh, {
      thumbprint: thumbprintOf(otherCertificate()),
    });

    reads[0]?.resolve(certificate());
    await quiet();
    assert.equal(provider.held().pinned, thumbprintOf(otherCertificate()));
  });
});

describe('the doomed-join window, alone', () => {
  it('a pin whose only waiter aborted: its late loader read pins nothing', async () => {
    const read = deferred<ICertificateMaterial>();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      clientAuthentication: {
        authenticate: async () => ({}),
        tlsMaterial: () => read.promise,
      },
    });
    const only = new AbortController();
    const doomed = rejectionOf(
      (
        provider as unknown as {
          pin(signal?: AbortSignal): Promise<unknown>;
        }
      ).pin(only.signal),
    );
    only.abort();
    assert.equal(isAborted(await doomed), true);
    read.resolve(certificate());
    await quiet();
    assert.equal(provider.held().pinned, undefined);
  });
});

describe('the commit queue', () => {
  it('commits run one at a time, in order: a renewal whose report is held delays the next one; the newest is persisted last', async () => {
    const hooks = new Arrivals<{ access: string; done: Deferred<void> }>();
    let active = 0;
    let most = 0;
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence: {
        report: async (report) => {
          active += 1;
          most = Math.max(most, active);
          const done = deferred();
          hooks.push({ access: report.credential.authorizationToken, done });
          await done.promise;
          active -= 1;
        },
      },
    });
    const first = new AbortController();
    const older = rejectionOf(provider.getTokens({ signal: first.signal }));
    const login1 = await provider.logins.nth(1);
    const T1 = jwt('one');
    login1.result.resolve(tokens(T1, 'R1'));
    // The first commit has begun: it is in its report.
    await hooks.nth(1);
    assert.deepEqual(
      hooks.items.map((h) => h.access),
      [T1],
    );
    first.abort();
    assert.equal(isAborted(await older), true);

    // The held token is T1 now; force another renewal: a login.
    provider.expire();
    const T2 = jwt('two');
    const newer = provider.refreshTokens();
    const refresh = await provider.refreshes.nth(1);
    assert.equal(refresh.refreshToken, 'R1');
    refresh.result.resolve(tokens(T2, 'R2'));
    // Its commit waits for the first hook: not called yet.
    await quiet();
    assert.deepEqual(
      hooks.items.map((h) => h.access),
      [T1],
    );
    hooks.items[0]?.done.resolve();
    await hooks.nth(2);
    assert.deepEqual(
      hooks.items.map((h) => h.access),
      [T1, T2],
    );
    hooks.items[1]?.done.resolve();
    matchObject(await newer, { authorizationToken: T2 });
    assert.equal(most, 1);
    assert.equal(provider.held().access, T2);
  });

  it('an older-generation commit arriving after a newer one is discarded whole', async () => {
    const { seen, persistence } = recorder();
    const lines: string[] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: (message: string) => {
        lines.push(message);
      },
      warn: () => undefined,
      error: () => undefined,
    };
    const T0 = jwt('zero', -3600);
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
      logger,
      accessToken: T0,
      refreshToken: 'R0',
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const refresh = await provider.refreshes.nth(1);
    only.abort();
    assert.equal(isAborted(await cut), true);

    // A newer renewal logs in (R0 is quarantined) and commits first.
    const newer = provider.getTokens();
    const login = await provider.logins.nth(1);
    const T2 = jwt('login');
    login.result.resolve(tokens(T2, 'R2'));
    matchObject(await newer, { authorizationToken: T2 });

    // The older refresh answers late: discarded, nothing applied, no report.
    refresh.result.resolve(tokens(jwt('late'), 'R1'));
    await quiet();
    matchObject(provider.held(), { access: T2, refresh: 'R2' });
    assert.deepEqual(seen, [
      [T0, undefined, 'clear'],
      [T2, 'R2', 'replace'],
    ]);
    // Progress lines: one per applied commit, none for the discarded one.
    assert.equal(lines.filter((l) => l.includes('Login completed')).length, 1);
    assert.equal(
      lines.filter((l) => l.includes('Token refreshed successfully')).length,
      0,
    );
    assert.equal(lines.filter((l) => l.includes('Tokens updated')).length, 1);
  });

  it('an applied refresh writes its progress lines once, after the tokens and before the report', async () => {
    const order: string[] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: (message: string) => {
        order.push(message);
      },
      warn: () => undefined,
      error: () => undefined,
    };
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      logger,
      accessToken: jwt('old', -3600),
      refreshToken: 'R0',
      persistence: {
        report: () => {
          order.push('report');
        },
      },
    });
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('new'), 'R1'));
    await renewed;
    const relevant = order.filter(
      (l) =>
        l === 'report' ||
        l.includes('Tokens updated') ||
        l.includes('Token refreshed successfully'),
    );
    assert.deepEqual(relevant, [
      '[BaseTokenProvider] Tokens updated',
      '[BaseTokenProvider] Token refreshed successfully',
      'report',
    ]);
  });
});

describe('separate watermarks: the pin commit and the credential commit', () => {
  const pinningStrategy = () => {
    const reads = mock.fn(async () => certificate());
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: reads,
    };
    return { reads, strategy };
  };

  it('a first login on an unpinned provider: tokens persisted once, material pinned once, markIfElsewhere sees that pin', async () => {
    const { seen, persistence } = recorder();
    const { reads, strategy } = pinningStrategy();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
      clientAuthentication: strategy,
    });
    const renewed = rejectionOf(provider.getTokens());
    const login = await provider.logins.nth(1);
    // Bound elsewhere than the certificate this renewal pinned.
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'login');
    login.result.resolve(tokens(elsewhere, 'R1'));
    // Committed, and the renewal stops with the binding refusal.
    assert.equal(isRenewedBoundElsewhere(await renewed), true);
    assert.deepEqual(seen, [[elsewhere, 'R1', 'replace']]);
    assert.equal(reads.mock.callCount(), 1);
    assert.deepEqual(provider.held(), {
      access: elsewhere,
      refresh: 'R1',
      pinned: thumbprintOf(certificate()),
    });
    // markIfElsewhere saw the pin: the token is remembered, not renewed
    // again — the strategy stops on its lastRenewal.
    assert.equal(
      isRenewedBoundElsewhere(await rejectionOf(provider.getTokens())),
      true,
    );
    assert.equal(provider.logins.items.length, 1);
    assert.equal(provider.refreshes.items.length, 0);
  });

  it('a refresh of a seeded token on an unpinned provider: the same', async () => {
    const { seen, persistence } = recorder();
    const { reads, strategy } = pinningStrategy();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
      clientAuthentication: strategy,
      accessToken: jwt('seeded', -3600),
      refreshToken: 'R0',
    });
    const renewed = rejectionOf(provider.getTokens());
    const refresh = await provider.refreshes.nth(1);
    assert.equal(refresh.refreshToken, 'R0');
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'refresh');
    refresh.result.resolve(tokens(elsewhere, 'R1'));
    assert.equal(isRenewedBoundElsewhere(await renewed), true);
    assert.deepEqual(seen, [[elsewhere, 'R1', 'replace']]);
    assert.equal(reads.mock.callCount(), 1);
    assert.deepEqual(provider.held(), {
      access: elsewhere,
      refresh: 'R1',
      pinned: thumbprintOf(certificate()),
    });
    assert.equal(
      isRenewedBoundElsewhere(await rejectionOf(provider.getTokens())),
      true,
    );
    assert.equal(provider.refreshes.items.length, 1);
  });
});

describe('what refreshStatePersistence writes', () => {
  it('a refresh returning a new token: written', async () => {
    const { seen, persistence } = recorder();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
      accessToken: jwt('old', -3600),
      refreshToken: 'R0',
    });
    const renewed = provider.getTokens();
    const T1 = jwt('new');
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await renewed;
    assert.deepEqual(seen, [[T1, 'R1', 'replace']]);
  });

  it('a result with none and nothing cut: the stored one left (undefined)', async () => {
    const { seen, persistence } = recorder();
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
    });
    const renewed = provider.getTokens();
    const T1 = jwt('token-only');
    (await provider.logins.nth(1)).result.resolve(tokens(T1));
    await renewed;
    assert.deepEqual(seen, [[T1, undefined, 'keep']]);
  });

  it('the queued clearing step of a cut: one write of null with the held access token', async () => {
    const { seen, notified, persistence } = recorder();
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
      accessToken: T0,
      refreshToken: 'R0',
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    assert.equal(isAborted(await cut), true);
    await notified.nth(1);
    // Once, and nothing after it.
    await quiet();
    assert.deepEqual(seen, [[T0, undefined, 'clear']]);
    assert.equal(provider.held().refresh, undefined);
  });
});

describe('a failed write stays pending', () => {
  it("the clearing step's write fails: the next token-only commit writes null again, not undefined", async () => {
    let fail = true;
    const { seen, persistence } = recorder(() => {
      if (fail) {
        fail = false;
        throw new Error('store unavailable');
      }
    });
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: T0,
      refreshToken: 'R0',
      persistence,
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    await cut;
    const next = provider.getTokens();
    const T1 = jwt('token-only');
    (await provider.logins.nth(1)).result.resolve(tokens(T1));
    await next;
    assert.deepEqual(seen, [
      [T0, undefined, 'clear'],
      [T1, undefined, 'clear'],
    ]);
  });

  it('a failed new refresh token is written again with that token', async () => {
    let fail = true;
    const { seen, persistence } = recorder(() => {
      if (fail) {
        fail = false;
        throw new Error('store unavailable');
      }
    });
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: jwt('held', -3600),
      refreshToken: 'R0',
      persistence,
    });
    const T1 = jwt('one');
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await first;
    provider.expire();
    const T2 = jwt('two');
    const second = provider.getTokens();
    const refresh = await provider.refreshes.nth(2);
    assert.equal(refresh.refreshToken, 'R1');
    // A refresh answering an access token only, no refresh token.
    refresh.result.resolve(tokens(T2));
    await second;
    assert.deepEqual(seen, [
      [T1, 'R1', 'replace'],
      [T2, 'R1', 'replace'],
    ]);
  });

  it('a new refresh token supersedes a pending clear', async () => {
    let fail = true;
    const { seen, persistence } = recorder(() => {
      if (fail) {
        fail = false;
        throw new Error('store unavailable');
      }
    });
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: T0,
      refreshToken: 'R0',
      persistence,
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    await cut;
    const T1 = jwt('one');
    const login = provider.getTokens();
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'R1'));
    await login;
    provider.expire();
    const T2 = jwt('two');
    const refreshed = provider.getTokens();
    (await provider.refreshes.nth(2)).result.resolve(tokens(T2));
    await refreshed;
    assert.deepEqual(seen, [
      [T0, undefined, 'clear'],
      [T1, 'R1', 'replace'],
      [T2, undefined, 'keep'],
    ]);
  });

  it("a refused refresh's clearing step runs through the queue, after a held earlier commit; the token-only login after it writes null", async () => {
    const firstCall = deferred<void>();
    const held = deferred();
    let holdFirst = true;
    const { seen, persistence } = recorder(async () => {
      firstCall.resolve();
      if (holdFirst) {
        holdFirst = false;
        await held.promise;
      }
    });
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      persistence,
    });
    const first = new AbortController();
    const older = rejectionOf(provider.getTokens({ signal: first.signal }));
    const T1 = jwt('one');
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'R1'));
    await firstCall.promise;
    assert.deepEqual(seen, [[T1, 'R1', 'replace']]);
    first.abort();
    await older;

    // R1 is installed (in memory); the token expires: the next renewal
    // refreshes it.
    provider.expire();
    const next = provider.getTokens();
    const refresh = await provider.refreshes.nth(1);
    assert.equal(refresh.refreshToken, 'R1');
    refresh.result.reject(new Error('invalid_grant'));
    await quiet();
    // The clearing step waits behind the held commit.
    assert.deepEqual(seen, [[T1, 'R1', 'replace']]);
    assert.equal(provider.logins.items.length, 1);
    held.resolve();
    const login = await provider.logins.nth(2);
    assert.deepEqual(seen, [
      [T1, 'R1', 'replace'],
      [T1, undefined, 'clear'],
    ]);
    const T2 = jwt('two');
    login.result.resolve(tokens(T2));
    await next;
    assert.deepEqual(seen, [
      [T1, 'R1', 'replace'],
      [T1, undefined, 'clear'],
      [T2, undefined, 'clear'],
    ]);
  });
});

describe('an aborted renewal is never remembered (rule 8)', () => {
  it('a renewal that throws after its waiters aborted leaves the held token unremembered: the next need renews again', async () => {
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: async () => certificate(),
    };
    // Held, valid, bound to another certificate than the one pinned.
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'held');
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      clientAuthentication: strategy,
      accessToken: elsewhere,
    });
    const only = new AbortController();
    const doomed = rejectionOf(provider.getTokens({ signal: only.signal }));
    const first = await provider.logins.nth(1);
    only.abort();
    assert.equal(isAborted(await doomed), true);
    first.result.reject(new Error('the login failed'));
    await quiet();

    const next = provider.getTokens();
    const second = await provider.logins.nth(2);
    const fresh = boundTo(thumbprintOf(certificate()), 'fresh');
    second.result.resolve(tokens(fresh, 'R1'));
    matchObject(await next, { authorizationToken: fresh });
  });

  it('the same renewal not aborted is remembered: getTokens answers its error without renewing', async () => {
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: async () => certificate(),
    };
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'held');
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      clientAuthentication: strategy,
      accessToken: elsewhere,
    });
    const failing = rejectionOf(provider.getTokens());
    (await provider.logins.nth(1)).result.reject(new Error('failed'));
    const first = readFailure(await failing, 'unfamiliar-error');
    // The remembered error reaches the strategy as lastRenewal, and
    // refreshThenLogin() stops with it: the same error, no step.
    const again = readFailure(
      await rejectionOf(provider.getTokens()),
      'unfamiliar-error',
    );
    assert.equal(again, first);
    assert.equal(provider.logins.items.length, 1);
    assert.equal(provider.held().access, elsewhere);
  });
});
