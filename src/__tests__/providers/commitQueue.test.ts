/**
 * What an attempt commits (spec §6b): one serialized commit queue per
 * provider, two watermarks (pin, credential), a late result of an aborted
 * attempt changing nothing — but a refresh's answer, which is the server's
 * state, committed when nothing newer was — the refresh-token disposition
 * every credential notification carries, and a failed notification kept
 * pending. The grant calls are scripted promises the test settles; the base
 * class runs as shipped.
 */

import { describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import type { TokenResultWithDisposition } from '../../providers/BaseTokenProvider';
import {
  type Deferred,
  deferred,
  jwt,
  rejectionOf,
  settle,
} from '../helpers/attemptHarness';
import {
  certificate,
  otherCertificate,
  thumbprintOf,
} from '../helpers/certificates';
import { ScriptedProvider, tokens } from '../helpers/scriptedProvider';

function isAborted(error: unknown): boolean {
  const read = readFailure(error, 'unfamiliar-error');
  return (
    read.kind === 'interactive-login' &&
    (read.facts as { outcome?: string }).outcome === 'aborted'
  );
}

/** What onTokens saw: access token, refresh token, disposition. */
type Seen = [string, string | undefined, string | undefined];
function recorder() {
  const seen: Seen[] = [];
  const onTokens = async (result: TokenResultWithDisposition) => {
    seen.push([
      result.authorizationToken,
      result.refreshToken,
      result.refreshTokenDisposition,
    ]);
  };
  return { seen, onTokens };
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
    const { seen, onTokens } = recorder();
    const provider = new ScriptedProvider({ onTokens });
    const only = new AbortController();
    const doomed = rejectionOf(provider.getTokens({ signal: only.signal }));
    const first = await provider.logins.nth(1);
    only.abort();
    expect(isAborted(await doomed)).toBe(true);
    expect(first.attempt.signal.aborted).toBe(true);

    // Arriving before the first login answers: a fresh attempt.
    const fresh = provider.getTokens();
    const second = await provider.logins.nth(2);
    expect(second.attempt).not.toBe(first.attempt);
    const T2 = jwt('second');
    second.result.resolve(tokens(T2, 'R2'));
    await expect(fresh).resolves.toMatchObject({
      authorizationToken: T2,
      refreshToken: 'R2',
    });

    first.result.resolve(tokens(jwt('first'), 'R1'));
    await settle();
    expect(provider.held()).toEqual({
      access: T2,
      refresh: 'R2',
      pinned: undefined,
    });
    expect(seen).toEqual([[T2, 'R2', 'replace']]);
    // Still the second login's: served from the cache, nothing renewed.
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: T2,
    });
    expect(provider.logins.items).toHaveLength(2);
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
    const provider = new ScriptedProvider({ clientAuthentication });
    const pin = (signal?: AbortSignal) =>
      (
        provider as unknown as {
          pin(signal?: AbortSignal): Promise<{ thumbprint: string }>;
        }
      ).pin(signal);
    const only = new AbortController();
    const doomed = rejectionOf(pin(only.signal));
    await settle();
    expect(reads).toHaveLength(1);
    only.abort();
    expect(isAborted(await doomed)).toBe(true);

    const fresh = pin();
    await settle();
    expect(reads).toHaveLength(2);
    reads[1]?.resolve(otherCertificate());
    await expect(fresh).resolves.toMatchObject({
      thumbprint: thumbprintOf(otherCertificate()),
    });

    reads[0]?.resolve(certificate());
    await settle();
    expect(provider.held().pinned).toBe(thumbprintOf(otherCertificate()));
  });
});

describe('the commit queue', () => {
  it('commits run one at a time, in order: a renewal whose onTokens is held delays the next one; the newest is persisted last', async () => {
    const hooks: { access: string; done: Deferred<void> }[] = [];
    let active = 0;
    let most = 0;
    const provider = new ScriptedProvider({
      onTokens: async (result) => {
        active += 1;
        most = Math.max(most, active);
        const done = deferred();
        hooks.push({ access: result.authorizationToken, done });
        await done.promise;
        active -= 1;
      },
    });
    const first = new AbortController();
    const older = rejectionOf(provider.getTokens({ signal: first.signal }));
    const login1 = await provider.logins.nth(1);
    const T1 = jwt('one');
    login1.result.resolve(tokens(T1, 'R1'));
    await settle();
    // The first commit has begun: it is in its onTokens.
    expect(hooks.map((h) => h.access)).toEqual([T1]);
    first.abort();
    expect(isAborted(await older)).toBe(true);

    // The held token is T1 now; force another renewal: a login.
    provider.expire();
    const T2 = jwt('two');
    const newer = provider.refreshTokens();
    const refresh = await provider.refreshes.nth(1);
    expect(refresh.refreshToken).toBe('R1');
    refresh.result.resolve(tokens(T2, 'R2'));
    await settle();
    // Its commit waits for the first hook: not called yet.
    expect(hooks.map((h) => h.access)).toEqual([T1]);
    hooks[0]?.done.resolve();
    await settle();
    expect(hooks.map((h) => h.access)).toEqual([T1, T2]);
    hooks[1]?.done.resolve();
    await expect(newer).resolves.toMatchObject({ authorizationToken: T2 });
    expect(most).toBe(1);
    expect(provider.held().access).toBe(T2);
  });

  it('an older-generation commit arriving after a newer one is discarded whole', async () => {
    const { seen, onTokens } = recorder();
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
      onTokens,
      logger,
      accessToken: T0,
      refreshToken: 'R0',
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    const refresh = await provider.refreshes.nth(1);
    only.abort();
    expect(isAborted(await cut)).toBe(true);

    // A newer renewal logs in (R0 is quarantined) and commits first.
    const newer = provider.getTokens();
    const login = await provider.logins.nth(1);
    const T2 = jwt('login');
    login.result.resolve(tokens(T2, 'R2'));
    await expect(newer).resolves.toMatchObject({ authorizationToken: T2 });

    // The older refresh answers late: discarded, nothing applied, no hook.
    refresh.result.resolve(tokens(jwt('late'), 'R1'));
    await settle();
    expect(provider.held()).toMatchObject({ access: T2, refresh: 'R2' });
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [T2, 'R2', 'replace'],
    ]);
    // Progress lines: one per applied commit, none for the discarded one.
    expect(lines.filter((l) => l.includes('Login completed'))).toHaveLength(1);
    expect(
      lines.filter((l) => l.includes('Token refreshed successfully')),
    ).toHaveLength(0);
    expect(lines.filter((l) => l.includes('Tokens updated'))).toHaveLength(1);
  });

  it('an applied refresh writes its progress lines once, after the tokens and before onTokens', async () => {
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
      logger,
      accessToken: jwt('old', -3600),
      refreshToken: 'R0',
      onTokens: async () => {
        order.push('onTokens');
      },
    });
    const renewed = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(jwt('new'), 'R1'));
    await renewed;
    const relevant = order.filter(
      (l) =>
        l === 'onTokens' ||
        l.includes('Tokens updated') ||
        l.includes('Token refreshed successfully'),
    );
    expect(relevant).toEqual([
      '[BaseTokenProvider] Tokens updated',
      '[BaseTokenProvider] Token refreshed successfully',
      'onTokens',
    ]);
  });
});

describe('separate watermarks: the pin commit and the credential commit', () => {
  const pinningStrategy = () => {
    const reads = jest.fn(async () => certificate());
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: reads,
    };
    return { reads, strategy };
  };

  it('a first login on an unpinned provider: tokens persisted once, material pinned once, markIfElsewhere sees that pin', async () => {
    const { seen, onTokens } = recorder();
    const { reads, strategy } = pinningStrategy();
    const provider = new ScriptedProvider({
      onTokens,
      clientAuthentication: strategy,
    });
    const renewed = provider.getTokens();
    const login = await provider.logins.nth(1);
    // Bound elsewhere than the certificate this renewal pinned.
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'login');
    login.result.resolve(tokens(elsewhere, 'R1'));
    await expect(renewed).resolves.toMatchObject({
      authorizationToken: elsewhere,
      refreshToken: 'R1',
    });
    expect(seen).toEqual([[elsewhere, 'R1', 'replace']]);
    expect(reads).toHaveBeenCalledTimes(1);
    expect(provider.held()).toEqual({
      access: elsewhere,
      refresh: 'R1',
      pinned: thumbprintOf(certificate()),
    });
    // markIfElsewhere saw the pin: the token is remembered, not renewed again.
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: elsewhere,
    });
    expect(provider.logins.items).toHaveLength(1);
    expect(provider.refreshes.items).toHaveLength(0);
  });

  it('a refresh of a seeded token on an unpinned provider: the same', async () => {
    const { seen, onTokens } = recorder();
    const { reads, strategy } = pinningStrategy();
    const provider = new ScriptedProvider({
      onTokens,
      clientAuthentication: strategy,
      accessToken: jwt('seeded', -3600),
      refreshToken: 'R0',
    });
    const renewed = provider.getTokens();
    const refresh = await provider.refreshes.nth(1);
    expect(refresh.refreshToken).toBe('R0');
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'refresh');
    refresh.result.resolve(tokens(elsewhere, 'R1'));
    await expect(renewed).resolves.toMatchObject({
      authorizationToken: elsewhere,
      refreshToken: 'R1',
    });
    expect(seen).toEqual([[elsewhere, 'R1', 'replace']]);
    expect(reads).toHaveBeenCalledTimes(1);
    expect(provider.held().pinned).toBe(thumbprintOf(certificate()));
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: elsewhere,
    });
    expect(provider.refreshes.items).toHaveLength(1);
  });
});

describe('dispositions', () => {
  it("a refresh returning a new token: 'replace'", async () => {
    const { seen, onTokens } = recorder();
    const provider = new ScriptedProvider({
      onTokens,
      accessToken: jwt('old', -3600),
      refreshToken: 'R0',
    });
    const renewed = provider.getTokens();
    const T1 = jwt('new');
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await renewed;
    expect(seen).toEqual([[T1, 'R1', 'replace']]);
  });

  it("a result with none and nothing cut: 'keep'", async () => {
    const { seen, onTokens } = recorder();
    const provider = new ScriptedProvider({ onTokens });
    const renewed = provider.getTokens();
    const T1 = jwt('token-only');
    (await provider.logins.nth(1)).result.resolve(tokens(T1));
    await renewed;
    expect(seen).toEqual([[T1, undefined, 'keep']]);
  });

  it("the queued clearing step of a cut: onTokens once with 'clear' and the held access token", async () => {
    const { seen, onTokens } = recorder();
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      onTokens,
      accessToken: T0,
      refreshToken: 'R0',
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    expect(isAborted(await cut)).toBe(true);
    await settle();
    expect(seen).toEqual([[T0, undefined, 'clear']]);
    expect(provider.held().refresh).toBeUndefined();
  });
});

describe('a failed notification stays pending', () => {
  it("the clearing step's onTokens throws: the next token-only commit says 'clear' again, not 'keep'", async () => {
    const seen: Seen[] = [];
    let fail = true;
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      accessToken: T0,
      refreshToken: 'R0',
      onTokens: async (result) => {
        seen.push([
          result.authorizationToken,
          result.refreshToken,
          result.refreshTokenDisposition,
        ]);
        if (fail) {
          fail = false;
          throw new Error('store unavailable');
        }
      },
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
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [T1, undefined, 'clear'],
    ]);
  });

  it("a failed 'replace' is sent again as 'replace' with the held token", async () => {
    const seen: Seen[] = [];
    let fail = true;
    const provider = new ScriptedProvider({
      accessToken: jwt('held', -3600),
      refreshToken: 'R0',
      onTokens: async (result) => {
        seen.push([
          result.authorizationToken,
          result.refreshToken,
          result.refreshTokenDisposition,
        ]);
        if (fail) {
          fail = false;
          throw new Error('store unavailable');
        }
      },
    });
    const T1 = jwt('one');
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(tokens(T1, 'R1'));
    await first;
    provider.expire();
    const T2 = jwt('two');
    const second = provider.getTokens();
    const refresh = await provider.refreshes.nth(2);
    expect(refresh.refreshToken).toBe('R1');
    // A refresh answering an access token only, no refresh token.
    refresh.result.resolve(tokens(T2));
    await second;
    expect(seen).toEqual([
      [T1, 'R1', 'replace'],
      [T2, 'R1', 'replace'],
    ]);
  });

  it("a new 'replace' supersedes a pending 'clear'", async () => {
    const seen: Seen[] = [];
    let fail = true;
    const T0 = jwt('held', -3600);
    const provider = new ScriptedProvider({
      accessToken: T0,
      refreshToken: 'R0',
      onTokens: async (result) => {
        seen.push([
          result.authorizationToken,
          result.refreshToken,
          result.refreshTokenDisposition,
        ]);
        if (fail) {
          fail = false;
          throw new Error('store unavailable');
        }
      },
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
    expect(seen).toEqual([
      [T0, undefined, 'clear'],
      [T1, 'R1', 'replace'],
      [T2, undefined, 'keep'],
    ]);
  });

  it("a refused refresh's clearing step runs through the queue, after a held earlier commit; the token-only login after it says 'clear'", async () => {
    const seen: Seen[] = [];
    const held = deferred();
    let holdFirst = true;
    const provider = new ScriptedProvider({
      onTokens: async (result) => {
        seen.push([
          result.authorizationToken,
          result.refreshToken,
          result.refreshTokenDisposition,
        ]);
        if (holdFirst) {
          holdFirst = false;
          await held.promise;
        }
      },
    });
    const first = new AbortController();
    const older = rejectionOf(provider.getTokens({ signal: first.signal }));
    const T1 = jwt('one');
    (await provider.logins.nth(1)).result.resolve(tokens(T1, 'R1'));
    await settle();
    expect(seen).toEqual([[T1, 'R1', 'replace']]);
    first.abort();
    await older;

    // R1 is installed (in memory); the token expires: the next renewal
    // refreshes it.
    provider.expire();
    const next = provider.getTokens();
    const refresh = await provider.refreshes.nth(1);
    expect(refresh.refreshToken).toBe('R1');
    refresh.result.reject(new Error('invalid_grant'));
    await settle();
    // The clearing step waits behind the held commit.
    expect(seen).toEqual([[T1, 'R1', 'replace']]);
    expect(provider.logins.items).toHaveLength(1);
    held.resolve();
    const login = await provider.logins.nth(2);
    expect(seen).toEqual([
      [T1, 'R1', 'replace'],
      [T1, undefined, 'clear'],
    ]);
    const T2 = jwt('two');
    login.result.resolve(tokens(T2));
    await next;
    expect(seen).toEqual([
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
      clientAuthentication: strategy,
      accessToken: elsewhere,
    });
    const only = new AbortController();
    const doomed = rejectionOf(provider.getTokens({ signal: only.signal }));
    const first = await provider.logins.nth(1);
    only.abort();
    expect(isAborted(await doomed)).toBe(true);
    first.result.reject(new Error('the login failed'));
    await settle();

    const next = provider.getTokens();
    const second = await provider.logins.nth(2);
    const fresh = boundTo(thumbprintOf(certificate()), 'fresh');
    second.result.resolve(tokens(fresh, 'R1'));
    await expect(next).resolves.toMatchObject({ authorizationToken: fresh });
  });

  it('the same renewal not aborted is remembered: getTokens answers it without renewing', async () => {
    const strategy: IClientAuthentication = {
      authenticate: async () => ({}),
      tlsMaterial: async () => certificate(),
    };
    const elsewhere = boundTo(thumbprintOf(otherCertificate()), 'held');
    const provider = new ScriptedProvider({
      clientAuthentication: strategy,
      accessToken: elsewhere,
    });
    const failing = rejectionOf(provider.getTokens());
    (await provider.logins.nth(1)).result.reject(new Error('failed'));
    await failing;
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: elsewhere,
    });
    expect(provider.logins.items).toHaveLength(1);
  });
});
