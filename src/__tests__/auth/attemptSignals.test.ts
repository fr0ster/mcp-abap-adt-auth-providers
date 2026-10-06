/**
 * An attempt's requests carry its signal; a refresh never does (spec §6b).
 * `sendTokenRequest` passes `site.signal` to axios on both paths — the
 * strategy's prepared request and each site's own — for every site but the
 * three refresh sites, which never set it. The network is never part of a
 * drain: an outstanding device poll, passcode exchange or code exchange
 * whose answer is held does not keep a replacement attempt waiting, and its
 * late answer changes nothing. Discovery under an attempt (C6), and the
 * device poll that stops at the abort (fake timers for the server's poll
 * interval only).
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { IAuthorizationStrategy } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { clientSecretPost } from '../../clientAuthentication';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import {
  type Deferred,
  deferred,
  jwt,
  rejectionOf,
  settle,
  waitingStrategy,
} from '../helpers/attemptHarness';
import { SITES, tokenReply } from '../helpers/tokenRequestSites';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock; get: Mock };

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

/** The config of the one request a site sent, by either path. */
function sentConfig(): { signal?: unknown } {
  const viaPost = mockedAxios.post.mock.calls[0];
  const viaConfig = mockedAxios.mock.calls[0];
  const config = viaPost ? viaPost[2] : viaConfig?.[0];
  expect(config).toBeDefined();
  return config as { signal?: unknown };
}

const REFRESH_SITES = new Set([
  'tokenRefresher',
  'saml2TokenExchange.refreshSamlBearerToken',
  'oidcToken.refreshOidcToken',
]);

beforeEach(() => {
  mockedAxios.mockReset();
  mockedAxios.post.mockReset();
  mockedAxios.get.mockReset();
});

describe('sendTokenRequest passes the attempt signal to axios on both paths', () => {
  for (const site of SITES) {
    const refresh = REFRESH_SITES.has(site.name);
    for (const path of ['without a strategy', 'with a strategy'] as const) {
      it(`${site.name}, ${path}: ${refresh ? 'no signal (a refresh)' : 'the attempt signal'}`, async () => {
        mockedAxios.mockResolvedValue(tokenReply);
        mockedAxios.post.mockResolvedValue(tokenReply);
        const signal = new AbortController().signal;
        const auth =
          path === 'with a strategy'
            ? { strategy: clientSecretPost('sec') }
            : undefined;
        await site.run(auth, undefined, undefined, { signal });
        const config = sentConfig();
        if (refresh) {
          expect(Object.hasOwn(config, 'signal')).toBe(false);
        } else {
          expect(config.signal).toBe(signal);
        }
      });
    }
  }

  it('a request cut by its own attempt ends aborted, with no refused-request line', async () => {
    const lines: string[] = [];
    const logger: ILogger = {
      ...silent,
      debug: (message: string) => {
        lines.push(message);
      },
    };
    const controller = new AbortController();
    mockedAxios.post.mockImplementation(async () => {
      controller.abort();
      throw new (jest.requireActual<typeof import('axios')>(
        'axios',
      ).CanceledError)();
    });
    const site = SITES.find((s) => s.name === 'oidcToken.passwordGrant');
    const failure = await rejectionOf(
      site!.run(undefined, logger, undefined, { signal: controller.signal }),
    );
    expect(isAborted(failure)).toBe(true);
    expect(lines.filter((l) => l.includes('refused'))).toEqual([]);
  });
});

describe('discovery under an attempt (C6)', () => {
  it('an aborted discovery: its request signal aborted, nothing cached, the next call fetches again', async () => {
    const url = `https://idp.example/issuer-${Math.random()}`;
    const held = deferred<unknown>();
    mockedAxios.get.mockImplementationOnce(
      () => held.promise as Promise<unknown>,
    );
    const controller = new AbortController();
    const discovering = rejectionOf(
      discoverOidc(url, undefined, controller.signal),
    );
    await settle();
    const config = mockedAxios.get.mock.calls[0]?.[1] as {
      signal?: AbortSignal;
    };
    expect(config.signal).toBe(controller.signal);
    controller.abort();
    expect(config.signal?.aborted).toBe(true);
    held.resolve({ status: 200, data: { token_endpoint: 'https://late' } });
    expect(isAborted(await discovering)).toBe(true);

    mockedAxios.get.mockResolvedValueOnce({
      status: 200,
      data: { token_endpoint: 'https://fresh/token' },
    });
    await expect(discoverOidc(url)).resolves.toMatchObject({
      token_endpoint: 'https://fresh/token',
    });
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });
});

describe('discovery inside a renewal carries the attempt signal', () => {
  const discovered = {
    status: 200,
    data: { token_endpoint: 'https://idp/token' },
  };
  const issued = {
    status: 200,
    data: { access_token: jwt('new'), refresh_token: 'R2' },
  };

  it('at login (the password grant) and at refresh, and the refresh request itself carries none', async () => {
    mockedAxios.get.mockResolvedValue(discovered);
    mockedAxios.post.mockResolvedValue(issued);
    const login = new OidcPasswordProvider({
      issuerUrl: `https://idp/login-${Math.random()}`,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      logger: silent,
    });
    await login.getTokens({ signal: new AbortController().signal });
    expect(
      (mockedAxios.get.mock.calls[0]?.[1] as { signal?: unknown } | undefined)
        ?.signal,
    ).toBeInstanceOf(AbortSignal);
    expect(
      (mockedAxios.post.mock.calls[0]?.[2] as { signal?: unknown } | undefined)
        ?.signal,
    ).toBeInstanceOf(AbortSignal);

    mockedAxios.get.mockClear();
    mockedAxios.post.mockClear();
    const refresh = new OidcPasswordProvider({
      issuerUrl: `https://idp/refresh-${Math.random()}`,
      clientId: 'cid',
      username: 'u',
      password: 'p',
      accessToken: jwt('old', -3600),
      refreshToken: 'R1',
      logger: silent,
    });
    await refresh.getTokens({ signal: new AbortController().signal });
    expect(
      (mockedAxios.get.mock.calls[0]?.[1] as { signal?: unknown } | undefined)
        ?.signal,
    ).toBeInstanceOf(AbortSignal);
    const sent = mockedAxios.post.mock.calls[0];
    expect(new URLSearchParams(sent?.[1] as string).get('grant_type')).toBe(
      'refresh_token',
    );
    expect(Object.hasOwn(sent?.[2] as object, 'signal')).toBe(false);
  });
});

/** A device flow provider on mocked endpoints. */
function deviceProvider() {
  return new OidcDeviceFlowProvider({
    clientId: 'cid',
    deviceAuthorizationEndpoint: 'https://idp/device',
    tokenEndpoint: 'https://idp/token',
    presenter: { present: async () => undefined },
    logger: silent,
  });
}

const deviceAnswer = {
  status: 200,
  data: {
    device_code: 'dc',
    user_code: 'uc',
    verification_uri: 'https://idp/verify',
    interval: 1,
  },
};

/** Routes axios.post by endpoint: device initiations answer, polls are held. */
function routeDevice() {
  const polls: {
    signal: AbortSignal | undefined;
    answer: Deferred<unknown>;
  }[] = [];
  let initiations = 0;
  mockedAxios.post.mockImplementation(async (url: unknown, _body, config) => {
    if (url === 'https://idp/device') {
      initiations += 1;
      return deviceAnswer;
    }
    const answer = deferred<unknown>();
    polls.push({
      signal: (config as { signal?: AbortSignal }).signal,
      answer,
    });
    // Held: the signal is not honoured here — only the test settles it.
    return answer.promise;
  });
  return { polls, initiations: () => initiations };
}

describe('the network never drains', () => {
  it('a held device poll: abort cuts its signal; a replacement initiation proceeds at once; the old loop never polls again', async () => {
    const { polls, initiations } = routeDevice();
    const provider = deviceProvider();
    const only = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: only.signal }));
    while (polls.length === 0) await settle(1);
    only.abort();
    expect(isAborted(await first)).toBe(true);
    expect(polls[0]?.signal?.aborted).toBe(true);

    // The replacement: a new initiation while the old poll is still held.
    const next = provider.getTokens();
    while (initiations() < 2) await settle(1);
    while (polls.length < 2) await settle(1);
    polls[1]?.answer.resolve({
      status: 200,
      data: { access_token: jwt('fresh'), refresh_token: 'R2' },
    });
    await expect(next).resolves.toMatchObject({ refreshToken: 'R2' });

    // The old poll answers at last: discarded, and no further poll.
    polls[0]?.answer.resolve({
      status: 200,
      data: { access_token: jwt('late'), refresh_token: 'R-late' },
    });
    await settle();
    expect(polls).toHaveLength(2);
    await expect(provider.getTokens()).resolves.toMatchObject({
      refreshToken: 'R2',
    });
  });

  it('a held passcode exchange: the replacement strategy runs at once; the late answer changes nothing', async () => {
    const strategy = waitingStrategy();
    const exchanges: Deferred<unknown>[] = [];
    mockedAxios.post.mockImplementation(() => {
      const answer = deferred<unknown>();
      exchanges.push(answer);
      return answer.promise as Promise<unknown>;
    });
    const provider = new UaaPasscodeProvider({
      uaaUrl: 'https://uaa',
      clientId: 'cf',
      authorization: strategy as IAuthorizationStrategy<string>,
      logger: silent,
    });
    await heldExchangeCase(provider, strategy, exchanges, () =>
      mockedAxios.post.mock.calls.map(
        (call) => (call[2] as { signal?: AbortSignal }).signal,
      ),
    );
  });

  it('a held code exchange: the same', async () => {
    const strategy = waitingStrategy();
    const exchanges: Deferred<unknown>[] = [];
    mockedAxios.mockImplementation(() => {
      const answer = deferred<unknown>();
      exchanges.push(answer);
      return answer.promise as Promise<unknown>;
    });
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'sec',
      authorization: strategy,
      logger: silent,
    });
    await heldExchangeCase(provider, strategy, exchanges, () =>
      mockedAxios.mock.calls.map(
        (call) => (call[0] as { signal?: AbortSignal }).signal,
      ),
    );
  });
});

async function heldExchangeCase(
  provider: { getTokens(options?: { signal?: AbortSignal }): Promise<unknown> },
  strategy: ReturnType<typeof waitingStrategy>,
  exchanges: Deferred<unknown>[],
  signals: () => (AbortSignal | undefined)[],
): Promise<void> {
  const only = new AbortController();
  const first = rejectionOf(provider.getTokens({ signal: only.signal }));
  (await strategy.nth(1)).answer('code-1');
  while (exchanges.length === 0) await settle(1);
  only.abort();
  expect(isAborted(await first)).toBe(true);
  expect(signals()[0]?.aborted).toBe(true);

  const next = provider.getTokens();
  const second = await strategy.nth(2);
  second.answer('code-2');
  while (exchanges.length < 2) await settle(1);
  exchanges[1]?.resolve({
    status: 200,
    data: { access_token: jwt('fresh'), refresh_token: 'R2' },
  });
  await expect(next).resolves.toMatchObject({ refreshToken: 'R2' });

  exchanges[0]?.resolve({
    status: 200,
    data: { access_token: jwt('late'), refresh_token: 'R-late' },
  });
  await settle();
  await expect(provider.getTokens()).resolves.toMatchObject({
    refreshToken: 'R2',
  });
}

describe('the device poll stops at the abort', () => {
  beforeEach(() => {
    jest.useFakeTimers({
      doNotFake: ['setImmediate', 'nextTick', 'queueMicrotask'],
    });
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  it('aborted while it waits for the server interval: no poll after the abort', async () => {
    const polls: unknown[] = [];
    mockedAxios.post.mockImplementation(async (url: unknown) => {
      if (url === 'https://idp/device') return deviceAnswer;
      polls.push(url);
      const pending = Object.assign(new Error('pending'), {
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      });
      throw pending;
    });
    const provider = deviceProvider();
    const only = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: only.signal }));
    while (polls.length === 0) await settle(1);
    await settle();
    // In the wait between polls.
    only.abort();
    expect(isAborted(await first)).toBe(true);
    await jest.advanceTimersByTimeAsync(600_000);
    await settle();
    expect(polls).toHaveLength(1);
  });

  it('aborted in the same turn the interval ends: no poll after it (checked after every await)', async () => {
    const polls: unknown[] = [];
    mockedAxios.post.mockImplementation(async (url: unknown) => {
      if (url === 'https://idp/device') return deviceAnswer;
      polls.push(url);
      throw Object.assign(new Error('pending'), {
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      });
    });
    const provider = deviceProvider();
    const only = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: only.signal }));
    while (polls.length === 0) await settle(1);
    await settle();
    // The server's interval ends — its timer fires synchronously here — and
    // the abort lands before the loop resumes.
    jest.advanceTimersByTime(1_000);
    only.abort();
    expect(isAborted(await first)).toBe(true);
    await settle();
    expect(polls).toHaveLength(1);
  });

  it('aborted while a poll is outstanding: no wait and no poll after it answers', async () => {
    const held = deferred<unknown>();
    const polls: unknown[] = [];
    mockedAxios.post.mockImplementation(async (url: unknown) => {
      if (url === 'https://idp/device') return deviceAnswer;
      polls.push(url);
      if (polls.length === 1) return held.promise;
      throw new Error('a second poll');
    });
    const provider = deviceProvider();
    const only = new AbortController();
    const first = rejectionOf(provider.getTokens({ signal: only.signal }));
    while (polls.length === 0) await settle(1);
    only.abort();
    expect(isAborted(await first)).toBe(true);
    held.reject(
      Object.assign(new Error('pending'), {
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      }),
    );
    await settle();
    await jest.advanceTimersByTimeAsync(600_000);
    await settle();
    expect(polls).toHaveLength(1);
  });
});
