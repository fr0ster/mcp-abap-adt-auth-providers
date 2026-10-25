/**
 * The device poll reads what a poll threw through `readSafely`, like every
 * other read of a foreign error: a value whose property read throws (a
 * Proxy) does not break the poll — and, like every rejection of a token
 * request, it is replaced by an `AuthProviderFailure`, never rethrown.
 *
 * Device polling: the poll reads
 * the failure's classified facts — `request-failed`, `status === 400` and a
 * registered `oauthError` of `authorization_pending` / `slow_down` keep
 * polling (`slow_down` adding 5 s to the server's interval); anything else
 * ends the poll with that failure. Each case runs without a strategy and
 * through one (`prepareTokenRequest`).
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
} from '../../auth/oidcToken';
import type { TokenRequestAuth } from '../../auth/tokenRequest';
import { clientSecretPost } from '../../clientAuthentication';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock };

describe('pollDeviceTokens', () => {
  it('a thrown value whose property read throws: replaced by fixed words', async () => {
    const hostile = new Proxy(
      {},
      {
        has: () => false,
        get: () => {
          throw new Error('read refused');
        },
      },
    );
    mockedAxios.post.mockImplementation(() => Promise.reject(hostile));
    // Wrapped: awaiting the bare Proxy would read its `then`.
    const outcome = await pollDeviceTokens(
      'https://idp.example/token',
      'client',
      undefined,
      'device-code',
      0,
    ).then(
      () => ({ thrown: undefined }),
      (error: unknown) => ({ thrown: error }),
    );
    expect(outcome.thrown).not.toBe(hostile);
    // `request-failed` `no-response` of the device poll, nothing of it.
    expect(isAuthProviderFailure(outcome.thrown)).toBe(true);
    expect(readFailure(outcome.thrown, 'unfamiliar-error').facts).toEqual({
      operation: 'device-poll',
      problem: 'no-response',
    });
    expect((outcome.thrown as Error).message).toBe(
      'the device poll failed (the token endpoint gave no reason)',
    );
    expect((outcome.thrown as Error).cause).toBeUndefined();
  });

  it('a logger that throws while the poll waits: the poll goes on', async () => {
    mockedAxios.post
      .mockImplementationOnce(() =>
        Promise.reject({
          isAxiosError: true,
          response: { status: 400, data: { error: 'authorization_pending' } },
        }),
      )
      .mockImplementationOnce(() =>
        Promise.resolve({ data: { access_token: 'at', expires_in: 60 } }),
      );
    const logger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {
        throw new Error('logger down');
      },
    };
    const tokens = await pollDeviceTokens(
      'https://idp.example/token',
      'client',
      undefined,
      'device-code',
      0,
      logger,
    );
    expect(tokens.accessToken).toBe('at');
  });
});

/** A `400` of the token endpoint, with the body given (none: no `data`). */
const refused = (body?: Record<string, unknown>, status = 400) => ({
  isAxiosError: true,
  response: { status, ...(body === undefined ? {} : { data: body }) },
});
const TOKENS = { data: { access_token: 'at', expires_in: 60 } };

/** The two paths: without a strategy (`axios.post`), with one (`axios(config)`). */
const PATHS: [string, () => TokenRequestAuth | undefined, () => Mock][] = [
  ['without a strategy', () => undefined, () => mockedAxios.post],
  [
    'with a strategy',
    () => ({ strategy: clientSecretPost('client-secret-0123456789') }),
    () => mockedAxios,
  ],
];

describe.each(PATHS)('device polling %s', (_path, auth, sender) => {
  beforeEach(() => {
    jest.resetAllMocks();
  });
  afterEach(() => {
    jest.useRealTimers();
    jest.resetAllMocks();
  });

  /** Lines a logger was given, with their level. */
  function recording(): {
    logger: ILogger;
    lines: [string, string, unknown][];
  } {
    const lines: [string, string, unknown][] = [];
    const at = (level: string) => (message: string, meta?: unknown) => {
      lines.push([level, message, meta]);
    };
    return {
      logger: {
        debug: at('debug'),
        info: at('info'),
        warn: at('warn'),
        error: at('error'),
      },
      lines,
    };
  }

  const poll = (interval: number, logger?: ILogger) =>
    pollDeviceTokens(
      'https://idp.example/token',
      'client',
      auth() ? undefined : 'secret',
      'device-code',
      interval,
      logger,
      auth(),
    );

  it('pending → success: one wait of the interval, no refused-request line', async () => {
    jest.useFakeTimers();
    sender()
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'authorization_pending' })),
      )
      .mockImplementationOnce(() => Promise.resolve(TOKENS));
    const { logger, lines } = recording();
    const tokens = poll(3, logger);
    await jest.advanceTimersByTimeAsync(2999);
    expect(sender()).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    expect((await tokens).accessToken).toBe('at');
    expect(sender()).toHaveBeenCalledTimes(2);
    // 5.4.2's own pending line, nothing else at debug.
    expect(lines.filter(([level]) => level === 'debug')).toEqual([
      ['debug', '[OIDC] Device authorization pending', { wait: 3 }],
    ]);
  });

  it('slow_down → success: the interval plus 5 s', async () => {
    jest.useFakeTimers();
    sender()
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'slow_down' })),
      )
      .mockImplementationOnce(() => Promise.resolve(TOKENS));
    const { logger, lines } = recording();
    const tokens = poll(2, logger);
    await jest.advanceTimersByTimeAsync(6999);
    expect(sender()).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    expect((await tokens).accessToken).toBe('at');
    expect(lines.filter(([level]) => level === 'debug')).toEqual([
      ['debug', '[OIDC] Device authorization pending', { wait: 7 }],
    ]);
  });

  it.each(['access_denied', 'expired_token'])(
    '%s ends the poll at once: request-failed carrying that oauthError',
    async (code) => {
      sender().mockImplementation(() =>
        Promise.reject(refused({ error: code })),
      );
      const thrown = await poll(0).catch((error: unknown) => error);
      expect(sender()).toHaveBeenCalledTimes(1);
      expect(isAuthProviderFailure(thrown)).toBe(true);
      const failure = readFailure(thrown, 'unfamiliar-error');
      expect(failure.kind).toBe('request-failed');
      expect(failure.facts).toEqual({
        operation: 'device-poll',
        problem: 'refused',
        status: 400,
        oauthError: code,
      });
    },
  );

  it('a 400 without a body ends at once: status 400, no oauthError', async () => {
    sender().mockImplementation(() => Promise.reject(refused()));
    const thrown = await poll(0).catch((error: unknown) => error);
    expect(sender()).toHaveBeenCalledTimes(1);
    expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
      operation: 'device-poll',
      problem: 'refused',
      status: 400,
    });
  });

  it('a logger whose every method throws: the pending line is guarded, the same token', async () => {
    jest.useFakeTimers();
    sender()
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'authorization_pending' })),
      )
      .mockImplementationOnce(() => Promise.resolve(TOKENS));
    const down = () => {
      throw new Error('logger down');
    };
    const tokens = poll(1, {
      debug: down,
      info: down,
      warn: down,
      error: down,
    });
    await jest.advanceTimersByTimeAsync(1000);
    expect((await tokens).accessToken).toBe('at');
  });

  it.each([
    [401, 'authorization_pending'],
    [401, 'slow_down'],
    [500, 'authorization_pending'],
    [500, 'slow_down'],
  ])(
    'a %s carrying %s ends the poll at once, with its safe-facts line',
    async (status, code) => {
      sender().mockImplementation(() =>
        Promise.reject(refused({ error: code }, status)),
      );
      const { logger, lines } = recording();
      const thrown = await poll(0, logger).catch((error: unknown) => error);
      expect(sender()).toHaveBeenCalledTimes(1);
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: 'device-poll',
        problem: 'refused',
        status,
        oauthError: code,
      });
      // Only a 400 is the protocol's wait: anything else is a refusal, noted.
      expect(lines.filter(([level]) => level === 'debug')).toEqual([
        [
          'debug',
          'the device poll: the token endpoint refused the request',
          { status, error: code },
        ],
      ]);
    },
  );

  it.each<[string, unknown]>([
    ['a non-numeric string', 'abc'],
    ['a numeric string', '5'],
    ['another numeric string', '7'],
    ['NaN', Number.NaN],
    ['a negative number', -3],
    ['Infinity', Number.POSITIVE_INFINITY],
  ])(
    'an interval that is %s: the RFC default of 5 s, no hot loop',
    async (_name, interval) => {
      jest.useFakeTimers();
      sender().mockImplementation(() =>
        Promise.reject(refused({ error: 'authorization_pending' })),
      );
      const { logger, lines } = recording();
      const ended = pollDeviceTokens(
        'https://idp.example/token',
        'client',
        auth() ? undefined : 'secret',
        'device-code',
        interval as number,
        logger,
        auth(),
      ).catch((error: unknown) => error);
      // 20 s: the first poll and one every 5 s.
      await jest.advanceTimersByTimeAsync(20_000);
      expect(sender()).toHaveBeenCalledTimes(5);
      expect(
        lines.filter(([, message]) => message.includes('pending')),
      ).toEqual(
        Array.from({ length: 5 }, () => [
          'debug',
          '[OIDC] Device authorization pending',
          { wait: 5 },
        ]),
      );
      sender().mockImplementation(() =>
        Promise.reject(refused({ error: 'access_denied' })),
      );
      await jest.advanceTimersByTimeAsync(5_000);
      await ended;
    },
  );

  it("a valid interval of 0 is the server's to choose: no wait", async () => {
    sender()
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'authorization_pending' })),
      )
      .mockImplementationOnce(() => Promise.resolve(TOKENS));
    const { logger, lines } = recording();
    expect((await poll(0, logger)).accessToken).toBe('at');
    expect(lines.filter(([level]) => level === 'debug')).toEqual([
      ['debug', '[OIDC] Device authorization pending', { wait: 0 }],
    ]);
  });

  it('slow_down is cumulative (RFC 8628 §3.5): +5 s for this and every later request', async () => {
    jest.useFakeTimers();
    sender()
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'slow_down' })),
      )
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'slow_down' })),
      )
      .mockImplementationOnce(() =>
        Promise.reject(refused({ error: 'authorization_pending' })),
      )
      .mockImplementationOnce(() => Promise.resolve(TOKENS));
    const { logger, lines } = recording();
    const tokens = poll(1, logger);
    await jest.advanceTimersByTimeAsync(6_000 + 11_000 + 11_000);
    expect((await tokens).accessToken).toBe('at');
    expect(sender()).toHaveBeenCalledTimes(4);
    expect(lines.filter(([level]) => level === 'debug')).toEqual([
      ['debug', '[OIDC] Device authorization pending', { wait: 6 }],
      ['debug', '[OIDC] Device authorization pending', { wait: 11 }],
      ['debug', '[OIDC] Device authorization pending', { wait: 11 }],
    ]);
  });

  it.each<[unknown, number | undefined]>([
    [7, 7],
    [0, 0],
    ['5', undefined],
    ['abc', undefined],
    [-1, undefined],
  ])(
    'the device initiation keeps an interval of %p only as a finite non-negative number',
    async (interval, expected) => {
      sender().mockImplementation(() =>
        Promise.resolve({
          status: 200,
          data: {
            device_code: 'dc',
            user_code: 'uc',
            verification_uri: 'https://idp.example/verify',
            interval,
          },
        }),
      );
      const started = await initiateDeviceAuthorization(
        'https://idp.example/device',
        'client',
        undefined,
        undefined,
        auth(),
      );
      expect(started.interval).toBe(expected);
    },
  );
});
