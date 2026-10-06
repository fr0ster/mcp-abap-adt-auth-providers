/**
 * The device poll reads what a poll threw through `readSafely`, like every
 * other read of a foreign error: a value whose property read throws (a
 * Proxy) does not break the poll — and, like every rejection of a token
 * request, it is replaced by an `AuthProviderFailure`, never rethrown.
 *
 * Device polling (spec §6, first row of the reader table): the poll reads
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
import { pollDeviceTokens } from '../../auth/oidcToken';
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
    // D2: `request-failed` `no-response` of the device poll, nothing of it.
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
const refused = (body?: Record<string, unknown>) => ({
  isAxiosError: true,
  response: { status: 400, ...(body === undefined ? {} : { data: body }) },
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

describe.each(PATHS)('device polling %s (spec §6)', (_path, auth, sender) => {
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
});
