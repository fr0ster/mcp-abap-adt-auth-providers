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

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  initiateDeviceAuthorization,
  pollDeviceTokens,
} from '../../auth/oidcToken';
import type { TokenRequestAuth } from '../../auth/tokenRequest';
import { clientSecretPost } from '../../clientAuthentication';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import { cases, caseTitle } from '../helpers/expectations';
import {
  advanceTimersByTimeAsync,
  useFakeTimers,
  useRealTimers,
} from '../helpers/fakeTime';
import { once } from '../helpers/mockOnce';

// Automocked, but with axios's own error class: the sites throw it.

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
    mockedAxios.post.mock.mockImplementation(() => Promise.reject(hostile));
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
    assert.notEqual(outcome.thrown, hostile);
    // `request-failed` `no-response` of the device poll, nothing of it.
    assert.equal(isAuthProviderFailure(outcome.thrown), true);
    assert.deepEqual(readFailure(outcome.thrown, 'unfamiliar-error').facts, {
      operation: 'device-poll',
      problem: 'no-response',
    });
    assert.equal(
      (outcome.thrown as Error).message,
      'the device poll failed (the token endpoint gave no reason)',
    );
    assert.equal((outcome.thrown as Error).cause, undefined);
  });

  it('a logger that throws while the poll waits: the poll goes on', async () => {
    once(mockedAxios.post, () =>
      Promise.reject({
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      }),
    );
    once(mockedAxios.post, () =>
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
    assert.equal(tokens.accessToken, 'at');
  });
});

/** A `400` of the token endpoint, with the body given (none: no `data`). */
const refused = (body?: Record<string, unknown>, status = 400) => ({
  isAxiosError: true,
  response: { status, ...(body === undefined ? {} : { data: body }) },
});
const TOKENS = { data: { access_token: 'at', expires_in: 60 } };

/** The two paths: without a strategy (`axios.post`), with one (`axios(config)`). */
const PATHS: [
  string,
  () => TokenRequestAuth | undefined,
  () => typeof mockedAxios.post | typeof mockedAxios,
  (impl: () => Promise<unknown>) => void,
][] = [
  [
    'without a strategy',
    () => undefined,
    () => mockedAxios.post,
    (impl) => once(mockedAxios.post, impl),
  ],
  [
    'with a strategy',
    () => ({ strategy: clientSecretPost('client-secret-0123456789') }),
    () => mockedAxios,
    (impl) => once(mockedAxios, impl),
  ],
];

for (const [caseIndex, caseRow] of PATHS.entries()) {
  // `queue` answers the next call the path's site makes, once.
  const [_path, auth, sender, queue] = caseRow;
  describe(caseTitle('device polling %s', caseRow, caseIndex), () => {
    beforeEach(() => {
      resetAxiosMock();
    });
    afterEach(() => {
      useRealTimers();
      resetAxiosMock();
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
      useFakeTimers();
      queue(() => Promise.reject(refused({ error: 'authorization_pending' })));
      queue(() => Promise.resolve(TOKENS));
      const { logger, lines } = recording();
      const tokens = poll(3, logger);
      await advanceTimersByTimeAsync(2999);
      assert.equal(sender().mock.callCount(), 1);
      await advanceTimersByTimeAsync(1);
      assert.equal((await tokens).accessToken, 'at');
      assert.equal(sender().mock.callCount(), 2);
      // 5.4.2's own pending line, nothing else at debug.
      assert.deepEqual(
        lines.filter(([level]) => level === 'debug'),
        [['debug', '[OIDC] Device authorization pending', { wait: 3 }]],
      );
    });

    it('slow_down → success: the interval plus 5 s', async () => {
      useFakeTimers();
      queue(() => Promise.reject(refused({ error: 'slow_down' })));
      queue(() => Promise.resolve(TOKENS));
      const { logger, lines } = recording();
      const tokens = poll(2, logger);
      await advanceTimersByTimeAsync(6999);
      assert.equal(sender().mock.callCount(), 1);
      await advanceTimersByTimeAsync(1);
      assert.equal((await tokens).accessToken, 'at');
      assert.deepEqual(
        lines.filter(([level]) => level === 'debug'),
        [['debug', '[OIDC] Device authorization pending', { wait: 7 }]],
      );
    });

    for (const [caseIndex, caseRow] of [
      'access_denied',
      'expired_token',
    ].entries()) {
      const code = caseRow;
      it(
        caseTitle(
          '%s ends the poll at once: request-failed carrying that oauthError',
          caseRow,
          caseIndex,
        ),
        async () => {
          sender().mock.mockImplementation(() =>
            Promise.reject(refused({ error: code })),
          );
          const thrown = await poll(0).catch((error: unknown) => error);
          assert.equal(sender().mock.callCount(), 1);
          assert.equal(isAuthProviderFailure(thrown), true);
          const failure = readFailure(thrown, 'unfamiliar-error');
          assert.equal(failure.kind, 'request-failed');
          assert.deepEqual(failure.facts, {
            operation: 'device-poll',
            problem: 'refused',
            status: 400,
            oauthError: code,
          });
        },
      );
    }

    it('a 400 without a body ends at once: status 400, no oauthError', async () => {
      sender().mock.mockImplementation(() => Promise.reject(refused()));
      const thrown = await poll(0).catch((error: unknown) => error);
      assert.equal(sender().mock.callCount(), 1);
      assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
        operation: 'device-poll',
        problem: 'refused',
        status: 400,
      });
    });

    it('a logger whose every method throws: the pending line is guarded, the same token', async () => {
      useFakeTimers();
      queue(() => Promise.reject(refused({ error: 'authorization_pending' })));
      queue(() => Promise.resolve(TOKENS));
      const down = () => {
        throw new Error('logger down');
      };
      const tokens = poll(1, {
        debug: down,
        info: down,
        warn: down,
        error: down,
      });
      await advanceTimersByTimeAsync(1000);
      assert.equal((await tokens).accessToken, 'at');
    });

    for (const [caseIndex, caseRow] of cases([
      [401, 'authorization_pending'],
      [401, 'slow_down'],
      [500, 'authorization_pending'],
      [500, 'slow_down'],
    ]).entries()) {
      const [status, code] = caseRow;
      it(
        caseTitle(
          'a %s carrying %s ends the poll at once, with its safe-facts line',
          caseRow,
          caseIndex,
        ),
        async () => {
          sender().mock.mockImplementation(() =>
            Promise.reject(refused({ error: code }, status)),
          );
          const { logger, lines } = recording();
          const thrown = await poll(0, logger).catch((error: unknown) => error);
          assert.equal(sender().mock.callCount(), 1);
          assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
            operation: 'device-poll',
            problem: 'refused',
            status,
            oauthError: code,
          });
          // Only a 400 is the protocol's wait: anything else is a refusal, noted.
          assert.deepEqual(
            lines.filter(([level]) => level === 'debug'),
            [
              [
                'debug',
                'the device poll: the token endpoint refused the request',
                { status, error: code },
              ],
            ],
          );
        },
      );
    }

    for (const [caseIndex, caseRow] of cases([
      ['a non-numeric string', 'abc'],
      ['a numeric string', '5'],
      ['another numeric string', '7'],
      ['NaN', Number.NaN],
      ['a negative number', -3],
      ['Infinity', Number.POSITIVE_INFINITY],
    ]).entries()) {
      const [_name, interval] = caseRow;
      it(
        caseTitle(
          'an interval that is %s: the RFC default of 5 s, no hot loop',
          caseRow,
          caseIndex,
        ),
        async () => {
          useFakeTimers();
          sender().mock.mockImplementation(() =>
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
          await advanceTimersByTimeAsync(20_000);
          assert.equal(sender().mock.callCount(), 5);
          assert.deepEqual(
            lines.filter(([, message]) => message.includes('pending')),
            Array.from({ length: 5 }, () => [
              'debug',
              '[OIDC] Device authorization pending',
              { wait: 5 },
            ]),
          );
          sender().mock.mockImplementation(() =>
            Promise.reject(refused({ error: 'access_denied' })),
          );
          await advanceTimersByTimeAsync(5_000);
          await ended;
        },
      );
    }

    it("a valid interval of 0 is the server's to choose: no wait", async () => {
      queue(() => Promise.reject(refused({ error: 'authorization_pending' })));
      queue(() => Promise.resolve(TOKENS));
      const { logger, lines } = recording();
      assert.equal((await poll(0, logger)).accessToken, 'at');
      assert.deepEqual(
        lines.filter(([level]) => level === 'debug'),
        [['debug', '[OIDC] Device authorization pending', { wait: 0 }]],
      );
    });

    it('slow_down is cumulative (RFC 8628 §3.5): +5 s for this and every later request', async () => {
      useFakeTimers();
      queue(() => Promise.reject(refused({ error: 'slow_down' })));
      queue(() => Promise.reject(refused({ error: 'slow_down' })));
      queue(() => Promise.reject(refused({ error: 'authorization_pending' })));
      queue(() => Promise.resolve(TOKENS));
      const { logger, lines } = recording();
      const tokens = poll(1, logger);
      await advanceTimersByTimeAsync(6_000 + 11_000 + 11_000);
      assert.equal((await tokens).accessToken, 'at');
      assert.equal(sender().mock.callCount(), 4);
      assert.deepEqual(
        lines.filter(([level]) => level === 'debug'),
        [
          ['debug', '[OIDC] Device authorization pending', { wait: 6 }],
          ['debug', '[OIDC] Device authorization pending', { wait: 11 }],
          ['debug', '[OIDC] Device authorization pending', { wait: 11 }],
        ],
      );
    });

    for (const [caseIndex, caseRow] of cases([
      [7, 7],
      [0, 0],
      ['5', undefined],
      ['abc', undefined],
      [-1, undefined],
    ]).entries()) {
      const [interval, expected] = caseRow;
      it(
        caseTitle(
          'the device initiation keeps an interval of %p only as a finite non-negative number',
          caseRow,
          caseIndex,
        ),
        async () => {
          sender().mock.mockImplementation(() =>
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
          assert.equal(started.interval, expected);
        },
      );
    }
  });
}
