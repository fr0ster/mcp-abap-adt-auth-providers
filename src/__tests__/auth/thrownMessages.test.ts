/**
 * A thrown error's message carries no foreign text. A failure a consumer
 * catches from getTokens(), refreshTokens() or a strategy is logged by
 * whoever catches it — the broker, a server — by its message. What a
 * collaborator or the network threw may hold a key, a passphrase or a token,
 * so the message is fixed words (the refusal's, `loggedError`); the original
 * is the `cause`, which a consumer reads only by choice.
 */

import http from 'node:http';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import axios from 'axios';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { refreshOidcToken } from '../../auth/oidcToken';
import { loggedError, refusalFrom } from '../../auth/refusal';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { TokenEndpointError } from '../../errors/TokenEndpointError';
import {
  BrowserAuthError,
  ValidationError,
} from '../../errors/TokenProviderErrors';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  oidcCallbackStrategy,
} from '../../strategies';

jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock;

const MARKER = 'REVIEW_TEST_PRIVATE_KEY_a41c07';

/** Thrown, with the message and String() of what was thrown. */
async function thrownBy(run: () => Promise<unknown>) {
  try {
    await run();
  } catch (error) {
    const e = error as Error & { cause?: unknown };
    return { error: e, text: `${e.message}\n${String(e)}` };
  }
  throw new Error('nothing was thrown');
}

describe('a thrown error carries no foreign message', () => {
  let original: Error;
  beforeEach(() => {
    jest.resetAllMocks();
    original = Object.assign(new Error(MARKER), { code: 'ECONNREFUSED' });
    mockedAxios.mockRejectedValue(original);
  });

  it.each([
    [
      'client credentials',
      () => getTokenWithClientCredentials('https://uaa', 'cid', 'secret'),
      'Client credentials authentication failed',
    ],
    [
      'UAA refresh',
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
      'Token refresh failed',
    ],
  ])('%s: fixed words, the original as cause', async (_name, run, words) => {
    const { error, text } = await thrownBy(run);
    expect(text).toContain(words);
    // The allowlisted code still says what happened.
    expect(text).toContain('ECONNREFUSED');
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBe(original);
  });

  it('through a provider: getTokens() throws no window of it', async () => {
    const provider = new ClientCredentialsProvider({
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
    });
    const { text } = await thrownBy(() => provider.getTokens());
    expect(text).not.toContain(MARKER);
  });

  it('BrowserCallbackStrategy: a BrowserAuthError in fixed words, the original as cause', async () => {
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: async () => {
        throw original;
      },
      openUrl: async () => undefined,
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    );
    expect(error).toBeInstanceOf(BrowserAuthError);
    expect(text).toContain('ECONNREFUSED');
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBe(original);
  });
});

/**
 * Fixed words must not mean "unknown error" when the facts are safe: an HTTP
 * status, a registered OAuth error code and an allowlisted system code are
 * carried on the error as properties and named in the refusal and the log.
 * The description, an unregistered code and any message never are.
 */
describe('a token-endpoint failure keeps its safe facts', () => {
  const DESCRIPTION = 'REVIEW_TEST_DESCRIPTION_3e91aa';
  const UNREGISTERED = 'REVIEW_TEST_UNREGISTERED_77c0';
  const axiosFailure = (status: number, data: object) => ({
    isAxiosError: true,
    message: `Request failed with status code ${status}`,
    response: { status, data },
  });

  beforeEach(() => {
    jest.resetAllMocks();
  });

  it.each([
    [
      'UAA refresh',
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    ],
    [
      'client credentials',
      () => getTokenWithClientCredentials('https://uaa', 'cid', 'secret'),
    ],
  ])(
    '%s: status and the registered code, never the description',
    async (_name, run) => {
      mockedAxios.mockRejectedValue(
        axiosFailure(401, {
          error: 'invalid_grant',
          error_description: DESCRIPTION,
        }),
      );
      const { error } = await thrownBy(run);
      expect(error).toBeInstanceOf(TokenEndpointError);
      const failure = error as TokenEndpointError;
      expect(failure.status).toBe(401);
      expect(failure.oauthError).toBe('invalid_grant');
      const words = loggedError(error, 'the refresh').error;
      expect(words).toContain('HTTP 401');
      expect(words).toContain('invalid_grant');
      expect(words).not.toContain(DESCRIPTION);
      const refusal = refusalFrom(error, 'the refresh');
      expect(JSON.stringify(refusal)).toContain('invalid_grant');
      expect(JSON.stringify(refusal)).not.toContain(DESCRIPTION);
    },
  );

  it('an unregistered error code is not kept', async () => {
    mockedAxios.mockRejectedValue(axiosFailure(400, { error: UNREGISTERED }));
    const { error } = await thrownBy(() =>
      refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    );
    expect((error as TokenEndpointError).oauthError).toBeUndefined();
    const words = loggedError(error, 'the refresh').error;
    expect(words).toContain('HTTP 400');
    expect(words).not.toContain(UNREGISTERED);
  });

  it.each([
    'ECONNREFUSED',
    'ECONNABORTED',
    'ERR_NETWORK',
    'EPROTO',
    'ETIMEDOUT',
  ])('a network failure with %s names the code', async (code) => {
    mockedAxios.mockRejectedValue(Object.assign(new Error(MARKER), { code }));
    const { error, text } = await thrownBy(() =>
      refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    );
    expect((error as TokenEndpointError).code).toBe(code);
    expect(text).toContain(code);
    expect(text).not.toContain(MARKER);
    expect(loggedError(error, 'the refresh').error).toContain(code);
  });

  it('an unlisted code never reaches the message', async () => {
    mockedAxios.mockRejectedValue(
      Object.assign(new Error(MARKER), { code: MARKER, config: {} }),
    );
    (axios as unknown as { post: Mock }).post = jest.fn(async () => {
      throw Object.assign(new Error(MARKER), { code: MARKER, config: {} });
    }) as unknown as Mock;
    const { text } = await thrownBy(() =>
      refreshOidcToken('https://idp/token', 'cid', 'secret', 'rt'),
    );
    expect(text).not.toContain(MARKER);
  });

  it('the provider logs the facts when its refresh is refused', async () => {
    mockedAxios.mockRejectedValue(
      axiosFailure(401, {
        error: 'invalid_grant',
        error_description: DESCRIPTION,
      }),
    );
    const lines: string[] = [];
    const record = (level: string) => (m: string, meta?: unknown) =>
      lines.push(`${level} ${m} ${JSON.stringify(meta ?? {})}`);
    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
      refreshToken: 'rt-0123456789',
      authorization: {
        authorize: async () => {
          throw new Error('no login in this test');
        },
      },
      logger: {
        debug: record('debug'),
        info: record('info'),
        warn: record('warn'),
        error: record('error'),
      },
    });
    await provider.getTokens().catch(() => undefined);
    const refreshLine = lines.find((l) => l.includes('Refresh failed')) ?? '';
    expect(refreshLine).toContain('HTTP 401');
    expect(refreshLine).toContain('invalid_grant');
    expect(lines.join('\n')).not.toContain(DESCRIPTION);
  });
});

/**
 * An identity provider's refusal on the browser callback keeps its registered
 * code — in the message, the log and the refusal — so a user who declined
 * consent reads "consent_required", not "unknown error". The description and
 * an unregistered code are dropped.
 */
describe('an IdP refusal on the browser callback', () => {
  const DESCRIPTION = 'REVIEW_TEST_IDP_DESCRIPTION_c5d2';

  const refuse =
    (query: string) =>
    async (_url: string, _browser: string, redirectUri: string) => {
      await new Promise<void>((resolve) => {
        const req = http.get(`${redirectUri}?${query}`, (res) => {
          res.resume();
          res.on('end', () => resolve());
        });
        req.on('error', () => resolve());
      });
    };

  it.each([
    ['UAA', browserCallbackStrategy],
    ['OIDC', oidcCallbackStrategy],
  ] as const)(
    '%s: a registered code is kept, the description is not',
    async (_name, make) => {
      const strategy = (
        make as (o: object) => {
          authorize: (r: object) => Promise<unknown>;
        }
      )({
        port: 0,
        timeoutMs: 5000,
        openUrl: refuse(
          `error=consent_required&error_description=${DESCRIPTION}`,
        ),
      });
      const { error, text } = await thrownBy(() =>
        strategy.authorize({
          buildAuthorizationUrl: async () => 'https://idp.example/a',
        }),
      );
      expect(error).toBeInstanceOf(BrowserAuthError);
      expect(text).toContain('consent_required');
      expect(text).not.toContain(DESCRIPTION);
      const refusal = JSON.stringify(refusalFrom(error, 'the login'));
      expect(refusal).toContain('consent_required');
      expect(refusal).not.toContain(DESCRIPTION);
      expect(loggedError(error, 'the login').error).toContain(
        'consent_required',
      );
    },
  );

  it('an unregistered code is dropped', async () => {
    const strategy = browserCallbackStrategy({
      port: 0,
      timeoutMs: 5000,
      openUrl: refuse(`error=${DESCRIPTION}`),
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    );
    expect(text).not.toContain(DESCRIPTION);
    expect(JSON.stringify(refusalFrom(error, 'the login'))).not.toContain(
      DESCRIPTION,
    );
    expect(text).toContain('refused');
  });

  it('a foreign failure with an HTTP status names the status', async () => {
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: async () => {
        throw Object.assign(new Error(DESCRIPTION), { status: 503 });
      },
      openUrl: async () => undefined,
    });
    const { text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    );
    expect(text).toContain('HTTP 503');
    expect(text).not.toContain(DESCRIPTION);
  });

  it('a ValidationError from building the URL passes through unchanged', async () => {
    const strategy = new BrowserCallbackStrategy<string>({
      callbackServer: async (_options, use) =>
        use({
          port: 1,
          redirectUri: 'http://localhost:1/callback',
          waitForResult: () => new Promise<string>(() => undefined),
          fail: () => undefined,
        }),
      openUrl: async () => undefined,
    });
    const mismatch = new ValidationError('redirect mismatch', [
      'authorizationUrl',
    ]);
    const { error } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => {
          throw mismatch;
        },
      }),
    );
    expect(error).toBe(mismatch);
  });
});
