/**
 * A thrown error's message carries no foreign text. A failure a consumer
 * catches from getTokens(), refreshTokens() or a strategy is logged by
 * whoever catches it — the broker, a server — by its message. What a
 * collaborator or the network threw may hold a key, a passphrase or a token,
 * so what is thrown is an `AuthProviderFailure` whose message is its error's
 * fixed words, with no `cause` (spec §6, L3).
 */

import http from 'node:http';
import { inspect } from 'node:util';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  AuthProviderFailure,
  authError,
  classify,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import axios from 'axios';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { refreshOidcToken } from '../../auth/oidcToken';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { refreshStatePersistence } from '../../persistence';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import {
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  oidcCallbackStrategy,
} from '../../strategies';
import { wordsOf } from '../helpers/minted';

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
      'the client credentials request failed (ECONNREFUSED)',
      'client-credentials',
    ],
    [
      'UAA refresh',
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
      'the token refresh failed (ECONNREFUSED)',
      'token-refresh',
    ],
  ])(
    '%s: fixed words; no cause at all, never the original',
    async (_name, run, words, operation) => {
      const { error, text } = await thrownBy(run);
      // D2: `request-failed` `no-response` of the site's operation, the
      // allowlisted code still saying what happened.
      expect(error.message).toBe(words);
      expect(readFailure(error, 'unfamiliar-error').facts).toEqual({
        operation,
        problem: 'no-response',
        code: 'ECONNREFUSED',
      });
      expect(text).not.toContain(MARKER);
      // L2: no cause — the original, nor a replacement (util.inspect prints causes).
      expect(error.cause).toBeUndefined();
      expect(inspect(error, { depth: null })).not.toContain(MARKER);
    },
  );

  it('through a provider: getTokens() throws no window of it', async () => {
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
    });
    const { text } = await thrownBy(() => provider.getTokens());
    expect(text).not.toContain(MARKER);
  });

  // K11 (6.0.0): an `interactive-login` `failed` failure naming only the
  // allowlisted code; no cause at all (L2), never the original.
  it('BrowserCallbackStrategy: interactive-login failed in fixed words, no cause', async () => {
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
    expect(isAuthProviderFailure(error)).toBe(true);
    expect(readFailure(error, 'browser-login').facts).toEqual({
      outcome: 'failed',
      code: 'ECONNREFUSED',
    });
    expect(text).toContain('ECONNREFUSED');
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBeUndefined();
    expect(inspect(error, { depth: null })).not.toContain(MARKER);
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
      // D1: the status and the registered code are the failure's facts.
      expect(isAuthProviderFailure(error)).toBe(true);
      expect(readFailure(error, 'unfamiliar-error').facts).toMatchObject({
        problem: 'refused',
        status: 401,
        oauthError: 'invalid_grant',
      });
      const words = logFields(classify(error, 'refresh')).error;
      expect(words).toContain('HTTP 401');
      expect(words).toContain('invalid_grant');
      expect(words).not.toContain(DESCRIPTION);
      const refusal = classify(error, 'refresh');
      expect(JSON.stringify(refusal)).toContain('invalid_grant');
      expect(JSON.stringify(refusal)).not.toContain(DESCRIPTION);
    },
  );

  it('an unregistered error code is not kept', async () => {
    mockedAxios.mockRejectedValue(axiosFailure(400, { error: UNREGISTERED }));
    const { error } = await thrownBy(() =>
      refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    );
    // D1: an unregistered code is no fact.
    expect(
      readFailure(error, 'unfamiliar-error').facts as Record<string, unknown>,
    ).not.toHaveProperty('oauthError');
    const words = logFields(classify(error, 'refresh')).error;
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
    // D2: the allowlisted code is the failure's `code` fact.
    expect(
      (readFailure(error, 'unfamiliar-error').facts as { code?: unknown }).code,
    ).toBe(code);
    expect(text).toContain(code);
    expect(text).not.toContain(MARKER);
    expect(logFields(classify(error, 'refresh')).error).toContain(code);
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
    const metas: Array<[string, unknown]> = [];
    const record = (level: string) => (m: string, meta?: unknown) => {
      lines.push(`${level} ${m} ${JSON.stringify(meta ?? {})}`);
      if (level === 'error') metas.push([m, meta]);
    };
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
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
    // The server's description: in no line at all.
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
        openUrl: refuse(
          `error=consent_required&error_description=${DESCRIPTION}`,
        ),
      });
      const { error, text } = await thrownBy(() =>
        strategy.authorize({
          buildAuthorizationUrl: async () => 'https://idp.example/a',
        }),
      );
      // K10 / A8 (6.0.0): identity-provider-refused with the registered code.
      expect(readFailure(error, 'browser-login').facts).toEqual({
        outcome: 'identity-provider-refused',
        oauthError: 'consent_required',
      });
      expect(text).toContain('consent_required');
      expect(text).not.toContain(DESCRIPTION);
      const refusal = JSON.stringify(classify(error, 'browser-login'));
      expect(refusal).toContain('consent_required');
      expect(refusal).not.toContain(DESCRIPTION);
      expect(logFields(classify(error, 'browser-login')).error).toContain(
        'consent_required',
      );
    },
  );

  it('an unregistered code is dropped', async () => {
    const strategy = browserCallbackStrategy({
      port: 0,
      openUrl: refuse(`error=${DESCRIPTION}`),
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a',
      }),
    );
    expect(text).not.toContain(DESCRIPTION);
    expect(JSON.stringify(classify(error, 'browser-login'))).not.toContain(
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

  // E12 (Task 26): the configuration failure the URL builder throws, once a
  // ValidationError, passes through as it is.
  it('a configuration failure from building the URL passes through unchanged (E12)', async () => {
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
    const configuration = authError.configuration({
      case: 'redirect-mismatch',
      fields: ['authorizationUrl'],
    });
    const mismatch = new AuthProviderFailure(configuration);
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

/** A value whose every read throws: a getter or a Proxy a consumer threw. */
const hostile = () =>
  new Proxy(
    {},
    {
      get() {
        throw new Error(MARKER);
      },
      has() {
        throw new Error(MARKER);
      },
      getPrototypeOf() {
        throw new Error(MARKER);
      },
      ownKeys() {
        throw new Error(MARKER);
      },
      getOwnPropertyDescriptor() {
        throw new Error(MARKER);
      },
    },
  );

describe('a persistence strategy’s failure carries no foreign message', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    mockedAxios.mockResolvedValue({
      status: 200,
      data: { access_token: 'the-access-token', expires_in: 3600 },
    });
  });

  const provider = (
    persistence: ConstructorParameters<
      typeof ClientCredentialsProvider
    >[0]['persistence'],
    logger?: ReturnType<typeof recording>['logger'],
  ) =>
    new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
      persistence,
      ...(logger ? { logger } : {}),
    });

  function recording() {
    const lines: string[] = [];
    const at = (level: string) => (m: string, meta?: unknown) => {
      lines.push(`${level} ${m} ${JSON.stringify(meta ?? {})}`);
    };
    return {
      lines,
      logger: {
        debug: at('debug'),
        info: at('info'),
        warn: at('warn'),
        error: at('error'),
      },
    };
  }

  it.each([
    ['an Error', () => new Error(MARKER)],
    ['a string', () => MARKER],
    ['a hostile value', () => hostile()],
  ])(
    'a report that throws %s: getTokens() throws persisting-tokens in fixed words, no cause',
    async (_name, make) => {
      const { lines, logger } = recording();
      const p = provider(
        {
          report: () => {
            throw make();
          },
        },
        logger,
      );
      const { error, text } = await thrownBy(() => p.getTokens());
      expect(isAuthProviderFailure(error)).toBe(true);
      expect(readFailure(error, 'token-request')).toMatchObject({
        kind: 'unknown',
        reason: 'persisting the tokens failed (unknown error)',
        facts: { operation: 'persisting-tokens' },
      });
      expect(text).not.toContain(MARKER);
      expect(error.cause).toBeUndefined();
      expect(inspect(error, { depth: null })).not.toContain(MARKER);
      expect(lines.join('\n')).not.toContain(MARKER);
    },
  );

  it("refreshStatePersistence 'fail': a write's failure fails getTokens() in fixed words; its logger writes no message", async () => {
    const { lines, logger } = recording();
    const p = provider(
      refreshStatePersistence(
        async () => {
          throw new Error(MARKER);
        },
        { onWriteFailure: 'fail', logger },
      ),
      logger,
    );
    const { error, text } = await thrownBy(() => p.getTokens());
    expect(readFailure(error, 'token-request')).toMatchObject({
      kind: 'unknown',
      reason: 'persisting the tokens failed (unknown error)',
      facts: { operation: 'persisting-tokens' },
    });
    expect(text).not.toContain(MARKER);
    expect(error.cause).toBeUndefined();
    const all = lines.join('\n');
    expect(all).toContain(
      '[refreshStatePersistence] Writing the tokens failed',
    );
    expect(all).not.toContain(MARKER);
  });
});

describe('classify and logFields are total', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  it('a value whose every read throws is "unknown error", not an exception', () => {
    expect(classify(hostile(), 'token-source').reason).toBe(
      'the token source failed (unknown error)',
    );
    expect(logFields(classify(hostile(), 'token-source'))).toEqual({
      error: 'the token source failed (unknown error)',
      kind: 'unknown',
    });
  });

  it('a provider answers Oops and logs a fixed line when a strategy throws one', async () => {
    const lines: string[] = [];
    const metas: Array<[string, unknown]> = [];
    const record = (level: string) => (m: string, meta?: unknown) => {
      lines.push(`${level} ${m} ${JSON.stringify(meta ?? {})}`);
      if (level === 'error') metas.push([m, meta]);
    };
    const logger = {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    };
    const strategy = {
      authenticate: async () => {
        throw hostile();
      },
    };
    const credentials = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientAuthentication: strategy,
      logger,
    });
    const prepared = await credentials.prepare();
    expect(prepared.ok).toBe(false);
    const code = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      refreshToken: 'rt-0123456789',
      clientAuthentication: strategy,
      authorization: {
        authorize: async () => ({
          payload: 'c',
          redirectUri: 'http://localhost:61001/callback',
        }),
      },
      logger,
    });
    const rejected = await code.rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    expect(rejected.ok).toBe(false);
    await code.getTokens().catch(() => undefined);
    expect(lines.join('\n')).toContain('Refresh failed');
    expect(lines.join('\n')).not.toContain(MARKER);
  });
});

describe('the facts are re-checked wherever they are read', () => {
  const FOREIGN = 'REVIEW_TEST_FOREIGN_CODE_19be';

  it('H6: the SAML bearer exchange and refresh log logFields of the failure, not the description', async () => {
    jest.resetAllMocks();
    (
      axios as unknown as { isAxiosError: (e: unknown) => boolean }
    ).isAxiosError = (e) =>
      !!(e as { isAxiosError?: boolean } | null)?.isAxiosError;
    const failure = {
      isAxiosError: true,
      config: {},
      message: 'Request failed with status code 400',
      response: {
        status: 400,
        data: { error: 'invalid_grant', error_description: FOREIGN },
      },
    };
    mockedAxios.mockRejectedValue(failure);
    (axios as unknown as { post: Mock }).post = jest.fn(async () => {
      throw failure;
    }) as unknown as Mock;
    const lines: string[] = [];
    const metas: Array<[string, unknown]> = [];
    const record = (level: string) => (m: string, meta?: unknown) => {
      lines.push(`${level} ${m} ${JSON.stringify(meta ?? {})}`);
      if (level === 'error') metas.push([m, meta]);
    };
    const logger = {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    };
    for (const run of [
      () =>
        exchangeSamlAssertion(
          'ASSERTION',
          'https://uaa/oauth/token',
          'cid',
          'secret',
          logger,
        ),
      () =>
        refreshSamlBearerToken(
          'rt',
          'https://uaa/oauth/token',
          'cid',
          'secret',
          logger,
        ),
    ]) {
      await run().catch(() => undefined);
    }
    const failed = lines.filter(
      (l) => l.includes('[SAML]') && l.startsWith('error'),
    );
    expect(failed).toHaveLength(2);
    for (const line of failed) {
      expect(line).toContain('HTTP 400');
      expect(line).toContain('invalid_grant');
      expect(line).not.toContain(FOREIGN);
    }
    // Exactly `logFields` of each site's failure: the words, kind, status.
    expect(metas).toEqual([
      [
        '[SAML] Token exchange failed',
        {
          error: 'the SAML token exchange failed (HTTP 400, invalid_grant)',
          kind: 'request-failed',
          status: 400,
        },
      ],
      [
        '[SAML] Token refresh failed',
        {
          error: 'the SAML token refresh failed (HTTP 400, invalid_grant)',
          kind: 'request-failed',
          status: 400,
        },
      ],
    ]);
  });
});
