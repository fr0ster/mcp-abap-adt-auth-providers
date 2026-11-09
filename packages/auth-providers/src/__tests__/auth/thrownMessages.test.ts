/**
 * A thrown error's message carries no foreign text. A failure a consumer
 * catches from getTokens(), refreshTokens() or a strategy is logged by
 * whoever catches it — the broker, a server — by its message. What a
 * collaborator or the network threw may hold a key, a passphrase or a token,
 * so what is thrown is an `AuthProviderFailure` whose message is its error's
 * fixed words, with no `cause`.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import http from 'node:http';
import { beforeEach, describe, it, mock } from 'node:test';
import { inspect } from 'node:util';
import {
  AuthProviderFailure,
  authError,
  classify,
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  IAnswerChannel,
  IAnswerTransport,
  IBrowser,
} from '@mcp-abap-adt/interfaces-auth';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { refreshOidcToken } from '../../auth/oidcToken';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { composeAuthorization } from '../../authorization/compose';
import { oauthCode } from '../../authorization/protocol';
import { refreshStatePersistence } from '../../persistence';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import {
  browserCallbackStrategy,
  oidcCallbackStrategy,
} from '../../strategies';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import {
  cases,
  caseTitle,
  contains,
  hasProperty,
  lacksProperty,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { wordsOf } from '../helpers/minted';
import { recordingBrowser } from '../helpers/recordingBrowser';

/** A composition whose transport is the test's `open`. */
const composedOver = (open: IAnswerTransport['open']) =>
  composeAuthorization({
    presentation: { present: () => undefined },
    transport: { label: 'browser', open },
    protocol: oauthCode(),
    endpoint: '/callback',
  });

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
    resetAxiosMock();
    original = Object.assign(new Error(MARKER), { code: 'ECONNREFUSED' });
    mockedAxios.mock.mockImplementation(async () => {
      throw original;
    });
  });

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_name, run, words, operation] = caseRow;
    it(
      caseTitle(
        '%s: fixed words; no cause at all, never the original',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { error, text } = await thrownBy(run);
        // `request-failed` `no-response` of the site's operation, the
        // allowlisted code still saying what happened.
        assert.equal(error.message, words);
        assert.deepEqual(readFailure(error, 'unfamiliar-error').facts, {
          operation,
          problem: 'no-response',
          code: 'ECONNREFUSED',
        });
        notContains(text, MARKER);
        // No cause — the original, nor a replacement (util.inspect prints
        // causes).
        assert.equal(error.cause, undefined);
        notContains(inspect(error, { depth: null }), MARKER);
      },
    );
  }

  it('through a provider: getTokens() throws no window of it', async () => {
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa',
      clientId: 'cid',
      clientSecret: 'secret',
    });
    const { text } = await thrownBy(() => provider.getTokens());
    notContains(text, MARKER);
  });

  // An `interactive-login` `failed` failure naming only the
  // allowlisted code; no cause at all, never the original.
  it('a composed strategy: interactive-login failed in fixed words, no cause', async () => {
    const strategy = composedOver(async () => {
      throw original;
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a?state=S',
      }),
    );
    assert.equal(isAuthProviderFailure(error), true);
    assert.deepEqual(readFailure(error, 'browser-login').facts, {
      outcome: 'failed',
      code: 'ECONNREFUSED',
    });
    contains(text, 'ECONNREFUSED');
    notContains(text, MARKER);
    assert.equal(error.cause, undefined);
    notContains(inspect(error, { depth: null }), MARKER);
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
    resetAxiosMock();
  });

  for (const [caseIndex, caseRow] of cases([
    [
      'UAA refresh',
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    ],
    [
      'client credentials',
      () => getTokenWithClientCredentials('https://uaa', 'cid', 'secret'),
    ],
  ]).entries()) {
    const [_name, run] = caseRow;
    it(
      caseTitle(
        '%s: status and the registered code, never the description',
        caseRow,
        caseIndex,
      ),
      async () => {
        mockedAxios.mock.mockImplementation(async () => {
          throw axiosFailure(401, {
            error: 'invalid_grant',
            error_description: DESCRIPTION,
          });
        });
        const { error } = await thrownBy(run);
        // The status and the registered code are the failure's facts.
        assert.equal(isAuthProviderFailure(error), true);
        matchObject(readFailure(error, 'unfamiliar-error').facts, {
          problem: 'refused',
          status: 401,
          oauthError: 'invalid_grant',
        });
        const words = logFields(classify(error, 'refresh')).error;
        contains(words, 'HTTP 401');
        contains(words, 'invalid_grant');
        notContains(words, DESCRIPTION);
        const refusal = classify(error, 'refresh');
        contains(JSON.stringify(refusal), 'invalid_grant');
        notContains(JSON.stringify(refusal), DESCRIPTION);
      },
    );
  }

  it('an unregistered error code is not kept', async () => {
    mockedAxios.mock.mockImplementation(async () => {
      throw axiosFailure(400, { error: UNREGISTERED });
    });
    const { error } = await thrownBy(() =>
      refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
    );
    // An unregistered code is no fact.
    lacksProperty(readFailure(error, 'unfamiliar-error').facts, 'oauthError');
    const words = logFields(classify(error, 'refresh')).error;
    contains(words, 'HTTP 400');
    notContains(words, UNREGISTERED);
  });

  for (const [caseIndex, caseRow] of [
    'ECONNREFUSED',
    'ECONNABORTED',
    'ERR_NETWORK',
    'EPROTO',
    'ETIMEDOUT',
  ].entries()) {
    const code = caseRow;
    it(
      caseTitle('a network failure with %s names the code', caseRow, caseIndex),
      async () => {
        mockedAxios.mock.mockImplementation(async () => {
          throw Object.assign(new Error(MARKER), { code });
        });
        const { error, text } = await thrownBy(() =>
          refreshJwtToken('rt', 'https://uaa', 'cid', 'secret'),
        );
        // The allowlisted code is the failure's `code` fact.
        assert.equal(
          (readFailure(error, 'unfamiliar-error').facts as { code?: unknown })
            .code,
          code,
        );
        contains(text, code);
        notContains(text, MARKER);
        contains(logFields(classify(error, 'refresh')).error, code);
      },
    );
  }

  it('an unlisted code never reaches the message', async () => {
    mockedAxios.mock.mockImplementation(async () => {
      throw Object.assign(new Error(MARKER), { code: MARKER, config: {} });
    });
    mockedAxios.post.mock.mockImplementation(async () => {
      throw Object.assign(new Error(MARKER), { code: MARKER, config: {} });
    });
    const { text } = await thrownBy(() =>
      refreshOidcToken('https://idp/token', 'cid', 'secret', 'rt'),
    );
    notContains(text, MARKER);
  });

  it('the provider logs the facts when its refresh is refused', async () => {
    mockedAxios.mock.mockImplementation(async () => {
      throw axiosFailure(401, {
        error: 'invalid_grant',
        error_description: DESCRIPTION,
      });
    });
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
    contains(refreshLine, 'HTTP 401');
    contains(refreshLine, 'invalid_grant');
    // The server's description: in no line at all.
    notContains(lines.join('\n'), DESCRIPTION);
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

  /** The consumer's IBrowser playing the IdP: refuses on the redirect the URL names. */
  const refuse = (query: string): IBrowser =>
    recordingBrowser({
      onOpen: async (url: string) => {
        // The IdP's refusal carries the request's state (RFC 6749 §4.1.2.1).
        const params = new URL(url).searchParams;
        const state = params.get('state') ?? '';
        const redirectUri = params.get('redirect_uri') ?? '';
        await new Promise<void>((resolve) => {
          const req = http.get(
            `${redirectUri}?${query}&state=${state}`,
            (res) => {
              res.resume();
              res.on('end', () => resolve());
            },
          );
          req.on('error', () => resolve());
        });
      },
    });
  const urlFor = async (redirectUri: string) =>
    `https://idp.example/a?state=S&redirect_uri=${encodeURIComponent(redirectUri)}`;

  for (const [caseIndex, caseRow] of (
    [
      ['UAA', browserCallbackStrategy],
      ['OIDC', oidcCallbackStrategy],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: a registered code is kept, the description is not',
        caseRow,
        caseIndex,
      ),
      async () => {
        const strategy = (
          make as (o: object) => {
            authorize: (r: object) => Promise<unknown>;
          }
        )({
          port: 0,
          browser: refuse(
            `error=consent_required&error_description=${DESCRIPTION}`,
          ),
        });
        const { error, text } = await thrownBy(() =>
          strategy.authorize({ buildAuthorizationUrl: urlFor }),
        );
        // `identity-provider-refused` with the registered code.
        assert.deepEqual(readFailure(error, 'browser-login').facts, {
          outcome: 'identity-provider-refused',
          oauthError: 'consent_required',
        });
        contains(text, 'consent_required');
        notContains(text, DESCRIPTION);
        const refusal = JSON.stringify(classify(error, 'browser-login'));
        contains(refusal, 'consent_required');
        notContains(refusal, DESCRIPTION);
        contains(
          logFields(classify(error, 'browser-login')).error,
          'consent_required',
        );
      },
    );
  }

  it('an unregistered code is dropped', async () => {
    const strategy = browserCallbackStrategy({
      port: 0,
      browser: refuse(`error=${DESCRIPTION}`),
    });
    const { error, text } = await thrownBy(() =>
      strategy.authorize({ buildAuthorizationUrl: urlFor }),
    );
    notContains(text, DESCRIPTION);
    notContains(JSON.stringify(classify(error, 'browser-login')), DESCRIPTION);
    contains(text, 'refused');
  });

  it('a foreign failure with an HTTP status names the status', async () => {
    const strategy = composedOver(async () => {
      throw Object.assign(new Error(DESCRIPTION), { status: 503 });
    });
    const { text } = await thrownBy(() =>
      strategy.authorize({
        buildAuthorizationUrl: async () => 'https://idp.example/a?state=S',
      }),
    );
    contains(text, 'HTTP 503');
    notContains(text, DESCRIPTION);
  });

  // The configuration failure the URL builder throws, once a
  // ValidationError, passes through as it is.
  it('a configuration failure from building the URL passes through unchanged', async () => {
    const strategy = composedOver(
      async <T>(
        _options: unknown,
        use: (channel: IAnswerChannel) => Promise<T>,
      ) =>
        use({
          redirectUri: 'http://localhost:1/callback',
          arm: () => ({ answer: () => new Promise<void>(() => undefined) }),
        }),
    );
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
    assert.equal(error, mismatch);
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
    resetAxiosMock();
    mockedAxios.mock.mockImplementation(async () => ({
      status: 200,
      data: { access_token: 'the-access-token', expires_in: 3600 },
    }));
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

  for (const [caseIndex, caseRow] of cases([
    ['an Error', () => new Error(MARKER)],
    ['a string', () => MARKER],
    ['a hostile value', () => hostile()],
  ]).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        'a report that throws %s: getTokens() throws persisting-tokens in fixed words, no cause',
        caseRow,
        caseIndex,
      ),
      async () => {
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
        assert.equal(isAuthProviderFailure(error), true);
        matchObject(readFailure(error, 'token-request'), {
          kind: 'unknown',
          reason: 'persisting the tokens failed (unknown error)',
          facts: { operation: 'persisting-tokens' },
        });
        notContains(text, MARKER);
        assert.equal(error.cause, undefined);
        notContains(inspect(error, { depth: null }), MARKER);
        notContains(lines.join('\n'), MARKER);
      },
    );
  }

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
    matchObject(readFailure(error, 'token-request'), {
      kind: 'unknown',
      reason: 'persisting the tokens failed (unknown error)',
      facts: { operation: 'persisting-tokens' },
    });
    notContains(text, MARKER);
    assert.equal(error.cause, undefined);
    const all = lines.join('\n');
    contains(all, '[refreshStatePersistence] Writing the tokens failed');
    notContains(all, MARKER);
  });
});

describe('classify and logFields are total', () => {
  beforeEach(() => {
    resetAxiosMock();
  });

  it('a value whose every read throws is "unknown error", not an exception', () => {
    assert.equal(
      classify(hostile(), 'token-source').reason,
      'the token source failed (unknown error)',
    );
    assert.deepEqual(logFields(classify(hostile(), 'token-source')), {
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
    assert.equal(prepared.ok, false);
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
    assert.equal(rejected.ok, false);
    await code.getTokens().catch(() => undefined);
    contains(lines.join('\n'), 'Refresh failed');
    notContains(lines.join('\n'), MARKER);
  });
});

describe('the facts are re-checked wherever they are read', () => {
  const FOREIGN = 'REVIEW_TEST_FOREIGN_CODE_19be';

  it('the SAML bearer exchange and refresh log logFields of the failure, not the description', async () => {
    resetAxiosMock();
    const failure = {
      isAxiosError: true,
      config: {},
      message: 'Request failed with status code 400',
      response: {
        status: 400,
        data: { error: 'invalid_grant', error_description: FOREIGN },
      },
    };
    mockedAxios.mock.mockImplementation(async () => {
      throw failure;
    });
    mockedAxios.post.mock.mockImplementation(async () => {
      throw failure;
    });
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
    assert.equal(failed.length, 2);
    for (const line of failed) {
      contains(line, 'HTTP 400');
      contains(line, 'invalid_grant');
      notContains(line, FOREIGN);
    }
    // Exactly `logFields` of each site's failure: the words, kind, status.
    assert.deepEqual(metas, [
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
