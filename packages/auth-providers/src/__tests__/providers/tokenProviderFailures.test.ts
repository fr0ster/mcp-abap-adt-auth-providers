/**
 * Token-provider failures:
 * `getTokens()` / `refreshTokens()` throw an `AuthProviderFailure` and
 * nothing else; a refused refresh token is discarded explicitly — reported
 * `refresh-token-discarded`, so `refreshStatePersistence` writes `null`; the
 * remembered refusal of rule 8 is
 * the very error the renewal produced.
 */

import { CERTIFICATES, SRC } from '../helpers/packagePaths';
import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, it, mock } from 'node:test';
import {
  AuthProviderFailure,
  isAuthProviderFailure,
  isMinted,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ICertificateMaterial,
  IClientAuthentication,
  ITokenResult,
  OAuth2GrantType,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { tlsClientCertificate } from '../../clientAuthentication/tlsClientCertificate';
import {
  type PersistedTokens,
  refreshStatePersistence,
} from '../../persistence';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { BaseTokenProvider } from '../../providers/BaseTokenProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
  objectContaining,
  stringContaining,
} from '../helpers/expectations';
import { mintedRefusal } from '../helpers/minted';
import { once } from '../helpers/mockOnce';
import { seenOf, stateRecorder } from '../helpers/persistence';
import { recordingTargets } from '../helpers/targets';

// Automocked, but with axios's own error class: the sites throw it.

const MARKER = 'MARKER-7f3a-SECRET';

/**
 * Every token request, by either path (a strategy's `axios(config)`, or a
 * site's own `axios.post(url, body)`), answered by `reply` from its url and
 * grant type.
 */
function answer(
  reply: (url: string, grant: string | null) => Promise<unknown>,
): void {
  const grantOf = (data: unknown) =>
    new URLSearchParams(String(data)).get('grant_type');
  mockedAxios.mock.mockImplementation(async (config: any) =>
    reply(String(config.url), grantOf(config.data)),
  );
  mockedAxios.post.mock.mockImplementation(
    async (url: unknown, data: unknown) => reply(String(url), grantOf(data)),
  );
}

beforeEach(() => {
  resetAxiosMock();
});

/** Every rendering of a thrown value a consumer could print or log. */
function renderings(thrown: unknown): string[] {
  const error = thrown as Error;
  return [
    JSON.stringify(thrown),
    String(thrown),
    error.message,
    String(error.stack),
    JSON.stringify(readFailure(thrown, 'token-request')),
  ];
}

/** The rejection of `promise`, which must reject. */
async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a rejection');
}

/** A thrown value is this copy's failure, not `original`, and carries no marker. */
function expectFailure(thrown: unknown, original?: unknown): void {
  assert.ok(thrown instanceof AuthProviderFailure);
  assert.equal(isAuthProviderFailure(thrown), true);
  if (original !== undefined) assert.notEqual(thrown, original);
  assert.equal(Object.hasOwn(thrown as object, 'cause'), false);
  for (const text of renderings(thrown)) notContains(text, MARKER);
  assert.equal(isMinted((thrown as AuthProviderFailure).error), true);
}

const inAnHour = () => Date.now() + 3600_000;
const result = (token: string, refresh?: string): ITokenResult =>
  ({
    authorizationToken: token,
    refreshToken: refresh,
    authType: 'client_credentials',
    tokenType: 'opaque',
    expiresAt: inAnHour(),
  }) as ITokenResult;

/** What happened, in order: logins, refreshes and the persistence writes. */
type Event =
  | { readonly step: 'login' | 'refresh' }
  | { readonly step: 'write'; readonly tokens: PersistedTokens };

/** What a test adds to the shipped persistence strategy's write. */
interface TestHooks {
  /** Runs inside each write, after it is recorded: may fail it. */
  readonly write?: (tokens: PersistedTokens) => Promise<void>;
  /** The persistence strategy's own logger. */
  readonly persistenceLogger?: ILogger;
}

/**
 * A provider whose persistence is `refreshStatePersistence(write, {
 * onWriteFailure: 'continue' })` — the behaviour `onTokens` had before
 * 6.0.0 — over a write that records each call.
 */
class TestProvider extends BaseTokenProvider {
  readonly events: Event[] = [];
  login = mock.fn(async () => result('T1', 'R1'));
  refresh = mock.fn(async () => result('T2', 'R2'));
  constructor(hooks: TestHooks = {}) {
    super({
      renewal: refreshThenLogin(),
      persistence: refreshStatePersistence(
        async (tokens) => {
          this.events.push({ step: 'write', tokens });
          await hooks.write?.(tokens);
        },
        { onWriteFailure: 'continue', logger: hooks.persistenceLogger },
      ),
    });
  }
  protected performLogin() {
    this.events.push({ step: 'login' });
    return this.login();
  }
  protected performRefresh(
    _refreshToken: string,
    _signal: AbortSignal,
    dispatched: () => void,
  ) {
    // The request leaves: the site would call this right before it.
    dispatched();
    this.events.push({ step: 'refresh' });
    return this.refresh();
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
  expire() {
    this.expiresAt = Date.now() - 1;
  }
  /**
   * What each write did to the stored refresh token, in order: `replace`
   * (a string), `clear` (`null`) or `keep` (`undefined`).
   */
  dispositions(): unknown[] {
    return this.events.flatMap((event) =>
      event.step === 'write' ? [seenOf(event.tokens)[2]] : [],
    );
  }
  steps(): string[] {
    return this.events.map((event) =>
      event.step === 'write' ? `write:${seenOf(event.tokens)[2]}` : event.step,
    );
  }
}

describe('getTokens() / refreshTokens() throw an AuthProviderFailure, never what a collaborator threw', () => {
  it("a consumer's authorization strategy throwing its own error", async () => {
    const original = new Error(`strategy down: ${MARKER}`);
    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      authorizationEndpoint: 'https://idp.example/auth',
      authorization: {
        authorize: async () => {
          throw original;
        },
      },
    });
    for (const call of [
      () => provider.getTokens(),
      () => provider.refreshTokens(),
    ]) {
      const thrown = await rejectionOf(call());
      expectFailure(thrown, original);
    }
  });

  it("a consumer's certificate loader throwing its own error", async () => {
    const original = Object.assign(new Error(`ENOENT ${MARKER}`), {
      code: 'ENOENT',
    });
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'cid',
      clientAuthentication: tlsClientCertificate({
        material: async () => {
          throw original;
        },
      }),
    });
    for (const call of [
      () => provider.getTokens(),
      () => provider.refreshTokens(),
    ]) {
      const thrown = await rejectionOf(call());
      expectFailure(thrown, original);
      matchObject((thrown as AuthProviderFailure).error, {
        kind: 'unknown',
        facts: {
          operation: 'token-request',
          grant: 'client_credentials',
          code: 'ENOENT',
        },
      });
    }
    assert.equal(mockedAxios.mock.callCount(), 0);
  });

  it("a consumer's device-code presenter throwing its own error", async () => {
    const original = new Error(`presenter down: ${MARKER}`);
    answer(async () => ({
      status: 200,
      data: {
        device_code: 'dc',
        user_code: 'UC',
        verification_uri: 'https://idp.example/activate',
        interval: 0,
      },
    }));
    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      deviceAuthorizationEndpoint: 'https://idp.example/device',
      presenter: {
        present: async () => {
          throw original;
        },
      },
    });
    for (const call of [
      () => provider.getTokens(),
      () => provider.refreshTokens(),
    ]) {
      const thrown = await rejectionOf(call());
      expectFailure(thrown, original);
      matchObject((thrown as AuthProviderFailure).error, {
        kind: 'interactive-login',
        facts: { outcome: 'device-code-not-shown' },
      });
    }
  });

  it("getTokens()' own path: a loader throwing while a valid token's binding is checked", async () => {
    const original = new Error(`loader down: ${MARKER}`);
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      username: 'u',
      password: 'p',
      // Valid and bound: getTokens() pins to compare, before any renewal.
      accessToken: boundTo('some-thumbprint'),
      clientAuthentication: {
        authenticate: async (draft) => ({
          parameters: { client_id: draft.clientId },
        }),
        tlsMaterial: async () => {
          throw original;
        },
      },
    });
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown, original);
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'unknown',
      facts: { operation: 'token-request', grant: 'password' },
    });
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });

  it('a performLogin throwing a bare Error: unknown, with the operation and the grant', async () => {
    const original = new Error(`login down: ${MARKER}`);
    const p = new TestProvider();
    p.login.mock.mockImplementation(async () => {
      throw original;
    });
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown, original);
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'unknown',
      facts: { operation: 'token-request', grant: 'client_credentials' },
    });
  });

  it('a performLogin throwing a non-Error (a string, a Proxy whose traps throw)', async () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error(MARKER);
        },
        getPrototypeOf() {
          throw new Error(MARKER);
        },
        has() {
          throw new Error(MARKER);
        },
        ownKeys() {
          throw new Error(MARKER);
        },
      },
    );
    for (const value of [MARKER, hostile]) {
      const p = new TestProvider();
      p.login.mock.mockImplementation(async () => {
        throw value;
      });
      expectFailure(await rejectionOf(p.getTokens()));
      expectFailure(await rejectionOf(p.refreshTokens()));
    }
  });

  it("a site's failure keeps its kind and facts through getTokens()", async () => {
    answer(async () => {
      throw Object.assign(new Error(MARKER), {
        isAxiosError: true,
        response: { status: 401, data: { error: 'invalid_client' } },
      });
    });
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      username: 'u',
      password: 'p',
    });
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown);
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'request-failed',
      facts: { status: 401, oauthError: 'invalid_client' },
    });
  });
});

describe('the unreachable missing-token guard', () => {
  it('a valid-looking cache without a token throws unknown token-request, never a bare Error', async () => {
    class Hollow extends TestProvider {
      protected override isTokenValid(): boolean {
        return true;
      }
    }
    const thrown = await rejectionOf(new Hollow().getTokens());
    expectFailure(thrown);
    const error = (thrown as AuthProviderFailure).error;
    assert.equal(error.kind, 'unknown');
    assert.deepEqual(error.facts, {
      operation: 'token-request',
      grant: 'client_credentials',
    });
    notContains((thrown as Error).message, 'Authorization token');
  });
});

/** The protected refresh, reached the way the base class reaches it. */
const refreshOf = (provider: unknown) =>
  (provider as { performRefresh(): Promise<ITokenResult> }).performRefresh();

const noStrategy = {
  authorize: async () => {
    throw new Error('not called');
  },
};
const validator = {
  validate: async () => {
    throw new Error('not called');
  },
};

describe('a provider without a refresh grant or token throws credential-refused refresh-token', () => {
  const sites: [string, () => unknown][] = [
    [
      'ClientCredentialsProvider (no refresh grant)',
      () =>
        new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          clientSecret: 's',
        }),
    ],
    [
      'OidcTokenExchangeProvider (no refresh grant)',
      () =>
        new OidcTokenExchangeProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          tokenEndpoint: 'https://idp.example/token',
          subjectToken: 'subject',
          subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
        }),
    ],
    [
      'Saml2PureProvider (no refresh grant)',
      () =>
        new Saml2PureProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp-entity',
          idpInitiated: true,
          authorization: noStrategy,
          assertionValidator: validator,
          cookieProvider: async () => 'SAP_SESSIONID=x',
        }),
    ],
    [
      'OidcPasswordProvider (no refresh token)',
      () =>
        new OidcPasswordProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          tokenEndpoint: 'https://idp.example/token',
          username: 'u',
          password: 'p',
        }),
    ],
    [
      'OidcBrowserProvider (no refresh token)',
      () =>
        new OidcBrowserProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          tokenEndpoint: 'https://idp.example/token',
          authorizationEndpoint: 'https://idp.example/auth',
          authorization: noStrategy,
        }),
    ],
    [
      'OidcDeviceFlowProvider (no refresh token)',
      () =>
        new OidcDeviceFlowProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          tokenEndpoint: 'https://idp.example/token',
          deviceAuthorizationEndpoint: 'https://idp.example/device',
          presenter: { present: async () => {} },
        }),
    ],
    [
      'UaaPasscodeProvider (no refresh token)',
      () =>
        new UaaPasscodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'cf',
          clientSecret: 's',
          authorization: noStrategy,
        }),
    ],
    [
      'Saml2BearerProvider (no refresh token)',
      () =>
        new Saml2BearerProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp-entity',
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          idpInitiated: true,
          authorization: noStrategy,
          assertionValidator: validator,
        }),
    ],
    [
      'AuthorizationCodeProvider (no refresh token)',
      () =>
        new AuthorizationCodeProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          clientSecret: 's',
          authorization: noStrategy,
        }),
    ],
  ];

  for (const [caseIndex, caseRow] of sites.entries()) {
    const [_name, build] = caseRow;
    it(
      caseTitle('%s → credential-refused refresh-token', caseRow, caseIndex),
      async () => {
        const thrown = await rejectionOf(refreshOf(build()));
        expectFailure(thrown);
        const error = (thrown as AuthProviderFailure).error;
        assert.equal(error.kind, 'credential-refused');
        assert.deepEqual(error.facts, { credential: 'refresh-token' });
        // 5.4.2's RefreshError words, verbatim.
        assert.equal(error.reason, 'the refresh token was refused');
        assert.equal(error.hint, 'log in again');
        assert.equal(mockedAxios.mock.callCount(), 0);
        assert.equal(mockedAxios.post.mock.callCount(), 0);
      },
    );
  }

  it('there are nine such sites', () => {
    assert.equal(sites.length, 9);
  });
});

/** A logger recording every call. */
function recordingLogger() {
  const calls: { level: string; message: string; fields: unknown }[] = [];
  const at =
    (level: string) =>
    (message: string, fields?: unknown): void => {
      calls.push({ level, message, fields });
    };
  return {
    calls,
    logger: {
      debug: at('debug'),
      info: at('info'),
      warn: at('warn'),
      error: at('error'),
    },
  };
}

describe('the refresh and persistence failure lines carry logFields', () => {
  it('Refresh failed — the failure the refresh threw, as logFields', async () => {
    const { calls, logger } = recordingLogger();
    const p = new TestProvider();
    (p as unknown as { logger: unknown }).logger = logger;
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error(MARKER);
    });
    await p.getTokens();
    const line = calls.find((c) => c.message.endsWith('Refresh failed'));
    assert.equal(line?.level, 'warn');
    assert.equal(line?.message, '[BaseTokenProvider] Refresh failed');
    assert.deepEqual(line?.fields, {
      error: 'the refresh failed (unknown error)',
      kind: 'unknown',
    });
    notContains(JSON.stringify(calls), MARKER);
  });

  it("a site's failure is logged by its own words, kind and status", async () => {
    const { calls, logger } = recordingLogger();
    const p = new TestProvider();
    (p as unknown as { logger: unknown }).logger = logger;
    await p.getTokens();
    p.expire();
    const failure = new AuthProviderFailure(
      readFailure(
        { status: 400, oauthError: 'invalid_grant' },
        'token-request',
      ),
    );
    p.refresh.mock.mockImplementation(async () => {
      throw failure;
    });
    await p.getTokens();
    const line = calls.find((c) => c.message.endsWith('Refresh failed'));
    assert.deepEqual(line?.fields, {
      error: failure.error.reason,
      kind: failure.error.kind,
      status: 400,
    });
  });

  it('a failed write — the persistence strategy logs fixed words, the kind, no message; the token stands', async () => {
    const { calls, logger } = recordingLogger();
    const p = new TestProvider({
      write: async () => {
        throw new Error(`store down ${MARKER}`);
      },
      persistenceLogger: logger,
    });
    matchObject(await p.getTokens(), {
      authorizationToken: 'T1',
    });
    const line = calls.find((c) => c.message.includes('Writing the tokens'));
    assert.equal(line?.level, 'warn');
    assert.equal(
      line?.message,
      '[refreshStatePersistence] Writing the tokens failed',
    );
    assert.deepEqual(line?.fields, {
      error: 'persisting the tokens failed (unknown error)',
      kind: 'unknown',
    });
    notContains(JSON.stringify(calls), MARKER);
  });
});

describe('a refused refresh token is discarded explicitly', () => {
  it('a refused refresh: a write of the held access token and null, before the login', async () => {
    const p = new TestProvider();
    await p.getTokens(); // T1 / R1, replace
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3', 'R3'));
    matchObject(await p.getTokens(), {
      authorizationToken: 'T3',
    });
    assert.deepEqual(p.steps(), [
      'login',
      'write:replace',
      'refresh',
      'write:clear',
      'login',
      'write:replace',
    ]);
    const clearing = p.events[3];
    assert.equal(clearing?.step, 'write');
    const cleared = (clearing as { tokens: PersistedTokens }).tokens;
    assert.equal(cleared.authorizationToken, 'T1');
    assert.equal(cleared.refreshToken, null);
    assert.equal(cleared.authType, 'client_credentials');
  });

  it('the token-only login that follows writes null, not undefined', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3'));
    await p.getTokens();
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'clear']);
    // Still cleared: a later token-only result says clear again.
    p.expire();
    await p.getTokens();
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'clear', 'clear']);
  });

  it('a failing login leaves the clear written', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => {
      throw new Error('login refused');
    });
    expectFailure(await rejectionOf(p.getTokens()));
    assert.deepEqual(p.steps(), [
      'login',
      'write:replace',
      'refresh',
      'write:clear',
      'login',
    ]);
  });

  it("a clearing write that fails does not stop the login (onWriteFailure 'continue')", async () => {
    let calls = 0;
    const p = new TestProvider({
      write: async () => {
        calls += 1;
        if (calls === 2) throw new Error('store down');
      },
    });
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3', 'R3'));
    matchObject(await p.getTokens(), {
      authorizationToken: 'T3',
    });
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'replace']);
  });

  it('a clearing report that cannot be built (getAuthType() throwing): the renewal fails with heldGrant()’s own error, not persisting-tokens, and no login', async () => {
    let broken = false;
    class Breaking extends TestProvider {
      protected override getAuthType(): OAuth2GrantType {
        if (broken) throw new Error(MARKER);
        return 'client_credentials';
      }
    }
    const { calls, logger } = recordingLogger();
    const p = new Breaking();
    (p as unknown as { logger: unknown }).logger = logger;
    // The login's report names the result's own grant: getAuthType() unread.
    await p.getTokens();
    p.expire();
    broken = true;
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3', 'R3'));
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown);
    // The provider's fault, not the strategy's: heldGrant()'s own error.
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'unknown',
      facts: { operation: 'token-request' },
    });
    assert.deepEqual(p.steps(), ['login', 'write:replace', 'refresh']);
    // The discard itself stands: R1 is never sent again.
    assert.equal(
      (p as unknown as { refreshToken?: string }).refreshToken,
      undefined,
    );
    notContains(JSON.stringify(calls), MARKER);
  });

  it('a refresh returning a new refresh token: written; a result with none and nothing cut: undefined', async () => {
    const p = new TestProvider();
    p.login.mock.mockImplementation(async () => result('T1'));
    await p.getTokens();
    assert.deepEqual(p.dispositions(), ['keep']);
    (p as unknown as { refreshToken?: string }).refreshToken = 'R1';
    p.expire();
    await p.getTokens(); // refresh → T2 / R2
    p.expire();
    p.refresh.mock.mockImplementation(async () => result('T4'));
    await p.getTokens();
    assert.deepEqual(p.dispositions(), ['keep', 'replace', 'keep']);
  });

  // What getTokens() returns carries the held refresh token
  // or none, nothing more — no disposition; the key is kept when absent.
  it('a renewal returns the result with the held refresh token, and no disposition', async () => {
    const p = new TestProvider();
    const login = await p.getTokens();
    assert.equal(login.refreshToken, 'R1');
    assert.equal(Object.hasOwn(login, 'refreshTokenDisposition'), false);
    p.expire();
    const refreshed = await p.refreshTokens();
    assert.equal(refreshed.refreshToken, 'R2');
    assert.equal(Object.hasOwn(refreshed, 'refreshTokenDisposition'), false);
    const written = p.events.flatMap((event) =>
      event.step === 'write' ? [event.tokens.refreshToken] : [],
    );
    assert.deepEqual(written, ['R1', 'R2']);
  });

  it('a cache hit carries the usable refresh token held, or none', async () => {
    const withRefresh = new TestProvider();
    await withRefresh.getTokens();
    const cached = await withRefresh.getTokens();
    assert.deepEqual(withRefresh.steps(), ['login', 'write:replace']);
    assert.equal(cached.refreshToken, 'R1');
    assert.equal(Object.hasOwn(cached, 'refreshTokenDisposition'), false);

    const without = new TestProvider();
    without.login.mock.mockImplementation(async () => result('T1'));
    await without.getTokens();
    const hit = await without.getTokens();
    assert.equal(Object.hasOwn(hit, 'refreshToken'), true);
    assert.equal(hit.refreshToken, undefined);
    assert.equal(Object.hasOwn(hit, 'refreshTokenDisposition'), false);
  });

  // A cache hit names its grant through readGrant, like
  // every other path — getAuthType() read once, a throw a minted failure.
  it('a cache hit reads getAuthType() once, through readGrant; a throwing one is an unknown failure', async () => {
    let calls = 0;
    class Throwing extends TestProvider {
      protected override getAuthType(): OAuth2GrantType {
        calls += 1;
        throw new Error(MARKER);
      }
    }
    const p = new Throwing();
    await p.getTokens(); // the login result carries its own authType
    for (let i = 0; i < 2; i += 1) {
      const thrown = await rejectionOf(p.getTokens());
      expectFailure(thrown);
      matchObject((thrown as AuthProviderFailure).error, {
        kind: 'unknown',
        facts: { operation: 'token-request' },
      });
    }
    assert.equal(calls, 1);
  });

  it('after a refused refresh and a login without one, the result and the cache hit carry no refresh token, and null was written', async () => {
    const p = new TestProvider();
    await p.getTokens(); // T1 / R1
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3'));
    const relogged = await p.getTokens();
    assert.equal(Object.hasOwn(relogged, 'refreshToken'), true);
    assert.equal(relogged.refreshToken, undefined);
    const cached = await p.getTokens();
    assert.equal(cached.authorizationToken, 'T3');
    assert.equal(cached.refreshToken, undefined);
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'clear']);
  });

  it('a refresh token refused by the server (a 400 invalid_grant) clears it, then logs in', async () => {
    answer(async (_url, grant) => {
      if (grant === 'refresh_token') {
        throw Object.assign(new Error('refused'), {
          isAxiosError: true,
          response: { status: 400, data: { error: 'invalid_grant' } },
        });
      }
      return {
        status: 200,
        data: { access_token: 'NEW', expires_in: 3600 },
      };
    });
    const { seen, persistence } = stateRecorder();
    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      username: 'u',
      password: 'p',
      accessToken: 'OLD',
      refreshToken: 'R1',
      persistence,
    });
    matchObject(await provider.getTokens(), {
      authorizationToken: 'NEW',
    });
    assert.deepEqual(seen, [
      ['OLD', undefined, 'clear'],
      ['NEW', undefined, 'clear'],
    ]);
  });
});

// ---- Rule 8's remembered refusal, on kinds (CLAUDE.md rule 8).

const dir = CERTIFICATES;
const readFixture = (name: string) => readFileSync(join(dir, name));
const A: ICertificateMaterial = {
  cert: readFixture('client.crt'),
  key: readFixture('client.key'),
};
const B: ICertificateMaterial = {
  cert: readFixture('other.crt'),
  key: readFixture('other.key'),
};
const THUMB_B = certificateThumbprint(B);
const THUMB_A = certificateThumbprint(A);
const b64url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (extra: Record<string, unknown> = {}, seconds = 3600) =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({ exp: Math.floor(Date.now() / 1000) + seconds, sub: 'u', ...extra })}.sig`;
const boundTo = (thumbprint: string, seconds = 3600) =>
  jwt({ cnf: { 'x5t#S256': thumbprint } }, seconds);

let grants: string[] = [];

/** A provider pinned to A, holding a valid token bound to B. */
function rotating(options: { refreshToken?: string; token?: string } = {}) {
  const strategy: IClientAuthentication = {
    authenticate: async (draft) => ({
      parameters: { client_id: draft.clientId },
    }),
    tlsMaterial: async () => A,
  };
  return new OidcPasswordProvider({
    renewal: refreshThenLogin(),
    clientId: 'client',
    username: 'user',
    password: 'pw',
    tokenEndpoint: 'https://idp.example/token',
    accessToken: options.token ?? boundTo(THUMB_B),
    ...(options.refreshToken ? { refreshToken: options.refreshToken } : {}),
    clientAuthentication: strategy,
  });
}

function issuing(...tokens: string[]) {
  let n = 0;
  answer(async (_url, grant) => {
    grants.push(String(grant));
    const token = tokens[Math.min(n, tokens.length - 1)];
    n += 1;
    return { status: 200, data: { access_token: token, expires_in: 3600 } };
  });
}

function refusingAll() {
  answer(async (_url, grant) => {
    grants.push(String(grant));
    throw Object.assign(new Error(MARKER), {
      isAxiosError: true,
      response: { status: 400, data: { error: 'invalid_grant' } },
    });
  });
}

const refusalOf = (outcome: AuthOutcome) => mintedRefusal(outcome);

describe('rule 8 on kinds: the remembered refusal', () => {
  beforeEach(() => {
    grants = [];
  });

  it('renewed bound elsewhere: token-binding renewed-bound-elsewhere, remembered, not renewed again', async () => {
    issuing(boundTo(THUMB_B, 3600), boundTo(THUMB_B, 3700));
    const provider = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    const first = refusalOf(await provider.authorize(t.requestTarget));
    assert.equal(first.kind, 'token-binding');
    assert.deepEqual(first.facts, { problem: 'renewed-bound-elsewhere' });
    const again = refusalOf(await provider.authorize(t.requestTarget));
    // The same minted error, not a copy.
    assert.equal(again, first);
    assert.equal(isMinted(again), true);
    assert.deepEqual(grants, ['refresh_token']);
  });

  it('a renewal that throws while the token is held: remembered with its own refusal — the very error getTokens() threw', async () => {
    refusingAll();
    const held = boundTo(THUMB_B);
    const provider = rotating({ refreshToken: 'R1', token: held });
    const t = recordingTargets();
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown);
    const produced = (thrown as AuthProviderFailure).error;
    assert.equal(produced.kind, 'request-failed');
    matchObject(produced.facts, {
      status: 400,
      oauthError: 'invalid_grant',
    });
    assert.deepEqual(grants, ['refresh_token', 'password']);
    // authorize() answers that very object, minted, not a copy.
    for (let i = 0; i < 2; i += 1) {
      const refusal = refusalOf(await provider.authorize(t.requestTarget));
      assert.equal(refusal, produced);
      assert.equal(isMinted(refusal), true);
    }
    // getTokens() throws the remembered error without renewing again: it
    // reaches the strategy as lastRenewal, and refreshThenLogin() stops
    // with it — the very object.
    const again = await rejectionOf(provider.getTokens());
    assert.equal((again as AuthProviderFailure).error, produced);
    assert.deepEqual(grants, ['refresh_token', 'password']);
    assert.deepEqual(t.request.headers, {});
  });

  it('a renewal that throws a foreign value while the token is held: remembered with its classified error — the very one getTokens() threw', async () => {
    const original = new Error(MARKER);
    class Throwing extends OidcPasswordProvider {
      protected override async performLogin(): Promise<ITokenResult> {
        throw original;
      }
    }
    const provider = new Throwing({
      renewal: refreshThenLogin(),
      clientId: 'client',
      username: 'user',
      password: 'pw',
      tokenEndpoint: 'https://idp.example/token',
      accessToken: boundTo(THUMB_B),
      clientAuthentication: {
        authenticate: async (draft) => ({
          parameters: { client_id: draft.clientId },
        }),
        tlsMaterial: async () => A,
      },
    });
    const t = recordingTargets();
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown, original);
    const produced = (thrown as AuthProviderFailure).error;
    assert.equal(produced.kind, 'unknown');
    // Classified once, in the renewal: authorize() answers that very object.
    for (let i = 0; i < 2; i += 1) {
      assert.equal(
        refusalOf(await provider.authorize(t.requestTarget)),
        produced,
      );
    }
  });

  it("rejected() renews once more; its refusal is the renewal's very error, and authorize() answers the same object", async () => {
    refusingAll();
    const provider = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    const before = grants.length;
    const outcome = await provider.rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    assert.equal(grants.length, before + 1);
    const refusal = refusalOf(outcome);
    assert.equal(refusal.kind, 'request-failed');
    assert.equal(refusalOf(await provider.authorize(t.requestTarget)), refusal);
    assert.equal(grants.length, before + 1);
  });

  it('prepare() renews a remembered token once more (moment prepare); its refusal is then the remembered one', async () => {
    refusingAll();
    const provider = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    const before = grants.length;
    const prepared = refusalOf(await provider.prepare());
    assert.equal(grants.length, before + 1);
    assert.equal(
      refusalOf(await provider.authorize(t.requestTarget)),
      prepared,
    );
    assert.equal(grants.length, before + 1);
  });

  it('a new token held clears the mark', async () => {
    refusingAll();
    const provider = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    const fresh = boundTo(THUMB_A);
    (
      provider as unknown as { authorizationToken?: string }
    ).authorizationToken = fresh;
    assert.deepEqual(await provider.authorize(t.requestTarget), {
      ok: true,
    });
  });

  it('a renewal refused because the client certificate expired: client-certificate expired, remembered, nothing sent', async () => {
    const provider = rotating({
      refreshToken: 'R1',
      token: boundTo(THUMB_B, 200 * 365 * 86400),
    });
    const t = recordingTargets();
    await provider.establish(t.logonTarget);
    const now = mock.method(Date, 'now', () => Date.UTC(2127, 0, 1));
    try {
      const thrown = await rejectionOf(provider.getTokens());
      expectFailure(thrown);
      const produced = (thrown as AuthProviderFailure).error;
      assert.equal(produced.kind, 'client-certificate');
      assert.deepEqual(produced.facts, { problem: 'expired' });
      // Pinned material is checked before the strategy is asked, so each
      // renewal refuses it afresh: the same error, minted again, and still
      // nothing sent.
      for (let i = 0; i < 2; i += 1) {
        assert.deepEqual(
          refusalOf(await provider.authorize(t.requestTarget)),
          produced,
        );
      }
    } finally {
      now.mock.restore();
    }
    assert.equal(grants.length, 0);
    assert.equal(mockedAxios.mock.callCount(), 0);
    assert.equal(mockedAxios.post.mock.callCount(), 0);
  });
});

describe('every throw is an AuthProviderFailure, the former classes gone', () => {
  // The 5.x classes are deleted: nothing passes through as it is
  // any more (`isUnmintedRung` and the pass-through are gone), and
  // `classify` alone reads a thrown value — never its class name, its
  // `missingFields` or its `check`: a look-alike of a former class is
  // `unknown` with the operation and the grant.
  class ValidationError extends Error {
    readonly missingFields = ['clientId', MARKER];
    constructor() {
      super(MARKER);
      this.name = 'ValidationError';
    }
  }
  const lookAlikes: [string, () => unknown][] = [
    ['a ValidationError look-alike (A11)', () => new ValidationError()],
    [
      'an AssertionValidationError look-alike (A3)',
      () =>
        Object.assign(new Error(MARKER), {
          name: 'AssertionValidationError',
          check: 'status',
        }),
    ],
    [
      'a ServiceKeyError look-alike (A12, no producer)',
      () =>
        Object.assign(new Error(MARKER), {
          name: 'ServiceKeyError',
          missingFields: ['clientId'],
        }),
    ],
    [
      'a CertificateMaterialError look-alike (A4)',
      () =>
        Object.assign(new Error(MARKER), {
          name: 'CertificateMaterialError',
          incomplete: false,
          expired: true,
        }),
    ],
  ];
  it('ServiceKeyError / SessionDataError look-alikes are unknown, wrapped (no producer, no kind)', async () => {
    for (const name of ['ServiceKeyError', 'SessionDataError']) {
      const original = Object.assign(new Error(MARKER), {
        name,
        missingFields: ['uaaUrl', 'refreshToken'],
      });
      const p = new TestProvider();
      p.login.mock.mockImplementation(async () => {
        throw original;
      });
      const thrown = await rejectionOf(p.getTokens());
      expectFailure(thrown, original);
      matchObject((thrown as AuthProviderFailure).error, {
        kind: 'unknown',
        facts: { operation: 'token-request', grant: 'client_credentials' },
      });
    }
  });

  for (const [caseIndex, caseRow] of lookAlikes.entries()) {
    const [_name, make] = caseRow;
    it(caseTitle('%s: unknown, wrapped', caseRow, caseIndex), async () => {
      const original = make();
      const p = new TestProvider();
      p.login.mock.mockImplementation(async () => {
        throw original;
      });
      for (const thrown of [
        await rejectionOf(p.getTokens()),
        await rejectionOf(p.refreshTokens()),
      ]) {
        expectFailure(thrown, original);
        matchObject((thrown as AuthProviderFailure).error, {
          kind: 'unknown',
          facts: { operation: 'token-request', grant: 'client_credentials' },
        });
      }
    });
  }
});

describe('a refused token request through a moment', () => {
  for (const [caseIndex, caseRow] of cases([
    [
      'with a registered error',
      {
        status: 401,
        data: { error: 'invalid_client', error_description: MARKER },
      },
      'refused',
      'the client credentials request failed (HTTP 401, invalid_client)',
    ],
    [
      'with no registered error',
      { status: 401, data: { error_description: MARKER } },
      'refused',
      'the client credentials request failed (HTTP 401)',
    ],
    [
      'with no response',
      undefined,
      'no-response',
      'the client credentials request failed (the token endpoint gave no reason)',
    ],
  ]).entries()) {
    const [_name, response, problem, reason] = caseRow;
    it(
      caseTitle(
        '%s: authorize() answers request-failed, verbatim',
        caseRow,
        caseIndex,
      ),
      async () => {
        answer(async () => {
          throw Object.assign(new Error(MARKER), {
            isAxiosError: true,
            ...(response === undefined ? {} : { response }),
          });
        });
        const provider = new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          clientSecret: 's',
        });
        const { requestTarget, request } = recordingTargets();
        const outcome = await provider.authorize(requestTarget);
        const refusal = mintedRefusal(outcome);
        assert.equal(refusal.kind, 'request-failed');
        matchObject(refusal.facts, {
          operation: 'client-credentials',
          problem,
        });
        assert.equal(refusal.reason, reason);
        assert.deepEqual(request.headers, {});
        notContains(JSON.stringify(outcome), MARKER);
      },
    );
  }
});

describe('the grant a failure names is read once, guarded', () => {
  it('getAuthType() throwing: the failure names the operation alone', async () => {
    class Throwing extends TestProvider {
      protected override getAuthType(): OAuth2GrantType {
        throw new Error(MARKER);
      }
    }
    const p = new Throwing();
    p.login.mock.mockImplementation(async () => {
      throw new Error('down');
    });
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown);
    assert.deepEqual((thrown as AuthProviderFailure).error.facts, {
      operation: 'token-request',
    });
  });
});

describe('RefreshError is no longer constructed', () => {
  it('no file in src constructs it, and no provider throws a bare Error for a missing refresh token', () => {
    const root = SRC;
    const files: string[] = [];
    const walk = (at: string): void => {
      for (const name of readdirSync(at)) {
        const path = join(at, name);
        if (name === '__tests__') continue;
        if (statSync(path).isDirectory()) walk(path);
        else if (name.endsWith('.ts')) files.push(path);
      }
    };
    walk(root);
    assert.ok(files.length > 20, `${files.length} > ${20}`);
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      assert.equal(text.includes('new RefreshError('), false);
      assert.equal(text.includes('Refresh token is required'), false);
    }
  });
});

/** A logger whose `levels` throw (a marker); the others record nothing. */
function throwingLogger(
  levels: readonly string[] = ['debug', 'info', 'warn', 'error'],
) {
  const at = (level: string) => () => {
    if (levels.includes(level)) throw new Error(`${level} ${MARKER}`);
  };
  return {
    debug: at('debug'),
    info: at('info'),
    warn: at('warn'),
    error: at('error'),
  };
}

const withLogger = <T>(provider: T, logger: unknown): T => {
  (provider as unknown as { logger: unknown }).logger = logger;
  return provider;
};

describe('a throwing logger changes nothing on the token paths (guarded)', () => {
  it('a refused refresh with a throwing logger still clears, logs in, and holds no refused refresh token', async () => {
    const p = withLogger(new TestProvider(), throwingLogger());
    once(p.login, async () => result('T1', 'R0'));
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3'));
    matchObject(await p.getTokens(), {
      authorizationToken: 'T3',
    });
    assert.deepEqual(p.steps(), [
      'login',
      'write:replace',
      'refresh',
      'write:clear',
      'login',
      'write:clear',
    ]);
    assert.equal(
      (p as unknown as { refreshToken?: string }).refreshToken,
      undefined,
    );
  });

  it('a failing clearing write and throwing loggers: the login still runs', async () => {
    let calls = 0;
    const p = withLogger(
      new TestProvider({
        write: async () => {
          calls += 1;
          if (calls === 2) throw new Error(`store down ${MARKER}`);
        },
        persistenceLogger: throwingLogger() as ILogger,
      }),
      throwingLogger(),
    );
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3', 'R3'));
    matchObject(await p.getTokens(), {
      authorizationToken: 'T3',
    });
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'replace']);
  });

  it('a failing write after a login and throwing loggers: the token stands', async () => {
    const p = withLogger(
      new TestProvider({
        write: async () => {
          throw new Error('store down');
        },
        persistenceLogger: throwingLogger() as ILogger,
      }),
      throwingLogger(),
    );
    matchObject(await p.getTokens(), {
      authorizationToken: 'T1',
    });
  });

  for (const [caseIndex, caseRow] of [
    'debug',
    'info',
    'warn',
    'error',
  ].entries()) {
    const level = caseRow;
    it(
      caseTitle(
        'a logger whose %s throws: login, cache hit, refresh, refused refresh all answer as with a working one',
        caseRow,
        caseIndex,
      ),
      async () => {
        const p = withLogger(new TestProvider(), throwingLogger([level]));
        matchObject(await p.getTokens(), {
          authorizationToken: 'T1',
        });
        matchObject(await p.getTokens(), {
          authorizationToken: 'T1',
        });
        p.expire();
        matchObject(await p.getTokens(), {
          authorizationToken: 'T2',
        });
        p.expire();
        p.refresh.mock.mockImplementation(async () => {
          throw new Error('refused');
        });
        p.login.mock.mockImplementation(async () => result('T3', 'R3'));
        matchObject(await p.getTokens(), {
          authorizationToken: 'T3',
        });
        assert.deepEqual(p.steps(), [
          'login',
          'write:replace',
          'refresh',
          'write:replace',
          'refresh',
          'write:clear',
          'login',
          'write:replace',
        ]);
        assert.equal(await p.validateToken('opaque'), true);
      },
    );
  }

  for (const [caseIndex, caseRow] of [
    'debug',
    'info',
    'warn',
    'error',
  ].entries()) {
    const level = caseRow;
    it(
      caseTitle(
        'a logger whose %s throws, through real sites: password grant, refresh, discovery',
        caseRow,
        caseIndex,
      ),
      async () => {
        let n = 0;
        answer(async (url, grant) => {
          n += 1;
          if (url.endsWith('/.well-known/openid-configuration')) {
            return {
              status: 200,
              data: { token_endpoint: 'https://idp.example/token' },
            };
          }
          return {
            status: 200,
            data: {
              access_token: `A${n}-${String(grant)}`,
              refresh_token: `R${n}`,
              expires_in: 3600,
            },
          };
        });
        mockedAxios.get.mock.mockImplementation(async () => ({
          status: 200,
          data: { token_endpoint: 'https://idp.example/token' },
        }));
        const provider = withLogger(
          new OidcPasswordProvider({
            renewal: refreshThenLogin(),
            clientId: 'cid',
            issuerUrl: 'https://idp.example',
            username: 'u',
            password: 'p',
          }),
          throwingLogger([level]),
        );
        matchObject(await provider.getTokens(), {
          authorizationToken: stringContaining('password'),
        });
        matchObject(await provider.refreshTokens(), {
          authorizationToken: stringContaining('refresh_token'),
        });
      },
    );
  }

  it('a logger that throws everywhere: AuthorizationCodeProvider constructs, logs in and refreshes', async () => {
    answer(async (_url, grant) => ({
      status: 200,
      data: {
        access_token: `A-${String(grant)}`,
        refresh_token: 'R',
        expires_in: 3600,
      },
    }));
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'cid',
      clientSecret: 's',
      accessToken: 'seeded',
      refreshToken: 'R0',
      logger: throwingLogger(),
      authorization: {
        authorize: async () => ({
          payload: 'the-code',
          redirectUri: 'http://localhost:61001/callback',
        }),
      },
    });
    matchObject(await provider.refreshTokens(), {
      authorizationToken: 'A-refresh_token',
    });
  });

  it("a throwing warn while the device presenter fails: the presenter's failure, not the logger's", async () => {
    answer(async () => ({
      status: 200,
      data: {
        device_code: 'dc',
        user_code: 'UC',
        verification_uri: 'https://idp.example/activate',
        interval: 0,
      },
    }));
    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      deviceAuthorizationEndpoint: 'https://idp.example/device',
      logger: throwingLogger(),
      presenter: {
        present: async () => {
          throw new Error('presenter down');
        },
      },
    });
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown);
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'interactive-login',
      facts: { outcome: 'device-code-not-shown' },
    });
  });
});

describe('the logical refresh state returns to held', () => {
  it('refused refresh → a login with a refresh token (written) → a token-only refresh writes undefined, not null', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    once(p.refresh, async () => {
      throw new Error('refused');
    });
    p.login.mock.mockImplementation(async () => result('T3', 'R3'));
    await p.getTokens();
    p.expire();
    p.refresh.mock.mockImplementation(async () => result('T4'));
    await p.getTokens();
    assert.deepEqual(p.dispositions(), ['replace', 'clear', 'replace', 'keep']);
  });
});
