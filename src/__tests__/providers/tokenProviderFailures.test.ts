/**
 * Token-provider failures (spec §6 "Where the throw is built", §6b, Task 22):
 * `getTokens()` / `refreshTokens()` throw an `AuthProviderFailure` and
 * nothing else; a refused refresh token is discarded explicitly
 * (`refreshTokenDisposition: 'clear'`); the remembered refusal of rule 8 is
 * the very error the renewal produced. Rows A10, D7, D8, H1, H2; L3.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
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
import axios from 'axios';
import { certificateThumbprint } from '../../auth/certificateMaterial';
import { tlsClientCertificate } from '../../clientAuthentication/tlsClientCertificate';
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import { CertificateMaterialError } from '../../errors/CertificateMaterialError';
import { ValidationError } from '../../errors/TokenProviderErrors';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import {
  BaseTokenProvider,
  type TokenProviderHooks,
} from '../../providers/BaseTokenProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { mintedRefusal } from '../helpers/minted';
import { recordingTargets } from '../helpers/targets';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock; get: Mock };

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
  mockedAxios.mockImplementation(async (config: any) =>
    reply(String(config.url), grantOf(config.data)),
  );
  mockedAxios.post.mockImplementation(async (url: unknown, data: unknown) =>
    reply(String(url), grantOf(data)),
  );
}

beforeEach(() => {
  jest.resetAllMocks();
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
  expect(thrown).toBeInstanceOf(AuthProviderFailure);
  expect(isAuthProviderFailure(thrown)).toBe(true);
  if (original !== undefined) expect(thrown).not.toBe(original);
  expect(Object.hasOwn(thrown as object, 'cause')).toBe(false);
  for (const text of renderings(thrown)) expect(text).not.toContain(MARKER);
  expect(isMinted((thrown as AuthProviderFailure).error)).toBe(true);
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

/** What happened, in order: logins, refreshes and onTokens calls. */
type Event =
  | { readonly step: 'login' | 'refresh' }
  | { readonly step: 'onTokens'; readonly result: ITokenResult };

class TestProvider extends BaseTokenProvider {
  readonly events: Event[] = [];
  login = jest.fn(async () => result('T1', 'R1'));
  refresh = jest.fn(async () => result('T2', 'R2'));
  constructor(hooks: TokenProviderHooks = {}) {
    super({
      ...hooks,
      onTokens: async (r: ITokenResult) => {
        this.events.push({ step: 'onTokens', result: r });
        await hooks.onTokens?.(r);
      },
    });
  }
  protected performLogin() {
    this.events.push({ step: 'login' });
    return this.login();
  }
  protected performRefresh() {
    this.events.push({ step: 'refresh' });
    return this.refresh();
  }
  protected getAuthType(): OAuth2GrantType {
    return 'client_credentials';
  }
  expire() {
    this.expiresAt = Date.now() - 1;
  }
  /** The disposition of each onTokens call, in order. */
  dispositions(): unknown[] {
    return this.events.flatMap((event) =>
      event.step === 'onTokens'
        ? [
            (event.result as { refreshTokenDisposition?: unknown })
              .refreshTokenDisposition,
          ]
        : [],
    );
  }
  steps(): string[] {
    return this.events.map((event) =>
      event.step === 'onTokens'
        ? `onTokens:${String((event.result as { refreshTokenDisposition?: unknown }).refreshTokenDisposition)}`
        : event.step,
    );
  }
}

describe('L3: getTokens() / refreshTokens() throw an AuthProviderFailure, never what a collaborator threw', () => {
  it("a consumer's authorization strategy throwing its own error", async () => {
    const original = new Error(`strategy down: ${MARKER}`);
    const provider = new OidcBrowserProvider({
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
      expect((thrown as AuthProviderFailure).error).toMatchObject({
        kind: 'unknown',
        facts: {
          operation: 'token-request',
          grant: 'client_credentials',
          code: 'ENOENT',
        },
      });
    }
    expect(mockedAxios).not.toHaveBeenCalled();
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
      expect((thrown as AuthProviderFailure).error).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'device-code-not-shown' },
      });
    }
  });

  it("getTokens()' own path: a loader throwing while a valid token's binding is checked", async () => {
    const original = new Error(`loader down: ${MARKER}`);
    const provider = new OidcPasswordProvider({
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
    expect((thrown as AuthProviderFailure).error).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'token-request', grant: 'password' },
    });
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('a performLogin throwing a bare Error: unknown, with the operation and the grant', async () => {
    const original = new Error(`login down: ${MARKER}`);
    const p = new TestProvider();
    p.login.mockRejectedValue(original);
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown, original);
    expect((thrown as AuthProviderFailure).error).toMatchObject({
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
      p.login.mockRejectedValue(value);
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
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      username: 'u',
      password: 'p',
    });
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown);
    expect((thrown as AuthProviderFailure).error).toMatchObject({
      kind: 'request-failed',
      facts: { status: 401, oauthError: 'invalid_client' },
    });
  });
});

describe('D7: the unreachable missing-token guard', () => {
  it('a valid-looking cache without a token throws unknown token-request, never a bare Error', async () => {
    class Hollow extends TestProvider {
      protected override isTokenValid(): boolean {
        return true;
      }
    }
    const thrown = await rejectionOf(new Hollow().getTokens());
    expectFailure(thrown);
    const error = (thrown as AuthProviderFailure).error;
    expect(error.kind).toBe('unknown');
    expect(error.facts).toEqual({
      operation: 'token-request',
      grant: 'client_credentials',
    });
    expect((thrown as Error).message).not.toContain('Authorization token');
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

describe('D8 / A10: a provider without a refresh grant or token throws credential-refused refresh-token', () => {
  const sites: [string, () => unknown][] = [
    [
      'ClientCredentialsProvider (no refresh grant)',
      () =>
        new ClientCredentialsProvider({
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          clientSecret: 's',
        }),
    ],
    [
      'OidcTokenExchangeProvider (no refresh grant)',
      () =>
        new OidcTokenExchangeProvider({
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
          uaaUrl: 'https://uaa.example',
          clientId: 'cid',
          clientSecret: 's',
          authorization: noStrategy,
        }),
    ],
  ];

  it.each(sites)('%s', async (_name, build) => {
    const thrown = await rejectionOf(refreshOf(build()));
    expectFailure(thrown);
    const error = (thrown as AuthProviderFailure).error;
    expect(error.kind).toBe('credential-refused');
    expect(error.facts).toEqual({ credential: 'refresh-token' });
    // A10: 5.4.2's RefreshError words, verbatim.
    expect(error.reason).toBe('the refresh token was refused');
    expect(error.hint).toBe('log in again');
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });

  it('there are nine such sites', () => {
    expect(sites).toHaveLength(9);
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

describe('H1 / H2: the refresh and onTokens failure lines carry logFields', () => {
  it('H1: Refresh failed — the failure the refresh threw, as logFields', async () => {
    const { calls, logger } = recordingLogger();
    const p = new TestProvider();
    (p as unknown as { logger: unknown }).logger = logger;
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error(MARKER));
    await p.getTokens();
    const line = calls.find((c) => c.message.endsWith('Refresh failed'));
    expect(line?.level).toBe('warn');
    expect(line?.message).toBe('[BaseTokenProvider] Refresh failed');
    expect(line?.fields).toEqual({
      error: 'the refresh failed (unknown error)',
      kind: 'unknown',
    });
    expect(JSON.stringify(calls)).not.toContain(MARKER);
  });

  it("H1: a site's failure is logged by its own words, kind and status", async () => {
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
    p.refresh.mockRejectedValue(failure);
    await p.getTokens();
    const line = calls.find((c) => c.message.endsWith('Refresh failed'));
    expect(line?.fields).toEqual({
      error: failure.error.reason,
      kind: failure.error.kind,
      status: 400,
    });
  });

  it('H2: onTokens failed — fixed words, the kind, no message', async () => {
    const { calls, logger } = recordingLogger();
    const p = new TestProvider({
      onTokens: async () => {
        throw new Error(`store down ${MARKER}`);
      },
    });
    (p as unknown as { logger: unknown }).logger = logger;
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T1',
    });
    const line = calls.find((c) => c.message.includes('onTokens failed'));
    expect(line?.level).toBe('warn');
    expect(line?.message).toBe(
      '[BaseTokenProvider] onTokens failed; the token stands',
    );
    expect(line?.fields).toEqual({
      error: 'onTokens failed (unknown error)',
      kind: 'unknown',
    });
    expect(JSON.stringify(calls)).not.toContain(MARKER);
  });
});

describe('refresh-token disposition (spec §6b): a refused refresh token is discarded explicitly', () => {
  it('a refused refresh: onTokens with the held access token and clear, before the login', async () => {
    const p = new TestProvider();
    await p.getTokens(); // T1 / R1, replace
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3', 'R3'));
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T3',
    });
    expect(p.steps()).toEqual([
      'login',
      'onTokens:replace',
      'refresh',
      'onTokens:clear',
      'login',
      'onTokens:replace',
    ]);
    const clearing = p.events[3];
    expect(clearing?.step).toBe('onTokens');
    const cleared = (clearing as { result: ITokenResult }).result;
    expect(cleared.authorizationToken).toBe('T1');
    expect(cleared.refreshToken).toBeUndefined();
    expect(Object.hasOwn(cleared, 'refreshToken')).toBe(true);
    expect(cleared.authType).toBe('client_credentials');
  });

  it('the token-only login that follows notifies clear, not keep', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3'));
    await p.getTokens();
    expect(p.dispositions()).toEqual(['replace', 'clear', 'clear']);
    // Still cleared: a later token-only result says clear again.
    p.expire();
    await p.getTokens();
    expect(p.dispositions()).toEqual(['replace', 'clear', 'clear', 'clear']);
  });

  it('a failing login leaves the clear notified', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockRejectedValue(new Error('login refused'));
    expectFailure(await rejectionOf(p.getTokens()));
    expect(p.steps()).toEqual([
      'login',
      'onTokens:replace',
      'refresh',
      'onTokens:clear',
      'login',
    ]);
  });

  it('a clearing onTokens that throws does not stop the login (best effort)', async () => {
    let calls = 0;
    const p = new TestProvider({
      onTokens: async () => {
        calls += 1;
        if (calls === 2) throw new Error('store down');
      },
    });
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3', 'R3'));
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T3',
    });
    expect(p.dispositions()).toEqual(['replace', 'clear', 'replace']);
  });

  it('a clearing notification that cannot be built (getAuthType() throwing) does not stop the login', async () => {
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
    await p.getTokens();
    p.expire();
    broken = true;
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3', 'R3'));
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T3',
    });
    expect(p.steps()).toEqual([
      'login',
      'onTokens:replace',
      'refresh',
      'login',
      'onTokens:replace',
    ]);
    expect(calls.some((c) => c.message.includes('onTokens failed'))).toBe(true);
    expect(JSON.stringify(calls)).not.toContain(MARKER);
  });

  it('a refresh returning a new refresh token: replace; a result with none and nothing cut: keep', async () => {
    const p = new TestProvider();
    p.login.mockResolvedValue(result('T1'));
    await p.getTokens();
    expect(p.dispositions()).toEqual(['keep']);
    (p as unknown as { refreshToken?: string }).refreshToken = 'R1';
    p.expire();
    await p.getTokens(); // refresh → T2 / R2
    p.expire();
    p.refresh.mockResolvedValue(result('T4'));
    await p.getTokens();
    expect(p.dispositions()).toEqual(['keep', 'replace', 'keep']);
  });

  it('what getTokens() returns carries no disposition: only the notification does (resultShapes unchanged)', async () => {
    const p = new TestProvider();
    const returned = await p.getTokens();
    expect(Object.hasOwn(returned, 'refreshTokenDisposition')).toBe(false);
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
    const seen: ITokenResult[] = [];
    const provider = new OidcPasswordProvider({
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      username: 'u',
      password: 'p',
      accessToken: 'OLD',
      refreshToken: 'R1',
      onTokens: async (r) => {
        seen.push(r);
      },
    });
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: 'NEW',
    });
    expect(
      seen.map((r) => [
        r.authorizationToken,
        (r as { refreshTokenDisposition?: unknown }).refreshTokenDisposition,
      ]),
    ).toEqual([
      ['OLD', 'clear'],
      ['NEW', 'clear'],
    ]);
  });
});

// ---- Rule 8's remembered refusal, on kinds (CLAUDE.md rule 8; C15).

const dir = join(__dirname, '..', 'fixtures', 'certificates');
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
    expect(first.kind).toBe('token-binding');
    expect(first.facts).toEqual({ problem: 'renewed-bound-elsewhere' });
    const again = refusalOf(await provider.authorize(t.requestTarget));
    // C15: the same minted error, not a copy.
    expect(again).toBe(first);
    expect(isMinted(again)).toBe(true);
    expect(grants).toEqual(['refresh_token']);
  });

  it('a renewal that throws while the token is held: remembered with its own refusal — the very error getTokens() threw', async () => {
    refusingAll();
    const held = boundTo(THUMB_B);
    const provider = rotating({ refreshToken: 'R1', token: held });
    const t = recordingTargets();
    const thrown = await rejectionOf(provider.getTokens());
    expectFailure(thrown);
    const produced = (thrown as AuthProviderFailure).error;
    expect(produced.kind).toBe('request-failed');
    expect(produced.facts).toMatchObject({
      status: 400,
      oauthError: 'invalid_grant',
    });
    expect(grants).toEqual(['refresh_token', 'password']);
    // C15: authorize() answers that very object, minted, not a copy.
    for (let i = 0; i < 2; i += 1) {
      const refusal = refusalOf(await provider.authorize(t.requestTarget));
      expect(refusal).toBe(produced);
      expect(isMinted(refusal)).toBe(true);
    }
    // getTokens() returns the remembered token without renewing again.
    await expect(provider.getTokens()).resolves.toMatchObject({
      authorizationToken: held,
    });
    expect(grants).toEqual(['refresh_token', 'password']);
    expect(t.request.headers).toEqual({});
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
    expect(grants.length).toBe(before + 1);
    const refusal = refusalOf(outcome);
    expect(refusal.kind).toBe('request-failed');
    expect(refusalOf(await provider.authorize(t.requestTarget))).toBe(refusal);
    expect(grants.length).toBe(before + 1);
  });

  it('prepare() clears the mark: one more renewal; its refusal is then the remembered one', async () => {
    refusingAll();
    const provider = rotating({ refreshToken: 'R1' });
    const t = recordingTargets();
    await provider.authorize(t.requestTarget);
    const before = grants.length;
    const prepared = refusalOf(await provider.prepare());
    expect(grants.length).toBe(before + 1);
    expect(refusalOf(await provider.authorize(t.requestTarget))).toBe(prepared);
    expect(grants.length).toBe(before + 1);
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
    await expect(provider.authorize(t.requestTarget)).resolves.toEqual({
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
    const now = jest.spyOn(Date, 'now').mockReturnValue(Date.UTC(2127, 0, 1));
    try {
      const thrown = await rejectionOf(provider.getTokens());
      expectFailure(thrown);
      const produced = (thrown as AuthProviderFailure).error;
      expect(produced.kind).toBe('client-certificate');
      expect(produced.facts).toEqual({ problem: 'expired' });
      for (let i = 0; i < 2; i += 1) {
        expect(refusalOf(await provider.authorize(t.requestTarget))).toBe(
          produced,
        );
      }
    } finally {
      now.mockRestore();
    }
    expect(grants).toHaveLength(0);
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
  });
});

describe('TRANSITION (Tasks 26, 27): the rungs still answering unminted words pass as they are', () => {
  it.each([
    [
      'ValidationError (A11, Task 26)',
      () => new ValidationError('clientId is required', ['clientId']),
    ],
  ])('%s', async (_name, build) => {
    const original = build();
    const p = new TestProvider();
    p.login.mockRejectedValue(original);
    await expect(p.getTokens()).rejects.toBe(original);
    await expect(p.refreshTokens()).rejects.toBe(original);
  });

  // Task 24 ended A3's pass-through: every SAML site throws its minted
  // `saml-assertion` rule, and the class — constructed by no site — is any
  // other own class when a consumer throws one (A13: `unknown`).
  it('AssertionValidationError no longer passes through: classified and wrapped (A3, Task 24)', async () => {
    const original = new AssertionValidationError('status', MARKER);
    const p = new TestProvider();
    p.login.mockRejectedValue(original);
    for (const thrown of [
      await rejectionOf(p.getTokens()),
      await rejectionOf(p.refreshTokens()),
    ]) {
      expectFailure(thrown, original);
      expect((thrown as AuthProviderFailure).error.kind).toBe('unknown');
    }
  });

  it('every other class of this package is classified and wrapped (CertificateMaterialError)', async () => {
    const original = new CertificateMaterialError(false, true);
    const p = new TestProvider();
    p.login.mockRejectedValue(original);
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown, original);
    expect((thrown as AuthProviderFailure).error).toMatchObject({
      kind: 'client-certificate',
      facts: { problem: 'expired' },
    });
  });
});

describe('the grant a failure names is read once, guarded', () => {
  it('getAuthType() answering a rejecting promise: getTokens() rejects with a failure, no unhandled rejection, one read', async () => {
    let calls = 0;
    class Rejecting extends TestProvider {
      protected override getAuthType(): OAuth2GrantType {
        calls += 1;
        return Promise.reject(new Error(MARKER)) as never;
      }
    }
    const seen: unknown[] = [];
    const listener = (reason: unknown) => seen.push(reason);
    process.on('unhandledRejection', listener);
    try {
      const p = new Rejecting();
      p.login.mockRejectedValue(new Error(MARKER));
      for (let i = 0; i < 2; i += 1) {
        const thrown = await rejectionOf(p.getTokens());
        expectFailure(thrown);
        expect((thrown as AuthProviderFailure).error.facts).toEqual({
          operation: 'token-request',
        });
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      process.off('unhandledRejection', listener);
    }
    expect(seen).toEqual([]);
    expect(calls).toBe(1);
  });

  it('getAuthType() throwing: the failure names the operation alone', async () => {
    class Throwing extends TestProvider {
      protected override getAuthType(): OAuth2GrantType {
        throw new Error(MARKER);
      }
    }
    const p = new Throwing();
    p.login.mockRejectedValue(new Error('down'));
    const thrown = await rejectionOf(p.getTokens());
    expectFailure(thrown);
    expect((thrown as AuthProviderFailure).error.facts).toEqual({
      operation: 'token-request',
    });
  });
});

describe('D8: RefreshError is no longer constructed', () => {
  it('no file in src constructs it, and no provider throws a bare Error for a missing refresh token', () => {
    const root = join(__dirname, '..', '..');
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
    expect(files.length).toBeGreaterThan(20);
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      expect(text.includes('new RefreshError(')).toBe(false);
      expect(text.includes('Refresh token is required')).toBe(false);
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

describe('a throwing logger changes nothing on the token paths (spec §6 guards)', () => {
  it('H1: a refused refresh with a throwing logger still clears, logs in, and holds no refused refresh token', async () => {
    const p = withLogger(new TestProvider(), throwingLogger());
    p.login.mockResolvedValueOnce(result('T1', 'R0'));
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3'));
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T3',
    });
    expect(p.steps()).toEqual([
      'login',
      'onTokens:replace',
      'refresh',
      'onTokens:clear',
      'login',
      'onTokens:clear',
    ]);
    expect(
      (p as unknown as { refreshToken?: string }).refreshToken,
    ).toBeUndefined();
  });

  it('H2: a throwing clearing onTokens and a throwing logger: the login still runs', async () => {
    let calls = 0;
    const p = withLogger(
      new TestProvider({
        onTokens: async () => {
          calls += 1;
          if (calls === 2) throw new Error(`store down ${MARKER}`);
        },
      }),
      throwingLogger(),
    );
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValue(new Error('refused'));
    p.login.mockResolvedValue(result('T3', 'R3'));
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T3',
    });
    expect(p.dispositions()).toEqual(['replace', 'clear', 'replace']);
  });

  it('H2: a throwing onTokens after a login and a throwing logger: the token stands', async () => {
    const p = withLogger(
      new TestProvider({
        onTokens: async () => {
          throw new Error('store down');
        },
      }),
      throwingLogger(),
    );
    await expect(p.getTokens()).resolves.toMatchObject({
      authorizationToken: 'T1',
    });
  });

  it.each(['debug', 'info', 'warn', 'error'])(
    'a logger whose %s throws: login, cache hit, refresh, refused refresh all answer as with a working one',
    async (level) => {
      const p = withLogger(new TestProvider(), throwingLogger([level]));
      await expect(p.getTokens()).resolves.toMatchObject({
        authorizationToken: 'T1',
      });
      await expect(p.getTokens()).resolves.toMatchObject({
        authorizationToken: 'T1',
      });
      p.expire();
      await expect(p.getTokens()).resolves.toMatchObject({
        authorizationToken: 'T2',
      });
      p.expire();
      p.refresh.mockRejectedValue(new Error('refused'));
      p.login.mockResolvedValue(result('T3', 'R3'));
      await expect(p.getTokens()).resolves.toMatchObject({
        authorizationToken: 'T3',
      });
      expect(p.steps()).toEqual([
        'login',
        'onTokens:replace',
        'refresh',
        'onTokens:replace',
        'refresh',
        'onTokens:clear',
        'login',
        'onTokens:replace',
      ]);
      await expect(p.validateToken('opaque')).resolves.toBe(true);
    },
  );

  it.each(['debug', 'info', 'warn', 'error'])(
    'a logger whose %s throws, through real sites: password grant, refresh, discovery',
    async (level) => {
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
      mockedAxios.get.mockImplementation(async () => ({
        status: 200,
        data: { token_endpoint: 'https://idp.example/token' },
      }));
      const provider = withLogger(
        new OidcPasswordProvider({
          clientId: 'cid',
          issuerUrl: 'https://idp.example',
          username: 'u',
          password: 'p',
        }),
        throwingLogger([level]),
      );
      await expect(provider.getTokens()).resolves.toMatchObject({
        authorizationToken: expect.stringContaining('password'),
      });
      await expect(provider.refreshTokens()).resolves.toMatchObject({
        authorizationToken: expect.stringContaining('refresh_token'),
      });
    },
  );

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
    await expect(provider.refreshTokens()).resolves.toMatchObject({
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
    expect((thrown as AuthProviderFailure).error).toMatchObject({
      kind: 'interactive-login',
      facts: { outcome: 'device-code-not-shown' },
    });
  });
});

describe('the logical refresh state returns to held', () => {
  it('refused refresh → a login with a refresh token (replace) → a token-only refresh says keep, not clear', async () => {
    const p = new TestProvider();
    await p.getTokens();
    p.expire();
    p.refresh.mockRejectedValueOnce(new Error('refused'));
    p.login.mockResolvedValue(result('T3', 'R3'));
    await p.getTokens();
    p.expire();
    p.refresh.mockResolvedValue(result('T4'));
    await p.getTokens();
    expect(p.dispositions()).toEqual(['replace', 'clear', 'replace', 'keep']);
  });
});
