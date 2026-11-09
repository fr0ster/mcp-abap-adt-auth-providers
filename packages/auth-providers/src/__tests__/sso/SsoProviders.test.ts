import assert from 'node:assert/strict';
import { after, beforeEach, describe, it, mock } from 'node:test';
import { inflateRawSync } from 'node:zlib';
import {
  AuthProviderFailure,
  authError,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import { generateKeyMaterial, signXml } from '@mcp-abap-adt/auth-mocks';
import type {
  IAssertionValidator,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import {
  AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
  AUTH_TYPE_PASSWORD,
  AUTH_TYPE_SAML2_BEARER,
  AUTH_TYPE_USER_TOKEN,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { discoverOidc } from '../../auth/oidcDiscovery';
import { generatePkceChallenge } from '../../auth/oidcPkce';
import {
  exchangeAuthorizationCode,
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
  refreshOidcToken,
  tokenExchange,
} from '../../auth/oidcToken';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { toBearerAssertion } from '../../auth/samlBearerAssertion';
import type { OidcCallbackResult } from '../../authorization/protocol';
import {
  consoleDeviceCodePresenter,
  type DeviceCodePrompt,
} from '../../deviceCode/DeviceCodePresenter';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { refreshThenLogin } from '../../renewal';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import {
  asOidcResult,
  browserCallbackStrategy,
  externalCodeStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from '../../strategies';
import {
  createSignedAssertionValidator,
  createSignedResponseValidator,
} from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import {
  anyOf,
  calledWith,
  cases,
  caseTitle,
  contains,
  matchObject,
  notContains,
  objectContaining,
  thrown,
} from '../helpers/expectations';
import { configurationOf } from '../helpers/minted';
import { clearMock } from '../helpers/mockOnce';
import { expectSamlRejection, rejectionOf } from '../helpers/samlRefusal';

import oidcDiscovery = require('../../auth/oidcDiscovery');
import oidcToken = require('../../auth/oidcToken');
import saml2TokenExchange = require('../../auth/saml2TokenExchange');

// The sites replaced on their module objects for the whole file (what were
// jest.mock factories; oidcDiscovery's mtlsAlias, a pure reader, stays
// real): the providers read them off the module at each call. Each answers
// `undefined` until a test gives it an implementation, as the automock did.
// `saml2Utils` is deliberately NOT mocked: `getSamlAssertion` is the code that
// drives the strategy, so stubbing it would stub away everything under test.
const unanswered = async () => undefined;
const mockDiscoverOidc = mock.method(oidcDiscovery, 'discoverOidc', unanswered);
const mockExchangeCode = mock.method(
  oidcToken,
  'exchangeAuthorizationCode',
  unanswered,
);
const mockRefresh = mock.method(oidcToken, 'refreshOidcToken', unanswered);
const mockInitiateDevice = mock.method(
  oidcToken,
  'initiateDeviceAuthorization',
  unanswered,
);
const mockPollDevice = mock.method(oidcToken, 'pollDeviceTokens', unanswered);
const mockPasswordGrant = mock.method(oidcToken, 'passwordGrant', unanswered);
const mockTokenExchange = mock.method(oidcToken, 'tokenExchange', unanswered);
const mockExchangeSaml = mock.method(
  saml2TokenExchange,
  'exchangeSamlAssertion',
  unanswered,
);
const mockRefreshSaml = mock.method(
  saml2TokenExchange,
  'refreshSamlBearerToken',
  unanswered,
);

/** Every site mock's calls forgotten, its implementation kept: Jest's `clearAllMocks`. */
function clearSiteMocks(): void {
  clearMock(mockDiscoverOidc);
  clearMock(mockExchangeCode);
  clearMock(mockRefresh);
  clearMock(mockInitiateDevice);
  clearMock(mockPollDevice);
  clearMock(mockPasswordGrant);
  clearMock(mockTokenExchange);
  clearMock(mockExchangeSaml);
  clearMock(mockRefreshSaml);
}

/** An unsigned JWT whose `exp` is `secondsFromNow` away. */
const jwtExpiringIn = (secondsFromNow: number): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + secondsFromNow;
  return `${encode({ alg: 'none' })}.${encode({ exp })}.sig`;
};

/**
 * A consumer-supplied validator that accepts anything, for tests about
 * wiring, ACS matching or strategy lifecycle rather than about validation
 * itself. Real validation of the shipped defaults is pinned separately,
 * below, against genuinely signed fixtures.
 */
/**
 * Placeholders for tests where `authorization` / `assertionValidator` must be
 * present to satisfy the required field, but the flow under test throws
 * before either is ever reached (a construction-time refusal).
 */
const unusedAuthorization: IAuthorizationStrategy<string> = {
  async authorize() {
    throw new Error('must not be reached');
  },
};
const unusedValidator: IAssertionValidator = {
  async validate() {
    throw new Error('must not be reached');
  },
};

const acceptingSamlValidator = (): IAssertionValidator => ({
  async validate(payload) {
    return {
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_stub',
      issuer: 'urn:stub:idp',
      raw: payload,
      signedXml: payload,
    };
  },
});

/**
 * The AuthnRequest ID a mint-and-authorize flow produced, read back out of
 * the URL the way `saml2Utils.test.ts` does: inflate `SAMLRequest` and pull
 * the `ID` attribute out of the AuthnRequest XML it decodes to.
 */
function mintedIdFrom(authorizationUrl: string): string {
  const encoded =
    new URL(authorizationUrl).searchParams.get('SAMLRequest') ?? '';
  const xml = inflateRawSync(Buffer.from(encoded, 'base64')).toString('utf8');
  const match = xml.match(/ID="([^"]+)"/);
  if (!match) {
    throw new Error('no ID attribute found in the inflated AuthnRequest XML');
  }
  return match[1]!;
}

/** Whatever `factory` throws, so it can be asserted on. */
function constructionError(factory: () => unknown): unknown {
  try {
    factory();
  } catch (error) {
    return error;
  }
  throw new Error('expected construction to throw, but it did not');
}

describe('SSO Providers', () => {
  const consoleLogSpy = mock.method(console, 'log', () => {});

  beforeEach(() => {
    clearSiteMocks();
  });

  after(() => {
    consoleLogSpy.mock.restore();
  });

  it('OidcBrowserProvider should exchange code and return tokens', async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      authorization_endpoint: 'https://issuer/authorize',
      token_endpoint: 'https://issuer/token',
    }));
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    }));

    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async () => 'auth-code',
        }),
      ),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.access.token');
    assert.equal(tokens.refreshToken, 'refresh');
    assert.equal(tokens.authType, AUTH_TYPE_AUTHORIZATION_CODE_PKCE);
    assert.equal(tokens.tokenType, 'jwt');
  });

  it('OidcBrowserProvider should use explicit endpoints', async () => {
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    }));

    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      authorizationEndpoint: 'https://issuer/authorize',
      tokenEndpoint: 'https://issuer/token',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async () => 'auth-code',
        }),
      ),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.access.token');
    assert.equal(mockDiscoverOidc.mock.callCount(), 0);
  });

  it('OidcBrowserProvider performs no discovery when it holds a code and a token endpoint', async () => {
    const discovery = mock.fn();
    mockDiscoverOidc.mock.mockImplementation(async (issuerUrl: string) => {
      discovery(issuerUrl);
      throw new Error('discovery must not be attempted');
    });
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'AT',
      expiresIn: 3600,
    }));

    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      tokenEndpoint: 'https://idp.example/token',
      authorization: asOidcResult(
        staticCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          payload: 'held-code',
        }),
      ),
      // deliberately no issuerUrl
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'AT');
    assert.equal(discovery.mock.callCount(), 0);
  });

  it('OidcBrowserProvider discovers once when it needs both endpoints', async () => {
    const discovery = mock.fn();
    mockDiscoverOidc.mock.mockImplementation(async (issuerUrl: string) => {
      discovery(issuerUrl);
      return {
        authorization_endpoint: 'https://idp.example/authorize',
        token_endpoint: 'https://idp.example/token',
      };
    });
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'AT2',
      expiresIn: 3600,
    }));

    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      issuerUrl: 'https://idp.example',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async (url) => {
            contains(url, 'code_challenge=');
            return 'external-code';
          },
        }),
      ),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'AT2');
    assert.equal(discovery.mock.callCount(), 1);
    // The code the strategy returned reaches the exchange at the redirect the
    // strategy actually used, against the endpoint discovery supplied. The
    // verifier is only shape-checked here; the test below pins what it must be.
    calledWith(
      mockExchangeCode,
      'https://idp.example/token',
      'cid',
      undefined,
      'external-code',
      'http://localhost:61001/callback',
      anyOf(String),
      undefined,
      // No client authentication configured: none given to the site.
      undefined,
      // The provider's authDebug and grant, threaded to the site,
      // and the attempt's signal — a login's request carries it.
      {
        authDebug: false,
        grant: 'authorization_code_pkce',
        signal: anyOf(AbortSignal),
        // The login step's dispatch notice.
        dispatched: anyOf(Function),
      },
    );
  });

  it('OidcBrowserProvider exchanges the verifier the challenge in the URL was derived from', async () => {
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'AT3',
      expiresIn: 3600,
    }));

    let authorizationUrl = '';
    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'cid',
      authorizationEndpoint: 'https://idp.example/authorize',
      tokenEndpoint: 'https://idp.example/token',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async (url) => {
            authorizationUrl = url;
            return 'paired-code';
          },
        }),
      ),
    });

    await provider.getTokens();

    const verifier = mockExchangeCode.mock.calls[0]?.arguments[5];
    assert.ok(verifier);
    // The pairing, not merely the presence, is the property. An implementation
    // that regenerated the verifier before the exchange would satisfy
    // `expect.any(String)` just as well — and that is precisely the defect the
    // old `authorizationCodeProvider` had, since it never saw the URL and so
    // could return a code minted against a challenge nobody could redeem.
    const params = new URL(authorizationUrl).searchParams;
    assert.equal(params.get('code_challenge'), generatePkceChallenge(verifier));
    assert.equal(params.get('code_challenge_method'), 'S256');
  });

  it('OidcDeviceFlowProvider should poll device tokens', async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      device_authorization_endpoint: 'https://issuer/device',
      token_endpoint: 'https://issuer/token',
    }));
    mockInitiateDevice.mock.mockImplementation(async () => ({
      deviceCode: 'dev-code',
      userCode: 'user-code',
      verificationUri: 'https://issuer/verify',
      interval: 1,
    }));
    mockPollDevice.mock.mockImplementation(async () => ({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    }));

    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      presenter: consoleDeviceCodePresenter(),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.device.token');
    assert.equal(tokens.tokenType, 'jwt');
  });

  it('OidcDeviceFlowProvider should use explicit endpoints', async () => {
    mockInitiateDevice.mock.mockImplementation(async () => ({
      deviceCode: 'dev-code',
      userCode: 'user-code',
      verificationUri: 'https://issuer/verify',
      interval: 1,
    }));
    mockPollDevice.mock.mockImplementation(async () => ({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    }));

    const provider = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      deviceAuthorizationEndpoint: 'https://issuer/device',
      tokenEndpoint: 'https://issuer/token',
      presenter: consoleDeviceCodePresenter(),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.device.token');
    assert.equal(mockDiscoverOidc.mock.callCount(), 0);
  });

  for (const [caseIndex, caseRow] of cases([
    [
      'the token endpoint',
      { deviceAuthorizationEndpoint: 'https://explicit/device' },
      { device: 'https://explicit/device', token: 'https://issuer/token' },
    ],
    [
      'the device endpoint',
      { tokenEndpoint: 'https://explicit/token' },
      { device: 'https://issuer/device', token: 'https://explicit/token' },
    ],
  ]).entries()) {
    const [_missing, given, expected] = caseRow;
    it(
      caseTitle(
        'OidcDeviceFlowProvider discovers %s it was not given, beside one it was',
        caseRow,
        caseIndex,
      ),
      async () => {
        mockDiscoverOidc.mock.mockImplementation(async () => ({
          device_authorization_endpoint: 'https://issuer/device',
          token_endpoint: 'https://issuer/token',
        }));
        mockInitiateDevice.mock.mockImplementation(async () => ({
          deviceCode: 'dev-code',
          userCode: 'user-code',
          verificationUri: 'https://issuer/verify',
          interval: 1,
        }));
        mockPollDevice.mock.mockImplementation(async () => ({
          accessToken: 'jwt.device.token',
          expiresIn: 1200,
        }));

        const provider = new OidcDeviceFlowProvider({
          renewal: refreshThenLogin(),
          issuerUrl: 'https://issuer',
          clientId: 'client',
          presenter: consoleDeviceCodePresenter(),
          ...given,
        });

        matchObject(await provider.getTokens(), {
          authorizationToken: 'jwt.device.token',
        });
        assert.equal(mockDiscoverOidc.mock.callCount(), 1);
        assert.equal(
          mockInitiateDevice.mock.calls[0]?.arguments[0],
          expected.device,
        );
        assert.equal(
          mockPollDevice.mock.calls[0]?.arguments[0],
          expected.token,
        );
      },
    );
  }

  /**
   * The device code and verification URI are prompts, not log lines — a user
   * who cannot see them cannot complete the flow. They must reach the logger
   * when one is supplied and stderr otherwise, and never stdout, which
   * carries protocol traffic under an MCP or LSP stdio transport (checked
   * statically: noStdoutSources.test.ts).
   */
  it('OidcDeviceFlowProvider prompts on stderr', async () => {
    mockInitiateDevice.mock.mockImplementation(async () => ({
      deviceCode: 'dev-code',
      userCode: 'USER-CODE-FIXTURE',
      verificationUri: 'https://verify.example',
      interval: 0,
    }));
    mockPollDevice.mock.mockImplementation(async () => ({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    }));

    const err: string[] = [];
    const errSpy = mock.method(process.stderr, 'write', (chunk: unknown) => {
      err.push(String(chunk));
      return true;
    });
    try {
      const provider = OidcDeviceFlowProvider.toConsole({
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        deviceAuthorizationEndpoint: 'https://issuer/device',
        tokenEndpoint: 'https://issuer/token',
      });
      await provider.getTokens();
    } finally {
      errSpy.mock.restore();
    }
    contains(err.join(''), 'USER-CODE-FIXTURE');
    contains(err.join(''), 'https://verify.example');
  });

  it('OidcDeviceFlowProvider sends the prompt to the logger, and nothing to stderr, when one is supplied', async () => {
    mockInitiateDevice.mock.mockImplementation(async () => ({
      deviceCode: 'dev-code',
      userCode: 'USER-CODE-FIXTURE',
      verificationUri: 'https://verify.example',
      interval: 0,
    }));
    mockPollDevice.mock.mockImplementation(async () => ({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    }));

    const infos: string[] = [];
    const logger: ILogger = {
      debug: () => undefined,
      info: (msg: string) => {
        infos.push(msg);
      },
      warn: () => undefined,
      error: () => undefined,
    };
    const err: string[] = [];
    const errSpy = mock.method(process.stderr, 'write', (chunk: unknown) => {
      err.push(String(chunk));
      return true;
    });
    try {
      const provider = OidcDeviceFlowProvider.toConsole({
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        deviceAuthorizationEndpoint: 'https://issuer/device',
        tokenEndpoint: 'https://issuer/token',
        logger,
      });
      await provider.getTokens();
    } finally {
      errSpy.mock.restore();
    }
    assert.deepEqual(err, []);
    const text = infos.join('\n');
    contains(text, 'USER-CODE-FIXTURE');
    contains(text, 'https://verify.example');
  });

  it('hands the presenter the structured prompt', async () => {
    mockInitiateDevice.mock.mockImplementation(async () => ({
      deviceCode: 'dc',
      userCode: 'SECRET-UC',
      verificationUri: 'https://idp/device',
      verificationUriComplete: 'https://idp/device?c=SECRET-UC',
      expiresIn: 600,
      interval: 1,
    }));
    mockPollDevice.mock.mockImplementation(async () => ({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    }));
    const present = mock.fn(async (_: DeviceCodePrompt) => {});
    const p = new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      clientId: 'c',
      deviceAuthorizationEndpoint: 'https://idp/device-auth',
      tokenEndpoint: 'https://idp/token',
      presenter: { present },
    });
    await p.prepare();
    calledWith(present, {
      verificationUri: 'https://idp/device',
      verificationUriComplete: 'https://idp/device?c=SECRET-UC',
      userCode: 'SECRET-UC',
      expiresInSeconds: 600,
    });
  });

  for (const [caseIndex, caseRow] of (
    ['prepare', 'rejected'] as const
  ).entries()) {
    const moment = caseRow;
    it(
      caseTitle(
        'a throwing presenter in %s → the fixed refusal, no code, no message',
        caseRow,
        caseIndex,
      ),
      async () => {
        mockInitiateDevice.mock.mockImplementation(async () => ({
          deviceCode: 'dc',
          userCode: 'SECRET-UC',
          verificationUri: 'https://idp/device',
          verificationUriComplete: 'https://idp/device?c=SECRET-UC',
          expiresIn: 600,
          interval: 1,
        }));
        mockPollDevice.mock.mockImplementation(async () => ({
          accessToken: 'jwt.device.token',
          refreshToken: 'refresh',
          expiresIn: 1200,
        }));
        const p = new OidcDeviceFlowProvider({
          renewal: refreshThenLogin(),
          clientId: 'c',
          deviceAuthorizationEndpoint: 'https://idp/device-auth',
          tokenEndpoint: 'https://idp/token',
          presenter: {
            present: async () => {
              throw new Error('UI down SECRET-UI');
            },
          },
        });
        const outcome =
          moment === 'prepare'
            ? await p.prepare()
            : await p.rejected({ at: 'request', status: 401, error: {} }); // no refresh token → one login → the presenter
        // The whole outcome, exactly: no hint, no code, no presenter message.
        assert.deepEqual(outcome, {
          ok: false,
          refusal: {
            kind: 'interactive-login',
            facts: { outcome: 'device-code-not-shown' },
            reason: 'showing the device code failed',
          },
        });
      },
    );
  }

  it('OidcPasswordProvider should use password grant', async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      token_endpoint: 'https://issuer/token',
    }));
    mockPasswordGrant.mock.mockImplementation(async () => ({
      accessToken: 'jwt.password.token',
      refreshToken: 'refresh',
      expiresIn: 600,
    }));

    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      username: 'user',
      password: 'pass',
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.password.token');
    assert.equal(tokens.authType, AUTH_TYPE_PASSWORD);
  });

  it('OidcPasswordProvider should use explicit token endpoint', async () => {
    mockPasswordGrant.mock.mockImplementation(async () => ({
      accessToken: 'jwt.password.token',
      refreshToken: 'refresh',
      expiresIn: 600,
    }));

    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      username: 'user',
      password: 'pass',
      tokenEndpoint: 'https://issuer/token',
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.password.token');
    assert.equal(mockDiscoverOidc.mock.callCount(), 0);
  });

  describe('an empty endpoint is none, at login and at refresh alike', () => {
    const discovered = {
      authorization_endpoint: 'https://issuer/authorize',
      device_authorization_endpoint: 'https://issuer/device',
      token_endpoint: 'https://issuer/token',
    };
    const renewed = { accessToken: 'jwt.renewed', expiresIn: 600 };

    it('OidcPasswordProvider refreshes at the discovered endpoint', async () => {
      mockDiscoverOidc.mock.mockImplementation(async () => discovered);
      mockPasswordGrant.mock.mockImplementation(async () => ({
        accessToken: 'jwt.password.token',
        refreshToken: 'refresh',
        expiresIn: 600,
      }));
      mockRefresh.mock.mockImplementation(async () => renewed);
      const provider = new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        username: 'user',
        password: 'pass',
        tokenEndpoint: '',
      });

      await provider.getTokens();
      await provider.refreshTokens();

      assert.equal(mockRefresh.mock.callCount(), 1);
      assert.equal(
        mockRefresh.mock.calls[0]?.arguments[0],
        'https://issuer/token',
      );
      assert.equal(mockPasswordGrant.mock.callCount(), 1);
    });

    it('OidcDeviceFlowProvider refreshes at the discovered endpoint — no second device prompt', async () => {
      mockDiscoverOidc.mock.mockImplementation(async () => discovered);
      mockInitiateDevice.mock.mockImplementation(async () => ({
        deviceCode: 'dev-code',
        userCode: 'user-code',
        verificationUri: 'https://issuer/verify',
        interval: 1,
      }));
      mockPollDevice.mock.mockImplementation(async () => ({
        accessToken: 'jwt.device.token',
        refreshToken: 'refresh',
        expiresIn: 1200,
      }));
      mockRefresh.mock.mockImplementation(async () => renewed);
      const provider = new OidcDeviceFlowProvider({
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        tokenEndpoint: '',
        deviceAuthorizationEndpoint: '',
        presenter: consoleDeviceCodePresenter(),
      });

      await provider.getTokens();
      await provider.refreshTokens();

      assert.equal(mockRefresh.mock.callCount(), 1);
      assert.equal(
        mockRefresh.mock.calls[0]?.arguments[0],
        'https://issuer/token',
      );
      assert.equal(mockInitiateDevice.mock.callCount(), 1);
    });

    it('OidcBrowserProvider logs in and refreshes at the discovered endpoints', async () => {
      mockDiscoverOidc.mock.mockImplementation(async () => discovered);
      mockExchangeCode.mock.mockImplementation(async () => ({
        accessToken: 'jwt.access.token',
        refreshToken: 'refresh',
        expiresIn: 3600,
      }));
      mockRefresh.mock.mockImplementation(async () => renewed);
      const provider = new OidcBrowserProvider({
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        clientSecret: 'secret',
        authorizationEndpoint: '',
        tokenEndpoint: '',
        authorization: asOidcResult(
          externalCodeStrategy({
            redirectUri: 'http://localhost:61001/callback',
            provide: async () => 'auth-code',
          }),
        ),
      });

      await provider.getTokens();
      await provider.refreshTokens();

      assert.equal(
        mockExchangeCode.mock.calls[0]?.arguments[0],
        'https://issuer/token',
      );
      assert.equal(mockRefresh.mock.callCount(), 1);
      assert.equal(
        mockRefresh.mock.calls[0]?.arguments[0],
        'https://issuer/token',
      );
    });
  });

  it("OidcPasswordProvider takes '' as no token endpoint and discovers it", async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      token_endpoint: 'https://issuer/token',
    }));
    mockPasswordGrant.mock.mockImplementation(async () => ({
      accessToken: 'jwt.password.token',
      expiresIn: 600,
    }));

    const provider = new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      username: 'user',
      password: 'pass',
      tokenEndpoint: '',
    });

    await provider.getTokens();
    assert.equal(mockDiscoverOidc.mock.callCount(), 1);
    assert.equal(
      mockPasswordGrant.mock.calls[0]?.arguments[0],
      'https://issuer/token',
    );
  });

  it("OidcTokenExchangeProvider takes '' as no token endpoint and discovers it", async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      token_endpoint: 'https://issuer/token',
    }));
    mockTokenExchange.mock.mockImplementation(async () => ({
      accessToken: 'jwt.exchange.token',
      expiresIn: 300,
    }));

    const provider = new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      tokenEndpoint: '',
    });

    await provider.getTokens();
    assert.equal(mockDiscoverOidc.mock.callCount(), 1);
    assert.equal(
      mockTokenExchange.mock.calls[0]?.arguments[0],
      'https://issuer/token',
    );
  });

  it('OidcTokenExchangeProvider should exchange subject token', async () => {
    mockDiscoverOidc.mock.mockImplementation(async () => ({
      token_endpoint: 'https://issuer/token',
    }));
    mockTokenExchange.mock.mockImplementation(async () => ({
      accessToken: 'jwt.exchange.token',
      expiresIn: 300,
    }));

    const provider = new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.exchange.token');
    assert.equal(tokens.authType, AUTH_TYPE_USER_TOKEN);
  });

  it('OidcTokenExchangeProvider should use explicit token endpoint', async () => {
    mockTokenExchange.mock.mockImplementation(async () => ({
      accessToken: 'jwt.exchange.token',
      expiresIn: 300,
    }));

    const provider = new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      tokenEndpoint: 'https://issuer/token',
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.exchange.token');
    assert.equal(mockDiscoverOidc.mock.callCount(), 0);
  });

  it('OidcBrowserProvider should throw when endpoints are missing', async () => {
    // A parsed document without the fields: data from outside the types.
    mockDiscoverOidc.mock.mockImplementation(async () => JSON.parse('{}'));

    // A strategy that needs the URL but binds no socket: the assertion here is
    // about the message, and the default strategy would have made it depend on
    // 61001 being free — a machine already holding it fails this for a reason
    // that has nothing to do with endpoints. The default's own port behaviour is
    // covered in the lifecycle block below, which tolerates that failure.
    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      issuerUrl: 'https://issuer',
      clientId: 'client',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async () => 'unreachable',
        }),
      ),
    });

    // A configuration failure naming the endpoint.
    const thrown = await provider.getTokens().catch((error: unknown) => error);
    matchObject(configurationOf(thrown), {
      case: 'oidc-endpoint-missing',
      fields: ['authorizationEndpoint'],
    });
  });

  /**
   * A SAMLResponse as an IdP posts it — the whole Response, standard base64 —
   * and what the provider must send for it. The conversion itself is pinned in
   * samlBearerAssertion.test.ts; here the point is that the provider applies it.
   */
  const samlResponseCarrying = (assertionId: string) => {
    const assertion = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}"><saml2:Issuer>idp</saml2:Issuer></saml2:Assertion>`;
    const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
    const payload = Buffer.from(response, 'utf8').toString('base64');
    return { payload, bearer: toBearerAssertion(payload) };
  };

  it('Saml2BearerProvider should exchange assertion for token', async () => {
    mockExchangeSaml.mock.mockImplementation(async () => ({
      accessToken: 'jwt.saml.token',
      refreshToken: 'refresh',
      expiresIn: 900,
    }));

    const saml = samlResponseCarrying('_a1');
    const provider = new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      uaaUrl: 'https://uaa',
      // staticCodeStrategy never calls the builder; declaring idpInitiated
      // says plainly that no request was sent for this assertion to answer.
      idpInitiated: true,
      authorization: staticCodeStrategy({ payload: saml.payload }),
      // This test is about the exchange call, not validation; the fixture
      // above is not signed.
      assertionValidator: acceptingSamlValidator(),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.saml.token');
    assert.equal(tokens.authType, AUTH_TYPE_SAML2_BEARER);
    // RFC 7522: the Assertion alone, base64url — not the Response it arrived in.
    calledWith(
      mockExchangeSaml,
      saml.bearer,
      'https://uaa/oauth/token',
      undefined,
      undefined,
      undefined,
      // No client authentication configured: none given to the site.
      undefined,
      // The exchange is the login's request: it carries the attempt's
      // signal; the refresh below gets none.
      {
        authDebug: false,
        grant: 'saml2_bearer',
        signal: anyOf(AbortSignal),
        // The login step's dispatch notice.
        dispatched: anyOf(Function),
      },
    );
  });

  describe('Saml2BearerProvider refresh', () => {
    const seededConfig = () => {
      const authorize = mock.fn(async () => ({
        payload: samlResponseCarrying('_fresh').payload,
        redirectUri: 'http://localhost:61001/callback',
      }));
      const authorization: IAuthorizationStrategy<string> = { authorize };
      return {
        authorize,
        config: {
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp/sso',
          spEntityId: 'sp-entity',
          uaaUrl: 'https://uaa',
          clientId: 'client',
          clientSecret: 'secret',
          accessToken: jwtExpiringIn(-3600),
          refreshToken: 'seeded-refresh',
          // `authorize` above never calls the builder either.
          idpInitiated: true,
          authorization,
          // The validator is resolved at construction; these cases
          // are about the refresh path, not validation, and the fixture
          // payload above is not signed.
          assertionValidator: acceptingSamlValidator(),
        },
      };
    };

    it('spends the refresh token instead of running the authorization strategy', async () => {
      const newAccess = jwtExpiringIn(3600);
      mockRefreshSaml.mock.mockImplementation(async () => ({
        accessToken: newAccess,
        refreshToken: 'rotated-refresh',
        expiresIn: 3600,
      }));
      const { authorize, config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      assert.equal(authorize.mock.callCount(), 0);
      assert.equal(mockExchangeSaml.mock.callCount(), 0);
      calledWith(
        mockRefreshSaml,
        'seeded-refresh',
        'https://uaa/oauth/token',
        'client',
        'secret',
        undefined,
        // No client authentication configured: none given to the site.
        undefined,
        {
          authDebug: false,
          grant: 'saml2_bearer',
          // The refresh step's dispatch gate.
          dispatched: anyOf(Function),
        },
      );
      assert.equal(tokens.authorizationToken, newAccess);
      assert.equal(tokens.refreshToken, 'rotated-refresh');
      assert.equal(tokens.authType, AUTH_TYPE_SAML2_BEARER);
    });

    it('keeps the refresh token it spent when the grant returns none', async () => {
      mockRefreshSaml.mock.mockImplementation(async () => ({
        accessToken: jwtExpiringIn(3600),
      }));
      const { config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      assert.equal(tokens.refreshToken, 'seeded-refresh');
    });

    it('refreshes against an explicit tokenUrl, not one derived from uaaUrl', async () => {
      mockRefreshSaml.mock.mockImplementation(async () => ({
        accessToken: jwtExpiringIn(3600),
      }));
      const { config } = seededConfig();

      await new Saml2BearerProvider({
        ...config,
        tokenUrl: 'https://tokens.example/custom/token',
      }).getTokens();

      assert.equal(
        mockRefreshSaml.mock.calls[0]?.arguments[1],
        'https://tokens.example/custom/token',
      );
    });

    it('falls back to a full login when the refresh grant is refused', async () => {
      mockRefreshSaml.mock.mockImplementation(async () => {
        throw new Error('invalid_grant');
      });
      mockExchangeSaml.mock.mockImplementation(async () => ({
        accessToken: 'jwt.after.login',
        refreshToken: 'login-refresh',
        expiresIn: 900,
      }));
      const { authorize, config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      assert.equal(mockRefreshSaml.mock.callCount(), 1);
      assert.equal(authorize.mock.callCount(), 1);
      assert.equal(
        mockExchangeSaml.mock.calls[0]?.arguments[0],
        samlResponseCarrying('_fresh').bearer,
      );
      assert.equal(tokens.authorizationToken, 'jwt.after.login');
      assert.equal(tokens.refreshToken, 'login-refresh');
    });

    /**
     * A `refresh_token` grant carries no assertion, so there is nothing to
     * validate. Without this, a later change routing refresh through
     * `performLogin()` again would pass every other test in this describe —
     * they all use a validator that accepts anything.
     */
    it('does not consult the validator on refresh', async () => {
      mockRefreshSaml.mock.mockImplementation(async () => ({
        accessToken: jwtExpiringIn(3600),
      }));
      const { config } = seededConfig();
      const validate = mock.fn<IAssertionValidator['validate']>();

      await new Saml2BearerProvider({
        ...config,
        assertionValidator: { validate },
      }).getTokens();

      assert.equal(validate.mock.callCount(), 0);
    });
  });

  it('Saml2PureProvider should return the saml response as the session', async () => {
    const samlXml =
      '<Assertion NotOnOrAfter="2030-01-01T00:00:00Z"></Assertion>';
    const samlResponse = Buffer.from(samlXml, 'utf8').toString('base64');
    const validatedExpiresAt = new Date(Date.now() + 3600_000);

    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      cookieProvider: async () => 'SAP_SESSION=abc123',
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      // staticCodeStrategy never calls the builder; declaring idpInitiated
      // says plainly that no request was sent for this assertion to answer.
      idpInitiated: true,
      authorization: staticCodeStrategy({ payload: samlResponse }),
      // This test is about wiring the cookie session, not validation; the
      // fixture above is not signed.
      assertionValidator: {
        async validate() {
          return {
            expiresAt: validatedExpiresAt,
            assertionId: '_a1',
            issuer: 'urn:mock:idp',
            raw: samlResponse,
            signedXml: samlResponse,
          };
        },
      },
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'SAP_SESSION=abc123');
    assert.equal(tokens.tokenType, 'saml');
    // `parseSamlNotOnOrAfter` is gone; `expiresAt` now comes from
    // `ValidatedAssertion`, not an unverified regex.
    assert.equal(tokens.expiresAt, validatedExpiresAt.getTime());
  });

  it('Saml2PureProvider rejects a pre-built URL without a declared acsUrl', () => {
    assert.throws(
      () =>
        new Saml2PureProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          authorizationUrl: 'https://idp.example/sso?SAMLRequest=abc',
          cookieProvider: async (saml) => saml,
          authorization: unusedAuthorization,
          assertionValidator: unusedValidator,
        }),
      thrown(/acsUrl is required/i),
    );
  });

  it('Saml2PureProvider takes an assertion from a strategy', async () => {
    const seen: string[] = [];
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: 'http://localhost:61001/callback',
      // staticCodeStrategy never calls the builder; declaring idpInitiated
      // says plainly that no request was sent for this assertion to answer.
      idpInitiated: true,
      authorization: staticCodeStrategy({
        redirectUri: 'http://localhost:61001/callback',
        payload: 'PHNhbWw+',
      }),
      // The pure provider exchanges the assertion for session cookies; echo it
      // so the assertion under test is the one the strategy delivered.
      cookieProvider: async (saml) => {
        seen.push(saml);
        return saml;
      },
      // This test is about which assertion reaches the cookie provider, not
      // validation; the fixture above is not signed.
      assertionValidator: acceptingSamlValidator(),
    });
    const tokens = await provider.getTokens();
    assert.deepEqual(seen, ['PHNhbWw+']);
    assert.equal(tokens.authorizationToken, 'PHNhbWw+');
  });

  it('Saml2PureProvider rejects an assertion delivered to the wrong ACS', async () => {
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: 'http://localhost:61001/callback',
      // Never calls the builder, so the check inside it never runs — this is
      // what the second net exists for.
      authorization: staticCodeStrategy({
        redirectUri: 'http://localhost:5555/callback',
        payload: 'PHNhbWw+',
      }),
      cookieProvider: async (saml) => saml,
      // Never reached: the ACS mismatch is thrown before validate() would run.
      assertionValidator: acceptingSamlValidator(),
    });
    // The two addresses are diagnostics, not words.
    const thrown = await provider.getTokens().catch((error: unknown) => error);
    matchObject(configurationOf(thrown), {
      case: 'saml-acs-mismatch',
      fields: ['acsUrl'],
    });
    assert.deepEqual(readFailure(thrown, 'unfamiliar-error').diagnostics, {
      configuredUri: 'http://localhost:61001/callback',
      strategyUri: 'http://localhost:5555/callback',
    });
  });

  it('Saml2BearerProvider rejects a pre-built URL without a declared acsUrl', () => {
    assert.throws(
      () =>
        new Saml2BearerProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          authorizationUrl: 'https://idp.example/sso?SAMLRequest=abc',
          uaaUrl: 'https://uaa',
          authorization: unusedAuthorization,
          assertionValidator: unusedValidator,
        }),
      thrown(/acsUrl is required/i),
    );
  });

  it('Saml2PureProvider refuses to open a browser at an ACS the IdP was never told about', async () => {
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: 'https://sp.example/acs',
      // Calls the builder, so the guard inside it runs before anything opens.
      authorization: externalCodeStrategy({
        redirectUri: 'http://localhost:61001/callback',
        provide: async () => 'unreachable',
      }),
      cookieProvider: async (saml) => saml,
      // Never reached: the ACS mismatch is thrown before validate() would run.
      assertionValidator: acceptingSamlValidator(),
    });
    // Refused inside the builder; the addresses as diagnostics.
    const thrown = await provider.getTokens().catch((error: unknown) => error);
    matchObject(configurationOf(thrown), {
      case: 'saml-acs-mismatch',
      fields: ['acsUrl'],
    });
    assert.deepEqual(readFailure(thrown, 'unfamiliar-error').diagnostics, {
      configuredUri: 'https://sp.example/acs',
      strategyUri: 'http://localhost:61001/callback',
    });
  });

  it('SsoProviderFactory should create configured providers', () => {
    const provider = SsoProviderFactory.create({
      protocol: 'oidc',
      flow: 'browser',
      config: {
        renewal: refreshThenLogin(),
        issuerUrl: 'https://issuer',
        clientId: 'client',
        authorization: oidcCallbackStrategy(),
      },
    });

    assert.ok(provider instanceof OidcBrowserProvider);
  });
});

/**
 * Whoever constructs, disposes.
 *
 * A consumer-supplied strategy may be a long-lived receiver that outlives many
 * logins, so the provider must never destroy it: the provider no longer
 * constructs one of its own — `authorization` is a required constructor
 * argument — so the strategy is always one the consumer supplied, and
 * disposing it is the consumer's call, never the provider's.
 */
describe('OidcBrowserProvider strategy lifecycle', () => {
  beforeEach(() => {
    clearSiteMocks();
    // A parsed document without the fields: data from outside the types.
    mockDiscoverOidc.mock.mockImplementation(async () => JSON.parse('{}'));
    mockExchangeCode.mock.mockImplementation(async () => ({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    }));
  });

  it('never disposes a strategy the consumer supplied', async () => {
    const dispose = mock.fn(async () => undefined);
    const redirectUri = 'http://localhost:61001/callback';
    const supplied: IAuthorizationStrategy<OidcCallbackResult> = {
      authorize: async (request) => {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload: { code: 'held-code' }, redirectUri };
      },
      dispose,
    };

    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      authorizationEndpoint: 'https://issuer/authorize',
      tokenEndpoint: 'https://issuer/token',
      authorization: supplied,
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'jwt.access.token');
    // A receiver the consumer owns must survive the login it served.
    assert.equal(dispose.mock.callCount(), 0);
  });

  it('leaves a supplied strategy alone when the login fails too', async () => {
    const dispose = mock.fn(async () => undefined);
    const supplied: IAuthorizationStrategy<OidcCallbackResult> = {
      authorize: async () => {
        throw new Error('consumer flow cancelled');
      },
      dispose,
    };
    const provider = new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      clientId: 'client',
      authorizationEndpoint: 'https://issuer/authorize',
      tokenEndpoint: 'https://issuer/token',
      authorization: supplied,
    });

    // The consumer's own error never comes back — an
    // AuthProviderFailure holding the classified error, without its message.
    const failed = provider.getTokens();
    await assert.rejects(failed, thrown(AuthProviderFailure));
    await assert.rejects(failed, (error) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, /consumer flow cancelled/);
      return true;
    });
    assert.equal(dispose.mock.callCount(), 0);
  });
});

/**
 * Whoever constructs, disposes — the SAML half.
 *
 * `getSamlAssertion` is shared by both SAML providers, so the rule is written
 * once and would be reversed once; asserting it through `Saml2PureProvider`
 * covers the helper, and the pure provider needs no token endpoint to reach it.
 * The provider no longer constructs a default of its own — `authorization` is
 * a required constructor argument — so the strategy under test is always one
 * the consumer supplied, and disposing it is the consumer's call.
 */
describe('SAML strategy lifecycle', () => {
  beforeEach(() => {
    clearSiteMocks();
  });

  it('never disposes a strategy the consumer supplied', async () => {
    const dispose = mock.fn(async () => undefined);
    const redirectUri = 'http://localhost:61001/callback';
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async (request) => {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload: 'PHNhbWw+', redirectUri };
      },
      dispose,
    };

    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: redirectUri,
      authorization: supplied,
      cookieProvider: async (saml) => saml,
      // This test is about the strategy lifecycle, not validation; the
      // fixture above is not signed.
      assertionValidator: acceptingSamlValidator(),
    });

    const tokens = await provider.getTokens();
    assert.equal(tokens.authorizationToken, 'PHNhbWw+');
    // A receiver the consumer owns must survive the login it served.
    assert.equal(dispose.mock.callCount(), 0);
  });

  it('leaves a supplied strategy alone when the login fails too', async () => {
    const dispose = mock.fn(async () => undefined);
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async () => {
        throw new Error('consumer flow cancelled');
      },
      dispose,
    };
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      authorization: supplied,
      cookieProvider: async (saml) => saml,
      // Never reached: `authorize` throws before validate() would run.
      assertionValidator: acceptingSamlValidator(),
    });

    // The consumer's own error never comes back — an
    // AuthProviderFailure holding the classified error, without its message.
    const failed = provider.getTokens();
    await assert.rejects(failed, thrown(AuthProviderFailure));
    await assert.rejects(failed, (error) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, /consumer flow cancelled/);
      return true;
    });
    assert.equal(dispose.mock.callCount(), 0);
  });
});

/**
 * Both providers run `assertionValidator` on every login. `idpCertificates`
 * and `idpEntityId` no longer configure the provider directly — they belong to
 * building a validator (`SamlTrust`), assembled by the static factories — so a
 * missing one is now a fault at that assembly, surfacing before a provider is
 * even constructed.
 */
describe('Saml2PureProvider assertion validation', () => {
  const CERT = generateKeyMaterial().certificatePem;
  const baseConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    acsUrl: 'http://localhost:61001/callback',
    idpInitiated: true,
    idpEntityId: 'urn:mock:idp',
    authorization: staticCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      payload: Buffer.from('<Assertion/>', 'utf8').toString('base64'),
    }),
    assertionValidator: createSignedResponseValidator({
      idpCertificates: [CERT],
      replayStore: createInMemoryReplayStore(),
    }),
    cookieProvider: async () => 'cookie',
  };

  it('refuses assembling the shipped validator without idpCertificates (Saml2PureProvider.inBrowser)', () => {
    assert.throws(
      () =>
        Saml2PureProvider.inBrowser(
          {
            renewal: refreshThenLogin(),
            idpSsoUrl: baseConfig.idpSsoUrl,
            spEntityId: baseConfig.spEntityId,
            acsUrl: baseConfig.acsUrl,
            idpInitiated: baseConfig.idpInitiated,
            idpEntityId: baseConfig.idpEntityId,
            cookieProvider: baseConfig.cookieProvider,
          },
          { idpCertificates: [] },
        ),
      thrown(/idpCertificates/),
    );
  });

  it('takes expiresAt from the validated assertion, not from a regex', async () => {
    // A stub validator, to prove the provider uses what validation returned.
    const expiresAt = new Date(Date.now() + 111_000);
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      ...baseConfig,
      assertionValidator: {
        async validate() {
          return {
            expiresAt,
            assertionId: '_a1',
            issuer: 'urn:mock:idp',
            raw: 'ignored',
            signedXml: 'ignored',
          };
        },
      },
      cookieProvider: async () => 'cookie=1',
    });
    const result = await provider.getTokens();
    // ITokenResult.expiresAt is an epoch-ms number, unlike
    // ValidatedAssertion.expiresAt, which is a Date.
    assert.equal(result.expiresAt, expiresAt.getTime());
  });

  /**
   * The pure counterpart of the bearer "does not reach the token endpoint"
   * test: a refused assertion must never reach the cookie provider, which is
   * this provider's equivalent of "the network call". Two mutants this must
   * catch: swallowing the validator's rejection, and calling the cookie
   * provider before validate() runs.
   */
  it('does not hand the assertion to the cookie provider when validation refuses it', async () => {
    const cookieProvider = mock.fn(async (saml: string) => saml);
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      ...baseConfig,
      assertionValidator: {
        async validate() {
          throw new Error('the IdP declined: SECRET-MARKER');
        },
      },
      cookieProvider,
    });

    // A custom validator's throw is classified with `validating-assertion`: its
    // own error and message are not handed back.
    const thrown = await rejectionOf(provider.getTokens());
    assert.ok(thrown instanceof AuthProviderFailure);
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'unknown',
      facts: { operation: 'validating-assertion' },
    });
    notContains(JSON.stringify(thrown), 'SECRET-MARKER');
    notContains(String(thrown), 'SECRET-MARKER');
    assert.equal(cookieProvider.mock.callCount(), 0);
  });

  // A custom validator delegating to a shipped one rejects with its minted
  // refusal: that error reaches the caller as it is, diagnostics included.
  it("passes a custom validator's minted SAML refusal through as it is", async () => {
    const refusal = authError['saml-assertion'](
      { rule: 'untrusted-issuer', check: 'issuer' },
      { issuer: 'urn:someone:else' },
    );
    const cookieProvider = mock.fn(async (saml: string) => saml);
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      ...baseConfig,
      assertionValidator: {
        async validate() {
          throw new AuthProviderFailure(refusal);
        },
      },
      cookieProvider,
    });

    const thrown = await rejectionOf(provider.getTokens());
    assert.ok(thrown instanceof AuthProviderFailure);
    assert.equal((thrown as AuthProviderFailure).error, refusal);
    assert.equal(cookieProvider.mock.callCount(), 0);
  });

  // This provider has no refresh grant: a renewal is the one login, and that
  // login validates again — a renewal that skipped validation would hand an
  // unverified assertion to cookieProvider.
  it('validates again when renewing', async () => {
    const payload = Buffer.from('<Assertion/>', 'utf8').toString('base64');
    const validate = mock.fn(async () => ({
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_a1',
      issuer: 'urn:mock:idp',
      raw: payload,
      signedXml: payload,
    }));
    const cookieProvider = mock.fn(async () => 'cookie');
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      idpEntityId: 'urn:mock:idp',
      idpInitiated: true,
      authorization: staticCodeStrategy({ payload }),
      assertionValidator: { validate },
      cookieProvider,
    });

    await provider.refreshTokens();

    assert.equal(validate.mock.callCount(), 1);
    calledWith(
      validate,
      payload,
      objectContaining({
        audience: 'sp-entity',
        expectedIssuer: 'urn:mock:idp',
      }),
    );
    calledWith(cookieProvider, payload);
  });
});

describe('Saml2BearerProvider assertion validation', () => {
  beforeEach(() => {
    clearSiteMocks();
  });

  it('does not reach the token endpoint when the assertion is refused', async () => {
    let exchanged = false;
    mockExchangeSaml.mock.mockImplementation(async () => {
      exchanged = true;
      return { accessToken: 'unreachable', expiresIn: 900 };
    });

    const provider = new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      uaaUrl: 'https://uaa',
      idpInitiated: true,
      authorization: staticCodeStrategy({
        payload: Buffer.from('<Assertion/>', 'utf8').toString('base64'),
      }),
      assertionValidator: {
        async validate() {
          throw new Error('the IdP declined: SECRET-MARKER');
        },
      },
    });

    const thrown = await rejectionOf(provider.getTokens());
    matchObject((thrown as AuthProviderFailure).error, {
      kind: 'unknown',
      facts: { operation: 'validating-assertion' },
    });
    notContains(JSON.stringify(thrown), 'SECRET-MARKER');
    assert.equal(exchanged, false);
  });
});

/**
 * Which shipped validator each provider defaults to is not a detail either
 * provider is allowed to get backwards: the token endpoint receives the
 * Assertion alone (RFC 7522, #40), so `Saml2BearerProvider` must default to
 * the assertion-only validator, while `Saml2PureProvider` hands the whole
 * response on and must default to the signed-Response one. A response signed
 * only at the Response level — what most identity providers send — is the
 * fixture that tells them apart.
 */
describe('Saml2 provider default validators', () => {
  const KEY = generateKeyMaterial();
  const ISSUER = 'urn:mock:idp';
  const AUDIENCE = 'sp-entity';
  const ACS = 'http://localhost:61001/callback';
  const REQUEST_ID = '_req1';

  const iso = (offsetMs: number) =>
    new Date(Date.now() + offsetMs).toISOString();

  /** A samlp:Response signed only at the Response level. */
  function buildResponseSignedAtResponseLevel(): string {
    const assertion =
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
      `<saml:Issuer>${ISSUER}</saml:Issuer>` +
      `<saml:Subject><saml:NameID>mock-user</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" Recipient="${ACS}" NotOnOrAfter="${iso(300_000)}"/>` +
      `</saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(300_000)}">` +
      `<saml:AudienceRestriction><saml:Audience>${AUDIENCE}</saml:Audience></saml:AudienceRestriction>` +
      `</saml:Conditions></saml:Assertion>`;
    const response =
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="${ACS}">` +
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
      `${assertion}</samlp:Response>`;
    return signXml(response, KEY, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: {
        reference: "//*[local-name(.)='Response']",
        action: 'prepend',
      },
    });
  }

  const payload = () =>
    Buffer.from(buildResponseSignedAtResponseLevel(), 'utf8').toString(
      'base64',
    );

  /**
   * An unsigned samlp:Response with `status` around the same Assertion,
   * signed by the trusted key at the Assertion level only.
   */
  const unsignedResponseAround = (status: string) => {
    const signed = buildResponseSignedAtResponseLevel();
    const start = signed.indexOf('<saml:Assertion');
    const end =
      signed.indexOf('</saml:Assertion>') + '</saml:Assertion>'.length;
    const assertion = signXml(signed.slice(start, end), KEY);
    return Buffer.from(
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Destination="${ACS}">` +
        `<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
        `${assertion}</samlp:Response>`,
      'utf8',
    ).toString('base64');
  };

  // An unsigned Status decides nothing (review, fix 1): the signed-Response
  // validator reads Status only once the Response is the signed element.
  for (const [caseIndex, caseRow] of [
    'urn:oasis:names:tc:SAML:2.0:status:Responder',
    'urn:example:status:Forged',
  ].entries()) {
    const status = caseRow;
    it(
      caseTitle(
        "Saml2PureProvider's default refuses an unsigned Response with Status %s as response-not-signed",
        caseRow,
        caseIndex,
      ),
      async () => {
        const cookieProvider = mock.fn(async (saml: string) => saml);
        const error = await expectSamlRejection(
          new Saml2PureProvider({
            renewal: refreshThenLogin(),
            idpSsoUrl: 'https://idp/sso',
            spEntityId: AUDIENCE,
            acsUrl: ACS,
            authnRequestId: REQUEST_ID,
            idpEntityId: ISSUER,
            authorization: staticCodeStrategy({
              redirectUri: ACS,
              payload: unsignedResponseAround(status),
            }),
            assertionValidator: createSignedResponseValidator({
              idpCertificates: [KEY.certificatePem],
              replayStore: createInMemoryReplayStore(),
            }),
            cookieProvider,
          }).getTokens(),
          'response-not-signed',
        );
        assert.deepEqual(error.facts, {
          rule: 'response-not-signed',
          check: 'signedNode',
        });
        notContains(JSON.stringify(error), status);
        assert.equal(cookieProvider.mock.callCount(), 0);
      },
    );
  }

  beforeEach(() => {
    clearSiteMocks();
  });

  it("Saml2PureProvider's default accepts a Response signed at the Response level", async () => {
    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: AUDIENCE,
      acsUrl: ACS,
      authnRequestId: REQUEST_ID,
      idpEntityId: ISSUER,
      authorization: staticCodeStrategy({
        redirectUri: ACS,
        payload: payload(),
      }),
      assertionValidator: createSignedResponseValidator({
        idpCertificates: [KEY.certificatePem],
        replayStore: createInMemoryReplayStore(),
      }),
      cookieProvider: async (saml) => saml,
    });

    const tokens = await provider.getTokens();
    assert.notEqual(tokens.authorizationToken, undefined);
    assert.ok(
      (tokens.expiresAt ?? 0) > Date.now(),
      `${tokens.expiresAt} > ${Date.now()}`,
    );
  });

  it("Saml2BearerProvider's default refuses the same Response, at signedNode", async () => {
    const provider = new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: AUDIENCE,
      acsUrl: ACS,
      authnRequestId: REQUEST_ID,
      uaaUrl: 'https://uaa',
      idpEntityId: ISSUER,
      authorization: staticCodeStrategy({
        redirectUri: ACS,
        payload: payload(),
      }),
      assertionValidator: createSignedAssertionValidator({
        idpCertificates: [KEY.certificatePem],
        replayStore: createInMemoryReplayStore(),
      }),
    });

    await expectSamlRejection(provider.getTokens(), 'assertion-not-signed');
    assert.equal(mockExchangeSaml.mock.callCount(), 0);
  });
});

/**
 * The exact `AssertionContext` each provider passes to `validate()`. Built
 * with `toHaveBeenCalledWith`, which catches a missing field, a substituted
 * value and an extra field with a defined value — but treats a key whose
 * value is `undefined` as absent, so an extra field set to `undefined` goes
 * unnoticed. `toMatchObject` would miss extra fields altogether.
 */
describe('Saml2PureProvider validation context', () => {
  it('passes exactly the validation context', async () => {
    const redirectUri = 'http://localhost:61001/callback';
    const payload = Buffer.from('<Assertion/>', 'utf8').toString('base64');
    const logger: ILogger = {
      debug: mock.fn(),
      info: mock.fn(),
      warn: mock.fn(),
      error: mock.fn(),
    };
    const validate = mock.fn(async () => ({
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_a1',
      issuer: 'urn:mock:idp',
      raw: payload,
      signedXml: payload,
    }));
    let builtUrl = '';
    // Calls the builder, so the package mints the AuthnRequest ID itself —
    // the only way `expectedInResponseTo` can be pinned against a value
    // this test did not just make up.
    const authorization: IAuthorizationStrategy<string> = {
      async authorize(request) {
        builtUrl = await request.buildAuthorizationUrl(redirectUri);
        return { payload, redirectUri };
      },
    };

    const provider = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      idpEntityId: 'urn:mock:idp',
      // No acsUrl: outcome.redirectUri is the only candidate value for
      // context.acsUrl, so a mutation reading it from config instead cannot
      // coincidentally agree.
      authorization,
      assertionValidator: { validate },
      cookieProvider: async () => 'cookie',
      logger,
    });

    await provider.getTokens();

    const mintedId = mintedIdFrom(builtUrl);
    assert.equal(validate.mock.callCount(), 1);
    calledWith(validate, payload, {
      expectedInResponseTo: mintedId,
      audience: 'sp-entity',
      acsUrl: redirectUri,
      expectedIssuer: 'urn:mock:idp',
      logger,
    });
  });
});

describe('Saml2BearerProvider validation context', () => {
  beforeEach(() => {
    clearSiteMocks();
  });

  it('passes exactly the validation context', async () => {
    mockExchangeSaml.mock.mockImplementation(async () => ({
      accessToken: 'AT',
      expiresIn: 900,
    }));

    const redirectUri = 'http://localhost:61001/callback';
    // A bare Assertion, so `toBearerAssertion` (called after validate()
    // resolves) accepts it without needing a whole signed Response.
    const payload = Buffer.from(
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/>',
      'utf8',
    ).toString('base64');
    const logger: ILogger = {
      debug: mock.fn(),
      info: mock.fn(),
      warn: mock.fn(),
      error: mock.fn(),
    };
    const validate = mock.fn(async () => ({
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_a1',
      issuer: 'urn:mock:idp',
      raw: payload,
      signedXml: payload,
    }));
    let builtUrl = '';
    const authorization: IAuthorizationStrategy<string> = {
      async authorize(request) {
        builtUrl = await request.buildAuthorizationUrl(redirectUri);
        return { payload, redirectUri };
      },
    };

    const provider = new Saml2BearerProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      idpEntityId: 'urn:mock:idp',
      uaaUrl: 'https://uaa',
      authorization,
      assertionValidator: { validate },
      logger,
    });

    await provider.getTokens();

    const mintedId = mintedIdFrom(builtUrl);
    assert.equal(validate.mock.callCount(), 1);
    calledWith(validate, payload, {
      expectedInResponseTo: mintedId,
      audience: 'sp-entity',
      acsUrl: redirectUri,
      expectedIssuer: 'urn:mock:idp',
      logger,
    });
  });
});

/**
 * Construction-time faults: each must throw from `new ...Provider(...)`
 * itself, before any login is attempted, and never be silently absorbed into
 * "the default validator" being built anyway.
 */
/**
 * `idpCertificates`, `clockSkewMs` and `idpEntityId` no longer configure a
 * provider directly: they describe the trust a static factory assembles into
 * a shipped validator (`SamlTrust`). A bad one is now a fault at that
 * assembly — `Saml2PureProvider.inBrowser` / `Saml2BearerProvider.inBrowser`
 * — rather than at `new ...Provider(...)`, except `idpEntityId`, which the
 * provider still checks itself once it has a shipped validator in hand
 * (`checkAssertionValidator`).
 */
describe('Saml2 provider construction faults', () => {
  const CERT = generateKeyMaterial().certificatePem;

  const validPureConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    idpEntityId: 'urn:mock:idp',
    cookieProvider: async (saml: string) => saml,
    renewal: refreshThenLogin(),
  };

  const validBearerConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    idpEntityId: 'urn:mock:idp',
    uaaUrl: 'https://uaa',
    renewal: refreshThenLogin(),
  };

  // 5.4.0 read the brand with a plain property access, so an untyped
  // consumer's non-object validator was taken for a custom one and the
  // provider constructed; it must not throw now either.
  for (const [caseIndex, caseRow] of cases([
    ['a string', 'str'],
    ['a number', 42],
  ]).entries()) {
    const [_label, value] = caseRow;
    it(
      caseTitle(
        'a non-object assertionValidator (%s) is not a shipped one: the provider constructs',
        caseRow,
        caseIndex,
      ),
      () => {
        const assertionValidator = value as unknown as IAssertionValidator;
        assert.doesNotThrow(
          () =>
            new Saml2PureProvider({
              ...validPureConfig,
              authorization: unusedAuthorization,
              assertionValidator,
            }),
        );
        assert.doesNotThrow(
          () =>
            new Saml2BearerProvider({
              ...validBearerConfig,
              authorization: unusedAuthorization,
              assertionValidator,
            }),
        );
      },
    );
  }

  // A configuration failure naming idpEntityId.
  it('Saml2PureProvider refuses construction when idpEntityId is missing', () => {
    const error = constructionError(() =>
      Saml2PureProvider.inBrowser(
        {
          ...validPureConfig,
          idpEntityId: undefined,
        },
        { idpCertificates: [CERT] },
      ),
    );
    matchObject(configurationOf(error), {
      case: 'saml-shipped-validator-without-issuer',
      fields: ['idpEntityId'],
    });
  });

  // A configuration failure naming idpEntityId.
  it('Saml2BearerProvider refuses construction when idpEntityId is missing', () => {
    const error = constructionError(() =>
      Saml2BearerProvider.inBrowser(
        {
          ...validBearerConfig,
          idpEntityId: undefined,
        },
        { idpCertificates: [CERT] },
      ),
    );
    matchObject(configurationOf(error), {
      case: 'saml-shipped-validator-without-issuer',
      fields: ['idpEntityId'],
    });
  });

  // Previously a provider-level check naming the field in `missingFields`
  // ("Saml2BearerProvider refuses construction when idpCertificates is
  // missing"). `idpCertificates` is now a required array on `SamlTrust`, so
  // "missing" is no longer reachable through typed code — only "empty" is,
  // and it was always the same runtime check (`!idpCertificates?.length`).
  // This is that assertion, moved: the factory's own plain Error, with no
  // `missingFields`, since the provider no longer intercepts it.
  it('refuses assembling the shipped validator when idpCertificates is an empty list (Saml2BearerProvider.inBrowser)', () => {
    assert.throws(
      () =>
        Saml2BearerProvider.inBrowser(validBearerConfig, {
          idpCertificates: [],
        }),
      thrown(/idpCertificates must not be empty/),
    );
  });

  it('refuses assembling the shipped validator when idpCertificates is an empty list (Saml2PureProvider.inBrowser)', () => {
    assert.throws(
      () =>
        Saml2PureProvider.inBrowser(validPureConfig, { idpCertificates: [] }),
      thrown(/idpCertificates must not be empty/),
    );
  });

  it('refuses assembling the shipped validator when a certificate is malformed', () => {
    assert.throws(
      () =>
        Saml2PureProvider.inBrowser(validPureConfig, {
          idpCertificates: ['not-a-cert'],
        }),
      thrown(/certificate/i),
    );
  });

  it('refuses assembling the shipped validator when clockSkewMs is negative', () => {
    assert.throws(
      () =>
        Saml2PureProvider.inBrowser(validPureConfig, {
          idpCertificates: [CERT],
          clockSkewMs: -1,
        }),
      thrown(/clockSkewMs/),
    );
  });
});
