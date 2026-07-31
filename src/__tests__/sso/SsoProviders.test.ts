import netModule from 'node:net';
import type { IAuthorizationStrategy, ILogger } from '@mcp-abap-adt/interfaces';
import {
  AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
  AUTH_TYPE_PASSWORD,
  AUTH_TYPE_SAML2_BEARER,
  AUTH_TYPE_USER_TOKEN,
} from '@mcp-abap-adt/interfaces';
import type { OidcCallbackResult } from '../../auth/oidcBrowserAuth';
import { discoverOidc } from '../../auth/oidcDiscovery';
import {
  exchangeAuthorizationCode,
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
  refreshOidcToken,
  tokenExchange,
} from '../../auth/oidcToken';
import { exchangeSamlAssertion } from '../../auth/saml2TokenExchange';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { getSamlAssertion } from '../../providers/saml2Utils';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import {
  asOidcResult,
  BrowserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies';

jest.mock('../../auth/oidcDiscovery', () => ({
  discoverOidc: jest.fn(),
}));
// `oidcBrowserAuth` is deliberately NOT mocked: the provider's default strategy
// takes its callback transport (`withOidcCallbackServer`) from that module, and
// the lifecycle tests below exercise the real one.
jest.mock('../../auth/oidcToken', () => ({
  exchangeAuthorizationCode: jest.fn(),
  refreshOidcToken: jest.fn(),
  initiateDeviceAuthorization: jest.fn(),
  pollDeviceTokens: jest.fn(),
  passwordGrant: jest.fn(),
  tokenExchange: jest.fn(),
}));
jest.mock('../../auth/saml2TokenExchange', () => ({
  exchangeSamlAssertion: jest.fn(),
}));
jest.mock('../../providers/saml2Utils', () => {
  const actual = jest.requireActual('../../providers/saml2Utils');
  return {
    ...actual,
    getSamlAssertion: jest.fn(),
  };
});

const mockDiscoverOidc = discoverOidc as jest.Mock;
const mockExchangeCode = exchangeAuthorizationCode as jest.Mock;
const mockRefresh = refreshOidcToken as jest.Mock;
const mockInitiateDevice = initiateDeviceAuthorization as jest.Mock;
const mockPollDevice = pollDeviceTokens as jest.Mock;
const mockPasswordGrant = passwordGrant as jest.Mock;
const mockTokenExchange = tokenExchange as jest.Mock;
const mockGetSamlAssertion = getSamlAssertion as jest.Mock;
const mockExchangeSaml = exchangeSamlAssertion as jest.Mock;

describe('SSO Providers', () => {
  const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    consoleLogSpy.mockRestore();
  });

  it('OidcBrowserProvider should exchange code and return tokens', async () => {
    mockDiscoverOidc.mockResolvedValue({
      authorization_endpoint: 'https://issuer/authorize',
      token_endpoint: 'https://issuer/token',
    });
    mockExchangeCode.mockResolvedValue({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    });

    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      clientSecret: 'secret',
      authorization: asOidcResult(
        externalCodeStrategy({ provide: async () => 'auth-code' }),
      ),
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.access.token');
    expect(tokens.refreshToken).toBe('refresh');
    expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE_PKCE);
    expect(tokens.tokenType).toBe('jwt');
  });

  it('OidcBrowserProvider should use explicit endpoints', async () => {
    mockExchangeCode.mockResolvedValue({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    });

    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      authorizationEndpoint: 'https://issuer/authorize',
      tokenEndpoint: 'https://issuer/token',
      authorization: asOidcResult(
        externalCodeStrategy({ provide: async () => 'auth-code' }),
      ),
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.access.token');
    expect(mockDiscoverOidc).not.toHaveBeenCalled();
  });

  it('OidcBrowserProvider performs no discovery when it holds a code and a token endpoint', async () => {
    const discovery = jest.fn();
    mockDiscoverOidc.mockImplementation(async (issuerUrl: string) => {
      discovery(issuerUrl);
      throw new Error('discovery must not be attempted');
    });
    mockExchangeCode.mockResolvedValue({
      accessToken: 'AT',
      expiresIn: 3600,
    });

    const provider = new OidcBrowserProvider({
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
    expect(tokens.authorizationToken).toBe('AT');
    expect(discovery).not.toHaveBeenCalled();
  });

  it('OidcBrowserProvider discovers once when it needs both endpoints', async () => {
    const discovery = jest.fn();
    mockDiscoverOidc.mockImplementation(async (issuerUrl: string) => {
      discovery(issuerUrl);
      return {
        authorization_endpoint: 'https://idp.example/authorize',
        token_endpoint: 'https://idp.example/token',
      };
    });
    mockExchangeCode.mockResolvedValue({
      accessToken: 'AT2',
      expiresIn: 3600,
    });

    const provider = new OidcBrowserProvider({
      clientId: 'cid',
      issuerUrl: 'https://idp.example',
      authorization: asOidcResult(
        externalCodeStrategy({
          redirectUri: 'http://localhost:61001/callback',
          provide: async (url) => {
            expect(url).toContain('code_challenge=');
            return 'external-code';
          },
        }),
      ),
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('AT2');
    expect(discovery).toHaveBeenCalledTimes(1);
    // The verifier the provider kept must reach the exchange beside the code the
    // strategy returned, at the redirect the strategy actually used.
    expect(mockExchangeCode).toHaveBeenCalledWith(
      'https://idp.example/token',
      'cid',
      undefined,
      'external-code',
      'http://localhost:61001/callback',
      expect.any(String),
      undefined,
    );
  });

  it('OidcDeviceFlowProvider should poll device tokens', async () => {
    mockDiscoverOidc.mockResolvedValue({
      device_authorization_endpoint: 'https://issuer/device',
      token_endpoint: 'https://issuer/token',
    });
    mockInitiateDevice.mockResolvedValue({
      deviceCode: 'dev-code',
      userCode: 'user-code',
      verificationUri: 'https://issuer/verify',
      interval: 1,
    });
    mockPollDevice.mockResolvedValue({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    });

    const provider = new OidcDeviceFlowProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.device.token');
    expect(tokens.tokenType).toBe('jwt');
  });

  it('OidcDeviceFlowProvider should use explicit endpoints', async () => {
    mockInitiateDevice.mockResolvedValue({
      deviceCode: 'dev-code',
      userCode: 'user-code',
      verificationUri: 'https://issuer/verify',
      interval: 1,
    });
    mockPollDevice.mockResolvedValue({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    });

    const provider = new OidcDeviceFlowProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      deviceAuthorizationEndpoint: 'https://issuer/device',
      tokenEndpoint: 'https://issuer/token',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.device.token');
    expect(mockDiscoverOidc).not.toHaveBeenCalled();
  });

  it('OidcPasswordProvider should use password grant', async () => {
    mockDiscoverOidc.mockResolvedValue({
      token_endpoint: 'https://issuer/token',
    });
    mockPasswordGrant.mockResolvedValue({
      accessToken: 'jwt.password.token',
      refreshToken: 'refresh',
      expiresIn: 600,
    });

    const provider = new OidcPasswordProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      username: 'user',
      password: 'pass',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.password.token');
    expect(tokens.authType).toBe(AUTH_TYPE_PASSWORD);
  });

  it('OidcPasswordProvider should use explicit token endpoint', async () => {
    mockPasswordGrant.mockResolvedValue({
      accessToken: 'jwt.password.token',
      refreshToken: 'refresh',
      expiresIn: 600,
    });

    const provider = new OidcPasswordProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      username: 'user',
      password: 'pass',
      tokenEndpoint: 'https://issuer/token',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.password.token');
    expect(mockDiscoverOidc).not.toHaveBeenCalled();
  });

  it('OidcTokenExchangeProvider should exchange subject token', async () => {
    mockDiscoverOidc.mockResolvedValue({
      token_endpoint: 'https://issuer/token',
    });
    mockTokenExchange.mockResolvedValue({
      accessToken: 'jwt.exchange.token',
      expiresIn: 300,
    });

    const provider = new OidcTokenExchangeProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.exchange.token');
    expect(tokens.authType).toBe(AUTH_TYPE_USER_TOKEN);
  });

  it('OidcTokenExchangeProvider should use explicit token endpoint', async () => {
    mockTokenExchange.mockResolvedValue({
      accessToken: 'jwt.exchange.token',
      expiresIn: 300,
    });

    const provider = new OidcTokenExchangeProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      subjectToken: 'subject',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      tokenEndpoint: 'https://issuer/token',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.exchange.token');
    expect(mockDiscoverOidc).not.toHaveBeenCalled();
  });

  it('OidcBrowserProvider should throw when endpoints are missing', async () => {
    mockDiscoverOidc.mockResolvedValue({});

    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
    });

    await expect(provider.getTokens()).rejects.toThrow(
      'OIDC authorization endpoint is required',
    );
  });

  it('Saml2BearerProvider should exchange assertion for token', async () => {
    mockGetSamlAssertion.mockResolvedValue('saml-response');
    mockExchangeSaml.mockResolvedValue({
      accessToken: 'jwt.saml.token',
      refreshToken: 'refresh',
      expiresIn: 900,
    });

    const provider = new Saml2BearerProvider({
      assertionFlow: 'assertion',
      assertionProvider: async () => 'saml-response',
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      uaaUrl: 'https://uaa',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.saml.token');
    expect(tokens.authType).toBe(AUTH_TYPE_SAML2_BEARER);
  });

  it('Saml2PureProvider should return saml response with expiresAt', async () => {
    const samlXml =
      '<Assertion NotOnOrAfter="2030-01-01T00:00:00Z"></Assertion>';
    const samlResponse = Buffer.from(samlXml, 'utf8').toString('base64');
    mockGetSamlAssertion.mockResolvedValue(samlResponse);

    const provider = new Saml2PureProvider({
      assertionFlow: 'assertion',
      assertionProvider: async () => samlResponse,
      cookieProvider: async () => 'SAP_SESSION=abc123',
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('SAP_SESSION=abc123');
    expect(tokens.tokenType).toBe('saml');
    expect(tokens.expiresAt).toBeDefined();
  });

  it('SsoProviderFactory should create configured providers', () => {
    const provider = SsoProviderFactory.create({
      protocol: 'oidc',
      flow: 'browser',
      config: {
        issuerUrl: 'https://issuer',
        clientId: 'client',
      },
    });

    expect(provider).toBeInstanceOf(OidcBrowserProvider);
  });
});

/**
 * Whoever constructs, disposes.
 *
 * A consumer-supplied strategy may be a long-lived receiver that outlives many
 * logins, so the provider must never destroy it; a default the provider built
 * itself holds a callback port, so it must always be released. Both halves are
 * one `if (!supplied)` away from being silently reversed, which is why they are
 * asserted rather than reasoned about.
 */
describe('OidcBrowserProvider strategy lifecycle', () => {
  function portIsFree(port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const s = netModule.createServer();
      s.once('error', () => resolve(false));
      s.listen(port, () => s.close(() => resolve(true)));
    });
  }

  const reasonFor = (p: Promise<unknown>): Promise<Error | null> =>
    p.then(
      () => null,
      (error: Error) => error,
    );

  /**
   * The failure a default login produces here — discovery answers with no
   * endpoints, so the URL builder throws inside the callback scope, in
   * milliseconds rather than after the 30 s timeout — or, if this machine
   * happens to hold 61001, the one the port probe produces first. Either ends
   * the login through the same `finally`, which is what these tests are about.
   */
  const DEFAULT_LOGIN_FAILURE =
    /authorization endpoint is required|already in use/i;

  beforeEach(() => {
    jest.clearAllMocks();
    mockDiscoverOidc.mockResolvedValue({});
    mockExchangeCode.mockResolvedValue({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    });
  });

  it('never disposes a strategy the consumer supplied', async () => {
    // Nothing here should construct a default at all; the class-level spy says
    // so without needing to mock the module the provider imports.
    const defaultDispose = jest.spyOn(
      BrowserCallbackStrategy.prototype,
      'dispose',
    );
    const dispose = jest.fn(async () => undefined);
    const redirectUri = 'http://localhost:61001/callback';
    const supplied: IAuthorizationStrategy<OidcCallbackResult> = {
      authorize: async (request) => {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload: { code: 'held-code' }, redirectUri };
      },
      dispose,
    };

    try {
      const provider = new OidcBrowserProvider({
        clientId: 'client',
        authorizationEndpoint: 'https://issuer/authorize',
        tokenEndpoint: 'https://issuer/token',
        authorization: supplied,
      });

      const tokens = await provider.getTokens();
      expect(tokens.authorizationToken).toBe('jwt.access.token');
      // A receiver the consumer owns must survive the login it served.
      expect(dispose).not.toHaveBeenCalled();
      expect(defaultDispose).not.toHaveBeenCalled();
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);

  it('leaves a supplied strategy alone when the login fails too', async () => {
    const dispose = jest.fn(async () => undefined);
    const supplied: IAuthorizationStrategy<OidcCallbackResult> = {
      authorize: async () => {
        throw new Error('consumer flow cancelled');
      },
      dispose,
    };
    const provider = new OidcBrowserProvider({
      clientId: 'client',
      authorizationEndpoint: 'https://issuer/authorize',
      tokenEndpoint: 'https://issuer/token',
      authorization: supplied,
    });

    await expect(provider.getTokens()).rejects.toThrow(
      /consumer flow cancelled/,
    );
    expect(dispose).not.toHaveBeenCalled();
  }, 30000);

  it('disposes the default it constructed, per login, leaving the port free', async () => {
    const defaultDispose = jest.spyOn(
      BrowserCallbackStrategy.prototype,
      'dispose',
    );
    // No `authorization`: the provider builds an OIDC browser callback on
    // DEFAULT_CALLBACK_PORT.
    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
    });

    try {
      const first = await reasonFor(provider.getTokens());
      expect(first?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      // The claim that matters is about the socket, not the mock: a settled
      // promise must mean the callback port is genuinely released.
      expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);

      // `dispose` disables an instance permanently, so a provider holding one
      // default would fail the second login with "has been disposed".
      const second = await reasonFor(provider.getTokens());
      expect(second?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(second?.message).not.toMatch(/disposed/i);
      expect(defaultDispose).toHaveBeenCalledTimes(2);
      expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);

  it('reports the login failure, not the cleanup failure, when dispose throws', async () => {
    const warn = jest.fn();
    const logger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn,
      error: jest.fn(),
    } as unknown as ILogger;
    const defaultDispose = jest
      .spyOn(BrowserCallbackStrategy.prototype, 'dispose')
      .mockImplementation(async () => {
        throw new Error('dispose exploded');
      });
    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      logger,
    });

    try {
      const error = await reasonFor(provider.getTokens());
      // The reason the login failed survives; the cleanup failure is logged.
      expect(error?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(error?.message).not.toContain('dispose exploded');
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(warn.mock.calls)).toContain('dispose exploded');
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);
});
