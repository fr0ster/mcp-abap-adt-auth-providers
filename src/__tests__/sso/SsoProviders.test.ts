import netModule from 'node:net';
import { inflateRawSync } from 'node:zlib';
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
import type { OidcCallbackResult } from '../../auth/oidcBrowserAuth';
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
import { AssertionValidationError } from '../../errors/AssertionValidationError';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { SsoProviderFactory } from '../../sso/SsoProviderFactory';
import {
  asOidcResult,
  BrowserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  externalCodeStrategy,
  staticCodeStrategy,
} from '../../strategies';
import { canOwnPort } from '../helpers/netHelpers';

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
  refreshSamlBearerToken: jest.fn(),
}));
// `saml2Utils` is deliberately NOT mocked: `getSamlAssertion` is the code that
// drives the strategy, so stubbing it would stub away everything under test.

const mockDiscoverOidc = discoverOidc as jest.Mock;
const mockExchangeCode = exchangeAuthorizationCode as jest.Mock;
const mockRefresh = refreshOidcToken as jest.Mock;
const mockInitiateDevice = initiateDeviceAuthorization as jest.Mock;
const mockPollDevice = pollDeviceTokens as jest.Mock;
const mockPasswordGrant = passwordGrant as jest.Mock;
const mockTokenExchange = tokenExchange as jest.Mock;
const mockExchangeSaml = exchangeSamlAssertion as jest.Mock;
const mockRefreshSaml = refreshSamlBearerToken as jest.Mock;

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
  return match[1];
}

/** Whatever `factory` throws, so its `message` and `missingFields` can be asserted on. */
function constructionError(factory: () => unknown): {
  message: string;
  missingFields?: string[];
} {
  try {
    factory();
  } catch (error) {
    return error as { message: string; missingFields?: string[] };
  }
  throw new Error('expected construction to throw, but it did not');
}

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
    // The code the strategy returned reaches the exchange at the redirect the
    // strategy actually used, against the endpoint discovery supplied. The
    // verifier is only shape-checked here; the test below pins what it must be.
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

  it('OidcBrowserProvider exchanges the verifier the challenge in the URL was derived from', async () => {
    mockExchangeCode.mockResolvedValue({
      accessToken: 'AT3',
      expiresIn: 3600,
    });

    let authorizationUrl = '';
    const provider = new OidcBrowserProvider({
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

    const verifier = mockExchangeCode.mock.calls[0][5] as string;
    expect(verifier).toBeTruthy();
    // The pairing, not merely the presence, is the property. An implementation
    // that regenerated the verifier before the exchange would satisfy
    // `expect.any(String)` just as well — and that is precisely the defect the
    // old `authorizationCodeProvider` had, since it never saw the URL and so
    // could return a code minted against a challenge nobody could redeem.
    const params = new URL(authorizationUrl).searchParams;
    expect(params.get('code_challenge')).toBe(generatePkceChallenge(verifier));
    expect(params.get('code_challenge_method')).toBe('S256');
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

  /**
   * The device code and verification URI are prompts, not log lines — a user
   * who cannot see them cannot complete the flow. They must reach the logger
   * when one is supplied and stderr otherwise, and never stdout, which
   * carries protocol traffic under an MCP or LSP stdio transport.
   */
  it('OidcDeviceFlowProvider prompts on stderr and writes nothing to stdout', async () => {
    mockInitiateDevice.mockResolvedValue({
      deviceCode: 'dev-code',
      userCode: 'USER-CODE-FIXTURE',
      verificationUri: 'https://verify.example',
      interval: 0,
    });
    mockPollDevice.mockResolvedValue({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    });

    const out: string[] = [];
    const err: string[] = [];
    const outSpy = jest
      .spyOn(process.stdout, 'write')
      .mockImplementation((chunk: unknown) => {
        out.push(String(chunk));
        return true;
      });
    const errSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        err.push(String(chunk));
        return true;
      });
    try {
      const provider = new OidcDeviceFlowProvider({
        issuerUrl: 'https://issuer',
        clientId: 'client',
        deviceAuthorizationEndpoint: 'https://issuer/device',
        tokenEndpoint: 'https://issuer/token',
      });
      await provider.getTokens();
    } finally {
      outSpy.mockRestore();
      errSpy.mockRestore();
    }
    expect(out).toEqual([]);
    expect(err.join('')).toContain('USER-CODE-FIXTURE');
    expect(err.join('')).toContain('https://verify.example');
  });

  it('OidcDeviceFlowProvider sends the prompt to the logger, and nothing to stderr, when one is supplied', async () => {
    mockInitiateDevice.mockResolvedValue({
      deviceCode: 'dev-code',
      userCode: 'USER-CODE-FIXTURE',
      verificationUri: 'https://verify.example',
      interval: 0,
    });
    mockPollDevice.mockResolvedValue({
      accessToken: 'jwt.device.token',
      refreshToken: 'refresh',
      expiresIn: 1200,
    });

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
    const errSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        err.push(String(chunk));
        return true;
      });
    try {
      const provider = new OidcDeviceFlowProvider({
        issuerUrl: 'https://issuer',
        clientId: 'client',
        deviceAuthorizationEndpoint: 'https://issuer/device',
        tokenEndpoint: 'https://issuer/token',
        logger,
      });
      await provider.getTokens();
    } finally {
      errSpy.mockRestore();
    }
    expect(err).toEqual([]);
    const text = infos.join('\n');
    expect(text).toContain('USER-CODE-FIXTURE');
    expect(text).toContain('https://verify.example');
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

    // A strategy that needs the URL but binds no socket: the assertion here is
    // about the message, and the default strategy would have made it depend on
    // 61001 being free — a machine already holding it fails this for a reason
    // that has nothing to do with endpoints. The default's own port behaviour is
    // covered in the lifecycle block below, which tolerates that failure.
    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      authorization: asOidcResult(
        externalCodeStrategy({ provide: async () => 'unreachable' }),
      ),
    });

    await expect(provider.getTokens()).rejects.toThrow(
      'OIDC authorization endpoint is required',
    );
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
    mockExchangeSaml.mockResolvedValue({
      accessToken: 'jwt.saml.token',
      refreshToken: 'refresh',
      expiresIn: 900,
    });

    const saml = samlResponseCarrying('_a1');
    const provider = new Saml2BearerProvider({
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
    expect(tokens.authorizationToken).toBe('jwt.saml.token');
    expect(tokens.authType).toBe(AUTH_TYPE_SAML2_BEARER);
    // RFC 7522: the Assertion alone, base64url — not the Response it arrived in.
    expect(mockExchangeSaml).toHaveBeenCalledWith(
      saml.bearer,
      'https://uaa/oauth/token',
      undefined,
      undefined,
      undefined,
    );
  });

  describe('Saml2BearerProvider refresh', () => {
    const seededConfig = () => {
      const authorize = jest.fn(async () => ({
        payload: samlResponseCarrying('_fresh').payload,
        redirectUri: 'http://localhost:61001/callback',
      }));
      const authorization: IAuthorizationStrategy<string> = { authorize };
      return {
        authorize,
        config: {
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
          // The validator is resolved at construction (Task 11); these cases
          // are about the refresh path, not validation, and the fixture
          // payload above is not signed.
          assertionValidator: acceptingSamlValidator(),
        },
      };
    };

    it('spends the refresh token instead of running the authorization strategy', async () => {
      const newAccess = jwtExpiringIn(3600);
      mockRefreshSaml.mockResolvedValue({
        accessToken: newAccess,
        refreshToken: 'rotated-refresh',
        expiresIn: 3600,
      });
      const { authorize, config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      expect(authorize).not.toHaveBeenCalled();
      expect(mockExchangeSaml).not.toHaveBeenCalled();
      expect(mockRefreshSaml).toHaveBeenCalledWith(
        'seeded-refresh',
        'https://uaa/oauth/token',
        'client',
        'secret',
        undefined,
      );
      expect(tokens.authorizationToken).toBe(newAccess);
      expect(tokens.refreshToken).toBe('rotated-refresh');
      expect(tokens.authType).toBe(AUTH_TYPE_SAML2_BEARER);
    });

    it('keeps the refresh token it spent when the grant returns none', async () => {
      mockRefreshSaml.mockResolvedValue({ accessToken: jwtExpiringIn(3600) });
      const { config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      expect(tokens.refreshToken).toBe('seeded-refresh');
    });

    it('refreshes against an explicit tokenUrl, not one derived from uaaUrl', async () => {
      mockRefreshSaml.mockResolvedValue({ accessToken: jwtExpiringIn(3600) });
      const { config } = seededConfig();

      await new Saml2BearerProvider({
        ...config,
        tokenUrl: 'https://tokens.example/custom/token',
      }).getTokens();

      expect(mockRefreshSaml.mock.calls[0][1]).toBe(
        'https://tokens.example/custom/token',
      );
    });

    it('falls back to a full login when the refresh grant is refused', async () => {
      mockRefreshSaml.mockRejectedValue(new Error('invalid_grant'));
      mockExchangeSaml.mockResolvedValue({
        accessToken: 'jwt.after.login',
        refreshToken: 'login-refresh',
        expiresIn: 900,
      });
      const { authorize, config } = seededConfig();

      const tokens = await new Saml2BearerProvider(config).getTokens();

      expect(mockRefreshSaml).toHaveBeenCalledTimes(1);
      expect(authorize).toHaveBeenCalledTimes(1);
      expect(mockExchangeSaml.mock.calls[0][0]).toBe(
        samlResponseCarrying('_fresh').bearer,
      );
      expect(tokens.authorizationToken).toBe('jwt.after.login');
      expect(tokens.refreshToken).toBe('login-refresh');
    });

    /**
     * A `refresh_token` grant carries no assertion, so there is nothing to
     * validate. Without this, a later change routing refresh through
     * `performLogin()` again would pass every other test in this describe —
     * they all use a validator that accepts anything.
     */
    it('does not consult the validator on refresh', async () => {
      mockRefreshSaml.mockResolvedValue({ accessToken: jwtExpiringIn(3600) });
      const { config } = seededConfig();
      const validate = jest.fn();

      await new Saml2BearerProvider({
        ...config,
        assertionValidator: { validate },
      }).getTokens();

      expect(validate).not.toHaveBeenCalled();
    });
  });

  it('Saml2PureProvider should return the saml response as the session', async () => {
    const samlXml =
      '<Assertion NotOnOrAfter="2030-01-01T00:00:00Z"></Assertion>';
    const samlResponse = Buffer.from(samlXml, 'utf8').toString('base64');
    const validatedExpiresAt = new Date(Date.now() + 3600_000);

    const provider = new Saml2PureProvider({
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
    expect(tokens.authorizationToken).toBe('SAP_SESSION=abc123');
    expect(tokens.tokenType).toBe('saml');
    // `parseSamlNotOnOrAfter` is gone (Task 9); `expiresAt` now comes from
    // `ValidatedAssertion`, not an unverified regex (Task 11).
    expect(tokens.expiresAt).toBe(validatedExpiresAt.getTime());
  });

  it('Saml2PureProvider rejects a pre-built URL without a declared acsUrl', () => {
    expect(
      () =>
        new Saml2PureProvider({
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          authorizationUrl: 'https://idp.example/sso?SAMLRequest=abc',
          cookieProvider: async (saml) => saml,
        }),
    ).toThrow(/acsUrl is required/i);
  });

  it('Saml2PureProvider takes an assertion from a strategy', async () => {
    const seen: string[] = [];
    const provider = new Saml2PureProvider({
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
    expect(seen).toEqual(['PHNhbWw+']);
    expect(tokens.authorizationToken).toBe('PHNhbWw+');
  });

  it('Saml2PureProvider rejects an assertion delivered to the wrong ACS', async () => {
    const provider = new Saml2PureProvider({
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
    await expect(provider.getTokens()).rejects.toThrow(
      /acsUrl is http:\/\/localhost:61001\/callback, but the authorization strategy used/i,
    );
  });

  it('Saml2BearerProvider rejects a pre-built URL without a declared acsUrl', () => {
    expect(
      () =>
        new Saml2BearerProvider({
          idpSsoUrl: 'https://idp.example/sso',
          spEntityId: 'sp',
          authorizationUrl: 'https://idp.example/sso?SAMLRequest=abc',
          uaaUrl: 'https://uaa',
        }),
    ).toThrow(/acsUrl is required/i);
  });

  it('Saml2PureProvider refuses to open a browser at an ACS the IdP was never told about', async () => {
    const provider = new Saml2PureProvider({
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
    await expect(provider.getTokens()).rejects.toThrow(
      /acsUrl is https:\/\/sp\.example\/acs, but the authorization strategy is listening on http:\/\/localhost:61001\/callback/i,
    );
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

    // Probed before the first login: if an unrelated process holds 61001, this
    // login never binds it and cannot release it, so the socket assertions
    // below would be about that process rather than about this code.
    const ownsPort = await canOwnPort(
      DEFAULT_CALLBACK_PORT,
      'OidcBrowserProvider disposes the default it constructed',
    );

    try {
      const first = await reasonFor(provider.getTokens());
      expect(first?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      // The claim that matters is about the socket, not the mock: a settled
      // promise must mean the callback port is genuinely released.
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);

      // `dispose` disables an instance permanently, so a provider holding one
      // default would fail the second login with "has been disposed".
      const second = await reasonFor(provider.getTokens());
      expect(second?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(second?.message).not.toMatch(/disposed/i);
      expect(defaultDispose).toHaveBeenCalledTimes(2);
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);
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

/**
 * Whoever constructs, disposes — the SAML half.
 *
 * `getSamlAssertion` is shared by both SAML providers, so the rule is written
 * once and would be reversed once; asserting it through `Saml2PureProvider`
 * covers the helper, and the pure provider needs no token endpoint to reach it.
 */
describe('SAML strategy lifecycle', () => {
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
   * The failure a default login produces here — a declared ACS the default
   * callback cannot be listening on, so the URL builder throws inside the
   * callback scope in milliseconds rather than after the 30 s timeout — or, if
   * this machine happens to hold 61001, the one the port probe produces first.
   * Either ends the login through the same `finally`, which is the subject.
   */
  const DEFAULT_LOGIN_FAILURE = /they must match|already in use/i;

  /** Registered with the IdP, and nothing on this machine can bind it. */
  const MISMATCHED_ACS = 'https://sp.example/acs';

  beforeEach(() => {
    jest.clearAllMocks();
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
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async (request) => {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload: 'PHNhbWw+', redirectUri };
      },
      dispose,
    };

    try {
      const provider = new Saml2PureProvider({
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
      expect(tokens.authorizationToken).toBe('PHNhbWw+');
      // A receiver the consumer owns must survive the login it served.
      expect(dispose).not.toHaveBeenCalled();
      expect(defaultDispose).not.toHaveBeenCalled();
    } finally {
      defaultDispose.mockRestore();
    }
  }, 30000);

  it('leaves a supplied strategy alone when the login fails too', async () => {
    const dispose = jest.fn(async () => undefined);
    const supplied: IAuthorizationStrategy<string> = {
      authorize: async () => {
        throw new Error('consumer flow cancelled');
      },
      dispose,
    };
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      authorization: supplied,
      cookieProvider: async (saml) => saml,
      // Never reached: `authorize` throws before validate() would run.
      assertionValidator: acceptingSamlValidator(),
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
    // No `authorization`: the provider builds a SAML browser callback on
    // DEFAULT_CALLBACK_PORT. The declared ACS is elsewhere, so the guard ends
    // the login in milliseconds rather than after the default 30 s.
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: MISMATCHED_ACS,
      cookieProvider: async (saml) => saml,
      // Never reached: the ACS mismatch is thrown before validate() would run.
      assertionValidator: acceptingSamlValidator(),
    });

    // Probed before the first login: if an unrelated process holds 61001, this
    // login never binds it and cannot release it, so the socket assertions
    // below would be about that process rather than about this code.
    const ownsPort = await canOwnPort(
      DEFAULT_CALLBACK_PORT,
      'Saml2PureProvider disposes the default it constructed',
    );

    try {
      const first = await reasonFor(provider.getTokens());
      expect(first?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(defaultDispose).toHaveBeenCalledTimes(1);
      // The claim that matters is about the socket, not the mock: a settled
      // promise must mean the callback port is genuinely released.
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);

      // `dispose` disables an instance permanently, so a provider holding one
      // default would fail the second login with "has been disposed".
      const second = await reasonFor(provider.getTokens());
      expect(second?.message).toMatch(DEFAULT_LOGIN_FAILURE);
      expect(second?.message).not.toMatch(/disposed/i);
      expect(defaultDispose).toHaveBeenCalledTimes(2);
      if (ownsPort) expect(await portIsFree(DEFAULT_CALLBACK_PORT)).toBe(true);
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
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'sp',
      acsUrl: MISMATCHED_ACS,
      cookieProvider: async (saml) => saml,
      logger,
      // Never reached: the ACS mismatch is thrown before validate() would run.
      assertionValidator: acceptingSamlValidator(),
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

/**
 * Task 11: both providers resolve `assertionValidator` at construction and run
 * it on every login. A missing `idpCertificates`/`idpEntityId` is a
 * configuration fault, and must surface before a login is even attempted.
 */
describe('Saml2PureProvider assertion validation', () => {
  const baseConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    acsUrl: 'http://localhost:61001/callback',
    idpInitiated: true,
    // A genuine certificate: this fixture is reused as-is by a test that
    // keeps idpCertificates, so a placeholder string would throw ("neither
    // PEM nor base64 DER") before that test's own assertion ever ran.
    idpCertificates: [generateKeyMaterial().certificatePem],
    idpEntityId: 'urn:mock:idp',
    authorization: staticCodeStrategy({
      redirectUri: 'http://localhost:61001/callback',
      payload: Buffer.from('<Assertion/>', 'utf8').toString('base64'),
    }),
    cookieProvider: async () => 'cookie',
  };

  it('refuses at construction when the identity provider is not configured', () => {
    expect(
      () =>
        new Saml2PureProvider({ ...baseConfig, idpCertificates: undefined }),
    ).toThrow(/idpCertificates/);
  });

  it('takes expiresAt from the validated assertion, not from a regex', async () => {
    // A stub validator, to prove the provider uses what validation returned.
    const expiresAt = new Date(Date.now() + 111_000);
    const provider = new Saml2PureProvider({
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
    expect(result.expiresAt).toBe(expiresAt.getTime());
  });

  /**
   * The pure counterpart of the bearer "does not reach the token endpoint"
   * test: a refused assertion must never reach the cookie provider, which is
   * this provider's equivalent of "the network call". Two mutants this must
   * catch: swallowing the validator's rejection, and calling the cookie
   * provider before validate() runs.
   */
  it('does not hand the assertion to the cookie provider when validation refuses it', async () => {
    const cookieProvider = jest.fn(async (saml: string) => saml);
    const provider = new Saml2PureProvider({
      ...baseConfig,
      assertionValidator: {
        async validate() {
          throw new AssertionValidationError('status', 'the IdP declined');
        },
      },
      cookieProvider,
    });

    const tokensPromise = provider.getTokens();
    const rejected = expect(tokensPromise).rejects.toMatchObject({
      check: 'status',
    });
    await rejected;
    expect(cookieProvider).not.toHaveBeenCalled();
  });

  // performRefresh re-runs the whole login, validation included. The base
  // class never calls it for this provider — it holds no refresh token — so
  // it is called directly; a refresh that skipped validation would hand an
  // unverified assertion to cookieProvider the day that changes.
  it('validates again when refreshing', async () => {
    const payload = Buffer.from('<Assertion/>', 'utf8').toString('base64');
    const validate = jest.fn(async () => ({
      expiresAt: new Date(Date.now() + 3600_000),
      assertionId: '_a1',
      issuer: 'urn:mock:idp',
      raw: payload,
      signedXml: payload,
    }));
    const cookieProvider = jest.fn(async () => 'cookie');
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      idpEntityId: 'urn:mock:idp',
      idpInitiated: true,
      authorization: staticCodeStrategy({ payload }),
      assertionValidator: { validate },
      cookieProvider,
    });

    await (
      provider as unknown as { performRefresh(): Promise<unknown> }
    ).performRefresh();

    expect(validate).toHaveBeenCalledTimes(1);
    expect(validate).toHaveBeenCalledWith(
      payload,
      expect.objectContaining({
        audience: 'sp-entity',
        expectedIssuer: 'urn:mock:idp',
      }),
    );
    expect(cookieProvider).toHaveBeenCalledWith(payload);
  });
});

describe('Saml2BearerProvider assertion validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('does not reach the token endpoint when the assertion is refused', async () => {
    let exchanged = false;
    mockExchangeSaml.mockImplementation(async () => {
      exchanged = true;
      return { accessToken: 'unreachable', expiresIn: 900 };
    });

    const provider = new Saml2BearerProvider({
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp-entity',
      uaaUrl: 'https://uaa',
      idpInitiated: true,
      authorization: staticCodeStrategy({
        payload: Buffer.from('<Assertion/>', 'utf8').toString('base64'),
      }),
      assertionValidator: {
        async validate() {
          throw new AssertionValidationError('status', 'the IdP declined');
        },
      },
    });

    const tokensPromise = provider.getTokens();
    const rejected = expect(tokensPromise).rejects.toMatchObject({
      check: 'status',
    });
    await rejected;
    expect(exchanged).toBe(false);
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

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("Saml2PureProvider's default accepts a Response signed at the Response level", async () => {
    const provider = new Saml2PureProvider({
      idpSsoUrl: 'https://idp/sso',
      spEntityId: AUDIENCE,
      acsUrl: ACS,
      authnRequestId: REQUEST_ID,
      idpCertificates: [KEY.certificatePem],
      idpEntityId: ISSUER,
      authorization: staticCodeStrategy({
        redirectUri: ACS,
        payload: payload(),
      }),
      cookieProvider: async (saml) => saml,
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBeDefined();
    expect(tokens.expiresAt).toBeGreaterThan(Date.now());
  });

  it("Saml2BearerProvider's default refuses the same Response, at signedNode", async () => {
    const provider = new Saml2BearerProvider({
      idpSsoUrl: 'https://idp/sso',
      spEntityId: AUDIENCE,
      acsUrl: ACS,
      authnRequestId: REQUEST_ID,
      uaaUrl: 'https://uaa',
      idpCertificates: [KEY.certificatePem],
      idpEntityId: ISSUER,
      authorization: staticCodeStrategy({
        redirectUri: ACS,
        payload: payload(),
      }),
    });

    await expect(provider.getTokens()).rejects.toMatchObject({
      check: 'signedNode',
      message: expect.stringContaining(
        'does not cover the saml:Assertion this validator requires',
      ),
    });
    expect(mockExchangeSaml).not.toHaveBeenCalled();
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
  it('passes exactly the context the spec requires', async () => {
    const redirectUri = 'http://localhost:61001/callback';
    const payload = Buffer.from('<Assertion/>', 'utf8').toString('base64');
    const logger: ILogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    const validate = jest.fn(async () => ({
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
    expect(validate).toHaveBeenCalledTimes(1);
    expect(validate).toHaveBeenCalledWith(payload, {
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
    jest.clearAllMocks();
  });

  it('passes exactly the context the spec requires', async () => {
    mockExchangeSaml.mockResolvedValue({ accessToken: 'AT', expiresIn: 900 });

    const redirectUri = 'http://localhost:61001/callback';
    // A bare Assertion, so `toBearerAssertion` (called after validate()
    // resolves) accepts it without needing a whole signed Response.
    const payload = Buffer.from(
      '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/>',
      'utf8',
    ).toString('base64');
    const logger: ILogger = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    const validate = jest.fn(async () => ({
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
    expect(validate).toHaveBeenCalledTimes(1);
    expect(validate).toHaveBeenCalledWith(payload, {
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
describe('Saml2 provider construction faults', () => {
  const CERT = generateKeyMaterial().certificatePem;

  const validPureConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    idpCertificates: [CERT],
    idpEntityId: 'urn:mock:idp',
    cookieProvider: async (saml: string) => saml,
  };

  const validBearerConfig = {
    idpSsoUrl: 'https://idp/sso',
    spEntityId: 'sp-entity',
    idpCertificates: [CERT],
    idpEntityId: 'urn:mock:idp',
    uaaUrl: 'https://uaa',
  };

  it('Saml2PureProvider refuses construction when idpEntityId is missing', () => {
    const error = constructionError(
      () =>
        new Saml2PureProvider({ ...validPureConfig, idpEntityId: undefined }),
    );
    expect(error.message).toMatch(/idpEntityId/);
    expect(error.missingFields).toContain('idpEntityId');
  });

  it('Saml2BearerProvider refuses construction when idpEntityId is missing', () => {
    const error = constructionError(
      () =>
        new Saml2BearerProvider({
          ...validBearerConfig,
          idpEntityId: undefined,
        }),
    );
    expect(error.message).toMatch(/idpEntityId/);
    expect(error.missingFields).toContain('idpEntityId');
  });

  it('Saml2BearerProvider refuses construction when idpCertificates is missing', () => {
    const error = constructionError(
      () =>
        new Saml2BearerProvider({
          ...validBearerConfig,
          idpCertificates: undefined,
        }),
    );
    expect(error.message).toMatch(/idpCertificates/);
    expect(error.missingFields).toContain('idpCertificates');
  });

  // The provider's own length check, not the shipped validator's guard:
  // only the provider names the field. Without it the factory's plain Error
  // ("must not be empty") would surface, with no missingFields.
  it('refuses construction when idpCertificates is an empty list', () => {
    const error = constructionError(
      () => new Saml2PureProvider({ ...validPureConfig, idpCertificates: [] }),
    );
    expect(error.message).toMatch(/missing idpCertificates/);
    expect(error.missingFields).toEqual(['idpCertificates']);
  });

  it('refuses construction when a certificate is malformed', () => {
    const error = constructionError(
      () =>
        new Saml2PureProvider({
          ...validPureConfig,
          idpCertificates: ['not-a-cert'],
        }),
    );
    expect(error.message).toMatch(/certificate/i);
  });

  it('refuses construction when clockSkewMs is negative', () => {
    const error = constructionError(
      () => new Saml2PureProvider({ ...validPureConfig, clockSkewMs: -1 }),
    );
    expect(error.message).toMatch(/clockSkewMs/);
  });
});
