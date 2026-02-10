import {
  AUTH_TYPE_AUTHORIZATION_CODE_PKCE,
  AUTH_TYPE_PASSWORD,
  AUTH_TYPE_SAML2_BEARER,
  AUTH_TYPE_USER_TOKEN,
} from '@mcp-abap-adt/interfaces';
import { startOidcBrowserAuth } from '../../auth/oidcBrowserAuth';
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

jest.mock('../../auth/oidcDiscovery', () => ({
  discoverOidc: jest.fn(),
}));
jest.mock('../../auth/oidcBrowserAuth', () => ({
  startOidcBrowserAuth: jest.fn(),
}));
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
const mockStartBrowser = startOidcBrowserAuth as jest.Mock;
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
    mockStartBrowser.mockResolvedValue({ code: 'auth-code' });
    mockExchangeCode.mockResolvedValue({
      accessToken: 'jwt.access.token',
      refreshToken: 'refresh',
      expiresIn: 3600,
    });

    const provider = new OidcBrowserProvider({
      issuerUrl: 'https://issuer',
      clientId: 'client',
      clientSecret: 'secret',
    });

    const tokens = await provider.getTokens();
    expect(tokens.authorizationToken).toBe('jwt.access.token');
    expect(tokens.refreshToken).toBe('refresh');
    expect(tokens.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE_PKCE);
    expect(tokens.tokenType).toBe('jwt');
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
