import { AUTH_TYPE_PASSWORD } from '@mcp-abap-adt/interfaces';
import { passwordGrant, refreshOidcToken } from '../../auth/oidcToken';
import { CfPasscodeProvider } from '../../providers/CfPasscodeProvider';

jest.mock('../../auth/oidcToken', () => ({
  passwordGrant: jest.fn(),
  refreshOidcToken: jest.fn(),
}));

const mockPasswordGrant = passwordGrant as jest.Mock;
const mockRefresh = refreshOidcToken as jest.Mock;

describe('CfPasscodeProvider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should exchange passcode for tokens', async () => {
    mockPasswordGrant.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresIn: 3600,
    });

    const provider = new CfPasscodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'cf',
      passcode: 'passcode-123',
    });

    const tokens = await provider.getTokens();

    expect(tokens.authorizationToken).toBe('access-token');
    expect(tokens.refreshToken).toBe('refresh-token');
    expect(tokens.authType).toBe(AUTH_TYPE_PASSWORD);
    expect(mockPasswordGrant).toHaveBeenCalledWith(
      'https://uaa.example.com/oauth/token',
      'cf',
      undefined,
      'passcode',
      'passcode-123',
      undefined,
      undefined,
    );
  });

  it('should use passcode provider when passcode is not provided', async () => {
    mockPasswordGrant.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      expiresIn: 3600,
    });

    const provider = new CfPasscodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'cf',
      passcodeProvider: async () => 'from-provider',
    });

    const tokens = await provider.getTokens();

    expect(tokens.authorizationToken).toBe('access-token');
    expect(mockPasswordGrant).toHaveBeenCalledWith(
      'https://uaa.example.com/oauth/token',
      'cf',
      undefined,
      'passcode',
      'from-provider',
      undefined,
      undefined,
    );
  });

  it('should refresh when refresh token is available', async () => {
    mockRefresh.mockResolvedValue({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresIn: 1800,
    });

    const provider = new CfPasscodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'cf',
      accessToken: 'invalid',
      refreshToken: 'refresh-token',
      passcode: 'passcode-123',
    });

    const tokens = await provider.getTokens();

    expect(tokens.authorizationToken).toBe('new-access');
    expect(tokens.refreshToken).toBe('new-refresh');
    expect(mockRefresh).toHaveBeenCalledWith(
      'https://uaa.example.com/oauth/token',
      'cf',
      undefined,
      'refresh-token',
      undefined,
    );
  });
});
