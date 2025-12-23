import { jest } from '@jest/globals';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import * as browserAuth from '../../auth/browserAuth';
import * as tokenRefresher from '../../auth/tokenRefresher';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';

const createJwtWithExp = (expSeconds: number): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ exp: expSeconds })).toString(
    'base64url',
  );
  return `${header}.${payload}.signature`;
};

describe('AuthorizationCodeProvider', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('logs in via browser auth and returns tokens', async () => {
    const accessToken = createJwtWithExp(Math.floor(Date.now() / 1000) + 3600);
    const startAuthSpy = jest
      .spyOn(browserAuth, 'startBrowserAuth')
      .mockResolvedValue({
        accessToken,
        refreshToken: 'refresh-token',
      });

    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      authorizationUrl: 'https://auth.example.com',
      browser: 'none',
      redirectPort: 4001,
    });

    const result = await provider.getTokens();

    expect(result.authorizationToken).toBe(accessToken);
    expect(result.refreshToken).toBe('refresh-token');
    expect(result.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
    expect(startAuthSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        uaaUrl: 'https://uaa.example.com',
        uaaClientId: 'client-id',
        uaaClientSecret: 'client-secret',
        authorizationUrl: 'https://auth.example.com',
      }),
      'none',
      undefined,
      4001,
    );
  });

  it('refreshes using refresh token when cached token is expired', async () => {
    const expiredToken = createJwtWithExp(Math.floor(Date.now() / 1000) - 3600);
    const refreshedToken = createJwtWithExp(
      Math.floor(Date.now() / 1000) + 3600,
    );

    const refreshSpy = jest
      .spyOn(tokenRefresher, 'refreshJwtToken')
      .mockResolvedValue({
        accessToken: refreshedToken,
      });

    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      accessToken: expiredToken,
      refreshToken: 'refresh-token',
    });

    const result = await provider.getTokens();

    expect(refreshSpy).toHaveBeenCalledWith(
      'refresh-token',
      'https://uaa.example.com',
      'client-id',
      'client-secret',
    );
    expect(result.authorizationToken).toBe(refreshedToken);
    expect(result.refreshToken).toBe('refresh-token');
  });

  it('falls back to login when refresh fails', async () => {
    const expiredToken = createJwtWithExp(Math.floor(Date.now() / 1000) - 3600);
    const accessToken = createJwtWithExp(Math.floor(Date.now() / 1000) + 3600);

    const refreshSpy = jest
      .spyOn(tokenRefresher, 'refreshJwtToken')
      .mockRejectedValue(new Error('refresh failed'));
    const startAuthSpy = jest
      .spyOn(browserAuth, 'startBrowserAuth')
      .mockResolvedValue({ accessToken });

    const provider = new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      accessToken: expiredToken,
      refreshToken: 'refresh-token',
    });

    const result = await provider.getTokens();

    expect(refreshSpy).toHaveBeenCalled();
    expect(startAuthSpy).toHaveBeenCalled();
    expect(result.authorizationToken).toBe(accessToken);
  });
});
