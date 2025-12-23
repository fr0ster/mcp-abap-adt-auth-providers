import { jest } from '@jest/globals';
import { AUTH_TYPE_AUTHORIZATION_CODE } from '@mcp-abap-adt/interfaces';
import * as deviceFlowAuth from '../../auth/deviceFlowAuth';
import * as tokenRefresher from '../../auth/tokenRefresher';
import { DeviceFlowProvider } from '../../providers/DeviceFlowProvider';

const createJwtWithExp = (expSeconds: number): string => {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString(
    'base64url',
  );
  const payload = Buffer.from(JSON.stringify({ exp: expSeconds })).toString(
    'base64url',
  );
  return `${header}.${payload}.signature`;
};

describe('DeviceFlowProvider', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('initiates device flow and polls for tokens', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const initiateSpy = jest
      .spyOn(deviceFlowAuth, 'initiateDeviceFlow')
      .mockResolvedValue({
        deviceCode: 'device-code',
        userCode: 'user-code',
        verificationUri: 'https://verify.example.com',
        verificationUriComplete: 'https://verify.example.com?user_code=abc',
        expiresIn: 600,
        interval: 1,
      });
    const pollSpy = jest
      .spyOn(deviceFlowAuth, 'pollForDeviceTokens')
      .mockResolvedValue({
        accessToken: createJwtWithExp(Math.floor(Date.now() / 1000) + 3600),
        refreshToken: 'refresh-token',
        expiresIn: 3600,
      });

    const provider = new DeviceFlowProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
    });

    const result = await provider.getTokens();

    expect(initiateSpy).toHaveBeenCalledWith(
      'https://uaa.example.com',
      'client-id',
      undefined,
      undefined,
    );
    expect(pollSpy).toHaveBeenCalled();
    expect(result.refreshToken).toBe('refresh-token');
    expect(result.authType).toBe(AUTH_TYPE_AUTHORIZATION_CODE);
    logSpy.mockRestore();
  });

  it('refreshes using refresh token when available', async () => {
    const expiredToken = createJwtWithExp(Math.floor(Date.now() / 1000) - 3600);
    const refreshedToken = createJwtWithExp(
      Math.floor(Date.now() / 1000) + 3600,
    );

    const refreshSpy = jest
      .spyOn(tokenRefresher, 'refreshJwtToken')
      .mockResolvedValue({
        accessToken: refreshedToken,
      });

    const provider = new DeviceFlowProvider({
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
  });
});
