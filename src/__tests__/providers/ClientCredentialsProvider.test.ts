import { jest } from '@jest/globals';
import { AUTH_TYPE_CLIENT_CREDENTIALS } from '@mcp-abap-adt/interfaces';
import * as clientCredentialsAuth from '../../auth/clientCredentialsAuth';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';

describe('ClientCredentialsProvider', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('fetches a token using client credentials and caches it', async () => {
    const getTokenSpy = jest
      .spyOn(clientCredentialsAuth, 'getTokenWithClientCredentials')
      .mockResolvedValue({
        accessToken: 'access-token',
        expiresIn: 3600,
      });

    const provider = new ClientCredentialsProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
      clientSecret: 'client-secret',
    });

    const first = await provider.getTokens();
    const second = await provider.getTokens();

    expect(first.authorizationToken).toBe('access-token');
    expect(first.refreshToken).toBeUndefined();
    expect(first.authType).toBe(AUTH_TYPE_CLIENT_CREDENTIALS);
    expect(second.authorizationToken).toBe('access-token');
    expect(getTokenSpy).toHaveBeenCalledTimes(1);
  });

  it('uses client credentials for refresh', async () => {
    const getTokenSpy = jest
      .spyOn(clientCredentialsAuth, 'getTokenWithClientCredentials')
      .mockResolvedValue({
        accessToken: 'refreshed-token',
      });

    const provider = new ClientCredentialsProvider({
      uaaUrl: 'https://uaa.example.com',
      clientId: 'client-id',
      clientSecret: 'client-secret',
    });

    const result = await (provider as any).performRefresh();

    expect(result.authorizationToken).toBe('refreshed-token');
    expect(getTokenSpy).toHaveBeenCalledWith(
      'https://uaa.example.com',
      'client-id',
      'client-secret',
    );
  });
});
