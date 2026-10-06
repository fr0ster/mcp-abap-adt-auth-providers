/**
 * Tests for the SAML bearer token exchange and its refresh grant
 */

import { jest } from '@jest/globals';
import axios from 'axios';
import { refreshSamlBearerToken } from '../../auth/saml2TokenExchange';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});

const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('refreshSamlBearerToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('posts a refresh_token grant to the token URL with client credentials', async () => {
    mockedAxios.post.mockResolvedValue({
      data: {
        access_token: 'new-access',
        refresh_token: 'new-refresh',
        expires_in: 3600,
        token_type: 'bearer',
      },
    });

    const result = await refreshSamlBearerToken(
      'old-refresh',
      'https://uaa/oauth/token',
      'client',
      'secret',
    );

    expect(result).toEqual({
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresIn: 3600,
      tokenType: 'bearer',
    });
    const [url, body, options] = mockedAxios.post.mock.calls[0] as [
      string,
      string,
      { headers: Record<string, string> },
    ];
    expect(url).toBe('https://uaa/oauth/token');
    const params = new URLSearchParams(body);
    expect(params.get('grant_type')).toBe('refresh_token');
    expect(params.get('refresh_token')).toBe('old-refresh');
    expect(params.get('client_id')).toBe('client');
    expect(options.headers.Authorization).toBe(
      `Basic ${Buffer.from('client:secret').toString('base64')}`,
    );
  });

  it('sends no Authorization header without a client secret', async () => {
    mockedAxios.post.mockResolvedValue({ data: { access_token: 'a' } });

    await refreshSamlBearerToken('r', 'https://uaa/oauth/token', 'client');

    const options = mockedAxios.post.mock.calls[0]![2] as {
      headers: Record<string, string>;
    };
    expect(options.headers.Authorization).toBeUndefined();
  });

  it('refuses a response without an access token', async () => {
    mockedAxios.post.mockResolvedValue({ data: { refresh_token: 'r2' } });

    await expect(
      refreshSamlBearerToken('r', 'https://uaa/oauth/token', 'c', 's'),
    ).rejects.toThrow(
      // D4
      'the SAML token refresh returned no access_token',
    );
  });
});
