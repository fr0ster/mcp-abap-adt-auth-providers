/**
 * The passcode exchange: UAA routes it to its passcode filter chain only when
 * the request asks for JSON, so that header is part of the contract.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import axios from 'axios';
import { exchangePasscode } from '../../auth/passcodeAuth';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const call = () =>
  mockedAxios.post.mock.calls[0] as [
    string,
    string,
    { headers: Record<string, string> },
  ];

describe('exchangePasscode', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedAxios.post.mockResolvedValue({
      data: { access_token: 'a', refresh_token: 'r', expires_in: 60 },
    });
  });

  it('sends the password grant with the passcode and asks for JSON', async () => {
    const tokens = await exchangePasscode(
      'https://uaa',
      'client',
      'secret',
      'CODE',
    );

    const [url, body, options] = call();
    expect(url).toBe('https://uaa/oauth/token');
    const params = new URLSearchParams(body);
    expect(params.get('grant_type')).toBe('password');
    expect(params.get('passcode')).toBe('CODE');
    expect(params.has('username')).toBe(false);
    expect(options.headers.Accept).toBe('application/json');
    expect(options.headers.Authorization).toBe(
      `Basic ${Buffer.from('client:secret').toString('base64')}`,
    );
    expect(tokens).toEqual({
      accessToken: 'a',
      refreshToken: 'r',
      expiresIn: 60,
    });
  });

  it('authenticates a public client with an empty secret, as cf does', async () => {
    await exchangePasscode('https://uaa/', 'cf', undefined, 'CODE');

    const [url, , options] = call();
    expect(url).toBe('https://uaa/oauth/token');
    expect(options.headers.Authorization).toBe(
      `Basic ${Buffer.from('cf:').toString('base64')}`,
    );
  });

  it('reports the reason UAA gives, such as a spent passcode', async () => {
    const refused = Object.assign(
      new Error('Request failed with status code 401'),
      {
        isAxiosError: true,
        response: {
          status: 401,
          data: {
            error: 'unauthorized',
            error_description: 'Invalid passcode',
          },
        },
      },
    );
    mockedAxios.post.mockRejectedValue(refused);
    mockedAxios.isAxiosError.mockReturnValue(true);

    await expect(
      exchangePasscode('https://uaa', 'c', 's', 'SPENT'),
    ).rejects.toThrow('Passcode exchange failed (401): Invalid passcode');
  });

  it('refuses a response without an access token', async () => {
    mockedAxios.post.mockResolvedValue({ data: {} });
    await expect(
      exchangePasscode('https://uaa', 'c', 's', 'CODE'),
    ).rejects.toThrow('Passcode exchange returned no access_token');
  });
});
