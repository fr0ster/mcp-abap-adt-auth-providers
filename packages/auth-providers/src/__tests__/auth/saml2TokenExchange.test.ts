/**
 * Tests for the SAML bearer token exchange and its refresh grant
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import { refreshSamlBearerToken } from '../../auth/saml2TokenExchange';
import { clearAxiosMockCalls, mockedAxios } from '../helpers/axiosModuleMock';
import { thrown } from '../helpers/expectations';

// Automocked, but with axios's own error class: the sites throw it.

describe('refreshSamlBearerToken', () => {
  beforeEach(() => {
    clearAxiosMockCalls();
  });

  it('posts a refresh_token grant to the token URL with client credentials', async () => {
    mockedAxios.post.mock.mockImplementation(async () => ({
      data: {
        access_token: 'new-access',
        refresh_token: 'new-refresh',
        expires_in: 3600,
        token_type: 'bearer',
      },
    }));

    const result = await refreshSamlBearerToken(
      'old-refresh',
      'https://uaa/oauth/token',
      'client',
      'secret',
    );

    assert.deepEqual(result, {
      accessToken: 'new-access',
      refreshToken: 'new-refresh',
      expiresIn: 3600,
      tokenType: 'bearer',
    });
    const [url, body, options] = mockedAxios.post.mock.calls.map(
      (call) => call.arguments,
    )[0] as [string, string, { headers: Record<string, string> }];
    assert.equal(url, 'https://uaa/oauth/token');
    const params = new URLSearchParams(body);
    assert.equal(params.get('grant_type'), 'refresh_token');
    assert.equal(params.get('refresh_token'), 'old-refresh');
    assert.equal(params.get('client_id'), 'client');
    assert.equal(
      options.headers.Authorization,
      `Basic ${Buffer.from('client:secret').toString('base64')}`,
    );
  });

  it('sends no Authorization header without a client secret', async () => {
    mockedAxios.post.mock.mockImplementation(async () => ({
      data: { access_token: 'a' },
    }));

    await refreshSamlBearerToken('r', 'https://uaa/oauth/token', 'client');

    const options = mockedAxios.post.mock.calls.map(
      (call) => call.arguments,
    )[0]![2] as {
      headers: Record<string, string>;
    };
    assert.equal(options.headers.Authorization, undefined);
  });

  it('refuses a response without an access token', async () => {
    mockedAxios.post.mock.mockImplementation(async () => ({
      data: { refresh_token: 'r2' },
    }));

    await assert.rejects(
      refreshSamlBearerToken('r', 'https://uaa/oauth/token', 'c', 's'),
      thrown('the SAML token refresh returned no access_token'),
    );
  });
});
