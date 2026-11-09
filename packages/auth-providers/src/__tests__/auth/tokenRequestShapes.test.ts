/**
 * Characterization of every token-request site: the exact request each sends
 * today (URL, method, form body, auth-relevant headers). These tests are not
 * edited when the sites are refactored behind them — a changed shape is a
 * failure here.
 */

import '../helpers/axiosModuleMock';
import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  exchangeCodeForToken,
  getJwtAuthorizationUrl,
} from '../../auth/browserAuth';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import {
  exchangeAuthorizationCode,
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
  refreshOidcToken,
  tokenExchange,
} from '../../auth/oidcToken';
import { exchangePasscode } from '../../auth/passcodeAuth';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import { mockedAxios, resetAxiosMock } from '../helpers/axiosModuleMock';
import { once } from '../helpers/mockOnce';

// Automocked, but with axios's own error class: the sites throw it.

const FORM = 'application/x-www-form-urlencoded';
const tokenReply = {
  data: { access_token: 'at', refresh_token: 'rt', expires_in: 60 },
};
const basic = (s: string) => `Basic ${Buffer.from(s).toString('base64')}`;

interface Sent {
  url: string;
  method: string;
  body: Record<string, string>;
  headers: Record<string, string>;
}

/** The request of `axios.post(url, body, config)`. */
function sentByPost(): Sent {
  assert.equal(mockedAxios.post.mock.callCount(), 1);
  const [url, body, config] = mockedAxios.post.mock.calls.map(
    (call) => call.arguments,
  )[0] as [
    string,
    string,
    { headers: Record<string, string>; maxRedirects: number },
  ];
  // Today's third argument is exactly `{ headers, maxRedirects: 0 }`: any added key fails here.
  assert.deepEqual(Object.keys(config), ['headers', 'maxRedirects']);
  assert.equal(config.maxRedirects, 0);
  return {
    url,
    method: 'post',
    body: Object.fromEntries(new URLSearchParams(body)),
    headers: config.headers,
  };
}

/** The request of `axios(config)`. */
function sentByConfig(): Sent {
  assert.equal(mockedAxios.mock.callCount(), 1);
  const config = mockedAxios.mock.calls.map(
    (call) => call.arguments,
  )[0]![0] as {
    url: string;
    method: string;
    data: string;
    headers: Record<string, string>;
    maxRedirects: number;
  };
  // The whole config object: any added key (httpsAgent, a timeout, ...)
  // fails — no request carries a timeout of this package's choosing.
  assert.deepEqual(Object.keys(config).sort(), [
    'data',
    'headers',
    'maxRedirects',
    'method',
    'url',
  ]);
  assert.equal(config.maxRedirects, 0);
  return {
    url: config.url,
    method: config.method,
    body: Object.fromEntries(new URLSearchParams(config.data)),
    headers: config.headers,
  };
}

describe('token request shapes, as sent today', () => {
  beforeEach(() => {
    resetAxiosMock();
    mockedAxios.mock.mockImplementation(async () => tokenReply);
    mockedAxios.post.mock.mockImplementation(async () => tokenReply);
  });

  describe('clientCredentialsAuth', () => {
    it('with a secret: client_id and client_secret in the body, no Authorization', async () => {
      await getTokenWithClientCredentials('https://uaa', 'cid', 'sec');
      const sent = sentByConfig();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.equal(sent.method, 'post');
      assert.deepEqual(sent.body, {
        grant_type: 'client_credentials',
        client_id: 'cid',
        client_secret: 'sec',
      });
      // Read before deepEqual, which narrows the type to what it compared.
      assert.equal(sent.headers.Authorization, undefined);
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });
  });

  describe('tokenRefresher (UAA refresh)', () => {
    it('with a secret: Basic header, refresh_token only in the body', async () => {
      await refreshJwtToken('old-rt', 'https://uaa', 'cid', 'sec');
      const sent = sentByConfig();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.equal(sent.method, 'post');
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      assert.deepEqual(sent.headers, {
        Authorization: basic('cid:sec'),
        'Content-Type': FORM,
      });
    });

    it('with an undefined secret: Basic "cid:undefined" (today, not endorsed)', async () => {
      await refreshJwtToken(
        'old-rt',
        'https://uaa',
        'cid',
        undefined as unknown as string,
      );
      const sent = sentByConfig();
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      assert.deepEqual(sent.headers, {
        Authorization: basic('cid:undefined'),
        'Content-Type': FORM,
      });
    });
  });

  describe('browserAuth.exchangeCodeForToken', () => {
    it('with a secret: Basic header, no client_id in the body', async () => {
      await exchangeCodeForToken(
        {
          uaaUrl: 'https://uaa',
          uaaClientId: 'cid',
          uaaClientSecret: 'sec',
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
      );
      const sent = sentByConfig();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.equal(sent.method, 'post');
      assert.deepEqual(sent.body, {
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
      });
      assert.deepEqual(sent.headers, {
        Authorization: basic('cid:sec'),
        'Content-Type': FORM,
      });
    });

    it('with an undefined secret: Basic "cid:undefined" (today, not endorsed)', async () => {
      await exchangeCodeForToken(
        { uaaUrl: 'https://uaa', uaaClientId: 'cid' } as Parameters<
          typeof exchangeCodeForToken
        >[0],
        'the-code',
        'http://localhost:61001/callback',
      );
      const sent = sentByConfig();
      assert.deepEqual(sent.body, {
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
      });
      assert.deepEqual(sent.headers, {
        Authorization: basic('cid:undefined'),
        'Content-Type': FORM,
      });
    });
  });

  describe('browserAuth: the UAA login bound by state and PKCE', () => {
    it('the URL it builds carries state, code_challenge and S256', () => {
      const url = new URL(
        getJwtAuthorizationUrl(
          {
            uaaUrl: 'https://uaa',
            uaaClientId: 'cid',
          } as Parameters<typeof getJwtAuthorizationUrl>[0],
          'http://localhost:61001/callback',
          { state: 'the-state', codeChallenge: 'the-challenge' },
        ),
      );
      assert.equal(
        `${url.origin}${url.pathname}`,
        'https://uaa/oauth/authorize',
      );
      assert.deepEqual(Object.fromEntries(url.searchParams), {
        client_id: 'cid',
        redirect_uri: 'http://localhost:61001/callback',
        response_type: 'code',
        state: 'the-state',
        code_challenge: 'the-challenge',
        code_challenge_method: 'S256',
      });
    });

    it('the exchange sends the code_verifier, beside the Basic header', async () => {
      await exchangeCodeForToken(
        {
          uaaUrl: 'https://uaa',
          uaaClientId: 'cid',
          uaaClientSecret: 'sec',
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
        undefined,
        undefined,
        undefined,
        'the-verifier',
      );
      const sent = sentByConfig();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.deepEqual(sent.body, {
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
        code_verifier: 'the-verifier',
      });
      assert.deepEqual(sent.headers, {
        Authorization: basic('cid:sec'),
        'Content-Type': FORM,
      });
    });
  });

  describe('passcodeAuth', () => {
    it('with a secret: Basic id:secret, JSON accepted', async () => {
      await exchangePasscode('https://uaa/', 'cf', 'sec', 'CODE');
      const sent = sentByPost();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.deepEqual(sent.body, { grant_type: 'password', passcode: 'CODE' });
      assert.deepEqual(sent.headers, {
        'Content-Type': FORM,
        Accept: 'application/json',
        Authorization: basic('cf:sec'),
      });
    });

    it('without a secret: Basic id: with an empty secret', async () => {
      await exchangePasscode('https://uaa', 'cf', undefined, 'CODE');
      const sent = sentByPost();
      assert.equal(sent.url, 'https://uaa/oauth/token');
      assert.deepEqual(sent.body, { grant_type: 'password', passcode: 'CODE' });
      assert.deepEqual(sent.headers, {
        'Content-Type': FORM,
        Accept: 'application/json',
        Authorization: basic('cf:'),
      });
    });
  });

  describe('saml2TokenExchange', () => {
    it('exchange with a secret: client_id in the body and Basic', async () => {
      await exchangeSamlAssertion('ASSERTION', 'https://t/token', 'cid', 'sec');
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, {
        'Content-Type': FORM,
        Authorization: basic('cid:sec'),
      });
    });

    it('exchange without a secret: client_id in the body, no Authorization', async () => {
      await exchangeSamlAssertion(
        'ASSERTION',
        'https://t/token',
        'cid',
        undefined,
      );
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });

    it('refresh with a secret: client_id in the body and Basic', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid', 'sec');
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, {
        'Content-Type': FORM,
        Authorization: basic('cid:sec'),
      });
    });

    it('refresh without a secret: client_id in the body, no Authorization', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid');
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });

    it('exchange with an empty secret: client_id in the body, no Authorization', async () => {
      await exchangeSamlAssertion('ASSERTION', 'https://t/token', 'cid', '');
      const sent = sentByPost();
      assert.deepEqual(sent.body, {
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });

    it('refresh with an empty secret: client_id in the body, no Authorization', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid', '');
      const sent = sentByPost();
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });

    it('exchange without a clientId: no client_id, no Authorization', async () => {
      await exchangeSamlAssertion(
        'ASSERTION',
        'https://t/token',
        undefined,
        'sec',
      );
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });

    it('refresh without a clientId: no client_id, no Authorization', async () => {
      await refreshSamlBearerToken(
        'old-rt',
        'https://t/token',
        undefined,
        'sec',
      );
      const sent = sentByPost();
      assert.equal(sent.url, 'https://t/token');
      assert.deepEqual(sent.body, {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      assert.deepEqual(sent.headers, { 'Content-Type': FORM });
    });
  });

  describe('oidcToken', () => {
    const endpoint = 'https://idp/token';

    describe('authorization code', () => {
      const expectedBody = {
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
        code_verifier: 'verifier',
        client_id: 'cid',
      };

      it('with a secret: client_id in the body and Basic', async () => {
        await exchangeAuthorizationCode(
          endpoint,
          'cid',
          'sec',
          'the-code',
          'http://localhost:61001/callback',
          'verifier',
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret: client_id in the body, no Authorization', async () => {
        await exchangeAuthorizationCode(
          endpoint,
          'cid',
          undefined,
          'the-code',
          'http://localhost:61001/callback',
          'verifier',
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });

      it('with an empty secret: Basic "cid:" (the check is !== undefined)', async () => {
        await exchangeAuthorizationCode(
          endpoint,
          'cid',
          '',
          'the-code',
          'http://localhost:61001/callback',
          'verifier',
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:'),
        });
      });
    });

    describe('authorization code without a verifier (no URL was built)', () => {
      it('sends no code_verifier', async () => {
        await exchangeAuthorizationCode(
          endpoint,
          'cid',
          undefined,
          'the-code',
          'http://localhost:61001/callback',
          undefined,
        );
        const sent = sentByPost();
        assert.deepEqual(sent.body, {
          grant_type: 'authorization_code',
          code: 'the-code',
          redirect_uri: 'http://localhost:61001/callback',
          client_id: 'cid',
        });
      });
    });

    describe('refresh', () => {
      const expectedBody = {
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      };

      it('with a secret: client_id in the body and Basic', async () => {
        await refreshOidcToken(endpoint, 'cid', 'sec', 'old-rt');
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret: client_id in the body, no Authorization', async () => {
        await refreshOidcToken(endpoint, 'cid', undefined, 'old-rt');
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });
    });

    describe('device poll', () => {
      const expectedBody = {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: 'dc',
        client_id: 'cid',
      };

      it('with a secret: client_id in the body and Basic', async () => {
        await pollDeviceTokens(endpoint, 'cid', 'sec', 'dc', 1);
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret: client_id in the body, no Authorization', async () => {
        await pollDeviceTokens(endpoint, 'cid', undefined, 'dc', 1);
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, expectedBody);
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });

      it('after authorization_pending: the second request is the same as the first', async () => {
        once(mockedAxios.post, async () => {
          throw {
            response: { status: 400, data: { error: 'authorization_pending' } },
          };
        });
        once(mockedAxios.post, async () => tokenReply);
        await pollDeviceTokens(endpoint, 'cid', 'sec', 'dc', 0);
        assert.equal(mockedAxios.post.mock.callCount(), 2);
        for (const call of mockedAxios.post.mock.calls.map(
          (call) => call.arguments,
        )) {
          const [url, body, config] = call as [
            string,
            string,
            Record<string, unknown>,
          ];
          assert.equal(url, endpoint);
          assert.deepEqual(
            Object.fromEntries(new URLSearchParams(body)),
            expectedBody,
          );
          assert.deepEqual(config, {
            headers: {
              'Content-Type': FORM,
              Authorization: basic('cid:sec'),
            },
            maxRedirects: 0,
          });
        }
      });
    });

    describe('password grant', () => {
      it('with a secret and a scope: client_id, scope in the body and Basic', async () => {
        await passwordGrant(endpoint, 'cid', 'sec', 'user', 'pw', 'openid');
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, {
          grant_type: 'password',
          username: 'user',
          password: 'pw',
          client_id: 'cid',
          scope: 'openid',
        });
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret or a scope: client_id in the body, no Authorization', async () => {
        await passwordGrant(
          endpoint,
          'cid',
          undefined,
          'user',
          'pw',
          undefined,
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, {
          grant_type: 'password',
          username: 'user',
          password: 'pw',
          client_id: 'cid',
        });
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });
    });

    describe('token exchange', () => {
      it('with a secret and every optional parameter: client_id in the body and Basic', async () => {
        await tokenExchange(
          endpoint,
          'cid',
          'sec',
          'subj',
          'urn:ietf:params:oauth:token-type:access_token',
          'openid',
          'aud',
          'actor',
          'urn:ietf:params:oauth:token-type:jwt',
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: 'subj',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: 'cid',
          scope: 'openid',
          audience: 'aud',
          actor_token: 'actor',
          actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        });
        assert.deepEqual(sent.headers, {
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret or optionals: client_id in the body, no Authorization', async () => {
        await tokenExchange(
          endpoint,
          'cid',
          undefined,
          'subj',
          'urn:ietf:params:oauth:token-type:access_token',
          undefined,
          undefined,
        );
        const sent = sentByPost();
        assert.equal(sent.url, endpoint);
        assert.deepEqual(sent.body, {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: 'subj',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: 'cid',
        });
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });
    });

    describe('initiateDeviceAuthorization', () => {
      const reply = {
        data: {
          device_code: 'dc',
          user_code: 'uc',
          verification_uri: 'https://idp/device',
        },
      };

      it('client_id in the body, never Authorization', async () => {
        mockedAxios.post.mock.mockImplementation(async () => reply);
        await initiateDeviceAuthorization(
          'https://idp/device-auth',
          'cid',
          'openid',
        );
        const sent = sentByPost();
        assert.equal(sent.url, 'https://idp/device-auth');
        assert.deepEqual(sent.body, { client_id: 'cid', scope: 'openid' });
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });

      it('without a scope: client_id only', async () => {
        mockedAxios.post.mock.mockImplementation(async () => reply);
        await initiateDeviceAuthorization(
          'https://idp/device-auth',
          'cid',
          undefined,
        );
        const sent = sentByPost();
        assert.deepEqual(sent.body, { client_id: 'cid' });
        assert.deepEqual(sent.headers, { 'Content-Type': FORM });
      });
    });
  });
});
