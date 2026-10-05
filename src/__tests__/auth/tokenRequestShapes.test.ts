/**
 * Characterization of every token-request site: the exact request each sends
 * today (URL, method, form body, auth-relevant headers). These tests are not
 * edited when the sites are refactored behind them — a changed shape is a
 * failure here.
 */

import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import axios from 'axios';
import { exchangeCodeForToken } from '../../auth/browserAuth';
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

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & { post: Mock };

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
  expect(mockedAxios.post).toHaveBeenCalledTimes(1);
  const [url, body, config] = mockedAxios.post.mock.calls[0] as [
    string,
    string,
    { headers: Record<string, string>; maxRedirects: number },
  ];
  // Today's third argument is exactly `{ headers, maxRedirects: 0 }`: any added key fails here.
  expect(Object.keys(config)).toEqual(['headers', 'maxRedirects']);
  expect(config.maxRedirects).toBe(0);
  return {
    url,
    method: 'post',
    body: Object.fromEntries(new URLSearchParams(body)),
    headers: config.headers,
  };
}

/** The request of `axios(config)`. */
function sentByConfig(expectTimeout = false): Sent & { timeout?: number } {
  expect(mockedAxios).toHaveBeenCalledTimes(1);
  const config = mockedAxios.mock.calls[0]![0] as {
    url: string;
    method: string;
    data: string;
    headers: Record<string, string>;
    timeout?: number;
    maxRedirects: number;
  };
  // The whole config object: any added key (httpsAgent, ...) fails, and
  // `timeout` is present exactly where today's code sets it.
  expect(Object.keys(config).sort()).toEqual(
    expectTimeout
      ? ['data', 'headers', 'maxRedirects', 'method', 'timeout', 'url']
      : ['data', 'headers', 'maxRedirects', 'method', 'url'],
  );
  expect(config.maxRedirects).toBe(0);
  return {
    url: config.url,
    method: config.method,
    body: Object.fromEntries(new URLSearchParams(config.data)),
    headers: config.headers,
    timeout: config.timeout,
  };
}

describe('token request shapes, as sent today', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    mockedAxios.mockResolvedValue(tokenReply);
    mockedAxios.post.mockResolvedValue(tokenReply);
  });

  describe('clientCredentialsAuth', () => {
    it('with a secret: client_id and client_secret in the body, no Authorization', async () => {
      await getTokenWithClientCredentials('https://uaa', 'cid', 'sec');
      const sent = sentByConfig(true);
      expect(sent.url).toBe('https://uaa/oauth/token');
      expect(sent.method).toBe('post');
      expect(sent.body).toEqual({
        grant_type: 'client_credentials',
        client_id: 'cid',
        client_secret: 'sec',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
      expect(sent.headers.Authorization).toBeUndefined();
      expect(sent.timeout).toBe(30000);
    });
  });

  describe('tokenRefresher (UAA refresh)', () => {
    it('with a secret: Basic header, refresh_token only in the body', async () => {
      await refreshJwtToken('old-rt', 'https://uaa', 'cid', 'sec');
      const sent = sentByConfig();
      expect(sent.url).toBe('https://uaa/oauth/token');
      expect(sent.method).toBe('post');
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      expect(sent.headers).toEqual({
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
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      expect(sent.headers).toEqual({
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
      expect(sent.url).toBe('https://uaa/oauth/token');
      expect(sent.method).toBe('post');
      expect(sent.body).toEqual({
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
      });
      expect(sent.headers).toEqual({
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
      expect(sent.body).toEqual({
        grant_type: 'authorization_code',
        code: 'the-code',
        redirect_uri: 'http://localhost:61001/callback',
      });
      expect(sent.headers).toEqual({
        Authorization: basic('cid:undefined'),
        'Content-Type': FORM,
      });
    });
  });

  describe('passcodeAuth', () => {
    it('with a secret: Basic id:secret, JSON accepted', async () => {
      await exchangePasscode('https://uaa/', 'cf', 'sec', 'CODE');
      const sent = sentByPost();
      expect(sent.url).toBe('https://uaa/oauth/token');
      expect(sent.body).toEqual({ grant_type: 'password', passcode: 'CODE' });
      expect(sent.headers).toEqual({
        'Content-Type': FORM,
        Accept: 'application/json',
        Authorization: basic('cf:sec'),
      });
    });

    it('without a secret: Basic id: with an empty secret', async () => {
      await exchangePasscode('https://uaa', 'cf', undefined, 'CODE');
      const sent = sentByPost();
      expect(sent.url).toBe('https://uaa/oauth/token');
      expect(sent.body).toEqual({ grant_type: 'password', passcode: 'CODE' });
      expect(sent.headers).toEqual({
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
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({
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
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
    });

    it('refresh with a secret: client_id in the body and Basic', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid', 'sec');
      const sent = sentByPost();
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({
        'Content-Type': FORM,
        Authorization: basic('cid:sec'),
      });
    });

    it('refresh without a secret: client_id in the body, no Authorization', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid');
      const sent = sentByPost();
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
    });

    it('exchange with an empty secret: client_id in the body, no Authorization', async () => {
      await exchangeSamlAssertion('ASSERTION', 'https://t/token', 'cid', '');
      const sent = sentByPost();
      expect(sent.body).toEqual({
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
    });

    it('refresh with an empty secret: client_id in the body, no Authorization', async () => {
      await refreshSamlBearerToken('old-rt', 'https://t/token', 'cid', '');
      const sent = sentByPost();
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
        client_id: 'cid',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
    });

    it('exchange without a clientId: no client_id, no Authorization', async () => {
      await exchangeSamlAssertion(
        'ASSERTION',
        'https://t/token',
        undefined,
        'sec',
      );
      const sent = sentByPost();
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        assertion: 'ASSERTION',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
    });

    it('refresh without a clientId: no client_id, no Authorization', async () => {
      await refreshSamlBearerToken(
        'old-rt',
        'https://t/token',
        undefined,
        'sec',
      );
      const sent = sentByPost();
      expect(sent.url).toBe('https://t/token');
      expect(sent.body).toEqual({
        grant_type: 'refresh_token',
        refresh_token: 'old-rt',
      });
      expect(sent.headers).toEqual({ 'Content-Type': FORM });
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({
          'Content-Type': FORM,
          Authorization: basic('cid:'),
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret: client_id in the body, no Authorization', async () => {
        await refreshOidcToken(endpoint, 'cid', undefined, 'old-rt');
        const sent = sentByPost();
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({
          'Content-Type': FORM,
          Authorization: basic('cid:sec'),
        });
      });

      it('without a secret: client_id in the body, no Authorization', async () => {
        await pollDeviceTokens(endpoint, 'cid', undefined, 'dc', 1);
        const sent = sentByPost();
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual(expectedBody);
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
      });

      it('after authorization_pending: the second request is the same as the first', async () => {
        mockedAxios.post
          .mockRejectedValueOnce({
            response: { status: 400, data: { error: 'authorization_pending' } },
          })
          .mockResolvedValueOnce(tokenReply);
        await pollDeviceTokens(endpoint, 'cid', 'sec', 'dc', 0);
        expect(mockedAxios.post).toHaveBeenCalledTimes(2);
        for (const call of mockedAxios.post.mock.calls) {
          const [url, body, config] = call as [
            string,
            string,
            Record<string, unknown>,
          ];
          expect(url).toBe(endpoint);
          expect(Object.fromEntries(new URLSearchParams(body))).toEqual(
            expectedBody,
          );
          expect(config).toEqual({
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual({
          grant_type: 'password',
          username: 'user',
          password: 'pw',
          client_id: 'cid',
          scope: 'openid',
        });
        expect(sent.headers).toEqual({
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual({
          grant_type: 'password',
          username: 'user',
          password: 'pw',
          client_id: 'cid',
        });
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual({
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: 'subj',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: 'cid',
          scope: 'openid',
          audience: 'aud',
          actor_token: 'actor',
          actor_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        });
        expect(sent.headers).toEqual({
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
        expect(sent.url).toBe(endpoint);
        expect(sent.body).toEqual({
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: 'subj',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: 'cid',
        });
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
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
        mockedAxios.post.mockResolvedValue(reply);
        await initiateDeviceAuthorization(
          'https://idp/device-auth',
          'cid',
          'openid',
        );
        const sent = sentByPost();
        expect(sent.url).toBe('https://idp/device-auth');
        expect(sent.body).toEqual({ client_id: 'cid', scope: 'openid' });
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
      });

      it('without a scope: client_id only', async () => {
        mockedAxios.post.mockResolvedValue(reply);
        await initiateDeviceAuthorization(
          'https://idp/device-auth',
          'cid',
          undefined,
        );
        const sent = sentByPost();
        expect(sent.body).toEqual({ client_id: 'cid' });
        expect(sent.headers).toEqual({ 'Content-Type': FORM });
      });
    });
  });
});
