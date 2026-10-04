/**
 * A redirect is never followed by any token request, with a strategy or
 * without — against real sockets, with axios unmocked: a 307 would re-send the
 * secret, the refresh token, the code, the passcode, the password, the
 * assertion and the client certificate to wherever it points.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import axios, { AxiosError } from 'axios';
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
import { clientSecretPost } from '../../clientAuthentication';

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    );
  });
}
const close = (server: Server) =>
  new Promise<void>((resolve) => server.close(() => resolve()));

describe('a 307 from the token endpoint', () => {
  let elsewhereHits = 0;
  const elsewhere = createServer((req, res) => {
    elsewhereHits++;
    req.resume();
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ access_token: 'at', expires_in: 60 }));
  });
  let elsewherePort = 0;
  const redirecting = createServer((req, res) => {
    req.resume();
    res.statusCode = 307;
    res.setHeader('Location', `http://127.0.0.1:${elsewherePort}/token`);
    res.end();
  });
  let base = '';

  beforeAll(async () => {
    elsewherePort = await listen(elsewhere);
    base = `http://127.0.0.1:${await listen(redirecting)}`;
  });
  afterAll(async () => {
    await Promise.all([close(elsewhere), close(redirecting)]);
  });

  it.each([
    [
      'client credentials',
      () =>
        getTokenWithClientCredentials(base, 'cid', undefined, {
          strategy: clientSecretPost('client-secret-value'),
        }),
    ],
    [
      'OIDC refresh',
      () =>
        refreshOidcToken(`${base}/token`, 'cid', undefined, 'rt', undefined, {
          strategy: clientSecretPost('client-secret-value'),
        }),
    ],
  ])(
    '%s with a strategy: fails, and the other host sees no request',
    async (_label, run) => {
      elsewhereHits = 0;
      const failed = expect(run()).rejects.toBeDefined();
      await failed;
      expect(elsewhereHits).toBe(0);
    },
  );

  it.each([
    [
      'client credentials',
      () => getTokenWithClientCredentials(base, 'cid', 'client-secret-value'),
    ],
    [
      'UAA refresh',
      () => refreshJwtToken('rt', base, 'cid', 'client-secret-value'),
    ],
    [
      'UAA authorization code',
      () =>
        exchangeCodeForToken(
          {
            uaaUrl: base,
            uaaClientId: 'cid',
            uaaClientSecret: 'client-secret-value',
          } as Parameters<typeof exchangeCodeForToken>[0],
          'the-code',
          'http://localhost:61001/callback',
        ),
    ],
    [
      'UAA passcode',
      () => exchangePasscode(base, 'cf', 'client-secret-value', 'PASSCODE'),
    ],
    [
      'SAML bearer exchange',
      () =>
        exchangeSamlAssertion(
          'ASSERTION',
          `${base}/token`,
          'cid',
          'client-secret-value',
        ),
    ],
    [
      'SAML bearer refresh',
      () =>
        refreshSamlBearerToken(
          'rt',
          `${base}/token`,
          'cid',
          'client-secret-value',
        ),
    ],
    [
      'OIDC authorization code',
      () =>
        exchangeAuthorizationCode(
          `${base}/token`,
          'cid',
          'client-secret-value',
          'the-code',
          'http://localhost:61001/callback',
          'verifier',
        ),
    ],
    [
      'OIDC refresh',
      () =>
        refreshOidcToken(`${base}/token`, 'cid', 'client-secret-value', 'rt'),
    ],
    [
      'OIDC device initiation',
      () => initiateDeviceAuthorization(`${base}/device`, 'cid', 'openid'),
    ],
    [
      'OIDC device poll',
      () =>
        pollDeviceTokens(
          `${base}/token`,
          'cid',
          'client-secret-value',
          'dc',
          0,
        ),
    ],
    [
      'OIDC password',
      () =>
        passwordGrant(
          `${base}/token`,
          'cid',
          'client-secret-value',
          'user',
          'pw',
          undefined,
        ),
    ],
    [
      'OIDC token exchange',
      () =>
        tokenExchange(
          `${base}/token`,
          'cid',
          'client-secret-value',
          'subject',
          'urn:ietf:params:oauth:token-type:access_token',
          undefined,
          undefined,
        ),
    ],
  ])(
    '%s without a strategy: fails, and the other host sees no request',
    async (_label, run) => {
      elsewhereHits = 0;
      const failed = expect(run()).rejects.toBeDefined();
      await failed;
      expect(elsewhereHits).toBe(0);
    },
  );
});

describe('a 400 from the token endpoint that echoes the request', () => {
  const SECRET = 'client-secret-0123456789';
  const REFRESH = 'refresh-token-abcdefghij';
  const DEVICE = 'device-code-klmnopqrstu';
  let lastBody = '';
  const echoing = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      lastBody = Buffer.concat(chunks).toString();
      res.statusCode = 400;
      res.statusMessage = 'Bad Request';
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('X-Echo', encodeURIComponent(lastBody));
      res.end(
        JSON.stringify({
          error: 'invalid_grant',
          error_description: 'refused',
          echoed: lastBody,
          authorization: req.headers.authorization ?? '',
        }),
      );
    });
  });
  let base = '';
  beforeAll(async () => {
    base = `http://127.0.0.1:${await listen(echoing)}`;
  });
  afterAll(() => close(echoing));

  const windows = (secret: string) => {
    const out: string[] = [];
    for (let i = 0; i + 8 <= secret.length; i++)
      out.push(secret.slice(i, i + 8));
    return out;
  };

  it.each([
    [
      'OIDC refresh without a strategy',
      () => refreshOidcToken(`${base}/token`, 'cid', SECRET, REFRESH),
    ],
    [
      'OIDC refresh with a strategy',
      () =>
        refreshOidcToken(
          `${base}/token`,
          'cid',
          undefined,
          REFRESH,
          undefined,
          {
            strategy: clientSecretPost(SECRET),
          },
        ),
    ],
    [
      'OIDC device poll without a strategy',
      () => pollDeviceTokens(`${base}/token`, 'cid', SECRET, DEVICE, 0),
    ],
    [
      'UAA authorization code without a strategy',
      () =>
        exchangeCodeForToken(
          {
            uaaUrl: base,
            uaaClientId: 'cid',
            uaaClientSecret: SECRET,
          } as Parameters<typeof exchangeCodeForToken>[0],
          REFRESH,
          'http://localhost:61001/callback',
        ),
    ],
  ])(
    '%s: an AxiosError without the request, whose JSON and string hold no secret',
    async (_label, run) => {
      let thrown: unknown;
      try {
        await run();
      } catch (error) {
        thrown = error;
      }
      // The server did receive, and echo, a secret of the grant.
      expect(lastBody.includes(REFRESH) || lastBody.includes(DEVICE)).toBe(
        true,
      );
      expect(thrown).toBeInstanceOf(AxiosError);
      expect(axios.isAxiosError(thrown)).toBe(true);
      const error = thrown as AxiosError;
      expect(error.name).toBe('AxiosError');
      expect(error.status).toBe(400);
      expect(error.response?.status).toBe(400);
      expect(error.response?.statusText).toBe('Bad Request');
      expect(error.response?.data).toEqual({
        error: 'invalid_grant',
        error_description: 'refused',
      });
      expect(error.config).toBeUndefined();
      expect(error.request).toBeUndefined();
      expect(error.response?.config).toBeUndefined();
      expect(error.response?.request).toBeUndefined();
      expect(error.cause).toBeUndefined();
      expect(JSON.stringify(error.toJSON())).not.toContain('"config":{');
      const text = `${JSON.stringify(error)}\n${JSON.stringify(error.toJSON())}\n${String(error)}\n${error.stack}`;
      const basic = Buffer.from(`cid:${SECRET}`).toString('base64');
      const needles = [
        ...windows(SECRET),
        ...windows(REFRESH),
        ...windows(DEVICE),
        ...windows(basic),
      ];
      expect(needles.filter((needle) => text.includes(needle))).toEqual([]);
    },
  );
});
