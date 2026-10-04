/**
 * A redirect is never followed on the strategy path — against real sockets,
 * with axios unmocked: a 307 would re-send the secret, the assertion and the
 * client certificate to wherever it points.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { refreshOidcToken } from '../../auth/oidcToken';
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
});
