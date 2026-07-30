/**
 * The OIDC callback route.
 *
 * Its missing-code branch used to serve two very different requests: an IdP
 * refusing the login, and a stray request that was never part of one. They now
 * part ways, and the refusal must keep failing fast.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';

const PORT = 7877;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

function httpGet(path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port: PORT, path, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on('error', reject);
  });
}

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('withOidcCallbackServer', () => {
  it('ends the login at once when the IdP refuses', async () => {
    const attempt = withOidcCallbackServer(
      { port: PORT, timeoutMs: 30000 },
      async (srv) => await srv.waitForResult(),
    );
    const res = await httpGet(
      '/callback?error=access_denied&error_description=User%20said%20no',
    );
    expect(res.status).toBe(400);
    await expect(attempt).rejects.toThrow(/access_denied: User said no/);
  }, 30000);

  it('answers 400 and keeps waiting for a request carrying neither', async () => {
    const result = await withOidcCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await httpGet('/callback');
        expect(stray.status).toBe(400);
        void httpGet('/callback?code=late&state=xyz').catch(() => undefined);
        return await waiting;
      },
    );
    expect(result).toEqual({ code: 'late', state: 'xyz' });
  }, 30000);
});
