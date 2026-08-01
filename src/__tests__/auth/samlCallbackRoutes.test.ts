/**
 * The SAML callback route, GET and POST separately.
 *
 * The two read the payload from different places — query versus form body — and
 * a shared handler makes it easy to fix one and miss the other.
 */

import http from 'node:http';
import net from 'node:net';
import { afterEach, describe, expect, it } from '@jest/globals';
import { withSamlCallbackServer } from '../../auth/saml2Auth';

const PORT = 7879;

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, () => s.close(() => resolve(true)));
  });
}

function request(
  method: 'GET' | 'POST',
  path: string,
  body?: string,
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path,
        method,
        agent: false,
        headers: body
          ? {
              'content-type': 'application/x-www-form-urlencoded',
              'content-length': Buffer.byteLength(body),
            }
          : undefined,
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          text += chunk;
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

afterEach(async () => {
  expect(await portIsFree(PORT)).toBe(true);
});

describe('withSamlCallbackServer', () => {
  it('answers 400 without the completion page on a POST with no SAMLResponse', async () => {
    const assertion = await withSamlCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await request('POST', '/callback', 'other=1');
        expect(stray.status).toBe(400);
        expect(stray.text).not.toMatch(/authentication complete/i);
        void request('POST', '/callback', 'SAMLResponse=PHNhbWw%2B').catch(
          () => undefined,
        );
        return await waiting;
      },
    );
    expect(assertion).toBe('PHNhbWw+');
  }, 30000);

  it('answers 400 without the completion page on a GET with no SAMLResponse', async () => {
    const assertion = await withSamlCallbackServer(
      { port: PORT, timeoutMs: 5000 },
      async (srv) => {
        const waiting = srv.waitForResult();
        const stray = await request('GET', '/callback');
        expect(stray.status).toBe(400);
        expect(stray.text).not.toMatch(/authentication complete/i);
        void request('GET', '/callback?SAMLResponse=PHNhbWw%2B').catch(
          () => undefined,
        );
        return await waiting;
      },
    );
    expect(assertion).toBe('PHNhbWw+');
  }, 30000);

  it('releases the port when the login is abandoned', async () => {
    const scope = withSamlCallbackServer(
      { port: PORT, timeoutMs: 300 },
      async (srv) => await srv.waitForResult(),
    );
    // Attached before anything can settle it — awaiting the timeout first
    // would leave this rejection unhandled at the moment it lands.
    const rejected = expect(scope).rejects.toThrow(/timeout/i);
    await rejected;
    expect(await portIsFree(PORT)).toBe(true);
  }, 30000);
});
