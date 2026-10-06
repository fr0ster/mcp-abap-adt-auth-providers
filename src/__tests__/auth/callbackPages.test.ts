/**
 * Every page a callback server writes is safe to render. `error` and
 * `error_description` are query parameters anyone can put in a link to the
 * local callback: written into the page unescaped, they were reflected HTML.
 * Every response also says what it is (`charset=utf-8`), forbids sniffing and
 * carries a CSP that runs no script.
 */

import http from 'node:http';
import { describe, expect, it } from '@jest/globals';
import type {
  CallbackServerFactory,
  ICallbackServerHandle,
} from '@mcp-abap-adt/interfaces-auth';
import { withBrowserCallbackServer } from '../../auth/callbackServer';
import { withOidcCallbackServer } from '../../auth/oidcBrowserAuth';
import { withSamlCallbackServer } from '../../auth/saml2Auth';

interface Reply {
  status: number;
  body: string;
  headers: http.IncomingHttpHeaders;
}

function request(port: number, path: string, method = 'GET'): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body, headers: res.headers }),
        );
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * Runs one scope on an ephemeral port; returns each path's reply. An IdP
 * refusal ends the scope at once, so the replies are awaited outside it.
 */
async function replies(
  factory: CallbackServerFactory<unknown>,
  paths: string[],
): Promise<Reply[]> {
  const pending: Promise<Reply>[] = [];
  await factory({ port: 0 }, async (srv: ICallbackServerHandle<unknown>) => {
    const result = srv.waitForResult();
    void result.catch(() => undefined);
    for (const path of paths) {
      const reply = request(srv.port, path);
      pending.push(reply);
      await reply;
    }
    srv.fail(new Error('done'));
    await result.catch(() => undefined);
  }).catch(() => undefined);
  return Promise.all(pending);
}

const SCRIPT = '<script>alert(1)</script>';
const IMG = '"><img src=x onerror=alert(2)>';
const ATTACK = `/callback?error=${encodeURIComponent(`x${IMG}`)}&error_description=${encodeURIComponent(SCRIPT + IMG)}`;

function expectSafe(reply: Reply) {
  expect(reply.body).not.toMatch(/<script/i);
  expect(reply.body).not.toMatch(/<img/i);
  expect(reply.body).not.toMatch(/<[^>]*onerror/i);
  expect(reply.headers['content-type']).toMatch(/charset=utf-8/i);
  expect(reply.headers['x-content-type-options']).toBe('nosniff');
  expect(reply.headers['content-security-policy']).toMatch(
    /default-src 'none'/,
  );
}

describe('callback pages', () => {
  it.each([
    ['UAA', withBrowserCallbackServer],
    ['OIDC', withOidcCallbackServer],
  ] as const)(
    '%s: the IdP refusal page escapes error and error_description',
    async (_name, factory) => {
      const [reply] = await replies(factory as CallbackServerFactory<unknown>, [
        ATTACK,
      ]);
      if (!reply) throw new Error('no reply');
      expect(reply.status).toBe(400);
      expect(reply.headers['content-type']).toMatch(/^text\/html/);
      // Not vacuous: the refusal is shown, escaped.
      expect(reply.body).toContain('&lt;script&gt;');
      expectSafe(reply);
    },
  );

  it.each([
    [
      'UAA',
      withBrowserCallbackServer,
      ['/callback', '/', '/submit?input=', '/callback?code=c'],
    ],
    ['OIDC', withOidcCallbackServer, ['/callback', '/callback?code=c']],
    ['SAML', withSamlCallbackServer, ['/callback', '/callback?SAMLResponse=x']],
  ] as const)(
    '%s: every other page carries the headers',
    async (_name, factory, paths) => {
      const all = await replies(factory as CallbackServerFactory<unknown>, [
        ...paths,
      ]);
      expect(all).toHaveLength(paths.length);
      for (const reply of all) expectSafe(reply);
    },
  );
});
