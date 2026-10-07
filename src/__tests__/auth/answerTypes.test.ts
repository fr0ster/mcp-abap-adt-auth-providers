/**
 * A token answer's fields are kept only with their protocol type (RFC 6749
 * §5.1): a token is a non-empty string, `expires_in` a finite non-negative
 * JSON number. A number as `access_token` is no access token — the site
 * refuses the answer (`request-failed`, `no-access-token`) and nothing is
 * presented; a refresh token that is not a string, and an `expires_in` that
 * is not such a number (a numeric string included), are absent. Against a
 * real socket, through providers and their sites.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { staticCodeStrategy } from '../../strategies/codeStrategies';

let body: unknown;
let base = '';
const server: Server = createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  });
});
beforeAll(async () => {
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

const providers = {
  'client credentials': () =>
    new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: base,
      clientId: 'c',
      clientSecret: 's',
    }),
  'OIDC password': () =>
    new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      tokenEndpoint: `${base}/token`,
      clientId: 'c',
      username: 'u',
      password: 'p',
    }),
  'UAA passcode': () =>
    new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: base,
      clientId: 'cf',
      authorization: staticCodeStrategy({ payload: 'pc' }),
    }),
};

const notTokens: Array<[string, unknown]> = [
  ['a number', 42],
  ['an empty string', ''],
  ['an object', { value: 't' }],
  ['true', true],
];

describe('an access_token that is not a non-empty string is no token', () => {
  for (const [name, build] of Object.entries(providers)) {
    for (const [label, token] of notTokens) {
      it(`${name}: access_token ${label} → request-failed no-access-token`, async () => {
        body = { access_token: token, expires_in: 3600 };
        const provider = build();
        const thrown = await provider.getTokens().then(
          () => undefined,
          (error: unknown) => error,
        );
        const failure = readFailure(thrown, 'token-request');
        expect(failure.kind).toBe('request-failed');
        expect(failure.facts).toEqual(
          expect.objectContaining({ problem: 'no-access-token' }),
        );
        // Nothing is presented either.
        const headers: Record<string, string> = {};
        const outcome = await provider.authorize({
          header: (header: string, value: string) => {
            headers[header] = value;
            return { ok: true };
          },
          cookies: () => ({ ok: true }),
        } as never);
        expect(outcome.ok).toBe(false);
        expect(headers).toEqual({});
      });
    }
  }
});

describe('expires_in and refresh_token of another type are absent', () => {
  for (const [name, build] of Object.entries(providers)) {
    for (const expiresIn of ['3600', 'abc', -5, null, { n: 1 }]) {
      it(`${name}: expires_in ${JSON.stringify(expiresIn)} is not handed on`, async () => {
        body = {
          access_token: 'opaque-token',
          refresh_token: 7,
          expires_in: expiresIn,
        };
        const result = await build().getTokens();
        expect(result.authorizationToken).toBe('opaque-token');
        expect(result.expiresIn).toBeUndefined();
        expect(result.refreshToken).toBeUndefined();
      });
    }

    it(`${name}: a finite non-negative expires_in is kept`, async () => {
      body = { access_token: 'opaque-token', expires_in: 3600 };
      const result = await build().getTokens();
      expect(result.expiresIn).toBe(3600);
    });
  }
});
