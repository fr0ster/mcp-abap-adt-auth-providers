/**
 * A redirect is never followed by any token request, with a strategy or
 * without — against real sockets, with axios unmocked: a 307 would re-send the
 * secret, the refresh token, the code, the passcode, the password, the
 * assertion and the client certificate to wherever it points.
 */

import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { inspect } from 'node:util';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
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
import { clientSecretPost } from '../../clientAuthentication';
import {
  cases,
  caseTitle,
  contains,
  matchObject,
  notContains,
} from '../helpers/expectations';

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

  before(async () => {
    elsewherePort = await listen(elsewhere);
    base = `http://127.0.0.1:${await listen(redirecting)}`;
  });
  after(async () => {
    await Promise.all([close(elsewhere), close(redirecting)]);
  });

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_label, run] = caseRow;
    it(
      caseTitle(
        '%s with a strategy: fails, and the other host sees no request',
        caseRow,
        caseIndex,
      ),
      async () => {
        elsewhereHits = 0;
        const failed = assert.rejects(run(), (error) => error !== undefined);
        await failed;
        assert.equal(elsewhereHits, 0);
      },
    );
  }

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_label, run] = caseRow;
    it(
      caseTitle(
        '%s without a strategy: fails, and the other host sees no request',
        caseRow,
        caseIndex,
      ),
      async () => {
        elsewhereHits = 0;
        const failed = assert.rejects(run(), (error) => error !== undefined);
        await failed;
        assert.equal(elsewhereHits, 0);
      },
    );
  }
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
  before(async () => {
    base = `http://127.0.0.1:${await listen(echoing)}`;
  });
  after(() => close(echoing));

  const windows = (secret: string) => {
    const out: string[] = [];
    for (let i = 0; i + 8 <= secret.length; i++)
      out.push(secret.slice(i, i + 8));
    return out;
  };

  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_label, run] = caseRow;
    it(
      caseTitle(
        '%s: an AuthProviderFailure without the request, whose JSON and string hold no secret',
        caseRow,
        caseIndex,
      ),
      async () => {
        let thrown: unknown;
        try {
          await run();
        } catch (error) {
          thrown = error;
        }
        // The server did receive, and echo, a secret of the grant.
        assert.equal(
          lastBody.includes(REFRESH) || lastBody.includes(DEVICE),
          true,
        );
        // No longer the reduced AxiosError — the failure of the
        // site's operation, its facts the status and the registered code.
        assert.equal(isAuthProviderFailure(thrown), true);
        assert.equal(axios.isAxiosError(thrown), false);
        const error = thrown as Error;
        matchObject(readFailure(thrown, 'unfamiliar-error').facts, {
          problem: 'refused',
          status: 400,
          oauthError: 'invalid_grant',
        });
        assert.deepEqual(Object.keys(error).sort(), [
          'error',
          'message',
          'name',
        ]);
        assert.equal(error.cause, undefined);
        const text = `${JSON.stringify(error)}\n${inspect(error, { depth: null })}\n${String(error)}\n${error.stack}`;
        const basic = Buffer.from(`cid:${SECRET}`).toString('base64');
        const needles = [
          ...windows(SECRET),
          ...windows(REFRESH),
          ...windows(DEVICE),
          ...windows(basic),
        ];
        assert.deepEqual(
          needles.filter((needle) => text.includes(needle)),
          [],
        );
      },
    );
  }
});

describe('a reason phrase that holds a secret', () => {
  const PHRASE_SECRET = 'REVIEW_TEST_SECRET_5d81e0';
  const replying = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.statusCode = 401;
      res.statusMessage = `echo ${PHRASE_SECRET}`;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'invalid_client' }));
    });
  });
  let base = '';
  before(async () => {
    base = `http://127.0.0.1:${await listen(replying)}`;
  });
  after(() => close(replying));

  const auth = () => ({ strategy: clientSecretPost('client-secret-value') });
  /** Every site; `withAuth` picks the path with a strategy. */
  const sites = (withAuth: boolean): [string, () => Promise<unknown>][] => {
    const a = withAuth ? auth() : undefined;
    const secret = withAuth ? undefined : 'client-secret-value';
    return [
      [
        'client credentials',
        () => getTokenWithClientCredentials(base, 'cid', secret, a),
      ],
      ['UAA refresh', () => refreshJwtToken('rt', base, 'cid', secret, a)],
      [
        'UAA authorization code',
        () =>
          exchangeCodeForToken(
            {
              uaaUrl: base,
              uaaClientId: 'cid',
              uaaClientSecret: secret,
            } as Parameters<typeof exchangeCodeForToken>[0],
            'the-code',
            'http://localhost:61001/callback',
            undefined,
            a,
          ),
      ],
      [
        'UAA passcode',
        () => exchangePasscode(base, 'cf', secret, 'PASSCODE', undefined, a),
      ],
      [
        'SAML bearer exchange',
        () =>
          exchangeSamlAssertion(
            'ASSERTION',
            `${base}/token`,
            'cid',
            secret,
            undefined,
            a,
          ),
      ],
      [
        'SAML bearer refresh',
        () =>
          refreshSamlBearerToken(
            'rt',
            `${base}/token`,
            'cid',
            secret,
            undefined,
            a,
          ),
      ],
      [
        'OIDC authorization code',
        () =>
          exchangeAuthorizationCode(
            `${base}/token`,
            'cid',
            secret,
            'the-code',
            'http://localhost:61001/callback',
            'verifier',
            undefined,
            a,
          ),
      ],
      [
        'OIDC refresh',
        () =>
          refreshOidcToken(`${base}/token`, 'cid', secret, 'rt', undefined, a),
      ],
      [
        'OIDC device initiation',
        () =>
          initiateDeviceAuthorization(
            `${base}/device`,
            'cid',
            'openid',
            undefined,
            a,
          ),
      ],
      [
        'OIDC device poll',
        () =>
          pollDeviceTokens(
            `${base}/token`,
            'cid',
            secret,
            'dc',
            0,
            undefined,
            a,
          ),
      ],
      [
        'OIDC password',
        () =>
          passwordGrant(
            `${base}/token`,
            'cid',
            secret,
            'user',
            'pw',
            undefined,
            undefined,
            a,
          ),
      ],
      [
        'OIDC token exchange',
        () =>
          tokenExchange(
            `${base}/token`,
            'cid',
            secret,
            'subject',
            'urn:ietf:params:oauth:token-type:access_token',
            undefined,
            undefined,
            undefined,
            undefined,
            undefined,
            a,
          ),
      ],
    ];
  };

  const windows = (secret: string) => {
    const out: string[] = [];
    for (let i = 0; i + 8 <= secret.length; i++)
      out.push(secret.slice(i, i + 8));
    return out;
  };

  /** Every way the error can be rendered or read, own and inherited. */
  const rendered = (thrown: unknown): string => {
    const parts = [
      String(thrown),
      JSON.stringify(thrown),
      inspect(thrown, { depth: 10, showHidden: true, getters: true }),
    ];
    const value = thrown as Record<string, unknown> & {
      toJSON?: () => unknown;
    };
    if (typeof value?.toJSON === 'function')
      parts.push(JSON.stringify(value.toJSON()));
    for (
      let o: object | null = value;
      o && o !== Object.prototype;
      o = Object.getPrototypeOf(o)
    ) {
      for (const key of Object.getOwnPropertyNames(o)) {
        try {
          const v = (value as Record<string, unknown>)[key];
          if (typeof v !== 'function')
            parts.push(`${key}=${inspect(v, { depth: 10, showHidden: true })}`);
        } catch {
          // a getter that throws renders nothing
        }
      }
    }
    return parts.join('\n');
  };

  for (const [caseIndex, caseRow] of (
    [
      ['without a strategy', false],
      ['with a strategy', true],
    ] as const
  ).entries()) {
    const [_path, withAuth] = caseRow;
    describe(caseTitle('%s', caseRow, caseIndex), () => {
      for (const [caseIndex, caseRow] of sites(withAuth)
        .map(([name], i) => [name, i] as const)
        .entries()) {
        const [_name, index] = caseRow;
        it(
          caseTitle(
            '%s: the thrown error carries no window of the reason phrase',
            caseRow,
            caseIndex,
          ),
          async () => {
            let thrown: unknown;
            try {
              await sites(withAuth)[index]![1]();
            } catch (error) {
              thrown = error;
            }
            assert.notEqual(thrown, undefined);
            const text = rendered(thrown);
            // Not vacuous: the failure is the server's 401.
            contains(text, '401');
            assert.deepEqual(
              windows(PHRASE_SECRET).filter((w) => text.includes(w)),
              [],
            );
            notContains(text, 'echo ');
          },
        );
      }
    });
  }
});
