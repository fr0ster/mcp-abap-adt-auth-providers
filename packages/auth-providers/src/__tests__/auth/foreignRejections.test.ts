/**
 * Whatever a token request's promise rejects with reaches the consumer only
 * as a safe replacement. A consumer's global axios response interceptor may
 * throw the server's own text — `new Error(r.data.error_description)` — or a
 * primitive, or an object whose getters throw; none of it may come back out
 * of a token site, through its message, any rendering, its cause chain, its
 * response data or a log line. Real socket, axios unmocked, both paths.
 */

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, afterEach, before, describe, it } from 'node:test';
import { inspect } from 'node:util';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import { exchangeCodeForToken } from '../../auth/browserAuth';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import { discoverOidc } from '../../auth/oidcDiscovery';
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
import type { TokenRequestAuth } from '../../auth/tokenRequest';
import { clientSecretPost } from '../../clientAuthentication';
import { cases, caseTitle, notContains } from '../helpers/expectations';

const MARKER = 'SERVER-TEXT-7f3c91e2';

let status = 200;
const server = createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        error: 'invalid_grant',
        error_description: `${MARKER} description`,
        error_uri: `https://idp.example/${MARKER}`,
      }),
    );
  });
});
let base = '';
before(async () => {
  base = `http://127.0.0.1:${await new Promise<number>((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    ),
  )}`;
});
after(() => new Promise<void>((resolve) => server.close(() => resolve())));

/** A consumer's global interceptor, on success and on failure alike. */
const INTERCEPTORS: [string, (data: unknown) => unknown][] = [
  [
    'throws the server description as an Error',
    (data) =>
      new Error(
        String((data as { error_description?: unknown })?.error_description),
      ),
  ],
  ['throws a primitive string', () => `${MARKER} primitive`],
  [
    'throws an object whose getters throw',
    () => ({
      note: `${MARKER} note`,
      get code(): string {
        throw new Error(`${MARKER} code getter`);
      },
      get response(): unknown {
        throw new Error(`${MARKER} response getter`);
      },
      get message(): string {
        throw new Error(`${MARKER} message getter`);
      },
    }),
  ],
];

let installed: number | undefined;
afterEach(() => {
  if (installed !== undefined) axios.interceptors.response.eject(installed);
  installed = undefined;
});
function intercept(make: (data: unknown) => unknown): void {
  installed = axios.interceptors.response.use(
    (response: AxiosResponse) => {
      throw make(response.data);
    },
    (error: unknown) => {
      throw make((error as { response?: { data?: unknown } })?.response?.data);
    },
  );
}

type Run = (
  auth: TokenRequestAuth | undefined,
  logger: ILogger,
) => Promise<unknown>;
const own = (auth: TokenRequestAuth | undefined) =>
  auth ? undefined : 'secret';

const SITES: [string, Run][] = [
  [
    'UAA authorization code',
    (auth, logger) =>
      exchangeCodeForToken(
        {
          uaaUrl: base,
          uaaClientId: 'cid',
          uaaClientSecret: own(auth),
        } as Parameters<typeof exchangeCodeForToken>[0],
        'code',
        'http://localhost:61001/callback',
        logger,
        auth,
      ),
  ],
  [
    'UAA refresh',
    (auth, logger) =>
      refreshJwtToken('rt', base, 'cid', own(auth), auth, logger),
  ],
  [
    'UAA passcode',
    (auth, logger) =>
      exchangePasscode(base, 'cid', own(auth), 'PC', logger, auth),
  ],
  [
    'client credentials',
    (auth, logger) =>
      getTokenWithClientCredentials(base, 'cid', own(auth), auth, logger),
  ],
  [
    'SAML bearer exchange',
    (auth, logger) =>
      exchangeSamlAssertion(
        'A',
        `${base}/token`,
        'cid',
        own(auth),
        logger,
        auth,
      ),
  ],
  [
    'SAML bearer refresh',
    (auth, logger) =>
      refreshSamlBearerToken(
        'rt',
        `${base}/token`,
        'cid',
        own(auth),
        logger,
        auth,
      ),
  ],
  [
    'OIDC authorization code',
    (auth, logger) =>
      exchangeAuthorizationCode(
        `${base}/token`,
        'cid',
        own(auth),
        'code',
        'http://localhost:61001/callback',
        'verifier',
        logger,
        auth,
      ),
  ],
  [
    'OIDC refresh',
    (auth, logger) =>
      refreshOidcToken(`${base}/token`, 'cid', own(auth), 'rt', logger, auth),
  ],
  [
    'OIDC token exchange',
    (auth, logger) =>
      tokenExchange(
        `${base}/token`,
        'cid',
        own(auth),
        'subject',
        'urn:ietf:params:oauth:token-type:access_token',
        undefined,
        undefined,
        undefined,
        undefined,
        logger,
        auth,
      ),
  ],
  [
    'OIDC device initiation',
    (auth, logger) =>
      initiateDeviceAuthorization(
        `${base}/device`,
        'cid',
        'openid',
        logger,
        auth,
      ),
  ],
  [
    'OIDC device poll',
    (auth, logger) =>
      pollDeviceTokens(
        `${base}/token`,
        'cid',
        own(auth),
        'dc',
        0,
        logger,
        auth,
      ),
  ],
  [
    'OIDC password grant',
    (auth, logger) =>
      passwordGrant(
        `${base}/token`,
        'cid',
        own(auth),
        'user',
        'pw',
        undefined,
        logger,
        auth,
      ),
  ],
  ['OIDC discovery', () => discoverOidc(`${base}/issuer-${Math.random()}`)],
];

function recordingLogger(): { logger: ILogger; text: () => string } {
  const lines: string[] = [];
  const record = (...args: unknown[]) => {
    lines.push(args.map((a) => inspect(a, { depth: null })).join(' '));
  };
  return {
    logger: {
      info: record,
      warn: record,
      error: record,
      debug: record,
    } as ILogger,
    text: () => lines.join('\n'),
  };
}

/** Every rendering of the thrown value, its whole cause chain included. */
function renderings(thrown: unknown): string {
  const out: string[] = [];
  let current: unknown = thrown;
  for (
    let depth = 0;
    current !== undefined && current !== null && depth < 10;
    depth++
  ) {
    const e = current as {
      message?: unknown;
      response?: { data?: unknown };
      cause?: unknown;
    };
    out.push(
      String(e.message),
      String(current),
      inspect(current, { depth: null }),
      JSON.stringify(current) ?? '',
      JSON.stringify(e.response?.data) ?? '',
    );
    current = e.cause;
  }
  return out.join('\n');
}

const PATHS: [string, () => TokenRequestAuth | undefined][] = [
  ['without a strategy', () => undefined],
  ['with clientSecretPost', () => ({ strategy: clientSecretPost('secret') })],
];

for (const [caseIndex, caseRow] of [200, 400].entries()) {
  const code = caseRow;
  describe(caseTitle('a %i', caseRow, caseIndex), () => {
    for (const [caseIndex, caseRow] of INTERCEPTORS.entries()) {
      const [_label, make] = caseRow;
      describe(
        caseTitle('a global response interceptor that %s', caseRow, caseIndex),
        () => {
          for (const [caseIndex, caseRow] of PATHS.entries()) {
            const [_path, auth] = caseRow;
            describe(caseTitle('%s', caseRow, caseIndex), () => {
              for (const [caseIndex, caseRow] of SITES.entries()) {
                const [_site, run] = caseRow;
                it(
                  caseTitle(
                    '%s: none of it comes back out',
                    caseRow,
                    caseIndex,
                  ),
                  async () => {
                    status = code;
                    intercept(make);
                    const { logger, text } = recordingLogger();
                    let thrown: unknown;
                    const failed = assert.rejects(
                      run(auth(), logger).catch((error: unknown) => {
                        thrown = error;
                        throw error;
                      }),
                      (error) => error !== undefined,
                    );
                    await failed;
                    assert.notEqual(thrown, undefined);
                    notContains(renderings(thrown), MARKER);
                    notContains(text(), MARKER);
                  },
                );
              }
            });
          }
        },
      );
    }
  });
}

describe('a consumer logger that throws while a site reports the failure', () => {
  const throwing = {
    info: () => {},
    warn: () => {},
    debug: () => {
      throw new Error(`${MARKER} debug`);
    },
    error: () => {
      throw new Error(`${MARKER} error`);
    },
  } as ILogger;
  const quiet = {
    info: () => {},
    warn: () => {},
    debug: () => {},
    error: () => {},
  } as ILogger;

  for (const [caseIndex, caseRow] of PATHS.entries()) {
    const [_path, auth] = caseRow;
    describe(caseTitle('%s', caseRow, caseIndex), () => {
      for (const [caseIndex, caseRow] of cases([
        [
          'SAML bearer exchange',
          'saml-token-exchange',
          (logger: ILogger) =>
            exchangeSamlAssertion(
              'A',
              `${base}/token`,
              'cid',
              auth() ? undefined : 'secret',
              logger,
              auth(),
            ),
        ],
        [
          'SAML bearer refresh',
          'saml-token-refresh',
          (logger: ILogger) =>
            refreshSamlBearerToken(
              'rt',
              `${base}/token`,
              'cid',
              auth() ? undefined : 'secret',
              logger,
              auth(),
            ),
        ],
      ]).entries()) {
        const [_site, operation, run] = caseRow;
        it(
          caseTitle(
            '%s: the same failure as with a working logger, not what the logger threw',
            caseRow,
            caseIndex,
          ),
          async () => {
            status = 400;
            const working = await run(quiet).catch((error: unknown) => error);
            let thrown: unknown;
            const failed = assert.rejects(
              run(throwing).catch((error: unknown) => {
                thrown = error;
                throw error;
              }),
              (error) => error !== undefined,
            );
            await failed;
            // Guarded failure-path logging: an
            // AuthProviderFailure of the site's operation, equal in kind and
            // facts to the one a working logger sees.
            assert.equal(isAuthProviderFailure(thrown), true);
            const failure = readFailure(thrown, 'unfamiliar-error');
            assert.equal(failure.kind, 'request-failed');
            assert.deepEqual(failure.facts, {
              operation,
              problem: 'refused',
              status: 400,
              oauthError: 'invalid_grant',
            });
            const expected = readFailure(working, 'unfamiliar-error');
            assert.equal(failure.kind, expected.kind);
            assert.deepEqual(failure.facts, expected.facts);
            notContains(renderings(thrown), MARKER);
          },
        );
      }
    });
  }
});

/**
 * A fulfilled interceptor hands the site data it cannot trust: a getter, a
 * Proxy trap or `toJSON` that throws the server's text. Every site reads
 * only a snapshot built through `readSafely`, so none of it comes out.
 */
const HOSTILE_DATA: [string, (data: unknown) => unknown][] = [
  [
    'a field getter that throws the description',
    (data) => {
      const words = String(
        (data as { error_description?: unknown })?.error_description,
      );
      return {
        get access_token(): string {
          throw new Error(words);
        },
        get token_endpoint(): string {
          throw new Error(words);
        },
        get device_code(): string {
          throw new Error(words);
        },
      };
    },
  ],
  [
    'a Proxy whose every trap throws',
    () =>
      new Proxy(
        {},
        {
          get: () => {
            throw new Error(`${MARKER} get trap`);
          },
          has: () => {
            throw new Error(`${MARKER} has trap`);
          },
          ownKeys: () => {
            throw new Error(`${MARKER} ownKeys trap`);
          },
          getOwnPropertyDescriptor: () => {
            throw new Error(`${MARKER} descriptor trap`);
          },
        },
      ),
  ],
  [
    'data whose toJSON throws',
    () => ({
      note: `${MARKER} note`,
      toJSON: () => {
        throw new Error(`${MARKER} toJSON`);
      },
    }),
  ],
];

for (const [caseIndex, caseRow] of HOSTILE_DATA.entries()) {
  const [_label, make] = caseRow;
  describe(
    caseTitle('a fulfilled interceptor returning %s', caseRow, caseIndex),
    () => {
      for (const [caseIndex, caseRow] of PATHS.entries()) {
        const [_path, auth] = caseRow;
        describe(caseTitle('%s', caseRow, caseIndex), () => {
          for (const [caseIndex, caseRow] of SITES.entries()) {
            const [_site, run] = caseRow;
            it(
              caseTitle('%s: none of it comes back out', caseRow, caseIndex),
              async () => {
                status = 200;
                installed = axios.interceptors.response.use(
                  (response: AxiosResponse) => ({
                    ...response,
                    data: make(response.data),
                  }),
                );
                const { logger, text } = recordingLogger();
                let thrown: unknown;
                const failed = assert.rejects(
                  run(auth(), logger).catch((error: unknown) => {
                    thrown = error;
                    throw error;
                  }),
                  (error) => error !== undefined,
                );
                await failed;
                notContains(renderings(thrown), MARKER);
                notContains(text(), MARKER);
              },
            );
          }
        });
      }
    },
  );
}
