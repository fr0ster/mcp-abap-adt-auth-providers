/**
 * Whatever a token request's promise rejects with reaches the consumer only
 * as a safe replacement. A consumer's global axios response interceptor may
 * throw the server's own text — `new Error(r.data.error_description)` — or a
 * primitive, or an object whose getters throw; none of it may come back out
 * of a token site, through its message, any rendering, its cause chain, its
 * response data or a log line. Real socket, axios unmocked, both paths.
 */

import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
} from '@jest/globals';
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
beforeAll(async () => {
  base = `http://127.0.0.1:${await new Promise<number>((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    ),
  )}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

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

describe.each([200, 400])('a %i', (code) => {
  describe.each(INTERCEPTORS)(
    'a global response interceptor that %s',
    (_label, make) => {
      describe.each(PATHS)('%s', (_path, auth) => {
        it.each(SITES)('%s: none of it comes back out', async (_site, run) => {
          status = code;
          intercept(make);
          const { logger, text } = recordingLogger();
          let thrown: unknown;
          const failed = expect(
            run(auth(), logger).catch((error: unknown) => {
              thrown = error;
              throw error;
            }),
          ).rejects.toBeDefined();
          await failed;
          expect(thrown).toBeDefined();
          expect(renderings(thrown)).not.toContain(MARKER);
          expect(text()).not.toContain(MARKER);
        });
      });
    },
  );
});

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

  describe.each(PATHS)('%s', (_path, auth) => {
    it.each([
      [
        'SAML bearer exchange',
        () =>
          exchangeSamlAssertion(
            'A',
            `${base}/token`,
            'cid',
            auth() ? undefined : 'secret',
            throwing,
            auth(),
          ),
      ],
      [
        'SAML bearer refresh',
        () =>
          refreshSamlBearerToken(
            'rt',
            `${base}/token`,
            'cid',
            auth() ? undefined : 'secret',
            throwing,
            auth(),
          ),
      ],
    ])(
      '%s: the safe rejection, not what the logger threw',
      async (_site, run) => {
        status = 400;
        let thrown: unknown;
        const failed = expect(
          run().catch((error: unknown) => {
            thrown = error;
            throw error;
          }),
        ).rejects.toBeDefined();
        await failed;
        expect(axios.isAxiosError(thrown)).toBe(true);
        expect((thrown as Error).message).toBe(
          'Request failed with status code 400',
        );
        expect(renderings(thrown)).not.toContain(MARKER);
      },
    );
  });
});
