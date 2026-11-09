/**
 * Every token site on the error contract's conversion point: real socket, axios
 * unmocked.
 *
 * A server echoes every secret the request carried — each body secret and
 * the `Authorization: Basic` header, in each form a server might echo it (as
 * sent, form-encoded, URI-encoded once and twice, form-decoded, base64; the
 * header whole, its credential, the decoded `id:secret`) — in its
 * `error_description` and `error_uri`, answering `400` or a `200` without a
 * token. Each site runs without a client-authentication strategy and with
 * each shipped one (Basic raw and form, `clientSecretPost`,
 * `privateKeyJwt`), without `authDebug` and with it:
 *
 * - the failure is an `AuthProviderFailure` of the site's operation —
 *   `request-failed` `refused` with the status and the registered code, or
 *   the site's problem for a `2xx` without what it needs — and no rendering
 *   of it holds the server's text or any form of a secret;
 * - exactly one line of the site's (beside the SAML sites' `error` line): by
 *   default the safe-facts line — for a `400` with 5.4.2's keys and values
 *   (before/after against 5.4.2's `logRefusedRequest`, copied as the oracle),
 *   for a `200` the missing-token line at the site's level (`error` at the
 *   UAA code exchange); with `authDebug` the same facts plus `sent`, every
 *   secret the request carried by name — read here from the wire — through
 *   `prepareSecret`, none whole; never the server's text.
 *
 * Header-echo: on the path without a strategy, the sites that
 * build their own Basic header run with a plain credential and with a client
 * id holding `:` and a secret holding `+`, `%` and `/`.
 */

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, afterEach, before, describe, it } from 'node:test';
import { inspect } from 'node:util';
import {
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  IClientAuthentication,
  Operation,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosAdapter } from 'axios';
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
import {
  prepareSecret,
  type TokenRequestAuth,
  type TokenSiteOptions,
} from '../../auth/tokenRequest';
import {
  clientSecretBasic,
  clientSecretPost,
  privateKeyJwt,
} from '../../clientAuthentication';
import { cases, caseTitle, notContains } from '../helpers/expectations';
import { phrase } from '../helpers/tokenRequestSites';
import { logRefusedRequest542 } from '../helpers/v542';

const SERVER_TEXT = 'SERVER-SAYS-5c0e1d';

/** The body parameters whose values are secrets (grant's and strategy's). */
const BODY_SECRETS = [
  'client_secret',
  'client_assertion',
  'refresh_token',
  'code',
  'code_verifier',
  'assertion',
  'passcode',
  'password',
  'device_code',
  'subject_token',
  'actor_token',
];

const formEncoded = (value: string): string =>
  new URLSearchParams({ s: value }).toString().slice(2);
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.split('&').join('%26')}`).get('v') ?? value;

/** Every form a server may echo a value in. */
function formsOf(value: string): string[] {
  return [
    value,
    formEncoded(value),
    encodeURIComponent(value),
    encodeURIComponent(encodeURIComponent(value)),
    formDecoded(value),
    Buffer.from(value).toString('base64'),
  ];
}

/** What a request carried on the wire: its secrets by name, as `sent` names them. */
interface Wire {
  readonly secrets: Record<string, string>;
  /** Every value worth looking for in the output: the secrets and the header. */
  readonly values: string[];
}

function wireOf(req: IncomingMessage, body: string): Wire {
  const secrets: Record<string, string> = {};
  const params = new URLSearchParams(body);
  for (const name of BODY_SECRETS) {
    const value = params.get(name);
    if (value !== null && value !== '') secrets[name] = value;
  }
  const values = [...Object.values(secrets)];
  const authorization = req.headers.authorization;
  if (authorization?.startsWith('Basic ')) {
    const credential = authorization.slice('Basic '.length);
    secrets.basic = credential;
    const decoded = Buffer.from(credential, 'base64').toString();
    const colon = decoded.indexOf(':');
    if (colon >= 0 && colon < decoded.length - 1) {
      secrets.basic_secret = decoded.slice(colon + 1);
    }
    values.push(authorization, credential, decoded);
    if (secrets.basic_secret !== undefined) values.push(secrets.basic_secret);
  }
  return { secrets, values };
}

let status = 400;
let wire: Wire | undefined;
let answered: Record<string, unknown> | undefined;

const echoing = createServer((req, res) => {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', (chunk: string) => {
    body += chunk;
  });
  req.on('end', () => {
    wire = wireOf(req, body);
    const echo = wire.values.flatMap(formsOf).join(' ');
    answered = {
      // A 400's OAuth error; a 200 carries no token (nor device fields).
      ...(status === 400 ? { error: 'invalid_client' } : {}),
      error_description: `${SERVER_TEXT} ${echo}`,
      error_uri: `https://idp.example/${SERVER_TEXT}?echo=${encodeURIComponent(echo)}&raw=${echo}`,
    };
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(answered));
  });
});

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    );
  });
}
let base = '';
before(async () => {
  base = `http://127.0.0.1:${await listen(echoing)}`;
});
after(() => new Promise<void>((resolve) => echoing.close(() => resolve())));

interface Credential {
  readonly label: string;
  readonly id: string;
  readonly secret: string;
}
const PLAIN: Credential = {
  label: 'a plain id',
  id: 'cid',
  secret: 's3cr3t>?~value-0123',
};
/** A ':' in the id; '+', '%' and '/' in the secret, '+' and '=' in its base64. */
const RESERVED: Credential = {
  label: "an id with ':'",
  id: 'my:client',
  secret: 'se+cr%25et/x',
};

interface SiteCase {
  readonly name: string;
  readonly operation: Operation;
  /** 5.4.2's label of the refused-request line. */
  readonly label542: string;
  /** Builds its own Basic header on the path without a strategy. */
  readonly legacyBasic: boolean;
  /** Takes a configured client secret (all but the device initiation). */
  readonly takesSecret: boolean;
  readonly missingLevel: 'error' | 'debug';
  readonly missingProblem: 'no-access-token' | 'incomplete-response';
  readonly run: (
    c: Credential,
    auth: TokenRequestAuth | undefined,
    logger: ILogger,
    options: TokenSiteOptions,
  ) => Promise<unknown>;
}

/** The configured secret: none beside a strategy. */
const own = (c: Credential, auth: TokenRequestAuth | undefined) =>
  auth ? undefined : c.secret;

const CODE = 'the-authorization-code-0123';
const VERIFIER = 'code-verifier-0123456789abcdef';
const REFRESH = 'refresh-token-0123456789abcdef';
const PASSCODE = 'passcode-0123456789';
const PASSWORD = 'pass-word-0123456789';
const DEVICE_CODE = 'device-code-0123456789';
const SUBJECT = 'subject-token-0123456789';
const ASSERTION = 'saml-assertion-0123456789abcdef';

const SITES: SiteCase[] = [
  {
    name: 'UAA code exchange',
    operation: 'code-exchange',
    label542: 'Token exchange failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'error',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      exchangeCodeForToken(
        {
          uaaUrl: base,
          uaaClientId: c.id,
          uaaClientSecret: own(c, auth),
        } as Parameters<typeof exchangeCodeForToken>[0],
        CODE,
        'http://localhost:61001/callback',
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'UAA refresh',
    operation: 'token-refresh',
    label542: 'Token refresh failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      refreshJwtToken(REFRESH, base, c.id, own(c, auth), auth, logger, options),
  },
  {
    name: 'UAA passcode exchange',
    operation: 'passcode-exchange',
    label542: 'Passcode exchange failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      exchangePasscode(
        base,
        c.id,
        own(c, auth),
        PASSCODE,
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'client credentials',
    operation: 'client-credentials',
    label542: 'Client credentials authentication failed',
    legacyBasic: false,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      getTokenWithClientCredentials(
        base,
        c.id,
        own(c, auth),
        auth,
        logger,
        options,
      ),
  },
  {
    name: 'SAML exchange',
    operation: 'saml-token-exchange',
    label542: '[SAML] Token exchange failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      exchangeSamlAssertion(
        ASSERTION,
        `${base}/token`,
        c.id,
        own(c, auth),
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'SAML refresh',
    operation: 'saml-token-refresh',
    label542: '[SAML] Token refresh failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      refreshSamlBearerToken(
        REFRESH,
        `${base}/token`,
        c.id,
        own(c, auth),
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC code exchange',
    operation: 'oidc-token-request',
    label542: 'OIDC authorization code exchange failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      exchangeAuthorizationCode(
        `${base}/token`,
        c.id,
        own(c, auth),
        CODE,
        'http://localhost:61001/callback',
        VERIFIER,
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC refresh',
    operation: 'oidc-token-request',
    label542: 'OIDC token refresh failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      refreshOidcToken(
        `${base}/token`,
        c.id,
        own(c, auth),
        REFRESH,
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC token exchange',
    operation: 'oidc-token-request',
    label542: 'OIDC token exchange failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      tokenExchange(
        `${base}/token`,
        c.id,
        own(c, auth),
        SUBJECT,
        'urn:ietf:params:oauth:token-type:access_token',
        undefined,
        undefined,
        undefined,
        undefined,
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC device initiation',
    operation: 'device-authorization',
    label542: 'OIDC device authorization failed',
    legacyBasic: false,
    takesSecret: false,
    missingLevel: 'debug',
    missingProblem: 'incomplete-response',
    run: (c, auth, logger, options) =>
      initiateDeviceAuthorization(
        `${base}/device`,
        c.id,
        'openid',
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC device poll',
    operation: 'device-poll',
    label542: 'OIDC device poll failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      pollDeviceTokens(
        `${base}/token`,
        c.id,
        own(c, auth),
        DEVICE_CODE,
        0,
        logger,
        auth,
        options,
      ),
  },
  {
    name: 'OIDC password grant',
    operation: 'password-grant',
    label542: 'OIDC password grant failed',
    legacyBasic: true,
    takesSecret: true,
    missingLevel: 'debug',
    missingProblem: 'no-access-token',
    run: (c, auth, logger, options) =>
      passwordGrant(
        `${base}/token`,
        c.id,
        own(c, auth),
        'user',
        PASSWORD,
        undefined,
        logger,
        auth,
        options,
      ),
  },
];

const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

const STRATEGIES: [string, (() => IClientAuthentication) | undefined][] = [
  ['without a strategy', undefined],
  [
    'with clientSecretBasic raw',
    () => clientSecretBasic(PLAIN.secret, { encoding: 'raw' }),
  ],
  [
    'with clientSecretBasic form',
    () => clientSecretBasic(PLAIN.secret, { encoding: 'form' }),
  ],
  ['with clientSecretPost', () => clientSecretPost(PLAIN.secret)],
  [
    'with privateKeyJwt',
    () => privateKeyJwt({ key: signingKey, algorithm: 'RS256' }),
  ],
];

interface Line {
  readonly level: string;
  readonly message: string;
  readonly meta: unknown;
  readonly args: number;
}

function recordingLogger(): { logger: ILogger; lines: Line[] } {
  const lines: Line[] = [];
  const at =
    (level: string) =>
    (...args: unknown[]): void => {
      lines.push({
        level,
        message: String(args[0]),
        meta: args[1],
        args: args.length,
      });
    };
  return {
    logger: {
      debug: at('debug'),
      info: at('info'),
      warn: at('warn'),
      error: at('error'),
    },
    lines,
  };
}

/** Every rendering of a thrown value a consumer may log or serialise. */
function renderings(thrown: unknown): string {
  const e = thrown as { message?: unknown; stack?: unknown };
  return [
    String(e?.message),
    String(thrown),
    String(e?.stack),
    inspect(thrown, { depth: null }),
    JSON.stringify(thrown) ?? '',
    JSON.stringify(logFields(readFailure(thrown, 'unfamiliar-error'))),
  ].join('\n');
}

/** The site's own lines: not `info`, not the SAML sites' `error` line. */
const siteLines = (lines: Line[]): Line[] =>
  lines.filter(
    (line) =>
      line.level !== 'info' &&
      !(line.level === 'error' && line.message.startsWith('[SAML] Token')),
  );

/** Values to look for whole: long enough that no preview can hold one. */
const searched = (w: Wire): string[] =>
  w.values.flatMap(formsOf).filter((form) => form.length >= 9);

/**
 * `sent` as the authDebug line must carry it: the wire's secrets, plus the
 * configured client secret a site names as `client_secret` itself.
 */
function expectedSent(
  site: SiteCase,
  c: Credential,
  strategy: boolean,
  w: Wire,
): Record<string, string> {
  const secrets: Record<string, string> = { ...w.secrets };
  if (!strategy && site.takesSecret && secrets.client_secret === undefined) {
    secrets.client_secret = c.secret;
  }
  return Object.fromEntries(
    Object.entries(secrets).map(([name, value]) => [
      name,
      prepareSecret(value, true),
    ]),
  );
}

async function runCase(
  site: SiteCase,
  c: Credential,
  make: (() => IClientAuthentication) | undefined,
  authDebug: boolean,
): Promise<{ thrown: unknown; lines: Line[]; w: Wire }> {
  wire = undefined;
  const { logger, lines } = recordingLogger();
  const auth = make ? { strategy: make() } : undefined;
  let thrown: unknown;
  const failed = assert.rejects(
    site
      .run(c, auth, logger, authDebug ? { authDebug: true } : {})
      .catch((error: unknown) => {
        thrown = error;
        throw error;
      }),
    (error) => error !== undefined,
  );
  await failed;
  if (wire === undefined) throw new Error('no request reached the server');
  return { thrown, lines, w: wire };
}

function expectNothingEchoed(thrown: unknown, lines: Line[], w: Wire): void {
  const output = [
    renderings(thrown),
    ...lines.map((l) => `${l.message} ${JSON.stringify(l.meta ?? null)}`),
  ].join('\n');
  notContains(output, SERVER_TEXT);
  notContains(output, 'idp.example');
  const found = searched(w).filter((form) => output.includes(form));
  assert.deepEqual(found, []);
}

for (const [caseIndex, caseRow] of SITES.entries()) {
  const site = caseRow;
  describe(caseTitle('$name', caseRow, caseIndex), () => {
    for (const [caseIndex, caseRow] of STRATEGIES.entries()) {
      const [strategyName, make] = caseRow;
      describe(caseTitle('%s', caseRow, caseIndex), () => {
        const credentials =
          make === undefined && site.legacyBasic ? [PLAIN, RESERVED] : [PLAIN];
        for (const [caseIndex, caseRow] of credentials.entries()) {
          const c = caseRow;
          describe(caseTitle('$label', caseRow, caseIndex), () => {
            for (const [caseIndex, caseRow] of cases([
              ['without authDebug', false],
              ['with authDebug', true],
            ]).entries()) {
              const [_mode, authDebug] = caseRow;
              it(
                caseTitle('a 400 echoing every secret, %s', caseRow, caseIndex),
                async () => {
                  status = 400;
                  const { thrown, lines, w } = await runCase(
                    site,
                    c,
                    make,
                    authDebug,
                  );
                  // Not vacuous: on the legacy path the site's own header was sent.
                  if (make === undefined) {
                    assert.equal(
                      w.secrets.basic !== undefined,
                      site.legacyBasic,
                    );
                  }
                  assert.equal(isAuthProviderFailure(thrown), true);
                  const failure = readFailure(thrown, 'unfamiliar-error');
                  assert.equal(failure.kind, 'request-failed');
                  assert.deepEqual(failure.facts, {
                    operation: site.operation,
                    problem: 'refused',
                    status: 400,
                    oauthError: 'invalid_client',
                  });
                  const mine = siteLines(lines);
                  assert.equal(mine.length, 1);
                  if (authDebug) {
                    assert.deepEqual(mine[0], {
                      level: 'debug',
                      message: `[${site.operation}] token endpoint said`,
                      meta: {
                        status: 400,
                        error: 'invalid_client',
                        sent: expectedSent(site, c, make !== undefined, w),
                      },
                      args: 2,
                    });
                  } else {
                    // Before/after: 5.4.2's line for the same answer, every key and
                    // value, no other (no code without a transport failure).
                    const legacy = recordingLogger();
                    logRefusedRequest542(
                      { logger: legacy.logger, label: site.label542 },
                      400,
                      answered,
                    );
                    assert.deepEqual(mine[0]?.meta, legacy.lines[0]?.meta);
                    assert.equal(mine[0]?.level, legacy.lines[0]?.level);
                    assert.equal(
                      mine[0]?.message,
                      `${phrase(site.operation)}: the token endpoint refused the request`,
                    );
                  }
                  expectNothingEchoed(thrown, lines, w);
                  if (strategyName.includes('Basic')) {
                    // The strategy's own Basic credential is named, not echoed.
                    assert.notEqual(w.secrets.basic, undefined);
                  }
                },
              );
            }

            for (const [caseIndex, caseRow] of cases([
              ['without authDebug', false],
              ['with authDebug', true],
            ]).entries()) {
              const [_mode, authDebug] = caseRow;
              it(
                caseTitle(
                  'a 200 without what it needs, echoing every secret, %s',
                  caseRow,
                  caseIndex,
                ),
                async () => {
                  status = 200;
                  const { thrown, lines, w } = await runCase(
                    site,
                    c,
                    make,
                    authDebug,
                  );
                  assert.equal(isAuthProviderFailure(thrown), true);
                  const failure = readFailure(thrown, 'unfamiliar-error');
                  assert.deepEqual(failure.facts, {
                    operation: site.operation,
                    problem: site.missingProblem,
                    status: 200,
                  });
                  const lead =
                    site.operation === 'code-exchange'
                      ? 'Token exchange failed'
                      : `${phrase(site.operation)} failed`;
                  const message = `${lead}: status 200, error: no error given`;
                  const mine = siteLines(lines);
                  assert.deepEqual(mine, [
                    authDebug
                      ? {
                          level: site.missingLevel,
                          message,
                          meta: {
                            status: 200,
                            sent: expectedSent(site, c, make !== undefined, w),
                          },
                          args: 2,
                        }
                      : {
                          level: site.missingLevel,
                          message,
                          meta: undefined,
                          args: 1,
                        },
                  ]);
                  expectNothingEchoed(thrown, lines, w);
                },
              );
            }
          });
        }
      });
    }

    for (const [caseIndex, caseRow] of cases([
      ['a 400', 400],
      ['a 200 without what it needs', 200],
    ]).entries()) {
      const [_name, answer] = caseRow;
      it(
        caseTitle(
          '%s with a logger whose every method throws: the same failure as with a working one',
          caseRow,
          caseIndex,
        ),
        async () => {
          status = answer;
          const working = await runCase(site, PLAIN, undefined, true);
          const down = () => {
            throw new Error(`${SERVER_TEXT} logger down`);
          };
          const throwing = {
            debug: down,
            info: down,
            warn: down,
            error: down,
          } as ILogger;
          // `info` throws before the request on some sites: only the failure
          // lines are under test, so `info` is let through.
          const thrown = await site
            .run(
              PLAIN,
              undefined,
              { ...throwing, info: () => {} },
              {
                authDebug: true,
              },
            )
            .catch((error: unknown) => error);
          assert.equal(isAuthProviderFailure(thrown), true);
          const expected = readFailure(working.thrown, 'unfamiliar-error');
          const failure = readFailure(thrown, 'unfamiliar-error');
          assert.equal(failure.kind, expected.kind);
          assert.deepEqual(failure.facts, expected.facts);
          notContains(renderings(thrown), SERVER_TEXT);
        },
      );
    }
  });
}

/**
 * The snapshot through the real flow: an axios adapter answers `200` without
 * `access_token`; `sendTokenRequest` → the site → `rejectMissingToken`. The
 * server's text is never read (a read-counting getter stays at 0, in both
 * modes), and a hostile body reaches the site only as an empty snapshot or a
 * minted failure — never a marker, never a foreign error.
 */
describe('a 200 without access_token through an axios adapter', () => {
  const MARKER = 'HOSTILE-MARKER-91b2';
  const previous = axios.defaults.adapter;
  afterEach(() => {
    if (previous === undefined) delete axios.defaults.adapter;
    else axios.defaults.adapter = previous;
  });
  const answering = (response: () => unknown): void => {
    axios.defaults.adapter = (async (config: unknown) => {
      const made = response() as Record<string, unknown>;
      return Object.assign(made, { config, request: {} });
    }) as unknown as AxiosAdapter;
  };

  const HOSTILE: [string, () => unknown][] = [
    [
      'a data Proxy whose every trap throws',
      () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        data: new Proxy(
          {},
          new Proxy(
            {},
            {
              get: () => () => {
                throw new Error(MARKER);
              },
            },
          ),
        ),
      }),
    ],
    [
      'getters on error_description, error_uri and access_token that throw',
      () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          get error_description(): string {
            throw new Error(MARKER);
          },
          get error_uri(): string {
            throw new Error(MARKER);
          },
          get access_token(): string {
            throw new Error(MARKER);
          },
        },
      }),
    ],
    [
      'getters on error_description and error_uri that return a marker',
      () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          get error_description(): string {
            return MARKER;
          },
          get error_uri(): string {
            return MARKER;
          },
        },
      }),
    ],
    [
      'a toJSON that throws',
      () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        data: {
          error_description: MARKER,
          toJSON: () => {
            throw new Error(MARKER);
          },
        },
      }),
    ],
    [
      'a data getter that throws',
      () => ({
        status: 200,
        statusText: 'OK',
        headers: {},
        get data(): unknown {
          throw new Error(MARKER);
        },
      }),
    ],
  ];

  for (const [caseIndex, caseRow] of SITES.entries()) {
    const site = caseRow;
    describe(caseTitle('$name', caseRow, caseIndex), () => {
      for (const [caseIndex, caseRow] of cases([
        ['without authDebug', false],
        ['with authDebug', true],
      ]).entries()) {
        const [_mode, authDebug] = caseRow;
        it(
          caseTitle(
            'error_description / error_uri are never read, %s',
            caseRow,
            caseIndex,
          ),
          async () => {
            let reads = 0;
            answering(() => ({
              status: 200,
              statusText: 'OK',
              headers: {},
              data: {
                get error_description(): string {
                  reads++;
                  return SERVER_TEXT;
                },
                get error_uri(): string {
                  reads++;
                  return SERVER_TEXT;
                },
              },
            }));
            const { logger, lines } = recordingLogger();
            const thrown = await site
              .run(PLAIN, undefined, logger, { authDebug })
              .catch((error: unknown) => error);
            assert.equal(reads, 0);
            assert.deepEqual(readFailure(thrown, 'unfamiliar-error').facts, {
              operation: site.operation,
              problem: site.missingProblem,
              status: 200,
            });
            assert.equal(siteLines(lines).length, 1);
          },
        );
      }

      for (const [caseIndex, caseRow] of HOSTILE.flatMap(([name, make]) => [
        [name, make, false] as const,
        [name, make, true] as const,
      ]).entries()) {
        const [_name, make, authDebug] = caseRow;
        it(
          caseTitle(
            '%s (authDebug %s): only a minted failure, no marker',
            caseRow,
            caseIndex,
          ),
          async () => {
            answering(make);
            const { logger, lines } = recordingLogger();
            const thrown = await site
              .run(PLAIN, undefined, logger, { authDebug })
              .catch((error: unknown) => error);
            assert.equal(isAuthProviderFailure(thrown), true);
            assert.equal(
              readFailure(thrown, 'unfamiliar-error').kind,
              'request-failed',
            );
            const output = [
              renderings(thrown),
              ...lines.map(
                (l) => `${l.message} ${JSON.stringify(l.meta ?? null)}`,
              ),
            ].join('\n');
            notContains(output, MARKER);
          },
        );
      }
    });
  }
});
