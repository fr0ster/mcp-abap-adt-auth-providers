/**
 * A server that echoes the request's `Authorization: Basic` header into its
 * answer gets no form of the client credential back out — against a real
 * socket, axios unmocked, on the path without a client-authentication
 * strategy, where each site builds that header itself (`legacyBasic`).
 *
 * The server echoes what it received — the whole header, the bare base64
 * credential, the credential URL-encoded and form-encoded, and the decoded
 * `id:secret` — in `error_description` and `error_uri`, answering `400`, or
 * `200` without `access_token` (the device initiation: without its required
 * fields). Nothing of the credential may be in the thrown error's message, in
 * any rendering of it, in the response data it keeps, or in any log line.
 */

import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
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
import { legacyBasic } from '../../auth/tokenRequest';

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    );
  });
}
const close = (server: Server) =>
  new Promise<void>((resolve) => server.close(() => resolve()));

/** Every form a server may echo a value in, as the redaction knows them. */
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;
const echoedForms = (value: string): string[] => [
  value,
  new URLSearchParams({ s: value }).toString().slice(2),
  encodeURIComponent(value),
  formDecoded(value),
];

/** What the server puts in its answer: every echo of the header it received. */
function echoesOf(authorization: string): string {
  const credential = authorization.replace(/^Basic\s+/i, '');
  return [
    `header=${authorization}`,
    `base64=${credential}`,
    `url=${encodeURIComponent(credential)}`,
    `form=${new URLSearchParams({ s: credential }).toString().slice(2)}`,
    `decoded=${Buffer.from(credential, 'base64').toString()}`,
  ].join(' ');
}

let status = 400;
let received: string | undefined;

const echoing = createServer((req: IncomingMessage, res) => {
  req.resume();
  req.on('end', () => {
    received = req.headers.authorization;
    const echo = echoesOf(received ?? '');
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        // A 400's OAuth error; a 200 carries no token (nor device fields).
        ...(status === 400 ? { error: 'invalid_client' } : {}),
        error_description: `refused: ${echo}`,
        error_uri: `https://idp.example/err?echo=${encodeURIComponent(echo)}&raw=${echo}`,
      }),
    );
  });
});
let base = '';
beforeAll(async () => {
  base = `http://127.0.0.1:${await listen(echoing)}`;
});
afterAll(() => close(echoing));

function recordingLogger(): { logger: ILogger; text: () => string } {
  const lines: string[] = [];
  const record =
    (level: string) =>
    (...args: unknown[]) => {
      lines.push(
        `${level} ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`,
      );
    };
  return {
    logger: {
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
      debug: record('debug'),
    } as ILogger,
    text: () => lines.join('\n'),
  };
}

/** Every rendering of a thrown value a consumer may log or serialise. */
function renderings(error: unknown): Record<string, string> {
  const e = error as {
    message?: unknown;
    toJSON?: () => unknown;
    response?: { data?: unknown };
    cause?: { response?: { data?: unknown } };
  };
  return {
    message: String(e?.message),
    String: String(error),
    inspect: inspect(error, { depth: null }),
    JSON: JSON.stringify(error) ?? '',
    toJSON:
      typeof e?.toJSON === 'function' ? (JSON.stringify(e.toJSON()) ?? '') : '',
    'response.data': JSON.stringify(e?.response?.data) ?? '',
    'cause.response.data': JSON.stringify(e?.cause?.response?.data) ?? '',
  };
}

interface Credential {
  readonly label: string;
  readonly id: string;
  readonly secret: string;
}
const CREDENTIALS: Credential[] = [
  // Its base64 holds a '/': the URL- and form-encoded echoes differ from it.
  { label: 'a plain id', id: 'cid', secret: 's3cr3t>?~value' },
  // A ':' in the id; '+', '%' and '/' in the secret, '+' and '=' in its base64.
  { label: "an id with ':'", id: 'my:client', secret: 'se+cr%25et/x' },
];

type Run = (c: Credential, logger: ILogger) => Promise<unknown>;

/** Every site that builds its own Basic header without a strategy. */
const BASIC_SITES: [string, Run][] = [
  [
    'UAA authorization code',
    (c, logger) =>
      exchangeCodeForToken(
        {
          uaaUrl: base,
          uaaClientId: c.id,
          uaaClientSecret: c.secret,
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
        logger,
      ),
  ],
  [
    'UAA refresh',
    (c, logger) =>
      refreshJwtToken('rt', base, c.id, c.secret, undefined, logger),
  ],
  [
    'UAA passcode',
    (c, logger) => exchangePasscode(base, c.id, c.secret, 'PASSCODE', logger),
  ],
  [
    'SAML bearer exchange',
    (c, logger) =>
      exchangeSamlAssertion(
        'ASSERTION',
        `${base}/token`,
        c.id,
        c.secret,
        logger,
      ),
  ],
  [
    'SAML bearer refresh',
    (c, logger) =>
      refreshSamlBearerToken('rt', `${base}/token`, c.id, c.secret, logger),
  ],
  [
    'OIDC authorization code',
    (c, logger) =>
      exchangeAuthorizationCode(
        `${base}/token`,
        c.id,
        c.secret,
        'the-code',
        'http://localhost:61001/callback',
        'verifier',
        logger,
      ),
  ],
  [
    'OIDC refresh',
    (c, logger) =>
      refreshOidcToken(`${base}/token`, c.id, c.secret, 'rt', logger),
  ],
  [
    'OIDC token exchange',
    (c, logger) =>
      tokenExchange(
        `${base}/token`,
        c.id,
        c.secret,
        'subject',
        'urn:ietf:params:oauth:token-type:access_token',
        undefined,
        undefined,
        undefined,
        undefined,
        logger,
      ),
  ],
  [
    'OIDC device poll',
    (c, logger) =>
      pollDeviceTokens(`${base}/token`, c.id, c.secret, 'dc', 0, logger),
  ],
  [
    'OIDC password grant',
    (c, logger) =>
      passwordGrant(
        `${base}/token`,
        c.id,
        c.secret,
        'user',
        'pw',
        undefined,
        logger,
      ),
  ],
];

/**
 * Sites with a 2xx-without-token branch that send no Basic header without a
 * strategy: nothing of a Basic credential to leak, checked all the same.
 */
const NON_BASIC_SITES: [string, Run][] = [
  [
    'client credentials',
    (c, logger) =>
      getTokenWithClientCredentials(base, c.id, c.secret, undefined, logger),
  ],
  [
    'OIDC device initiation',
    (c, logger) =>
      initiateDeviceAuthorization(`${base}/device`, c.id, 'openid', logger),
  ],
];

/** Every form of the credential that must not come back out. */
function forbidden(c: Credential, authorization: string | undefined): string[] {
  const credential = authorization?.replace(/^Basic\s+/i, '');
  return [
    ...(credential ? echoedForms(credential) : []),
    ...echoedForms(c.secret),
  ];
}

/**
 * The server's free text (its description and URI) is in no rendering of the
 * thrown error and in no log line: by default nothing the server wrote
 * reaches the consumer. Where the site has a logger, one debug line names the
 * refusal's safe facts (`says`).
 */
function expectNoFreeText(
  rendered: Record<string, string>,
  logs: string,
  says: boolean,
): void {
  for (const [where, text] of Object.entries({ ...rendered, logs })) {
    expect({ where, free: /refused:|idp\.example/.test(text) }).toEqual({
      where,
      free: false,
    });
  }
  const noted = logs
    .split('\n')
    .filter((l) => l.includes('the token endpoint refused the request'));
  expect(noted).toHaveLength(says ? 1 : 0);
  for (const line of noted) expect(line).toMatch(/^debug /);
}

async function expectNoCredential(
  run: Run,
  c: Credential,
  basic: boolean,
  says = false,
): Promise<void> {
  received = undefined;
  const { logger, text } = recordingLogger();
  let thrown: unknown;
  const failed = expect(
    run(c, logger).catch((error: unknown) => {
      thrown = error;
      throw error;
    }),
  ).rejects.toBeDefined();
  await failed;

  if (basic) {
    // Not vacuous: the request carried the credential the server echoed.
    expect(received).toBe(
      `Basic ${Buffer.from(`${c.id}:${c.secret}`).toString('base64')}`,
    );
  } else {
    expect(received).toBeUndefined();
  }
  expectNoFreeText(renderings(thrown), text(), says);
  const surfaces = { ...renderings(thrown), logs: text() };
  for (const form of forbidden(c, received)) {
    for (const [where, rendered] of Object.entries(surfaces)) {
      expect({ where, form, found: rendered.includes(form) }).toEqual({
        where,
        form,
        found: false,
      });
    }
  }
}

describe.each(CREDENTIALS)('a server echoing the Basic header, $label', (c) => {
  describe('in a 400', () => {
    it.each(BASIC_SITES)(
      '%s without a strategy: no form of the credential comes back out',
      async (_label, run) => {
        status = 400;
        await expectNoCredential(run, c, true, true);
      },
    );
  });

  describe('in a 200 without access_token', () => {
    it.each(BASIC_SITES)(
      '%s without a strategy: no form of the credential comes back out',
      async (_label, run) => {
        status = 200;
        // A 200 is no refused request: no debug line.
        await expectNoCredential(run, c, true, false);
      },
    );
    it.each(NON_BASIC_SITES)(
      '%s without a strategy sends no Basic header, and nothing comes back out',
      async (_label, run) => {
        status = 200;
        await expectNoCredential(run, c, false);
      },
    );
  });
});

describe('the UAA code exchange logging a 200 without access_token', () => {
  it('a logger that throws does not replace the failure', async () => {
    status = 200;
    const throwing = {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {
        throw new Error('logger down');
      },
    } as ILogger;
    const failed = expect(
      exchangeCodeForToken(
        {
          uaaUrl: base,
          uaaClientId: 'cid',
          uaaClientSecret: 'secret',
        } as Parameters<typeof exchangeCodeForToken>[0],
        'the-code',
        'http://localhost:61001/callback',
        throwing,
      ),
      // `request-failed` `no-access-token` of the code exchange.
    ).rejects.toThrow('the code exchange returned no access_token');
    await failed;
  });
});

describe('legacyBasic carries its own secrets', () => {
  // They feed the authDebug line's `sent`, by name, each through
  // prepareSecret: the base64 credential and the secret after its first colon.
  it.each(CREDENTIALS)('$label: `basic` and `basic_secret`', (c) => {
    const basic = legacyBasic(c.id, c.secret);
    const credential = basic.header.slice('Basic '.length);
    const decoded = Buffer.from(credential, 'base64').toString();
    expect(basic.secrets).toEqual({
      basic: credential,
      basic_secret: decoded.slice(decoded.indexOf(':') + 1),
    });
  });
});

describe('the debug line never replaces the failure', () => {
  it('a logger whose debug throws: the same error as with none', async () => {
    status = 400;
    const throwing = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {
        throw new Error('logger down');
      },
    } as ILogger;
    const withThrowing = expect(
      refreshJwtToken('rt', base, 'cid', 'secret', undefined, throwing),
      // The operation's words, the status and the registered code.
    ).rejects.toThrow(
      /^the token refresh failed \(HTTP 400, invalid_client\)$/,
    );
    await withThrowing;
    const withNone = expect(
      refreshJwtToken('rt', base, 'cid', 'secret'),
    ).rejects.toThrow(
      /^the token refresh failed \(HTTP 400, invalid_client\)$/,
    );
    await withNone;
  });
});
