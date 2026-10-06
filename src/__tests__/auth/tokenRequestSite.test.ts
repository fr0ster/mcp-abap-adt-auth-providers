/**
 * The token-request conversion point (spec §6; plan Task 20; H10, D1–D4):
 * `sendTokenRequest` with a `TokenRequestSite` turns every failure into an
 * `AuthProviderFailure` after its one debug line, and `rejectMissingToken`
 * does the same for a 2xx without a token.
 *
 * The rule (spec §6, "The secret preparer, not a redactor", 2026-10-06): the
 * server's text is never read, never logged, never kept — with or without
 * `authDebug`. By default the line carries the safe facts only; with
 * `authDebug: true` it carries the same facts plus `sent`, each secret the
 * request carried by name through `prepareSecret`. Nothing scans text for
 * secrets. Here the helper is driven directly, against a server echoing every
 * secret in every form; the sites' own cases are in `tokenSites.test.ts`.
 */

import { inspect } from 'node:util';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import {
  isAuthProviderFailure,
  logFields,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosResponse } from 'axios';
import {
  legacyBasic,
  type PreparedTokenRequest,
  prepareSecret,
  prepareTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  type TokenRequestSite,
  type TokenResponseSnapshot,
} from '../../auth/tokenRequest';
import {
  codeExchangeMissingTokenLine542,
  logRefusedRequest542,
} from '../helpers/v542';

// Automocked, with axios's own error classes: the prepared path calls axios.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  const actual = jest.requireActual<Record<string, unknown>>('axios');
  mocked.AxiosError = actual.AxiosError;
  mocked.CanceledError = actual.CanceledError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock;

// ------------------------------------------------------------------ prepareSecret

describe('prepareSecret', () => {
  it.each([
    ['', '<redacted, 0 chars>'],
    ['a', '<redacted, 1 chars>'],
    ['abcdefghijklmno', '<redacted, 15 chars>'],
    ['abcdefghijklwxyz', 'abcd…wxyz <redacted, 16 chars>'],
    ['abcdefghijklmwxyz', 'abcd…wxyz <redacted, 17 chars>'],
  ])('authDebug: %j → %j', (value, prepared) => {
    expect(prepareSecret(value, true)).toBe(prepared);
  });

  it.each([
    '',
    'a',
    'abcdefghijklwxyz',
    'a-much-longer-secret-value-0123456789',
  ])('without authDebug %j is its length only', (value) => {
    expect(prepareSecret(value, false)).toBe(
      `<redacted, ${[...value].length} chars>`,
    );
  });

  it("anything but `true` is off: 'true', 1", () => {
    expect(
      prepareSecret('abcdefghijklwxyz', 'true' as unknown as boolean),
    ).toBe('<redacted, 16 chars>');
    expect(prepareSecret('abcdefghijklwxyz', 1 as unknown as boolean)).toBe(
      '<redacted, 16 chars>',
    );
  });

  it('whole characters: an astral character at each edge, counted once', () => {
    const value = `😀bcd${'x'.repeat(10)}wxy😀`;
    expect(prepareSecret(value, true)).toBe('😀bcd…wxy😀 <redacted, 18 chars>');
    expect(prepareSecret('😀'.repeat(15), true)).toBe('<redacted, 15 chars>');
  });

  it('a long JWT: 4 + 4 characters and its length', () => {
    const jwt = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(4)}.c2lnbmF0dXJl`;
    expect(prepareSecret(jwt, true)).toBe(
      `eyJh…dXJl <redacted, ${jwt.length} chars>`,
    );
  });
});

// ------------------------------------------------------------------ secrets

/** The grant's and the configured client secret: `site.secrets`. */
const REFRESH = 'refresh-token-0123456789abcdefghij';
const CLIENT_SECRET = 'client-secret+with%2Fescapes-0123';
const FIFTEEN = 'abcdefghijklmno';
const SIXTEEN = 'abcdefghijklwxyz';
const PASSWORD = 'pw7Q';

/** The site's own Basic header: `site.basic`. */
const LEGACY_SECRET = `legacy-basic-secret-${'L'.repeat(40)}`;
const BASIC = legacyBasic('legacy-client-id', LEGACY_SECRET);
const LEGACY_CREDENTIAL = BASIC.header.slice('Basic '.length);

/** The strategy's: `prepared.secrets`. */
const ASSERTION = 'strategy-client-assertion-0123456789-zz';
const STRATEGY_SECRET = `strategy-basic-secret-${'S'.repeat(40)}`;
const STRATEGY_CREDENTIAL = Buffer.from(
  `strategy-client:${STRATEGY_SECRET}`,
).toString('base64');
const PREPARED: PreparedTokenRequest = {
  config: { method: 'post', url: 'https://as.example/token' },
  secrets: {
    client_assertion: ASSERTION,
    basic: STRATEGY_CREDENTIAL,
    basic_secret: STRATEGY_SECRET,
  },
};

const SITE_SECRETS = {
  refresh_token: REFRESH,
  client_secret: CLIENT_SECRET,
  code: FIFTEEN,
  code_verifier: SIXTEEN,
  password: PASSWORD,
};

/** The server's own words around the echoes: never read, never logged. */
const SERVER_TEXT = 'SERVER-SAID-THIS';
const SERVER_URI = 'https://as.example/errors/SERVER-URI-PATH';

const ALL_SECRETS = [
  REFRESH,
  CLIENT_SECRET,
  FIFTEEN,
  SIXTEEN,
  PASSWORD,
  LEGACY_CREDENTIAL,
  LEGACY_SECRET,
  ASSERTION,
  STRATEGY_CREDENTIAL,
  STRATEGY_SECRET,
];

const formEncoded = (value: string): string =>
  new URLSearchParams({ v: value }).toString().slice(2);
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;

/** Every form a server may echo a secret in. */
const formsOf = (secret: string): string[] => [
  ...new Set([
    secret,
    formEncoded(secret),
    encodeURIComponent(secret),
    encodeURIComponent(encodeURIComponent(secret)),
    formDecoded(secret),
    Buffer.from(secret).toString('base64'),
  ]),
];

/** Each whole form of every secret: none may appear anywhere. */
const WHOLE_FORMS = ALL_SECRETS.flatMap(formsOf);

const ECHO = ALL_SECRETS.flatMap(formsOf).join(' | ');
const JWT_ECHO =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTAxMjM0NTY3ODkifQ.c2lnbmF0dXJlLXZhbHVl';

function echoingBody(error = 'invalid_grant'): Record<string, string> {
  return {
    error,
    error_description: `${SERVER_TEXT} ${ECHO} ${JWT_ECHO}`,
    error_uri: `${SERVER_URI}?echo=${encodeURIComponent(ECHO)}`,
  };
}

function site(overrides: Partial<TokenRequestSite> = {}): TokenRequestSite {
  return {
    operation: 'token-refresh',
    grant: 'authorization_code',
    authDebug: false,
    secrets: SITE_SECRETS,
    basic: BASIC,
    ...overrides,
  };
}

/** `sent` as the authDebug line must carry it for these sources. */
function expectedSent(
  authDebug: boolean,
  prepared: PreparedTokenRequest | undefined,
): Record<string, string> {
  const named: Record<string, string> = {
    ...SITE_SECRETS,
    basic: LEGACY_CREDENTIAL,
    basic_secret: LEGACY_SECRET,
  };
  const all = prepared
    ? { ...(prepared.secrets as Record<string, string>), ...named }
    : named;
  // The site's own come first; a name already given is not replaced.
  const out: Record<string, string> = {};
  for (const source of [
    SITE_SECRETS,
    { basic: LEGACY_CREDENTIAL, basic_secret: LEGACY_SECRET },
    prepared?.secrets ?? {},
  ]) {
    for (const [name, value] of Object.entries(source)) {
      if (typeof value === 'string' && !(name in out)) {
        out[name] = prepareSecret(value, authDebug);
      }
    }
  }
  expect(Object.keys(out).sort()).toEqual(Object.keys(all).sort());
  return out;
}

// ------------------------------------------------------------------ logging

interface Line {
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  meta: unknown;
  args: number;
}

function recordingLogger(): { logger: ILogger; lines: Line[] } {
  const lines: Line[] = [];
  const at =
    (level: Line['level']) =>
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

const rendered = (line: Line): string =>
  `${line.message} ${JSON.stringify(line.meta ?? null)}`;

// ------------------------------------------------------------------ failures

function rejection(status: unknown, data: unknown, code?: string): unknown {
  return {
    isAxiosError: true,
    message: `Request failed: ${SERVER_TEXT}`,
    ...(code === undefined ? {} : { code }),
    response: { status, data, statusText: SERVER_TEXT },
  };
}

async function failureOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a failure');
}

/** Every rendering a catcher may write of a thrown failure, its refusal included. */
function renderingsOf(failure: unknown): string {
  const error = readFailure(failure, 'unfamiliar-error');
  return [
    JSON.stringify(failure),
    (failure as Error).message,
    String(failure),
    inspect(failure, { depth: null }),
    JSON.stringify(error),
    error.reason,
    error.hint ?? '',
    JSON.stringify(logFields(error)),
  ].join('\n');
}

/** No server text and no whole echoed form of any secret. */
function expectNothingOfTheServerOrAnEcho(text: string): void {
  expect(text).not.toContain(SERVER_TEXT);
  expect(text).not.toContain('SERVER-URI-PATH');
  expect(text).not.toContain(JWT_ECHO);
  for (const form of WHOLE_FORMS) expect(text).not.toContain(form);
}

const send = (
  s: TokenRequestSite,
  failure: unknown,
  prepared?: PreparedTokenRequest,
): Promise<unknown> => {
  if (prepared) mockedAxios.mockRejectedValueOnce(failure as never);
  return sendTokenRequest(
    prepared,
    () => Promise.reject(failure) as Promise<AxiosResponse<unknown>>,
    s,
  );
};

/** A 2xx answer through the new arm, as the site would receive it. */
async function answered(
  s: TokenRequestSite,
  data: unknown,
): Promise<TokenResponseSnapshot> {
  return sendTokenRequest(
    undefined,
    () => Promise.resolve({ status: 200, data } as AxiosResponse<unknown>),
    s,
  ) as Promise<TokenResponseSnapshot>;
}

function missing(
  s: TokenRequestSite,
  snapshot: TokenResponseSnapshot,
  level: 'error' | 'debug',
  prepared?: PreparedTokenRequest,
): unknown {
  try {
    rejectMissingToken(s, prepared, snapshot, 'no-access-token', level);
  } catch (error) {
    return error;
  }
  throw new Error('expected rejectMissingToken to throw');
}

/** One answer through the site — a 400 or 500 refused, or a 200 without a token. */
async function through(
  s: TokenRequestSite,
  status: 400 | 500 | 200,
  prepared: PreparedTokenRequest | undefined,
): Promise<unknown> {
  return status === 200
    ? missing(s, await answered(s, echoingBody()), 'debug', prepared)
    : failureOf(send(s, rejection(status, echoingBody()), prepared));
}

beforeEach(() => {
  mockedAxios.mockReset();
});

// ------------------------------------------------------------------ the rule

describe('a server echoing every secret in every form', () => {
  const ENV = process.env.DEBUG_AUTH_PROVIDERS;
  afterEach(() => {
    if (ENV === undefined) delete process.env.DEBUG_AUTH_PROVIDERS;
    else process.env.DEBUG_AUTH_PROVIDERS = ENV;
  });

  const OFF: [string, () => TokenRequestSite][] = [
    [
      'absent',
      () => {
        const { authDebug: _dropped, ...absent } = site();
        return absent as TokenRequestSite;
      },
    ],
    ['false', () => site({ authDebug: false })],
    [
      "the string 'true'",
      () => site({ authDebug: 'true' as unknown as boolean }),
    ],
    [
      'false, with DEBUG_AUTH_PROVIDERS=true in the environment',
      () => {
        process.env.DEBUG_AUTH_PROVIDERS = 'true';
        return site({ authDebug: false });
      },
    ],
  ];
  const STATUSES: [400 | 500 | 200][] = [[400], [500], [200]];
  const PATHS: [string, PreparedTokenRequest | undefined][] = [
    ['without a strategy', undefined],
    ['with a strategy', PREPARED],
  ];

  describe.each(OFF)('authDebug %s', (_name, make) => {
    describe.each(STATUSES)('a %i', (status) => {
      it.each(PATHS)(
        '%s: exactly the safe-facts line — no secret, no server text',
        async (_path, prepared) => {
          const { logger, lines } = recordingLogger();
          const failure = await through(
            { ...make(), logger },
            status,
            prepared,
          );
          expect(lines).toEqual([
            status === 200
              ? {
                  level: 'debug',
                  message:
                    'the token refresh failed: status 200, error: "invalid_grant"',
                  meta: undefined,
                  args: 1,
                }
              : {
                  level: 'debug',
                  message:
                    'the token refresh: the token endpoint refused the request',
                  meta: { status, error: 'invalid_grant' },
                  args: 2,
                },
          ]);
          expectNothingOfTheServerOrAnEcho(lines.map(rendered).join('\n'));
          expect(isAuthProviderFailure(failure)).toBe(true);
          expect(readFailure(failure, 'unfamiliar-error').facts).toEqual(
            status === 200
              ? {
                  operation: 'token-refresh',
                  grant: 'authorization_code',
                  problem: 'no-access-token',
                  status: 200,
                }
              : {
                  operation: 'token-refresh',
                  grant: 'authorization_code',
                  problem: 'refused',
                  status,
                  oauthError: 'invalid_grant',
                },
          );
          expectNothingOfTheServerOrAnEcho(renderingsOf(failure));
        },
      );
    });
  });

  describe('authDebug: true', () => {
    describe.each(STATUSES)('a %i', (status) => {
      it.each(PATHS)(
        '%s: the safe facts plus `sent` only — no server text, no echoed form',
        async (_path, prepared) => {
          const { logger, lines } = recordingLogger();
          const failure = await through(
            site({ authDebug: true, logger }),
            status,
            prepared,
          );
          expect(lines).toHaveLength(1);
          const [line] = lines;
          expect(line).toEqual(
            status === 200
              ? {
                  level: 'debug',
                  message:
                    'the token refresh failed: status 200, error: "invalid_grant"',
                  meta: {
                    status: 200,
                    error: 'invalid_grant',
                    sent: expectedSent(true, prepared),
                  },
                  args: 2,
                }
              : {
                  level: 'debug',
                  message: '[token-refresh] token endpoint said',
                  meta: {
                    status,
                    error: 'invalid_grant',
                    sent: expectedSent(true, prepared),
                  },
                  args: 2,
                },
          );
          expectNothingOfTheServerOrAnEcho(rendered(line as Line));
          expectNothingOfTheServerOrAnEcho(renderingsOf(failure));
        },
      );
    });

    it('the boundaries: a 15-character secret its length only, a 16-character one abcd…wxyz', async () => {
      const { logger, lines } = recordingLogger();
      await through(site({ authDebug: true, logger }), 400, undefined);
      expect(lines).toHaveLength(1);
      const sent = (
        lines[0] as Line & { meta: { sent: Record<string, string> } }
      ).meta.sent;
      expect(sent.code).toBe('<redacted, 15 chars>');
      expect(sent.code_verifier).toBe('abcd…wxyz <redacted, 16 chars>');
      expect(sent.password).toBe('<redacted, 4 chars>');
    });

    it('no logger: no line, the same failure', async () => {
      const failure = await through(site({ authDebug: true }), 400, PREPARED);
      expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'refused',
        status: 400,
        oauthError: 'invalid_grant',
      });
    });
  });

  it.each([[false], [true]])(
    'a logger whose methods throw (authDebug %s): the same failure',
    async (authDebug) => {
      const broken = (): never => {
        throw new Error(`logger broke: ${SERVER_TEXT}`);
      };
      const logger: ILogger = {
        debug: broken,
        info: broken,
        warn: broken,
        error: broken,
      };
      for (const status of [400, 200] as const) {
        const failure = await through(
          site({ authDebug, logger }),
          status,
          PREPARED,
        );
        expect(isAuthProviderFailure(failure)).toBe(true);
        expectNothingOfTheServerOrAnEcho(renderingsOf(failure));
      }
    },
  );

  it('the server text is never read, in either mode: getters counting reads stay at zero', async () => {
    for (const authDebug of [false, true]) {
      let reads = 0;
      const body = {
        error: 'invalid_grant',
        get error_description(): string {
          reads++;
          return SERVER_TEXT;
        },
        get error_uri(): string {
          reads++;
          return SERVER_URI;
        },
      };
      const { logger } = recordingLogger();
      const s = site({ authDebug, logger });
      await failureOf(send(s, rejection(400, body)));
      missing(s, await answered(s, body), 'debug');
      expect(reads).toBe(0);
    }
  });

  it.each([['authorization_pending'], ['slow_down']])(
    '%s: no line in either mode, and the failure carries the code',
    async (code) => {
      for (const authDebug of [false, true]) {
        const { logger, lines } = recordingLogger();
        const failure = await failureOf(
          send(
            site({
              operation: 'device-poll',
              grant: undefined,
              authDebug,
              logger,
            }),
            rejection(400, echoingBody(code)),
          ),
        );
        expect(lines).toEqual([]);
        expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
          operation: 'device-poll',
          problem: 'refused',
          status: 400,
          oauthError: code,
        });
      }
    },
  );
});

describe('a failure without a response', () => {
  it('a TLS code: `tls`, and the safe-facts line with status undefined and the code', async () => {
    const { logger, lines } = recordingLogger();
    const failure = await failureOf(
      send(site({ logger }), {
        code: 'CERT_HAS_EXPIRED',
        message: SERVER_TEXT,
      }),
    );
    expect(lines).toEqual([
      {
        level: 'debug',
        message: 'the token refresh: the token endpoint refused the request',
        meta: { status: undefined, code: 'CERT_HAS_EXPIRED' },
        args: 2,
      },
    ]);
    const error = readFailure(failure, 'unfamiliar-error');
    expect(error.kind).toBe('tls');
    expect(error.facts).toEqual({
      operation: 'token-refresh',
      grant: 'authorization_code',
      code: 'CERT_HAS_EXPIRED',
    });
  });

  it('ECONNREFUSED: `request-failed` `no-response`, the line with status undefined and the code', async () => {
    const { logger, lines } = recordingLogger();
    const failure = await failureOf(
      send(site({ logger }), { code: 'ECONNREFUSED', message: SERVER_TEXT }),
    );
    expect(lines[0]?.meta).toEqual({ status: undefined, code: 'ECONNREFUSED' });
    expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
      operation: 'token-refresh',
      grant: 'authorization_code',
      problem: 'no-response',
      code: 'ECONNREFUSED',
    });
  });

  // RF2: a status that is not an HTTP status is no response.
  it.each([
    ['status 0', rejection(0, echoingBody())],
    ['status 999', rejection(999, echoingBody())],
    [
      'a response without status',
      { response: { data: echoingBody() }, message: SERVER_TEXT },
    ],
  ])(
    '%s: `no-response`, no status key, the line still written',
    async (_name, thrown) => {
      const { logger, lines } = recordingLogger();
      const failure = await failureOf(send(site({ logger }), thrown));
      expect(isAuthProviderFailure(failure)).toBe(true);
      expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'no-response',
      });
      expect(lines).toHaveLength(1);
    },
  );
});

/**
 * Before / after against 5.4.2: 5.4.2's `logRefusedRequest`, copied verbatim
 * as the oracle (`helpers/v542.ts`), run on the same input — the line keeps
 * every key and value it writes, the only extra key `code` (H10).
 */
describe("the line against 5.4.2's", () => {
  it.each([
    ['a 400 with a registered error', () => rejection(400, echoingBody()), []],
    [
      'a TLS failure',
      () => ({ code: 'SELF_SIGNED_CERT_IN_CHAIN', message: SERVER_TEXT }),
      ['code'],
    ],
    [
      'a rejection with no response',
      () => ({ code: 'ECONNREFUSED', message: SERVER_TEXT }),
      ['code'],
    ],
  ])('%s', async (_name, thrown, extra) => {
    const legacy = recordingLogger();
    const input = thrown() as {
      response?: { status?: unknown; data?: unknown };
    };
    logRefusedRequest542(
      { logger: legacy.logger, label: 'Token refresh failed' },
      input.response?.status,
      input.response?.data,
    );
    const current = recordingLogger();
    await failureOf(send(site({ logger: current.logger }), thrown()));
    const before = legacy.lines[0]?.meta as Record<string, unknown>;
    const after = current.lines[0]?.meta as Record<string, unknown>;
    expect(before).toBeDefined();
    for (const key of Object.keys(before))
      expect(after[key]).toEqual(before[key]);
    expect(Object.keys(after).filter((key) => !(key in before))).toEqual(extra);
    expect(current.lines[0]?.level).toBe(legacy.lines[0]?.level);
  });
});

describe('a 200 without access_token (rejectMissingToken)', () => {
  /**
   * At the UAA code exchange the default line is 5.4.2's own, verbatim: 5.4.2's
   * formatting, copied as the oracle (`helpers/v542.ts`), on the same answer.
   */
  it.each([
    [
      'with a registered error',
      { error: 'invalid_grant', error_description: SERVER_TEXT },
    ],
    ['without one', { error_description: SERVER_TEXT }],
  ])(
    "the code exchange's line is 5.4.2's verbatim (%s)",
    async (_name, body) => {
      const current = recordingLogger();
      const s = site({
        operation: 'code-exchange',
        grant: 'authorization_code',
        logger: current.logger,
      });
      missing(s, await answered(s, body), 'error');
      expect(current.lines).toEqual([
        {
          level: 'error',
          message: codeExchangeMissingTokenLine542({ status: 200, data: body }),
          meta: undefined,
          // 5.4.2 passed the message alone.
          args: 1,
        },
      ]);
    },
  );

  it.each([[false], [true]])(
    'a hostile answer (authDebug %s) reads as absent: an empty snapshot',
    async (authDebug) => {
      const hostile = new Proxy(
        {},
        {
          get() {
            throw new Error(SERVER_TEXT);
          },
          getOwnPropertyDescriptor() {
            throw new Error(SERVER_TEXT);
          },
        },
      );
      const unreadable = {
        get status(): unknown {
          throw new Error(SERVER_TEXT);
        },
        data: hostile,
      };
      const snapshot = await sendTokenRequest(
        undefined,
        () => Promise.resolve(unreadable as unknown as AxiosResponse<unknown>),
        site({ authDebug }),
      );
      expect(snapshot).toEqual({ status: undefined, data: {} });
    },
  );
});

/**
 * Every token site's operation phrase, pinned: a change in auth-errors'
 * words fails here instead of falling back to `the token request`.
 */
describe("each token site's phrase", () => {
  it.each([
    ['code-exchange', undefined, 'the code exchange'],
    ['token-refresh', undefined, 'the token refresh'],
    ['client-credentials', undefined, 'the client credentials request'],
    ['passcode-exchange', undefined, 'the passcode exchange'],
    ['saml-token-exchange', undefined, 'the SAML token exchange'],
    ['saml-token-refresh', undefined, 'the SAML token refresh'],
    ['oidc-token-request', undefined, 'the OIDC token request'],
    ['device-authorization', undefined, 'the OIDC device authorization'],
    ['device-poll', undefined, 'the device poll'],
    ['password-grant', undefined, 'the OIDC password grant'],
    ['token-request', 'authorization_code', 'authorization_code token request'],
  ] as const)('%s (grant %s): %s', async (operation, grant, phrase) => {
    const { logger, lines } = recordingLogger();
    await failureOf(
      send(site({ operation, grant, logger }), rejection(400, {})),
    );
    expect(lines[0]?.message).toBe(
      `${phrase}: the token endpoint refused the request`,
    );
    const quiet = recordingLogger();
    const s = site({ operation, grant, logger: quiet.logger });
    missing(s, await answered(s, {}), 'debug');
    const lead =
      operation === 'code-exchange'
        ? 'Token exchange failed'
        : `${phrase} failed`;
    expect(quiet.lines[0]?.message).toBe(
      `${lead}: status 200, error: no error given`,
    );
  });
});

/**
 * `basicSecrets` in plain code accepts exactly what 5.4.2's
 * `/^Basic\s+(\S+)$/i` accepted (the regex is the oracle here, in the test
 * only), and names every `Authorization` header, in any casing of the name.
 */
describe("a strategy's Basic header, read without a regex", () => {
  const ORACLE = /^Basic\s+(\S+)$/i;
  const credential = Buffer.from('id:the-secret').toString('base64');
  const preparedWith = (headers: Record<string, string>) =>
    prepareTokenRequest(
      {
        endpoint: 'https://as.example/token',
        clientId: 'id',
        grantType: 'client_credentials',
        parameters: new URLSearchParams({ grant_type: 'client_credentials' }),
      },
      { strategy: { authenticate: async () => ({ headers }) } },
    );

  it.each([
    `Basic ${credential}`,
    `basic  ${credential}`,
    `BASIC\t${credential}`,
    `Basic ${credential}`,
    `Basic\v${credential}`,
    `Basic  ${credential}`,
    `Basic ${credential} `,
    `Basic ${credential} `,
    `Basic a bc`,
    'Basic a\fbc',
    `Basic${credential}`,
    'Basic ',
    'Basic',
    `xBasic ${credential}`,
    `Bearer ${credential}`,
  ])('%j: as the regex read it', async (value) => {
    const expected = ORACLE.exec(value)?.[1];
    const prepared = await preparedWith({ Authorization: value });
    if (expected === undefined) {
      expect(prepared.secrets).toEqual({});
    } else {
      const decoded = Buffer.from(expected, 'base64').toString();
      const colon = decoded.indexOf(':');
      expect(prepared.secrets).toEqual(
        colon >= 0 && colon < decoded.length - 1
          ? { basic: expected, basic_secret: decoded.slice(colon + 1) }
          : { basic: expected },
      );
    }
  });

  it('every Authorization header, in any casing of the name, is named', async () => {
    const other = Buffer.from('id2:other-secret').toString('base64');
    const prepared = await preparedWith({
      Authorization: `Basic ${credential}`,
      authorization: `Basic ${other}`,
    });
    expect(prepared.secrets).toEqual({
      basic: credential,
      basic_secret: 'the-secret',
      basic_2: other,
      basic_secret_2: 'other-secret',
    });
  });
});
