/**
 * The token-request conversion point (spec §6; plan Task 20; H10, D1–D4):
 * `sendTokenRequest` with a `TokenRequestSite` turns every failure into an
 * `AuthProviderFailure` after its one debug line, and `rejectMissingToken`
 * does the same for a 2xx without a token. By default the line carries the
 * safe facts only — never the server's text, never a secret; only with
 * `authDebug: true` the server's text, every secret the request carried
 * previewed. The sites move onto this in Task 21; here the helper is driven
 * directly.
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
import { exchangeCodeForToken } from '../../auth/browserAuth';
import { previewSecret } from '../../auth/oauthErrorBody';
import {
  legacyBasic,
  type PreparedTokenRequest,
  rejectMissingToken,
  sendTokenRequest,
  type TokenRequestSite,
  type TokenResponseSnapshot,
} from '../../auth/tokenRequest';

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

// ------------------------------------------------------------------ secrets

/** The grant's and the configured client secret: `site.secrets`. */
const REFRESH = 'refresh-token-0123456789abcdefghij';
const CLIENT_SECRET = 'client-secret+with%2Fescapes-0123';
const CLIENT_SECRET_DECODED = 'client-secret with/escapes-0123';
const FIFTEEN = 'abcdefghijklmno';
const SIXTEEN = 'abcdefghijklwxyz';
const SHORT = 'pw7Q';

/** The site's own Basic header: `site.basic`. */
const LEGACY_SECRET = `legacy-basic-secret-${'L'.repeat(40)}`;
const BASIC = legacyBasic('legacy-client-id', LEGACY_SECRET);
const LEGACY_CREDENTIAL = BASIC.header.slice('Basic '.length);

/** The strategy's: `prepared.secrets` (an assertion and a Basic credential). */
const ASSERTION = 'strategy-client-assertion-0123456789-zz';
const STRATEGY_SECRET = `strategy-basic-secret-${'S'.repeat(40)}`;
const STRATEGY_CREDENTIAL = Buffer.from(
  `strategy-client:${STRATEGY_SECRET}`,
).toString('base64');
const PREPARED: PreparedTokenRequest = {
  config: { method: 'post', url: 'https://as.example/token' },
  secrets: [ASSERTION, STRATEGY_CREDENTIAL, STRATEGY_SECRET],
};

/** An unrelated JWT the server put in its text. */
const JWT =
  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTAxMjM0NTY3ODkifQ.c2lnbmF0dXJlLXZhbHVl';

/** The server's own words around the echoes: kept under authDebug only. */
const SERVER_TEXT = 'SERVER-SAID-THIS';
const SERVER_URI = 'https://as.example/errors/SERVER-URI-PATH';

const formEncoded = (value: string): string =>
  new URLSearchParams({ v: value }).toString().slice(2);

/** Each echo of a secret, and the form it is recognised (and previewed) as. */
function echoesOf(secret: string): [echo: string, form: string][] {
  return [
    [secret, secret],
    [formEncoded(secret), secret],
    [encodeURIComponent(secret), secret],
  ];
}

const ALL_ECHOES: [string, string][] = [
  ...echoesOf(REFRESH),
  ...echoesOf(CLIENT_SECRET),
  [CLIENT_SECRET_DECODED, CLIENT_SECRET_DECODED],
  [FIFTEEN, FIFTEEN],
  [SIXTEEN, SIXTEEN],
  [SHORT, SHORT],
  ...echoesOf(LEGACY_CREDENTIAL),
  [LEGACY_SECRET, LEGACY_SECRET],
  ...echoesOf(ASSERTION),
  ...echoesOf(STRATEGY_CREDENTIAL),
  [STRATEGY_SECRET, STRATEGY_SECRET],
  [JWT, JWT],
];

/** Every whole secret form an echo carried: none may survive anywhere. */
const WHOLE_FORMS = [...new Set(ALL_ECHOES.flat())];

// Split over the two fields: each stays under the 512-character cap.
const FIRST = ALL_ECHOES.slice(0, 11);
const SECOND = ALL_ECHOES.slice(11);
const DESCRIPTION = `${SERVER_TEXT} ${FIRST.map(([echo]) => echo).join(' | ')}`;
const EXPECTED_DESCRIPTION = `${SERVER_TEXT} ${FIRST.map(([, form]) => previewSecret(form)).join(' | ')}`;
const URI = `${SERVER_URI}?c=${encodeURIComponent(CLIENT_SECRET)} ${SECOND.map(([echo]) => echo).join(' | ')}`;
const EXPECTED_URI = `${SERVER_URI}?c=${previewSecret(CLIENT_SECRET)} ${SECOND.map(([, form]) => previewSecret(form)).join(' | ')}`;

function site(overrides: Partial<TokenRequestSite> = {}): TokenRequestSite {
  return {
    arm: 'site',
    operation: 'token-refresh',
    grant: 'authorization_code',
    authDebug: false,
    secrets: [REFRESH, CLIENT_SECRET, FIFTEEN, SIXTEEN, SHORT],
    basic: BASIC,
    ...overrides,
  };
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

/** The first line's meta object (the test fails when there is none). */
function metaOf(lines: Line[]): Record<string, unknown> {
  const meta = lines[0]?.meta;
  expect(typeof meta).toBe('object');
  return meta as Record<string, unknown>;
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

function echoingBody(error = 'invalid_grant'): Record<string, string> {
  return { error, error_description: DESCRIPTION, error_uri: URI };
}

async function failureOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected a failure');
}

/** Every rendering a catcher may write of a thrown failure. */
function renderingsOf(failure: unknown): string {
  const error = readFailure(failure, 'unfamiliar-error');
  return [
    JSON.stringify(failure),
    (failure as Error).message,
    String(failure),
    inspect(failure, { depth: null }),
    error.reason,
    error.hint ?? '',
    JSON.stringify(logFields(error)),
  ].join('\n');
}

function expectNothingOfTheServerOrASecret(text: string): void {
  expect(text).not.toContain(SERVER_TEXT);
  expect(text).not.toContain('SERVER-URI-PATH');
  for (const form of WHOLE_FORMS) expect(text).not.toContain(form);
}

/**
 * Each preview at most 4 characters after its `…` and N ≥ 16 when it shows
 * any, under 16 when it shows none. The head is not delimited from the text
 * before it, so the 4-character bound on both ends is checked as "no run of
 * a secret longer than 4" (`longestRunOf`) where it matters, and exactly by
 * the expected strings elsewhere.
 */
function expectBoundedPreviews(text: string): void {
  const previews = [...text.matchAll(/(?:…(\S*) )?<redacted, (\d+) chars>/gu)];
  expect(previews.length).toBeGreaterThan(0);
  for (const [whole, tail, n] of previews) {
    if (whole.startsWith('…')) {
      expect(Number(n)).toBeGreaterThanOrEqual(16);
      expect([...(tail ?? '')].length).toBeLessThanOrEqual(4);
    } else {
      expect(Number(n)).toBeLessThan(16);
    }
  }
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

beforeEach(() => {
  mockedAxios.mockReset();
});

// ------------------------------------------------------------------ the tests

describe('a refused request (400) echoing every secret', () => {
  const ENV = process.env.DEBUG_AUTH_PROVIDERS;
  afterEach(() => {
    if (ENV === undefined) delete process.env.DEBUG_AUTH_PROVIDERS;
    else process.env.DEBUG_AUTH_PROVIDERS = ENV;
  });

  describe.each([
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
  ])('without authDebug (%s)', (_name, make) => {
    it.each([
      ['without a strategy', undefined],
      ['with a strategy', PREPARED],
    ])(
      '%s: exactly the safe-facts line, the same failure, nothing of the server or a secret',
      async (_path, prepared) => {
        const { logger, lines } = recordingLogger();
        const failure = await failureOf(
          send({ ...make(), logger }, rejection(400, echoingBody()), prepared),
        );

        expect(lines).toEqual([
          {
            level: 'debug',
            message:
              'the token refresh: the token endpoint refused the request',
            meta: { status: 400, error: 'invalid_grant' },
            args: 2,
          },
        ]);
        expect(Object.keys(lines[0]?.meta as object)).toEqual([
          'status',
          'error',
        ]);
        expectNothingOfTheServerOrASecret(lines.map(rendered).join('\n'));

        expect(isAuthProviderFailure(failure)).toBe(true);
        const error = readFailure(failure, 'unfamiliar-error');
        expect(error.kind).toBe('request-failed');
        expect(error.facts).toEqual({
          operation: 'token-refresh',
          grant: 'authorization_code',
          problem: 'refused',
          status: 400,
          oauthError: 'invalid_grant',
        });
        expect(error.reason).toBe(
          'the token refresh failed (HTTP 400, invalid_grant)',
        );
        expectNothingOfTheServerOrASecret(renderingsOf(failure));
      },
    );
  });

  describe('with authDebug: true', () => {
    it.each([
      ['without a strategy', undefined],
      ['with a strategy', PREPARED],
    ])(
      '%s: one debug line, the safe facts plus the previewed text',
      async (_path, prepared) => {
        const { logger, lines } = recordingLogger();
        const failure = await failureOf(
          send(
            site({ authDebug: true, logger }),
            rejection(400, echoingBody()),
            prepared,
          ),
        );
        expect(lines).toHaveLength(1);
        const [line] = lines;
        expect(line?.level).toBe('debug');
        expect(line?.message).toBe('[token-refresh] token endpoint said');
        const meta = line?.meta as Record<string, unknown>;
        expect(Object.keys(meta)).toEqual([
          'status',
          'error',
          'error_description',
          'error_uri',
        ]);
        expect(meta.status).toBe(400);
        expect(meta.error).toBe('invalid_grant');
        if (prepared) {
          // Every echoed form of every secret: its own preview, the server's
          // other text kept.
          expect(meta.error_description).toBe(EXPECTED_DESCRIPTION);
        } else {
          // Without the strategy's secrets joined (no `prepared`), only theirs
          // are left: the join's third source is what the other case proves.
          expect(meta.error_description).toContain(SERVER_TEXT);
        }
        if (prepared) expect(meta.error_uri).toBe(EXPECTED_URI);
        else expect(meta.error_uri).toContain('SERVER-URI-PATH');
        const text = rendered(line as Line);
        if (prepared) {
          for (const form of WHOLE_FORMS) expect(text).not.toContain(form);
        }
        expectBoundedPreviews(text);

        // The failure is the default mode's: no server text, no secret.
        const error = readFailure(failure, 'unfamiliar-error');
        expect(error.facts).toEqual({
          operation: 'token-refresh',
          grant: 'authorization_code',
          problem: 'refused',
          status: 400,
          oauthError: 'invalid_grant',
        });
        expectNothingOfTheServerOrASecret(renderingsOf(failure));
      },
    );

    it('the boundary: a 15-character form shows its length only, a 16-character one abcd…wxyz', async () => {
      const { logger, lines } = recordingLogger();
      await failureOf(
        send(
          site({ authDebug: true, logger }),
          rejection(400, { error_description: `a ${FIFTEEN} b ${SIXTEEN} c` }),
        ),
      );
      expect(metaOf(lines).error_description).toBe(
        'a <redacted, 15 chars> b abcd…wxyz <redacted, 16 chars> c',
      );
    });

    it('two forms of one secret are previewed separately', async () => {
      const { logger, lines } = recordingLogger();
      await failureOf(
        send(
          site({ authDebug: true, logger }),
          rejection(400, {
            error_description: `${CLIENT_SECRET} / ${CLIENT_SECRET_DECODED}`,
          }),
        ),
      );
      expect(metaOf(lines).error_description).toBe(
        `${previewSecret(CLIENT_SECRET)} / ${previewSecret(CLIENT_SECRET_DECODED)}`,
      );
    });

    it("the site's Basic credential is previewed only because `basic` is joined", async () => {
      const { logger, lines } = recordingLogger();
      await failureOf(
        send(
          site({ authDebug: true, logger }),
          rejection(400, {
            error_description: `got ${BASIC.header} and ${LEGACY_SECRET}`,
          }),
        ),
      );
      expect(metaOf(lines).error_description).toBe(
        `got Basic ${previewSecret(LEGACY_CREDENTIAL)} and ${previewSecret(LEGACY_SECRET)}`,
      );
    });

    it('no logger: no line, the same failure', async () => {
      const failure = await failureOf(
        send(site({ authDebug: true }), rejection(400, echoingBody())),
      );
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
    'a logger whose debug throws (authDebug %s): the same failure',
    async (authDebug) => {
      const logger: ILogger = {
        debug: () => {
          throw new Error(`logger broke: ${SERVER_TEXT}`);
        },
        info: () => {},
        warn: () => {},
        error: () => {},
      };
      const failure = await failureOf(
        send(site({ authDebug, logger }), rejection(400, echoingBody())),
      );
      expect(isAuthProviderFailure(failure)).toBe(true);
      expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'refused',
        status: 400,
        oauthError: 'invalid_grant',
      });
      expectNothingOfTheServerOrASecret(renderingsOf(failure));
    },
  );

  it.each([['authorization_pending'], ['slow_down']])(
    '%s: no line in either mode — the protocol, not a failure — and the failure carries the code',
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
        message: `certificate ${SERVER_TEXT}`,
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
    expectNothingOfTheServerOrASecret(renderingsOf(failure));
  });

  it('ECONNREFUSED: `request-failed` `no-response`, the safe-facts line with status undefined and the code', async () => {
    const { logger, lines } = recordingLogger();
    const failure = await failureOf(
      send(site({ logger }), {
        code: 'ECONNREFUSED',
        message: `connect ${SERVER_TEXT}`,
      }),
    );
    expect(lines).toEqual([
      {
        level: 'debug',
        message: 'the token refresh: the token endpoint refused the request',
        meta: { status: undefined, code: 'ECONNREFUSED' },
        args: 2,
      },
    ]);
    const error = readFailure(failure, 'unfamiliar-error');
    expect(error.kind).toBe('request-failed');
    expect(error.facts).toEqual({
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
    '%s: `no-response`, no status key, the line still written, no throw from the conversion',
    async (_name, thrown) => {
      const { logger, lines } = recordingLogger();
      const failure = await failureOf(send(site({ logger }), thrown));
      expect(isAuthProviderFailure(failure)).toBe(true);
      const error = readFailure(failure, 'unfamiliar-error');
      expect(error.facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'no-response',
      });
      expect('status' in error.facts).toBe(false);
      expect(lines).toHaveLength(1);
      expect(lines[0]?.message).toBe(
        'the token refresh: the token endpoint refused the request',
      );
    },
  );
});

/**
 * Before / after against 5.4.2: the legacy arm is 5.4.2's code, run on the
 * same input — the new arm's line keeps every key and value it writes, the
 * only extra key `code`.
 */
describe("the new arm's line against 5.4.2's", () => {
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
    await failureOf(
      sendTokenRequest(
        undefined,
        () => Promise.reject(thrown()) as Promise<AxiosResponse<unknown>>,
        { logger: legacy.logger, label: 'Token refresh failed' },
      ),
    );
    const current = recordingLogger();
    await failureOf(send(site({ logger: current.logger }), thrown()));

    expect(legacy.lines).toHaveLength(1);
    expect(current.lines).toHaveLength(1);
    const before = legacy.lines[0]?.meta as Record<string, unknown>;
    const after = current.lines[0]?.meta as Record<string, unknown>;
    for (const key of Object.keys(before)) {
      expect(key in after).toBe(true);
      expect(after[key]).toEqual(before[key]);
    }
    expect(Object.keys(after).filter((key) => !(key in before))).toEqual(extra);
    expect(current.lines[0]?.level).toBe(legacy.lines[0]?.level);
    // The message keeps 5.4.2's shape, the operation's phrase in front.
    expect(legacy.lines[0]?.message).toMatch(
      /: the token endpoint refused the request$/,
    );
    expect(current.lines[0]?.message).toMatch(
      /: the token endpoint refused the request$/,
    );
  });
});

// ------------------------------------------------------------------ a 2xx

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

describe('a 200 without access_token (rejectMissingToken)', () => {
  it.each([['debug' as const], ['error' as const]])(
    'default, at %s: exactly the safe-facts line at that level, nothing of the server or a secret',
    async (level) => {
      const { logger, lines } = recordingLogger();
      const s = site({ logger });
      const snapshot = await answered(s, echoingBody());
      expect('diagnostic' in snapshot).toBe(false);
      const failure = missing(s, snapshot, level, PREPARED);
      expect(lines).toEqual([
        {
          level,
          message:
            'the token refresh failed: status 200, error: "invalid_grant"',
          meta: undefined,
          args: 1,
        },
      ]);
      const error = readFailure(failure, 'unfamiliar-error');
      expect(error.facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'no-access-token',
        status: 200,
      });
      expectNothingOfTheServerOrASecret(renderingsOf(failure));
    },
  );

  it('default: the server text is never read — a getter counting reads stays at zero', async () => {
    let reads = 0;
    const body = {
      error: 'invalid_grant',
      get error_description(): string {
        reads++;
        return DESCRIPTION;
      },
      get error_uri(): string {
        reads++;
        return URI;
      },
    };
    const { logger } = recordingLogger();
    const s = site({ logger });
    const snapshot = await answered(s, body);
    missing(s, snapshot, 'debug');
    expect(reads).toBe(0);
    expect('diagnostic' in snapshot).toBe(false);
  });

  it('authDebug: the same facts plus the previewed text, at the level passed', async () => {
    const { logger, lines } = recordingLogger();
    const s = site({ authDebug: true, logger });
    const snapshot = await answered(s, echoingBody());
    expect(snapshot.diagnostic).toEqual({
      error_description: DESCRIPTION,
      error_uri: URI,
    });
    const failure = missing(s, snapshot, 'debug', PREPARED);
    expect(lines).toHaveLength(1);
    expect(lines[0]?.level).toBe('debug');
    expect(lines[0]?.message).toBe(
      'the token refresh failed: status 200, error: "invalid_grant"',
    );
    expect(lines[0]?.meta).toEqual({
      status: 200,
      error: 'invalid_grant',
      error_description: EXPECTED_DESCRIPTION,
      error_uri: EXPECTED_URI,
    });
    const text = rendered(lines[0] as Line);
    for (const form of WHOLE_FORMS) expect(text).not.toContain(form);
    expectBoundedPreviews(text);
    expectNothingOfTheServerOrASecret(renderingsOf(failure));
  });

  it("the site's Basic credential, and the strategy's, are previewed only because both are joined", async () => {
    const { logger, lines } = recordingLogger();
    const s = site({ authDebug: true, logger });
    const snapshot = await answered(s, {
      error_description: `${BASIC.header} ${STRATEGY_CREDENTIAL}`,
    });
    missing(s, snapshot, 'debug', PREPARED);
    expect(metaOf(lines).error_description).toBe(
      `Basic ${previewSecret(LEGACY_CREDENTIAL)} ${previewSecret(STRATEGY_CREDENTIAL)}`,
    );
  });

  it('no logger: no line, the same failure; a throwing logger: the same failure', async () => {
    const s = site({ authDebug: true });
    const snapshot = await answered(s, echoingBody());
    const quiet = missing(s, snapshot, 'error');
    const throwing = missing(
      {
        ...s,
        logger: {
          debug: () => {
            throw new Error(SERVER_TEXT);
          },
          info: () => {},
          warn: () => {},
          error: () => {
            throw new Error(SERVER_TEXT);
          },
        },
      },
      snapshot,
      'error',
    );
    for (const failure of [quiet, throwing]) {
      expect(isAuthProviderFailure(failure)).toBe(true);
      expect(readFailure(failure, 'unfamiliar-error').facts).toEqual({
        operation: 'token-refresh',
        grant: 'authorization_code',
        problem: 'no-access-token',
        status: 200,
      });
    }
  });

  /**
   * At the UAA code exchange the default line is 5.4.2's own, verbatim: the
   * 5.4.2 site (still on the legacy arm until Task 21) is run on the same
   * answer, and the two `error` lines must be identical.
   */
  it.each([
    [
      'with a registered error',
      { error: 'invalid_grant', error_description: DESCRIPTION },
    ],
    ['without one', { error_description: DESCRIPTION }],
  ])(
    "the code exchange's line is 5.4.2's verbatim (%s)",
    async (_name, body) => {
      const legacy = recordingLogger();
      mockedAxios.mockResolvedValueOnce({ status: 200, data: body } as never);
      await failureOf(
        exchangeCodeForToken(
          {
            uaaUrl: 'https://uaa.example',
            uaaClientId: 'client',
            uaaClientSecret: CLIENT_SECRET,
          },
          'the-code',
          'http://localhost:61001/callback',
          legacy.logger,
        ),
      );
      const before = legacy.lines.filter((line) => line.level === 'error');
      expect(before).toHaveLength(1);

      const current = recordingLogger();
      const s = site({
        operation: 'code-exchange',
        grant: 'authorization_code',
        logger: current.logger,
      });
      missing(s, await answered(s, body), 'error');
      expect(current.lines).toEqual(before);
    },
  );

  it.each([[false], [true]])(
    'a hostile answer (authDebug %s) reads as absent: an empty snapshot, no foreign error',
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
      expect(snapshot.status).toBeUndefined();
      expect(snapshot.data).toEqual({});
      expect(JSON.stringify(snapshot)).not.toContain(SERVER_TEXT);
      if (authDebug) expect(snapshot.diagnostic).toEqual({});
    },
  );
});

/**
 * Recognition first (spec §6), through the helper: the legacy Basic
 * credential and a strategy's Basic credential echoed wrapped — CRLF, LF,
 * tab, spaces and each escaped — at widths 76 and 4, in a 400 and in a 200
 * without access_token.
 */
describe('a whitespace-wrapped Basic credential', () => {
  const wrap = (text: string, width: number, breaker: string): string =>
    (text.match(new RegExp(`.{1,${width}}`, 'g')) ?? []).join(breaker);

  const flattened = (text: string): string =>
    decodeURIComponent(text.replace(/%(?![0-9A-Fa-f]{2})/g, '%25')).replace(
      /\s+/g,
      '',
    );

  const longestRunOf = (text: string, of: string): number => {
    let best = 0;
    for (let i = 0; i < of.length; i++) {
      for (let j = i + best + 1; j <= of.length; j++) {
        if (text.includes(of.slice(i, j))) best = j - i;
        else break;
      }
    }
    return best;
  };

  const BREAKERS: readonly (readonly [string, string])[] = [
    ['CRLF', '\r\n'],
    ['LF', '\n'],
    ['a tab', '\t'],
    ['spaces', ' '],
    ['%0D%0A', '%0D%0A'],
    ['%0A', '%0A'],
    ['%09', '%09'],
    ['%20', '%20'],
  ];
  const CREDENTIALS: [
    string,
    string,
    string,
    PreparedTokenRequest | undefined,
  ][] = [
    [
      'the legacy Basic credential',
      LEGACY_CREDENTIAL,
      LEGACY_SECRET,
      undefined,
    ],
    [
      "a strategy's Basic credential",
      STRATEGY_CREDENTIAL,
      STRATEGY_SECRET,
      PREPARED,
    ],
  ];

  describe.each(CREDENTIALS)('%s', (_name, credential, secret, prepared) => {
    it('is long enough to be wrapped at 76', () => {
      expect(credential.length).toBeGreaterThan(76);
    });
    const cases = BREAKERS.flatMap(([name, breaker]) =>
      [76, 4].map(
        (width) => [`${name}, width ${width}`, breaker, width] as const,
      ),
    );

    const lineOf = async (
      authDebug: boolean,
      status: 400 | 200,
      echoed: string,
    ): Promise<{
      text: string;
      meta: Record<string, unknown>;
      failure: unknown;
    }> => {
      const { logger, lines } = recordingLogger();
      const s = site({ authDebug, logger });
      const body = {
        error: 'invalid_client',
        error_description: `got ${echoed} end`,
      };
      const failure =
        status === 400
          ? await failureOf(send(s, rejection(400, body), prepared))
          : missing(s, await answered(s, body), 'debug', prepared);
      expect(lines).toHaveLength(1);
      return {
        text: rendered(lines[0] as Line),
        meta: (lines[0]?.meta ?? {}) as Record<string, unknown>,
        failure,
      };
    };

    describe.each([[400 as const], [200 as const]])('in a %i', (status) => {
      it.each(cases)(
        '%s: default — only the safe-facts line',
        async (_c, breaker, width) => {
          const echoed = `Basic ${wrap(credential, width, breaker)}`;
          const { text, meta, failure } = await lineOf(false, status, echoed);
          expect(meta.error_description).toBeUndefined();
          expect(longestRunOf(flattened(text), credential)).toBeLessThanOrEqual(
            4,
          );
          expect(longestRunOf(flattened(text), secret)).toBeLessThanOrEqual(4);
          const renderings = flattened(renderingsOf(failure));
          expect(longestRunOf(renderings, credential)).toBeLessThanOrEqual(4);
        },
      );

      it.each(cases)(
        '%s: authDebug — the whole wrapped span is one preview',
        async (_c, breaker, width) => {
          const echoed = `Basic ${wrap(credential, width, breaker)}`;
          const { text, meta, failure } = await lineOf(true, status, echoed);
          expect(meta.error_description).toBe(
            `got Basic ${previewSecret(credential)} end`,
          );
          expect(longestRunOf(flattened(text), credential)).toBeLessThanOrEqual(
            4,
          );
          expect(longestRunOf(flattened(text), secret)).toBeLessThanOrEqual(4);
          const renderings = flattened(renderingsOf(failure));
          expect(longestRunOf(renderings, credential)).toBeLessThanOrEqual(4);
        },
      );
    });
  });
});

/**
 * Review fix 1 (the user's rule: under authDebug a secret shows at most
 * 4 + 4 characters): a server that escapes the echo again — `%252B`,
 * `%2525`, a form body URL-encoded into `error_uri` — is recognised at any
 * depth; without authDebug nothing of it is written at all.
 */
describe('a multiply-escaped echo', () => {
  const once = (value: string): string => encodeURIComponent(value);
  const twice = (value: string): string => once(once(value));
  const thrice = (value: string): string => once(twice(value));
  const formTwice = (value: string): string => formEncoded(formEncoded(value));

  const decodedOf = (value: string): string =>
    new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;

  const SECRETS_UNDER_TEST: [
    string,
    string,
    PreparedTokenRequest | undefined,
  ][] = [
    ['the client secret', CLIENT_SECRET, undefined],
    ['the assertion', `${ASSERTION}+/=`, undefined],
    ['the refresh token', `${REFRESH}/+`, undefined],
    ['the legacy Basic credential', LEGACY_CREDENTIAL, undefined],
    ["the strategy's Basic credential", STRATEGY_CREDENTIAL, PREPARED],
  ];

  const ESCAPINGS: [string, (value: string) => string][] = [
    ['escaped twice (%252B, %2525)', twice],
    ['escaped three times', thrice],
    ['form-encoded twice', formTwice],
    [
      'a form body URL-encoded into error_uri',
      // The parameter is named `p`: a name like `client_secret` would share a
      // 5-character run ("client") with the secrets under test.
      (value) => once(`p=${formEncoded(value)}&x=1`),
    ],
  ];

  describe.each(SECRETS_UNDER_TEST)('%s', (_name, secret, prepared) => {
    const s = (authDebug: boolean, logger: ILogger): TokenRequestSite =>
      site({
        authDebug,
        logger,
        secrets: [`${REFRESH}/+`, CLIENT_SECRET, `${ASSERTION}+/=`],
      });

    const lineFor = async (
      authDebug: boolean,
      status: 400 | 500 | 200,
      echoed: string,
    ): Promise<{ text: string; echoed: string; failure: unknown }> => {
      const { logger, lines } = recordingLogger();
      const body = {
        error: 'invalid_client',
        error_description: `got ${echoed} end`,
        error_uri: `https://as.example/e?r=${echoed}`,
      };
      const failure =
        status === 200
          ? missing(
              s(authDebug, logger),
              await answered(s(authDebug, logger), body),
              'debug',
              prepared,
            )
          : await failureOf(
              send(s(authDebug, logger), rejection(status, body), prepared),
            );
      expect(lines).toHaveLength(1);
      // What became of the echo alone: the server's fields without the
      // fixed words around it — a 5-character run is checked there, where
      // no ordinary word ("client", "refresh") of the line can collide.
      const meta = (lines[0]?.meta ?? {}) as Record<string, unknown>;
      const echoedBack = [
        String(meta.error_description ?? '')
          .replace(/^got /, '')
          .replace(/ end$/, ''),
        String(meta.error_uri ?? '').replace('https://as.example/e?r=', ''),
      ].join(' ');
      return { text: rendered(lines[0] as Line), echoed: echoedBack, failure };
    };

    /** No whole form of the secret, at any depth of decoding. */
    const expectNoWholeForm = (text: string): void => {
      let decoded = text;
      for (let round = 0; round < 6; round++) {
        for (const form of [secret, decodedOf(secret)]) {
          expect(decoded).not.toContain(form);
        }
        decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_e, hex: string) =>
          String.fromCharCode(Number.parseInt(hex, 16)),
        );
      }
    };

    /** No whole form of the secret, nor any 5 characters of it, at any depth of decoding. */
    const expectNoForm = (text: string): void => {
      let flat = text;
      for (let round = 0; round < 6; round++) {
        flat = flat.replace(/%([0-9A-Fa-f]{2})/g, (_e, hex: string) =>
          String.fromCharCode(Number.parseInt(hex, 16)),
        );
      }
      for (const form of [secret, decodedOf(secret)]) {
        let best = 0;
        for (let i = 0; i + best < form.length; i++) {
          while (
            i + best < form.length &&
            flat.includes(form.slice(i, i + best + 1))
          )
            best++;
        }
        expect(best).toBeLessThanOrEqual(4);
      }
      let decoded = text;
      for (let round = 0; round < 6; round++) {
        for (const form of [secret, decodedOf(secret)]) {
          expect(decoded).not.toContain(form);
        }
        try {
          decoded = decodeURIComponent(decoded);
        } catch {
          break;
        }
      }
    };

    describe.each([[400 as const], [500 as const], [200 as const]])(
      'in a %i',
      (status) => {
        it.each(ESCAPINGS)(
          '%s: authDebug — previews only',
          async (_e, escapeOf) => {
            const echoed = escapeOf(secret);
            // Not vacuous: a credential without `+`, `/` or `=` escapes to itself.
            if (/[+/=%]/.test(secret)) expect(echoed).not.toBe(secret);
            const {
              text,
              echoed: back,
              failure,
            } = await lineFor(true, status, echoed);
            expectNoForm(back);
            expectNoWholeForm(text);
            expect(text).toContain('<redacted, ');
            expectBoundedPreviews(text);
            expectNoWholeForm(renderingsOf(failure));
          },
        );

        it.each(ESCAPINGS)(
          '%s: without authDebug — nothing of it',
          async (_e, escapeOf) => {
            const { text, failure } = await lineFor(
              false,
              status,
              escapeOf(secret),
            );
            expectNoWholeForm(text);
            expect(text).not.toContain('got ');
            expect(text).not.toContain('as.example');
            expectNoWholeForm(renderingsOf(failure));
          },
        );
      },
    );
  });
});

/**
 * Review fix 2: the authDebug text is capped after redaction at 512
 * characters (5.4.2's DESCRIPTION_CAP), never inside a preview or a
 * surrogate pair.
 */
describe('the authDebug text is capped', () => {
  const descriptionOf = async (description: string): Promise<string> => {
    const { logger, lines } = recordingLogger();
    await failureOf(
      send(
        site({ authDebug: true, logger }),
        rejection(400, { error_description: description }),
      ),
    );
    return metaOf(lines).error_description as string;
  };

  it('a long text is cut at 512 characters, with an ellipsis', async () => {
    const out = await descriptionOf('x'.repeat(5000));
    expect(out).toBe(`${'x'.repeat(512)}…`);
  });

  it('a text that fits is kept whole', async () => {
    expect(await descriptionOf('y'.repeat(512))).toBe('y'.repeat(512));
  });

  it('never inside a preview: one that does not fit is left out whole', async () => {
    const out = await descriptionOf(
      `${'x'.repeat(500)}${REFRESH}${'z'.repeat(100)}`,
    );
    expect(out).toBe(`${'x'.repeat(500)}…`);
    expect(out).not.toContain('refr');
  });

  it('a preview that fits is kept whole before the cut', async () => {
    const preview = previewSecret(REFRESH);
    const out = await descriptionOf(
      `${'x'.repeat(400)}${REFRESH}${'z'.repeat(500)}`,
    );
    expect(out.startsWith(`${'x'.repeat(400)}${preview}`)).toBe(true);
    expect([...out]).toHaveLength(513);
  });

  it('never inside a surrogate pair', async () => {
    const out = await descriptionOf(`${'x'.repeat(511)}${'😀'.repeat(10)}`);
    expect(out).toBe(`${'x'.repeat(511)}😀…`);
    expect(out).not.toMatch(
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/,
    );
  });
});

/**
 * Review fix 3: the operation's phrase of every token site, pinned — a
 * change in auth-errors' words fails here instead of falling back to
 * `the token request`.
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
    const expected =
      operation === 'code-exchange'
        ? 'Token exchange failed'
        : `${phrase} failed`;
    expect(quiet.lines[0]?.message).toBe(
      `${expected}: status 200, error: no error given`,
    );
  });
});
