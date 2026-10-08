/**
 * No token the provider holds reaches a log line, not even in part. formatToken used to return a
 * token of 50 characters or fewer whole, and a longer one's first and last 25
 * characters. A UAA refresh token is about 34 characters, so it was logged
 * outright.
 */

import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AuthorizationRequest,
  IAssertionValidator,
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { exchangeCodeForToken } from '../../auth/browserAuth';
import {
  composeAuthorization,
  consumerPresentation,
  loopback,
  oauthCode,
  openInBrowser,
} from '../../authorization';
import {
  clientSecretBasic,
  clientSecretPost,
  privateKeyJwt,
  tlsClientCertificate,
} from '../../clientAuthentication';
import { refreshStatePersistence } from '../../persistence';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { refreshThenLogin } from '../../renewal';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { staticCodeStrategy } from '../../strategies';
import { jwt, quiet, rejectionOf } from '../helpers/attemptHarness';
import { recordingBrowser } from '../helpers/recordingBrowser';
import { ScriptedProvider, tokens } from '../helpers/scriptedProvider';
import { SITES, tokenReply } from '../helpers/tokenRequestSites';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & {
  post: Mock;
  isAxiosError: jest.Mock<(e: unknown) => boolean>;
};

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');

/** An unexpired JWT, so getTokens returns it from cache without a request. */
const ACCESS_TOKEN = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
  exp: Math.floor(Date.now() / 1000) + 3600,
  sub: 'user',
})}.signaturepartthatislongenoughtomatter`;
/** Shaped like a UAA refresh token: opaque, 34 characters. */
const REFRESH_TOKEN = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-r';

/** One logged call: its level, message and meta as given. */
interface Line {
  readonly level: string;
  readonly message: string;
  readonly meta: Record<string, unknown> | undefined;
}

function recordingLogger(): {
  logger: ILogger;
  lines: string[];
  entries: Line[];
} {
  const lines: string[] = [];
  const entries: Line[] = [];
  const record = (level: string) => (message: string, meta?: unknown) => {
    lines.push(`${level} ${message} ${JSON.stringify(meta ?? {})}`);
    entries.push({
      level,
      message,
      meta:
        meta !== null && typeof meta === 'object'
          ? { ...(meta as Record<string, unknown>) }
          : undefined,
    });
  };
  return {
    logger: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    } as ILogger,
    lines,
    entries,
  };
}

/** Every 8-character window of a secret, so a partial leak is caught too. */
const windows = (secret: string) =>
  Array.from({ length: secret.length - 7 }, (_, i) => secret.slice(i, i + 8));

describe('no token in the logs', () => {
  it('logs neither the access token nor the refresh token, in whole or in part', async () => {
    const { logger, lines } = recordingLogger();
    const provider = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      accessToken: ACCESS_TOKEN,
      refreshToken: REFRESH_TOKEN,
      authorization: staticCodeStrategy({ payload: 'unused' }),
      logger,
    });
    await provider.getTokens();

    expect(lines.length).toBeGreaterThan(0);
    const all = lines.join('\n');
    for (const secret of [ACCESS_TOKEN, REFRESH_TOKEN]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
    // What is logged instead says a token was there, and how long it was.
    expect(all).toContain(`<redacted, ${REFRESH_TOKEN.length} chars>`);
  });

  it('the tokens persistence is handed reach no log line — the provider’s, or the shipped strategy’s on a failed write', async () => {
    const { logger, lines } = recordingLogger();
    const NEW_ACCESS = jwt('new-access-token-value');
    const NEW_REFRESH = 'f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4-n';
    let failures = 2;
    const provider = new ScriptedProvider({
      renewal: refreshThenLogin(),
      accessToken: jwt('held', -3600),
      refreshToken: REFRESH_TOKEN,
      logger,
      persistence: refreshStatePersistence(
        async () => {
          if (failures-- > 0) throw new Error('store unavailable');
        },
        { onWriteFailure: 'continue', logger },
      ),
    });
    const first = provider.getTokens();
    (await provider.refreshes.nth(1)).result.resolve(
      tokens(NEW_ACCESS, NEW_REFRESH),
    );
    await first;
    // The next report delivers the pending refresh token again, and fails.
    provider.expire();
    const second = provider.getTokens();
    (await provider.refreshes.nth(2)).result.resolve(tokens(jwt('third')));
    await second;
    const all = lines.join('\n');
    expect(all).toContain(
      '[refreshStatePersistence] Writing the tokens failed',
    );
    for (const secret of [NEW_ACCESS, NEW_REFRESH, REFRESH_TOKEN]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
  });

  it('logs no part of seeded cookies, or of an opaque token seeded with expiresAt', async () => {
    const COOKIES =
      'SAP_SESSIONID_ABC_100=cookievaluethatissecret; sap-usercontext=c';
    const OPAQUE = 'opaque-seeded-token-with-no-exp-claim';
    const { logger, lines } = recordingLogger();
    const expiresAt = Date.now() + 3600_000;
    const saml = new Saml2PureProvider({
      renewal: refreshThenLogin(),
      idpSsoUrl: 'https://idp/sso',
      spEntityId: 'sp',
      idpInitiated: true,
      authorization: staticCodeStrategy({ payload: 'unused' }),
      assertionValidator: {} as IAssertionValidator,
      cookieProvider: async () => 'unused',
      accessToken: COOKIES,
      expiresAt,
      logger,
    });
    await saml.getTokens();
    const code = new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientSecret: 'secret',
      accessToken: OPAQUE,
      expiresAt,
      authorization: staticCodeStrategy({ payload: 'unused' }),
      logger,
    });
    await code.getTokens();

    const all = lines.join('\n');
    // Both were answered from the seed, and said so.
    expect(all).toContain(`<redacted, ${COOKIES.length} chars>`);
    expect(all).toContain(`<redacted, ${OPAQUE.length} chars>`);
    for (const secret of [COOKIES, OPAQUE]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
  });
});

describe('no secret of a client authentication in the logs', () => {
  const dir = join(__dirname, '..', 'fixtures', 'certificates');
  const PASSPHRASE = 'test-passphrase';
  const SECRET = 'Zq8vK2pX9wLm4rT7nB3c';
  const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();
  const pemPair: ICertificateMaterial = {
    cert: readFileSync(join(dir, 'client.crt')),
    key: readFileSync(join(dir, 'client-encrypted.key')),
    passphrase: PASSPHRASE,
  };
  const pfx: ICertificateMaterial = {
    pfx: readFileSync(join(dir, 'client.pfx')),
    passphrase: PASSPHRASE,
  };

  /** The base64 body of a PEM, or of DER bytes: what a leak would show. */
  const body = (value: string | Buffer | undefined): string =>
    value === undefined
      ? ''
      : Buffer.isBuffer(value) && !value.toString().includes('-----BEGIN')
        ? value.toString('base64')
        : value
            .toString()
            .replace(/-----[^-]+-----/g, '')
            .replace(/\s+/g, '');
  const longWindows = (secret: string) =>
    Array.from({ length: Math.max(0, secret.length - 15) }, (_, i) =>
      secret.slice(i, i + 16),
    );

  /** Every value a strategy sent in a body or a header, recorded as it left. */
  const recordedFrom = (strategy: IClientAuthentication, seen: string[]) => ({
    ...strategy,
    authenticate: async (
      draft: Parameters<IClientAuthentication['authenticate']>[0],
    ) => {
      const result = await strategy.authenticate(draft);
      for (const record of [result.parameters, result.headers]) {
        for (const [name, value] of Object.entries(record ?? {})) {
          if (name !== 'client_id' && name !== 'client_assertion_type') {
            seen.push(value);
          }
        }
      }
      return result;
    },
  });

  const STRATEGIES: [
    string,
    () => IClientAuthentication,
    ICertificateMaterial?,
  ][] = [
    ['clientSecretBasic', () => clientSecretBasic(SECRET, { encoding: 'raw' })],
    [
      'clientSecretBasic form',
      () => clientSecretBasic(SECRET, { encoding: 'form' }),
    ],
    ['clientSecretPost', () => clientSecretPost(SECRET)],
    [
      'privateKeyJwt',
      () => privateKeyJwt({ key: signingKey, algorithm: 'RS256' }),
    ],
    [
      'tlsClientCertificate (PEM, encrypted key)',
      () => tlsClientCertificate({ material: pemPair }),
      pemPair,
    ],
    [
      'tlsClientCertificate (PFX)',
      () => tlsClientCertificate({ material: pfx }),
      pfx,
    ],
  ];

  beforeEach(() => {
    jest.resetAllMocks();
    mockedAxios.isAxiosError.mockImplementation(
      (e) => !!(e as { isAxiosError?: boolean } | null)?.isAxiosError,
    );
  });

  describe.each(STRATEGIES)('%s', (_name, make, material) => {
    it.each(SITES.map((site) => [site.name, site] as const))(
      '%s: neither on success nor in a failure whose body echoes what was sent',
      async (_site, site) => {
        const sent: string[] = [];
        const { logger, lines } = recordingLogger();
        const auth = { strategy: recordedFrom(make(), sent), material };

        mockedAxios.mockResolvedValue(tokenReply);
        await site.run(auth, logger);

        // The server echoes what this request sent, not an earlier one.
        const before = sent.length;
        mockedAxios.mockImplementation(async () => {
          const echoed = sent.slice(before).join(' ');
          throw {
            isAxiosError: true,
            message: 'Request failed with status code 400',
            response: {
              status: 400,
              data: {
                error: `invalid_client ${echoed}`,
                error_description: echoed,
              },
            },
          };
        });
        let message = '';
        let data = '';
        try {
          await site.run(auth, logger);
        } catch (error) {
          // Since 6.0.0 an AuthProviderFailure: its message and every
          // rendering of it are its error's fixed words.
          expect(isAuthProviderFailure(error)).toBe(true);
          message = String((error as { message?: unknown }).message ?? error);
          data = `${JSON.stringify(error)} ${JSON.stringify(
            readFailure(error, 'unfamiliar-error'),
          )}`;
        }

        expect(sent.length > 0 || material !== undefined).toBe(true);
        const all = `${lines.join('\n')}\n${message}\n${data}`;
        // The failure is not vacuous: the site failed on the 400. Nothing the
        // server wrote reached the message, a log line or the reduced body —
        // its `error` here is not a registered code, so not even that.
        expect(message).toContain('400');
        expect(all).not.toContain('invalid_client');
        for (const secret of [SECRET, PASSPHRASE, ...sent]) {
          for (const window of windows(secret)) {
            expect(all).not.toContain(window);
          }
        }
        for (const bytes of [
          signingKey,
          body(material?.cert),
          body(material?.key),
          body(material?.pfx),
        ]) {
          for (const window of longWindows(body(bytes))) {
            expect(all).not.toContain(window);
          }
        }
      },
    );
  });
});

/**
 * No message of a thrown value reaches a log line. A collaborator the consumer
 * supplies — a client-authentication strategy, a certificate loader, the
 * interactive strategy, a device-code presenter, a SAML validator, a
 * persistence strategy (and the shipped one's `write`), a browser launcher, an
 * SNC locator or probe — may throw an error whose text holds a key, a
 * passphrase or a token, and so may a network failure. A line about a failure
 * carries `logFields` of its classified error — `{ error: reason, kind,
 * status?, diagnostics? }` — and nothing else of it: never its message.
 */
describe('no message of a thrown error in the logs', () => {
  const MARKER = 'REVIEW_TEST_PRIVATE_KEY_7f3a9c';
  const thrown = (kind: 'Error' | 'string') =>
    kind === 'Error' ? new Error(MARKER) : MARKER;
  /** What `logFields` may carry, and nothing else of a failure. */
  const FIELDS = new Set(['error', 'kind', 'status', 'diagnostics']);

  /** Expired, so getTokens renews: a refresh first, then a login. */
  const EXPIRED = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) - 60,
  })}.sig`;
  type Exercised = Pick<
    AuthorizationCodeProvider,
    'prepare' | 'getTokens' | 'refreshTokens' | 'rejected'
  >;
  const refused400 = () => ({
    isAxiosError: true,
    message: 'Request failed with status code 400',
    response: { status: 400, data: { error: 'invalid_grant' } },
  });

  beforeEach(() => {
    jest.resetAllMocks();
    mockedAxios.isAxiosError.mockImplementation(
      (e) => !!(e as { isAxiosError?: boolean } | null)?.isAxiosError,
    );
    answer(async () => tokenReply);
  });

  /** Both ways a site sends: `axios(config)` and `axios.post(url, …)`. */
  const answer = (reply: (url: string) => Promise<unknown>) => {
    mockedAxios.mockImplementation(async (config: any) => reply(config.url));
    mockedAxios.post.mockImplementation(async (url: any) => reply(url));
  };

  /**
   * Every moment that can run the collaborator; none may throw out but
   * `getTokens()` / `refreshTokens()`, and they throw only an
   * `AuthProviderFailure` holding nothing of the marker.
   */
  async function exercise(provider: Exercised) {
    for (const run of [
      () => provider.getTokens(),
      () => provider.refreshTokens(),
    ]) {
      try {
        await run();
      } catch (error) {
        expect(isAuthProviderFailure(error)).toBe(true);
        expect(JSON.stringify(error)).not.toContain(MARKER);
        expect(String(error)).not.toContain(MARKER);
      }
    }
    await provider.prepare();
    await provider.rejected({ at: 'request', status: 401, error: undefined });
  }

  const codeProvider = (
    logger: ILogger,
    extra: Partial<ConstructorParameters<typeof AuthorizationCodeProvider>[0]>,
  ) =>
    new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      accessToken: EXPIRED,
      refreshToken: REFRESH_TOKEN,
      authorization: staticCodeStrategy({ payload: 'the-code' }),
      logger,
      ...(extra.clientAuthentication ? {} : { clientSecret: 'secret' }),
      ...extra,
    } as ConstructorParameters<typeof AuthorizationCodeProvider>[0]);

  /** A line the case must write: its message, and its exact `logFields`. */
  interface Expected {
    readonly message: string;
    readonly fields: Readonly<Record<string, unknown>>;
  }

  const REFRESH_LINE = '[BaseTokenProvider] Refresh failed';
  const CASES: [
    string,
    (logger: ILogger, kind: 'Error' | 'string') => Exercised,
    Expected | undefined,
  ][] = [
    [
      'H1 — a client-authentication strategy whose authenticate() throws',
      (logger, kind) =>
        codeProvider(logger, {
          clientAuthentication: {
            authenticate: async () => {
              throw thrown(kind);
            },
          },
        }),
      {
        message: REFRESH_LINE,
        fields: {
          error: 'the refresh failed (unknown error)',
          kind: 'unknown',
        },
      },
    ],
    [
      'rule 2 — a client-authentication strategy whose tlsMaterial() throws',
      (logger, kind) =>
        codeProvider(logger, {
          clientAuthentication: {
            authenticate: async (draft) => ({
              parameters: { client_id: draft.clientId },
            }),
            tlsMaterial: async () => {
              throw thrown(kind);
            },
          },
        }),
      undefined,
    ],
    [
      'rule 2 — a certificate loader that throws',
      (logger, kind) =>
        codeProvider(logger, {
          clientAuthentication: tlsClientCertificate({
            material: async () => {
              throw thrown(kind);
            },
          }),
        }),
      undefined,
    ],
    [
      'H1 — a network failure whose message holds the secret',
      (logger, kind) => {
        answer(async () => {
          throw thrown(kind);
        });
        return codeProvider(logger, {});
      },
      {
        message: REFRESH_LINE,
        fields: {
          error: 'the token refresh failed (the token endpoint gave no reason)',
          kind: 'request-failed',
        },
      },
    ],
    [
      'H1 — an interactive strategy that throws, after a refused refresh',
      (logger, kind) => {
        answer(async () => {
          throw refused400();
        });
        return codeProvider(logger, {
          authorization: {
            authorize: async () => {
              throw thrown(kind);
            },
          },
        });
      },
      {
        message: REFRESH_LINE,
        fields: {
          error: 'the token refresh failed (HTTP 400, invalid_grant)',
          kind: 'request-failed',
          status: 400,
        },
      },
    ],
    [
      'H2 — a persistence strategy whose awaited report throws',
      (logger, kind) =>
        codeProvider(logger, {
          persistence: {
            report: async () => {
              throw thrown(kind);
            },
          },
        }),
      undefined,
    ],
    [
      "H2 — refreshStatePersistence whose write throws, logging to the provider's logger",
      (logger, kind) =>
        codeProvider(logger, {
          persistence: refreshStatePersistence(
            async () => {
              throw thrown(kind);
            },
            { onWriteFailure: 'fail', logger },
          ),
        }),
      {
        message: '[refreshStatePersistence] Writing the tokens failed',
        fields: {
          error: 'persisting the tokens failed (unknown error)',
          kind: 'unknown',
        },
      },
    ],
    [
      'H3 — a device-code presenter that throws',
      (logger, kind) => {
        answer(async (url) => {
          if (String(url).includes('/device')) return tokenReply;
          throw refused400();
        });
        return new OidcDeviceFlowProvider({
          renewal: refreshThenLogin(),
          clientId: 'cid',
          clientSecret: 'secret',
          tokenEndpoint: 'https://idp/token',
          deviceAuthorizationEndpoint: 'https://idp/device',
          refreshToken: REFRESH_TOKEN,
          presenter: {
            present: async () => {
              throw thrown(kind);
            },
          },
          logger,
        } as ConstructorParameters<typeof OidcDeviceFlowProvider>[0]);
      },
      {
        message: '[OidcDeviceFlowProvider] presenter failed',
        fields: {
          error: 'the presenter failed (unknown error)',
          kind: 'unknown',
        },
      },
    ],
    [
      'H6 — a SAML refresh refused, then a validator that throws',
      (logger, kind) => {
        answer(async () => {
          throw refused400();
        });
        return new Saml2BearerProvider({
          renewal: refreshThenLogin(),
          idpSsoUrl: 'https://idp/sso',
          spEntityId: 'sp',
          uaaUrl: 'https://uaa',
          clientId: 'cid',
          clientSecret: 'secret',
          idpInitiated: true,
          refreshToken: REFRESH_TOKEN,
          authorization: staticCodeStrategy({ payload: 'PHNhbWw+' }),
          assertionValidator: {
            validate: async () => {
              throw thrown(kind);
            },
          },
          logger,
        } as ConstructorParameters<typeof Saml2BearerProvider>[0]);
      },
      {
        message: '[SAML] Token refresh failed',
        fields: {
          error: 'the SAML token refresh failed (HTTP 400, invalid_grant)',
          kind: 'request-failed',
          status: 400,
        },
      },
    ],
  ];

  /**
   * Every line carrying a failure's `kind` carries `logFields` only — a
   * string `error` and the kind, a status, rendered diagnostics — and no line
   * holds the marker.
   */
  function expectOnlyLogFields(lines: readonly Line[]): void {
    for (const line of lines) {
      expect(`${line.message} ${JSON.stringify(line.meta)}`).not.toContain(
        MARKER,
      );
      if (line.meta === undefined || !('kind' in line.meta)) continue;
      const failure = Object.fromEntries(
        Object.entries(line.meta).filter(([key]) => key !== 'url'),
      );
      for (const key of Object.keys(failure)) {
        expect([line.message, key, FIELDS.has(key)]).toEqual([
          line.message,
          key,
          true,
        ]);
      }
      expect(typeof failure.error).toBe('string');
    }
  }

  describe.each(['Error', 'string'] as const)('thrown as %s', (kind) => {
    it.each(CASES)('%s', async (_name, make, expected) => {
      const { logger, entries } = recordingLogger();
      await exercise(make(logger, kind));
      expectOnlyLogFields(entries);
      if (expected !== undefined) {
        // Not vacuous: the failure was logged, as its `logFields` exactly.
        const line = entries.find((e) => e.message === expected.message);
        expect(line?.meta).toEqual(expected.fields);
      }
    });
  });

  it.each(['Error', 'string'] as const)(
    'H2 — a detached report that throws %s: one line of logFields, no marker',
    async (kind) => {
      const { logger, entries } = recordingLogger();
      const provider = new ScriptedProvider({
        renewal: refreshThenLogin(),
        accessToken: jwt('held', -3600),
        refreshToken: REFRESH_TOKEN,
        logger,
        persistence: {
          report: (report) => {
            if (!report.awaited) throw thrown(kind);
          },
        },
      });
      const only = new AbortController();
      const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
      await provider.refreshes.nth(1);
      only.abort();
      await cut;
      await quiet();
      expectOnlyLogFields(entries);
      const failed = entries.filter(
        (e) => e.message === '[BaseTokenProvider] Persisting the tokens failed',
      );
      expect(failed.map((e) => e.meta)).toEqual([
        {
          error: 'persisting the tokens failed (unknown error)',
          kind: 'unknown',
        },
      ]);
    },
  );

  it('H4, H5 — an SNC locator and probe that throw', async () => {
    const { logger, entries } = recordingLogger();
    const failing = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => {
          throw new Error(MARKER);
        },
      },
      probes: [],
      logger,
    });
    await failing.prepare();
    const probing = new SncLogonProvider({
      partnerName: 'p:CN=SID',
      locator: {
        locate: async () => ({ path: '/lib/libsapcrypto.so', archs: [] }),
      },
      probes: [
        {
          product: 'probe',
          appliesTo: async () => {
            throw new Error(MARKER);
          },
        },
      ],
      logger,
    });
    await probing.prepare();
    expectOnlyLogFields(entries);
    const notFound = entries.find((e) =>
      e.message.startsWith('SNC library not found: '),
    );
    expect(notFound?.meta).toEqual({
      error: 'no usable SNC library was found',
      kind: 'snc',
    });
    const probe = entries.find((e) =>
      e.message.startsWith('an SNC product probe failed: '),
    );
    expect(probe?.meta).toEqual({
      error: 'the probe failed (unknown error)',
      kind: 'unknown',
    });
  });

  it('H7 — a consumer presentation that rejects: logFields, no URL', async () => {
    const { logger, entries } = recordingLogger();
    const strategy = composeAuthorization({
      presentation: consumerPresentation({
        show: async () => {
          throw new Error(MARKER);
        },
      }),
      transport: loopback({ port: 0 }),
      protocol: oauthCode(),
      endpoint: '/callback',
    });
    // A launcher that fails ends nothing: the login waits, and
    // the test's own signal ends it once the line and the prompt are out.
    const controller = new AbortController();
    const login = strategy
      .authorize({
        buildAuthorizationUrl: async (redirectUri) =>
          `https://idp.example/authorize?redirect_uri=${redirectUri}&state=S1`,
        logger,
        signal: controller.signal,
      } as AuthorizationRequest)
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    await new Promise((resolve) => setTimeout(resolve, 100));
    controller.abort();
    const failure = await login;
    await strategy.dispose?.();
    expect(isAuthProviderFailure(failure)).toBe(true);
    expect(JSON.stringify(failure)).not.toContain(MARKER);
    expect(JSON.stringify(failure)).not.toContain('idp.example');
    expectOnlyLogFields(entries);
    const line = entries.find((e) =>
      e.message.startsWith('Failed to present the authorization URL: '),
    );
    expect(line?.meta).toEqual({
      error: 'presenting the authorization URL failed (unknown error)',
      kind: 'unknown',
    });
    // The URL reaches no log line, and — the consumer's own UI having
    // failed — no prompt either (its stderr may be collected).
    expect(entries.filter((e) => e.message.includes('idp.example'))).toEqual(
      [],
    );
    expect(JSON.stringify(line)).not.toContain('idp.example');
  });

  it('H8 — a browser that rejects with a message holding a secret: logFields, no URL', async () => {
    jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const { logger, entries } = recordingLogger();
    const controller = new AbortController();
    const login = composeAuthorization({
      presentation: openInBrowser({
        browser: recordingBrowser({
          rejectWith: Object.assign(new Error(MARKER), { code: 'ENOENT' }),
        }),
      }),
      transport: loopback({ port: 0 }),
      protocol: oauthCode(),
      endpoint: '/callback',
    })
      .authorize({
        buildAuthorizationUrl: async (redirectUri) =>
          `https://idp.example/authorize?redirect_uri=${redirectUri}&state=S1`,
        logger,
        signal: controller.signal,
      } as AuthorizationRequest)
      .catch((error: unknown) => error);
    for (
      let i = 0;
      i < 200 &&
      !entries.some((e) =>
        e.message.startsWith('Failed to present the authorization URL: '),
      );
      i += 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    controller.abort();
    await login;
    expectOnlyLogFields(entries);
    const line = entries.find((e) =>
      e.message.startsWith('Failed to present the authorization URL: '),
    );
    expect(line?.meta).toEqual({
      error: 'presenting the authorization URL failed (unknown error, ENOENT)',
      kind: 'unknown',
    });
    expect(JSON.stringify(entries)).not.toContain(MARKER);
    expect(JSON.stringify(entries)).not.toContain('idp.example');
  });

  it('H10 — a 200 without a token whose error echoes the secret and the code', async () => {
    const { logger, lines } = recordingLogger();
    const SECRET = 'client-secret-9c41d2e7';
    const CODE = 'authorization-code-55aa13';
    answer(async () => ({
      status: 200,
      data: { error: `${SECRET} ${CODE}`, error_description: SECRET },
    }));
    const failure = await exchangeCodeForToken(
      {
        uaaUrl: 'https://uaa.example',
        uaaClientId: 'cid',
        uaaClientSecret: SECRET,
      } as Parameters<typeof exchangeCodeForToken>[0],
      CODE,
      'http://localhost:61001/callback',
      logger,
    ).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(isAuthProviderFailure(failure)).toBe(true);
    expect(readFailure(failure, 'code-exchange')).toMatchObject({
      kind: 'request-failed',
      facts: { operation: 'code-exchange', problem: 'no-access-token' },
    });
    const all = `${lines.join('\n')}\n${JSON.stringify(failure)}`;
    expect(all).toContain('Token exchange failed: status 200');
    for (const secret of [SECRET, CODE]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
  });
});
