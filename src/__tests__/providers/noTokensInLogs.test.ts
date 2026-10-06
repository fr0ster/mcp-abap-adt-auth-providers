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
import type {
  IAssertionValidator,
  ICertificateMaterial,
  IClientAuthentication,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { exchangeCodeForToken, launchBrowser } from '../../auth/browserAuth';
import {
  clientSecretBasic,
  clientSecretPost,
  privateKeyJwt,
  tlsClientCertificate,
} from '../../clientAuthentication';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { SncLogonProvider } from '../../snc/SncLogonProvider';
import { browserCallbackStrategy, staticCodeStrategy } from '../../strategies';
import { SITES, tokenReply } from '../helpers/tokenRequestSites';

// Automocked, but with axios's own error class: the sites throw it.
jest.mock('axios', () => {
  const mocked = jest.createMockFromModule<Record<string, unknown>>('axios');
  mocked.AxiosError =
    jest.requireActual<Record<string, unknown>>('axios').AxiosError;
  return mocked;
});
// `open` and `spawn`, each replaceable per test: the browser launch logs
// what a failed launch said. No launcher is ever really started.
const mockOpen: { default?: unknown } = {};
jest.mock('open', () => ({
  __esModule: true,
  get default() {
    return mockOpen.default;
  },
}));
const mockSpawn: { run?: (...args: unknown[]) => unknown } = {};
jest.mock('node:child_process', () => ({
  ...jest.requireActual<Record<string, unknown>>('node:child_process'),
  spawn: (...args: unknown[]) => mockSpawn.run?.(...args),
}));
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

function recordingLogger(): { logger: ILogger; lines: string[] } {
  const lines: string[] = [];
  const record = (level: string) => (message: string, meta?: unknown) => {
    lines.push(`${level} ${message} ${JSON.stringify(meta ?? {})}`);
  };
  return {
    logger: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    } as ILogger,
    lines,
  };
}

/** Every 8-character window of a secret, so a partial leak is caught too. */
const windows = (secret: string) =>
  Array.from({ length: secret.length - 7 }, (_, i) => secret.slice(i, i + 8));

describe('no token in the logs', () => {
  it('logs neither the access token nor the refresh token, in whole or in part', async () => {
    const { logger, lines } = recordingLogger();
    const provider = new AuthorizationCodeProvider({
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

  it('logs no part of seeded cookies, or of an opaque token seeded with expiresAt', async () => {
    const COOKIES =
      'SAP_SESSIONID_ABC_100=cookievaluethatissecret; sap-usercontext=c';
    const OPAQUE = 'opaque-seeded-token-with-no-exp-claim';
    const { logger, lines } = recordingLogger();
    const expiresAt = Date.now() + 3600_000;
    const saml = new Saml2PureProvider({
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
          message = String((error as { message?: unknown }).message ?? error);
          data = JSON.stringify(
            (error as { response?: { data?: unknown } }).response?.data ?? '',
          );
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
 * interactive strategy, a device-code presenter, a SAML validator, `onTokens`,
 * a browser launcher, an SNC locator or probe — may throw an error whose text
 * holds a key, a passphrase or a token, and so may a network failure. What a
 * log line says of it is fixed per class (`refusal.ts`), never its message.
 */
describe('no message of a thrown error in the logs', () => {
  const MARKER = 'REVIEW_TEST_PRIVATE_KEY_7f3a9c';
  const thrown = (kind: 'Error' | 'string') =>
    kind === 'Error' ? new Error(MARKER) : MARKER;

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

  /** Every moment that can run the collaborator; none may throw out. */
  async function exercise(provider: Exercised) {
    for (const run of [
      () => provider.getTokens(),
      () => provider.refreshTokens(),
      () => provider.prepare(),
      () => provider.rejected({ at: 'request', status: 401, error: undefined }),
    ]) {
      try {
        await run();
      } catch {
        // Thrown to the caller, who decides; only the log is asserted here.
      }
    }
  }

  const codeProvider = (
    logger: ILogger,
    extra: Partial<ConstructorParameters<typeof AuthorizationCodeProvider>[0]>,
  ) =>
    new AuthorizationCodeProvider({
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      accessToken: EXPIRED,
      refreshToken: REFRESH_TOKEN,
      authorization: staticCodeStrategy({ payload: 'the-code' }),
      logger,
      ...(extra.clientAuthentication ? {} : { clientSecret: 'secret' }),
      ...extra,
    } as ConstructorParameters<typeof AuthorizationCodeProvider>[0]);

  const CASES: [
    string,
    (logger: ILogger, kind: 'Error' | 'string') => Exercised,
    string,
  ][] = [
    [
      'a client-authentication strategy whose authenticate() throws',
      (logger, kind) =>
        codeProvider(logger, {
          clientAuthentication: {
            authenticate: async () => {
              throw thrown(kind);
            },
          },
        }),
      'Refresh failed',
    ],
    [
      'a client-authentication strategy whose tlsMaterial() throws',
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
      '',
    ],
    [
      'a certificate loader that throws',
      (logger, kind) =>
        codeProvider(logger, {
          clientAuthentication: tlsClientCertificate({
            material: async () => {
              throw thrown(kind);
            },
          }),
        }),
      '',
    ],
    [
      'a network failure whose message holds the secret',
      (logger, kind) => {
        answer(async () => {
          throw thrown(kind);
        });
        return codeProvider(logger, {});
      },
      'Refresh failed',
    ],
    [
      'an interactive strategy that throws',
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
      'Refresh failed',
    ],
    [
      'onTokens that throws',
      (logger, kind) =>
        codeProvider(logger, {
          onTokens: async () => {
            throw thrown(kind);
          },
        }),
      'onTokens failed',
    ],
    [
      'a device-code presenter that throws',
      (logger, kind) => {
        answer(async (url) => {
          if (String(url).includes('/device')) return tokenReply;
          throw refused400();
        });
        return new OidcDeviceFlowProvider({
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
      'presenter failed',
    ],
    [
      'a SAML validator that throws',
      (logger, kind) => {
        answer(async () => {
          throw refused400();
        });
        return new Saml2BearerProvider({
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
      'Refresh failed',
    ],
  ];

  describe.each(['Error', 'string'] as const)('thrown as %s', (kind) => {
    it.each(CASES)('%s', async (_name, make, expected) => {
      const { logger, lines } = recordingLogger();
      await exercise(make(logger, kind));
      const all = lines.join('\n');
      // Not vacuous: the failure was logged, in the words it is allowed.
      if (expected) expect(all).toContain(expected);
      expect(all).not.toContain(MARKER);
    });
  });

  it('an SNC locator and probe that throw', async () => {
    const { logger, lines } = recordingLogger();
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
    const all = lines.join('\n');
    expect(all).toContain('SNC library not found');
    expect(all).toContain('an SNC product probe failed');
    expect(all).not.toContain(MARKER);
  });

  it('a browser launcher that rejects', async () => {
    const { logger, lines } = recordingLogger();
    const strategy = browserCallbackStrategy({
      port: 0,
      openUrl: async () => {
        throw new Error(MARKER);
      },
    });
    await expect(
      strategy.authorize({
        buildAuthorizationUrl: async (redirectUri) =>
          `https://idp.example/authorize?redirect_uri=${redirectUri}`,
        logger,
      }),
    ).rejects.toThrow();
    await strategy.dispose?.();
    const all = lines.join('\n');
    expect(all).toContain('Failed to open browser');
    expect(all).not.toContain(MARKER);
  });

  it('`open` that rejects, and the shell fallback that fails', async () => {
    const { logger, lines } = recordingLogger();
    mockOpen.default = async () => {
      throw new Error(MARKER);
    };
    await launchBrowser(
      'https://idp/a',
      'auto',
      'http://localhost/cb',
      () => {},
      logger,
    );
    mockOpen.default = undefined;
    // Every candidate launcher fails to start, with a message holding the
    // marker; the failure line is written once, after the last.
    let started = 0;
    mockSpawn.run = () => {
      started += 1;
      const { EventEmitter } =
        jest.requireActual<typeof import('node:events')>('node:events');
      const child = new EventEmitter() as InstanceType<typeof EventEmitter> & {
        unref(): void;
      };
      child.unref = () => undefined;
      setImmediate(() => child.emit('error', new Error(MARKER)));
      return child;
    };
    const exited = new Promise<void>((resolve) => {
      const poll = setInterval(() => {
        if (lines.some((line) => line.includes('Failed to open browser'))) {
          clearInterval(poll);
          resolve();
        }
      }, 5);
    });
    await launchBrowser(
      'https://idp/a',
      'chrome',
      'http://localhost/cb',
      () => {},
      logger,
    );
    await exited;
    expect(started).toBeGreaterThan(0);
    const all = lines.join('\n');
    expect(all).toContain('Could not open browser automatically');
    expect(all).toContain('Failed to open browser');
    expect(all).not.toContain(MARKER);
  });

  it('a 200 without a token whose error echoes the secret and the code', async () => {
    const { logger, lines } = recordingLogger();
    const SECRET = 'client-secret-9c41d2e7';
    const CODE = 'authorization-code-55aa13';
    answer(async () => ({
      status: 200,
      data: { error: `${SECRET} ${CODE}`, error_description: SECRET },
    }));
    await expect(
      exchangeCodeForToken(
        {
          uaaUrl: 'https://uaa.example',
          uaaClientId: 'cid',
          uaaClientSecret: SECRET,
        } as Parameters<typeof exchangeCodeForToken>[0],
        CODE,
        'http://localhost:61001/callback',
        logger,
      ),
    ).rejects.toThrow();
    const all = lines.join('\n');
    expect(all).toContain('Token exchange failed: status 200');
    for (const secret of [SECRET, CODE]) {
      for (const window of windows(secret)) {
        expect(all).not.toContain(window);
      }
    }
  });
});
