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
import {
  clientSecretBasic,
  clientSecretPost,
  privateKeyJwt,
  tlsClientCertificate,
} from '../../clientAuthentication';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { staticCodeStrategy } from '../../strategies';
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
    ['clientSecretBasic', () => clientSecretBasic(SECRET)],
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
        // The failure is not vacuous: the server's OAuth summary reached the
        // message, a log line or the reduced body — with what was sent redacted.
        expect(all).toContain('invalid_client');
        if (sent.length > before) expect(all).toContain('<redacted');
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
