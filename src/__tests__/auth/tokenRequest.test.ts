/**
 * One token-request path: with a client authentication strategy, every site
 * sends the grant's own parameters plus what `authenticate(draft)` returned,
 * to the endpoint it named, through an agent carrying the pinned TLS material.
 * Without one, each site sends exactly what it sends today — that is pinned,
 * unedited, in tokenRequestShapes.test.ts.
 */

import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Agent } from 'node:https';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type {
  ICertificateMaterial,
  IClientAuthentication,
  ITokenRequestAuthentication,
  ITokenRequestDraft,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios from 'axios';
import { getTokenWithClientCredentials } from '../../auth/clientCredentialsAuth';
import {
  initiateDeviceAuthorization,
  passwordGrant,
  pollDeviceTokens,
} from '../../auth/oidcToken';
import { exchangePasscode } from '../../auth/passcodeAuth';
import { refusalFrom } from '../../auth/refusal';
import { exchangeSamlAssertion } from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import {
  clientSecretPost,
  privateKeyJwt,
  tlsClientCertificate,
} from '../../clientAuthentication';
import { OIDC, tokenReply as reply, SITES } from '../helpers/tokenRequestSites';

jest.mock('axios');
type Mock = jest.Mock<(...args: any[]) => Promise<unknown>>;
const mockedAxios = axios as unknown as Mock & {
  post: Mock;
  isAxiosError: jest.Mock<(e: unknown) => boolean>;
};

const FORM = 'application/x-www-form-urlencoded';
const dir = join(__dirname, '..', 'fixtures', 'certificates');
const material: ICertificateMaterial = {
  cert: readFileSync(join(dir, 'client.crt')),
  key: readFileSync(join(dir, 'client.key')),
};
const pfxMaterial: ICertificateMaterial = {
  pfx: readFileSync(join(dir, 'client.pfx')),
  passphrase: 'test-passphrase',
};

/** A strategy that returns `result` and records every draft it saw. */
function returning(result: unknown): IClientAuthentication & {
  drafts: ITokenRequestDraft[];
} {
  const drafts: ITokenRequestDraft[] = [];
  return {
    drafts,
    authenticate: async (draft) => {
      drafts.push(draft);
      return result as ITokenRequestAuthentication;
    },
  };
}

interface SentConfig {
  maxRedirects?: number;
  url: string;
  method: string;
  data: string;
  headers: Record<string, string>;
  httpsAgent?: Agent;
  timeout?: number;
}

function sent(index = 0): SentConfig {
  expect(mockedAxios.post).not.toHaveBeenCalled();
  return mockedAxios.mock.calls[index][0] as SentConfig;
}

const bodyOf = (config: SentConfig) =>
  Object.fromEntries(new URLSearchParams(config.data));

async function failureOf(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (error) {
    return error;
  }
  throw new Error('expected a rejection');
}

const messageOf = (error: unknown): string =>
  String((error as { message?: unknown } | null)?.message ?? error);

beforeEach(() => {
  jest.resetAllMocks();
  mockedAxios.mockResolvedValue(reply);
  mockedAxios.post.mockResolvedValue(reply);
  mockedAxios.isAxiosError.mockImplementation(
    (e) => !!(e as { isAxiosError?: boolean } | null)?.isAxiosError,
  );
});

describe.each(SITES)('$name with a client authentication', (site) => {
  it('sends the grant parameters plus the strategy parameters and headers, to the strategy endpoint', async () => {
    const strategy = returning({
      endpoint: 'https://alt.example/token',
      parameters: { client_id: 'cid', extra: 'x' },
      headers: { Authorization: 'Custom y' },
    });
    await site.run({ strategy });
    const config = sent();
    expect(config.url).toBe('https://alt.example/token');
    expect(config.method).toBe('post');
    expect(bodyOf(config)).toEqual({
      ...site.grant,
      client_id: 'cid',
      extra: 'x',
    });
    expect(config.headers).toEqual({
      'Content-Type': FORM,
      ...site.ownHeaders,
      Authorization: 'Custom y',
    });
    expect('httpsAgent' in config).toBe(false);
    expect(strategy.drafts).toEqual([
      {
        endpoint: site.endpoint,
        clientId: 'cid',
        grantType: site.grantType,
      },
    ]);
  });

  it('sends to the configured endpoint when the strategy names none', async () => {
    await site.run({
      strategy: returning({ parameters: { client_id: 'cid' } }),
    });
    expect(sent().url).toBe(site.endpoint);
  });

  it('passes the mTLS alias it was given in the draft', async () => {
    const strategy = returning({});
    await site.run({ strategy, mtlsEndpoint: 'https://mtls.idp/token' });
    expect(strategy.drafts[0].mtlsEndpoint).toBe('https://mtls.idp/token');
  });

  it.each([
    ['a PEM pair', material],
    ['a PFX with its passphrase', pfxMaterial],
  ])(
    'with %s: an agent carrying exactly that material, never rejectUnauthorized',
    async (_label, m) => {
      await site.run({
        strategy: tlsClientCertificate({ material: m }),
        material: m,
      });
      const agent = sent().httpsAgent;
      expect(agent).toBeInstanceOf(Agent);
      const options = (agent as unknown as { options: Record<string, unknown> })
        .options;
      for (const [field, value] of Object.entries(m)) {
        expect(options[field]).toBe(value);
      }
      for (const field of ['cert', 'key', 'pfx', 'passphrase']) {
        if (!(field in m)) expect(options[field]).toBeUndefined();
      }
      expect('rejectUnauthorized' in options).toBe(false);
    },
  );

  it.each<[string, unknown]>([
    ['a non-string parameter', { parameters: { client_id: 42 } }],
    ['a non-string header', { headers: { Authorization: { b: 1 } } }],
    [
      "a header that replaces the request's own",
      { headers: { 'content-type': 'text/plain' } },
    ],
    [
      'a header value with a line break',
      { headers: { Authorization: 'Basic x\r\nX-Injected: 1' } },
    ],
    [
      'a parameter that replaces a grant parameter',
      {
        parameters: Object.fromEntries(
          Object.keys(site.grant).map((k) => [k, 'other']),
        ),
      },
    ],
    [
      'an http: endpoint for an https: configuration',
      { endpoint: 'http://alt.example/token' },
    ],
    ['an endpoint that is not a URL', { endpoint: 'alt.example/token' }],
    ['an endpoint of another scheme', { endpoint: 'ftp://alt.example/token' }],
    ['a non-string endpoint', { endpoint: 7 }],
    ['parameters that are not a record', { parameters: 'client_id=cid' }],
    ['a result that is not an object', null],
  ])(
    'returning %s: a fixed refusal, no request sent',
    async (_label, result) => {
      const error = await failureOf(site.run({ strategy: returning(result) }));
      expect(mockedAxios).not.toHaveBeenCalled();
      expect(mockedAxios.post).not.toHaveBeenCalled();
      expect(refusalFrom(error, 'the token request')).toEqual({
        ok: false,
        refusal: {
          reason:
            'the client authentication returned a request that cannot be sent',
          hint: 'check the client authentication strategy',
        },
      });
    },
  );

  it('a strategy that throws: a fixed refusal carrying nothing of its message, no request sent', async () => {
    const error = await failureOf(
      site.run({
        strategy: {
          authenticate: async () => {
            throw new Error('SECRET-FROM-STRATEGY');
          },
        },
      }),
    );
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(mockedAxios.post).not.toHaveBeenCalled();
    const refusal = refusalFrom(error, 'the token request');
    expect(refusal).toEqual({
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('material with an endpoint that is not https: a fixed refusal, no request sent', async () => {
    const error = await failureOf(
      site.run({
        strategy: returning({ endpoint: 'http://alt.example/token' }),
        material,
      }),
    );
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(refusalFrom(error, 'x')).toEqual({
      ok: false,
      refusal: {
        reason:
          'the client authentication returned a request that cannot be sent',
        hint: 'check the client authentication strategy',
      },
    });
  });

  it('a TLS trust failure: fixed words naming the code, the hint naming NODE_EXTRA_CA_CERTS', async () => {
    mockedAxios.mockRejectedValue(
      Object.assign(new Error('self-signed certificate SECRET-TLS-TEXT'), {
        code: 'SELF_SIGNED_CERT_IN_CHAIN',
        isAxiosError: true,
      }),
    );
    const error = await failureOf(
      site.run({ strategy: tlsClientCertificate({ material }), material }),
    );
    const refusal = refusalFrom(error, 'the token request');
    expect(refusal).toEqual({
      ok: false,
      refusal: {
        reason:
          "the token request failed: the server's certificate is not trusted (SELF_SIGNED_CERT_IN_CHAIN)",
        hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
      },
    });
  });

  it('a 401 after mTLS: the same error, and the same refusal, as without a strategy', async () => {
    const unauthorized = () => ({
      isAxiosError: true,
      message: 'Request failed with status code 401',
      response: {
        status: 401,
        data: { error: 'invalid_client', error_description: 'Bad credentials' },
      },
    });
    mockedAxios.mockRejectedValue(unauthorized());
    mockedAxios.post.mockRejectedValue(unauthorized());
    const today = await failureOf(site.run());
    const withMtls = await failureOf(
      site.run({ strategy: tlsClientCertificate({ material }), material }),
    );
    expect(messageOf(withMtls)).toBe(messageOf(today));
    expect(refusalFrom(withMtls, 'x')).toEqual(refusalFrom(today, 'x'));
  });

  it('a secret or a non-JWT assertion the strategy sent is redacted from an echoing error body', async () => {
    const SECRET = 'client-secret-0123456789';
    const ASSERTION =
      'PHNhbWw6QXNzZXJ0aW9uPm5vdC1hLWp3dDwvc2FtbDpBc3NlcnRpb24-';
    const echo = () => ({
      isAxiosError: true,
      message: 'Request failed with status code 400',
      response: {
        status: 400,
        data: {
          error: `invalid_client ${SECRET}`,
          error_description: `bad assertion ${ASSERTION} with ${SECRET}`,
        },
      },
    });
    mockedAxios.mockRejectedValue(echo());
    const lines: string[] = [];
    const record = (message: string, meta?: unknown) =>
      lines.push(`${message} ${JSON.stringify(meta ?? {})}`);
    const logger = {
      debug: record,
      info: record,
      warn: record,
      error: record,
    } as ILogger;
    const error = await failureOf(
      site.run(
        {
          strategy: returning({
            parameters: {
              client_id: 'cid',
              client_secret: SECRET,
              client_assertion_type:
                'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
              client_assertion: ASSERTION,
            },
          }),
        },
        logger,
      ),
    );
    const text = `${messageOf(error)}\n${lines.join('\n')}`;
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain(ASSERTION);
  });
});

describe('client authentication per request', () => {
  it('the device poll authenticates every request anew', async () => {
    mockedAxios
      .mockRejectedValueOnce({
        isAxiosError: true,
        response: { status: 400, data: { error: 'authorization_pending' } },
      })
      .mockResolvedValueOnce(reply);
    const strategy = returning({ parameters: { client_id: 'cid' } });
    await pollDeviceTokens(OIDC, 'cid', undefined, 'dc', 0, undefined, {
      strategy,
    });
    expect(mockedAxios).toHaveBeenCalledTimes(2);
    expect(strategy.drafts).toHaveLength(2);
  });

  it('keeps the client_credentials timeout on the strategy path', async () => {
    await getTokenWithClientCredentials('https://uaa', 'cid', undefined, {
      strategy: clientSecretPost('sec'),
    });
    expect(sent().timeout).toBe(30000);
  });

  it('an http: endpoint is accepted when the configured endpoint is http: (a local server), without material', async () => {
    await getTokenWithClientCredentials(
      'http://localhost:8080/uaa',
      'cid',
      undefined,
      {
        strategy: returning({ endpoint: 'http://localhost:8080/uaa/alt' }),
      },
    );
    expect(sent().url).toBe('http://localhost:8080/uaa/alt');
  });

  it('a SAML exchange with a strategy and no clientId: a configuration refusal naming clientId, no request sent', async () => {
    const error = await failureOf(
      exchangeSamlAssertion(
        'A',
        'https://t/token',
        undefined,
        undefined,
        undefined,
        {
          strategy: returning({}),
        },
      ),
    );
    expect(mockedAxios).not.toHaveBeenCalled();
    expect(refusalFrom(error, 'x')).toEqual({
      ok: false,
      refusal: {
        reason: 'the provider configuration is incomplete or invalid: clientId',
        hint: 'check the provider configuration',
      },
    });
  });
});

describe('a TLS trust failure, by code', () => {
  it.each([
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'CERT_HAS_EXPIRED',
    'ERR_TLS_CERT_ALTNAME_INVALID',
  ])('%s: fixed words, the hint naming NODE_EXTRA_CA_CERTS', (code) => {
    const refusal = refusalFrom(
      Object.assign(new Error('SECRET-TEXT'), { code }),
      'the token request',
    );
    expect(refusal).toEqual({
      ok: false,
      refusal: {
        reason: `the token request failed: the server's certificate is not trusted (${code})`,
        hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
      },
    });
  });

  it('a code off the list stays unknown, and nothing of the message', () => {
    expect(
      refusalFrom(
        Object.assign(new Error('SECRET-TEXT'), { code: 'SECRET_CODE' }),
        'the token request',
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('without a strategy, a site that wraps its errors lets a TLS trust failure through', async () => {
    mockedAxios.mockRejectedValue(
      Object.assign(new Error('SECRET-TLS'), {
        code: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
        isAxiosError: true,
      }),
    );
    for (const run of [
      () => getTokenWithClientCredentials('https://uaa', 'cid', 'sec'),
      () => refreshJwtToken('rt', 'https://uaa', 'cid', 'sec'),
    ]) {
      const refusal = refusalFrom(await failureOf(run()), 'x');
      expect(refusal.ok === false && refusal.refusal.hint).toContain(
        'NODE_EXTRA_CA_CERTS',
      );
    }
  });
});

/**
 * What a real AxiosError carries: the request config (httpsAgent with its
 * options, the form body, the headers) on itself, on `request` and on
 * `response.config`.
 */
function realisticFailure(config: Record<string, unknown>) {
  return {
    isAxiosError: true,
    name: 'AxiosError',
    message: 'Request failed with status code 400',
    code: 'ERR_BAD_REQUEST',
    config,
    request: { _header: JSON.stringify(config.headers), body: config.data },
    response: {
      status: 400,
      statusText: 'Bad Request',
      headers: {},
      config,
      data: { error: 'invalid_client' },
    },
  };
}

function failRealistically(): void {
  mockedAxios.mockImplementation(async (config: Record<string, unknown>) => {
    throw realisticFailure(config);
  });
  mockedAxios.post.mockImplementation(
    async (url: string, data: string, config: Record<string, unknown>) => {
      throw realisticFailure({ url, data, method: 'post', ...config });
    },
  );
}

/** JSON of anything, circular references included. */
function serialized(value: unknown): string {
  const seen = new WeakSet<object>();
  return JSON.stringify(value, (_key, item) => {
    if (item && typeof item === 'object') {
      if (seen.has(item)) return '[circular]';
      seen.add(item);
    }
    return typeof item === 'function' ? '[function]' : item;
  });
}

/**
 * Windows of `size` characters, every `stride`: any leaked run of
 * `size + stride - 1` characters or more contains one of them.
 */
const windowsOf = (secret: string, size = 8, stride = 1) => {
  const out: string[] = [];
  for (let i = 0; i + size <= secret.length; i += stride) {
    out.push(secret.slice(i, i + size));
  }
  return out;
};

const signingKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

describe.each(SITES)('$name: the thrown error carries no request', (site) => {
  // Every row has three cells: a shorter row makes jest pass `done` instead.
  it.each<
    [string, () => IClientAuthentication, ICertificateMaterial | undefined]
  >([
    [
      'a PFX and its passphrase',
      () => tlsClientCertificate({ material: pfxMaterial }),
      pfxMaterial,
    ],
    [
      'a private_key_jwt assertion',
      () => privateKeyJwt({ key: signingKey, algorithm: 'RS256' }),
      undefined,
    ],
    [
      'a client secret in the body',
      () => clientSecretPost('Zq8vK2pX9wLm4rT7nB3c'),
      undefined,
    ],
  ])(
    'with %s: neither its JSON nor its string holds any of it',
    async (_label, make, m) => {
      const sentValues: string[] = [];
      const strategy = make();
      const recording: IClientAuthentication = {
        ...strategy,
        authenticate: async (draft) => {
          const result = await strategy.authenticate(draft);
          for (const [name, value] of Object.entries(result.parameters ?? {})) {
            if (name !== 'client_id' && name !== 'client_assertion_type') {
              sentValues.push(value);
            }
          }
          return result;
        },
      };
      failRealistically();
      const thrown = await failureOf(
        site.run({ strategy: recording, material: m }),
      );
      const text = `${serialized(thrown)}\n${String(thrown)}`;
      const needles = [
        ...sentValues.flatMap((v) => windowsOf(v)),
        ...(m?.passphrase ? windowsOf(m.passphrase) : []),
        ...(m?.pfx ? windowsOf(JSON.stringify(m.pfx).slice(26), 40, 40) : []),
        ...(m?.pfx ? windowsOf(m.pfx.toString('base64'), 16, 16) : []),
        ...windowsOf(signingKey.replace(/-----[^-]+-----|\s/g, ''), 16, 16),
      ];
      expect(sentValues.length > 0 || m !== undefined).toBe(true);
      expect(needles.filter((needle) => text.includes(needle))).toEqual([]);
      // The status the sites report is still there.
      expect(String(thrown)).toContain('400');
    },
  );

  it('without a strategy: no config, request, secret, Basic or refresh token', async () => {
    failRealistically();
    const thrown = await failureOf(site.run());
    const text = `${serialized(thrown)}\n${String(thrown)}`;
    expect(text).not.toContain('"config"');
    expect(text).not.toContain('"request"');
    expect(text).not.toContain('client_secret');
    expect(text).not.toContain('Authorization');
    expect(text).not.toContain(Buffer.from('cid:sec').toString('base64'));
    expect(text).not.toContain('old-rt');
  });
});

describe.each(SITES)(
  '$name: redirects and the agent on the strategy path',
  (site) => {
    it('follows no redirect: a 307 to another host fails the request', async () => {
      mockedAxios.mockImplementation(
        async (config: { maxRedirects?: number }) => {
          // axios with maxRedirects 0 rejects a 3xx; with redirects it would follow.
          if (config.maxRedirects === 0) {
            throw {
              isAxiosError: true,
              message: 'Request failed with status code 307',
              response: {
                status: 307,
                headers: { location: 'https://elsewhere.example/token' },
                data: '',
              },
            };
          }
          return reply;
        },
      );
      await failureOf(
        site.run({ strategy: tlsClientCertificate({ material }), material }),
      );
      expect(sent().maxRedirects).toBe(0);
    });

    it('the agent takes cert, key, pfx and passphrase only: no field the material happens to carry', async () => {
      const loaded = {
        ...material,
        rejectUnauthorized: false,
        ca: 'ROGUE-CA',
        checkServerIdentity: () => undefined,
      } as ICertificateMaterial;
      await site.run({
        strategy: tlsClientCertificate({ material }),
        material: loaded,
      });
      const options = (
        sent().httpsAgent as unknown as { options: Record<string, unknown> }
      ).options;
      expect('rejectUnauthorized' in options).toBe(false);
      expect('ca' in options).toBe(false);
      expect('checkServerIdentity' in options).toBe(false);
      expect(options.cert).toBe(material.cert);
      expect(options.key).toBe(material.key);
    });
  },
);

describe('the server never reads back the password or the passcode', () => {
  const echoing = (secrets: string[]) => ({
    isAxiosError: true,
    message: 'Request failed with status code 401',
    response: {
      status: 401,
      data: {
        error: `unauthorized ${secrets.join(' ')}`,
        error_description: `refused ${secrets.join(' and ')}`,
      },
    },
  });
  const PASSCODE = 'PASSCODE-0123456789';
  const PASSWORD = 'pass-word-9876543210';
  const CLIENT_SECRET = 'client-secret-555555';

  it.each([
    ['as today', undefined],
    ['with a strategy', { strategy: clientSecretPost(CLIENT_SECRET) }],
  ])('passcode, %s', async (_label, auth) => {
    mockedAxios.post.mockRejectedValue(echoing([PASSCODE, CLIENT_SECRET]));
    mockedAxios.mockRejectedValue(echoing([PASSCODE, CLIENT_SECRET]));
    const thrown = await failureOf(
      exchangePasscode(
        'https://uaa',
        'cid',
        auth ? undefined : CLIENT_SECRET,
        PASSCODE,
        undefined,
        auth,
      ),
    );
    const message = messageOf(thrown);
    expect(message).toContain('Passcode exchange failed (401)');
    expect(message).toContain('refused');
    expect(message).not.toContain(PASSCODE);
    expect(message).not.toContain(CLIENT_SECRET);
  });

  it.each([
    ['as today', undefined],
    ['with a strategy', { strategy: clientSecretPost(CLIENT_SECRET) }],
  ])('password grant, %s', async (_label, auth) => {
    mockedAxios.post.mockRejectedValue(echoing([PASSWORD, CLIENT_SECRET]));
    mockedAxios.mockRejectedValue(echoing([PASSWORD, CLIENT_SECRET]));
    const thrown = await failureOf(
      passwordGrant(
        OIDC,
        'cid',
        auth ? undefined : CLIENT_SECRET,
        'user',
        PASSWORD,
        undefined,
        undefined,
        auth,
      ),
    );
    const message = messageOf(thrown);
    expect(message).toContain('OIDC password grant failed (401)');
    expect(message).toContain('refused');
    expect(message).not.toContain(PASSWORD);
    expect(message).not.toContain(CLIENT_SECRET);
  });

  it("device authorization: the OAuth summary in the message, the strategy's secret redacted", async () => {
    mockedAxios.mockRejectedValue(echoing([CLIENT_SECRET]));
    const thrown = await failureOf(
      initiateDeviceAuthorization(
        'https://idp/device-auth',
        'cid',
        'openid',
        undefined,
        { strategy: clientSecretPost(CLIENT_SECRET) },
      ),
    );
    const message = messageOf(thrown);
    expect(message).toContain('OIDC device authorization failed (401)');
    expect(message).toContain('unauthorized');
    expect(message).toContain('refused');
    expect(message).not.toContain(CLIENT_SECRET);
  });

  it('device authorization as today: the OAuth summary in the message', async () => {
    mockedAxios.post.mockRejectedValue(echoing([]));
    const thrown = await failureOf(
      initiateDeviceAuthorization('https://idp/device-auth', 'cid', 'openid'),
    );
    expect(messageOf(thrown)).toMatch(
      /^OIDC device authorization failed \(401\): .*unauthorized.*refused/,
    );
  });

  it.each([
    ['as today', undefined],
    [
      'with a strategy',
      { strategy: tlsClientCertificate({ material }), material },
    ],
  ])(
    'device authorization %s: a TLS trust failure keeps its code, and the refusal names NODE_EXTRA_CA_CERTS',
    async (_label, auth) => {
      const untrusted = () =>
        Object.assign(new Error('self-signed certificate SECRET-TLS-TEXT'), {
          code: 'SELF_SIGNED_CERT_IN_CHAIN',
          isAxiosError: true,
        });
      mockedAxios.mockRejectedValue(untrusted());
      mockedAxios.post.mockRejectedValue(untrusted());
      const thrown = await failureOf(
        initiateDeviceAuthorization(
          'https://idp/device-auth',
          'cid',
          'openid',
          undefined,
          auth,
        ),
      );
      expect((thrown as { code?: unknown }).code).toBe(
        'SELF_SIGNED_CERT_IN_CHAIN',
      );
      expect(refusalFrom(thrown, 'the token request')).toEqual({
        ok: false,
        refusal: {
          reason:
            "the token request failed: the server's certificate is not trusted (SELF_SIGNED_CERT_IN_CHAIN)",
          hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
        },
      });
    },
  );
});

describe.each(SITES)('$name: the error body on the thrown object', (site) => {
  const SECRET = 'client-secret-0123456789';
  const ASSERTION = 'opaque-assertion-abcdefghijklmnop';
  const LEAKED = 'LEAKED-ACCESS-TOKEN-0123456789';
  const echoing = (echoed: string) => ({
    isAxiosError: true,
    message: 'Request failed with status code 400',
    response: {
      status: 400,
      data: {
        error: 'invalid_grant',
        error_description: `refused ${echoed}`,
        error_uri: 'https://docs.example/errors',
        access_token: LEAKED,
        extra: { nested: echoed },
      },
    },
  });
  const onlyOAuthFields = (thrown: unknown) => {
    const data = (thrown as { response?: { data?: unknown } }).response?.data;
    if (data !== undefined) {
      expect(
        Object.keys(data as object).every((k) =>
          ['error', 'error_description', 'error_uri'].includes(k),
        ),
      ).toBe(true);
    }
  };

  it('with a strategy: only the OAuth fields, nothing the strategy sent', async () => {
    mockedAxios.mockRejectedValue(echoing(`${SECRET} ${ASSERTION}`));
    const thrown = await failureOf(
      site.run({
        strategy: returning({
          parameters: {
            client_id: 'cid',
            client_secret: SECRET,
            client_assertion: ASSERTION,
          },
        }),
      }),
    );
    onlyOAuthFields(thrown);
    const text = `${serialized(thrown)}\n${String(thrown)}`;
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain(ASSERTION);
    expect(text).not.toContain(LEAKED);
  });

  it('without a strategy: only the OAuth fields, nothing the site sent', async () => {
    // What this site itself sent that is a secret: those it must not return.
    const secretKeys = [
      'refresh_token',
      'assertion',
      'code',
      'code_verifier',
      'subject_token',
      'passcode',
      'password',
      'device_code',
    ];
    const sentByToday = Object.entries(site.grant)
      .filter(([key]) => secretKeys.includes(key))
      .map(([, value]) => value);
    mockedAxios.mockRejectedValue(echoing(sentByToday.join(' ')));
    mockedAxios.post.mockRejectedValue(echoing(sentByToday.join(' ')));
    const thrown = await failureOf(site.run());
    onlyOAuthFields(thrown);
    const text = `${serialized(thrown)}\n${String(thrown)}`;
    expect(text).not.toContain(LEAKED);
    for (const value of sentByToday.filter((v) => v.length >= 4)) {
      expect(text).not.toContain(value);
    }
  });
});

describe('the device poll reads the reduced body', () => {
  it.each([
    ['as today', undefined],
    ['with a strategy', { strategy: clientSecretPost('client-secret-xyz') }],
  ])(
    '%s: authorization_pending, beside extra fields, is still recognised',
    async (_label, auth) => {
      const pending = {
        isAxiosError: true,
        response: {
          status: 400,
          data: { error: 'authorization_pending', interval: 5, extra: 'x' },
        },
      };
      mockedAxios.mockRejectedValueOnce(pending).mockResolvedValueOnce(reply);
      mockedAxios.post
        .mockRejectedValueOnce(pending)
        .mockResolvedValueOnce(reply);
      await pollDeviceTokens(OIDC, 'cid', undefined, 'dc', 0, undefined, auth);
      expect(
        mockedAxios.mock.calls.length + mockedAxios.post.mock.calls.length,
      ).toBe(2);
    },
  );
});
