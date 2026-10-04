/**
 * One token-request path: with a client authentication strategy, every site
 * sends the grant's own parameters plus what `authenticate(draft)` returned,
 * to the endpoint it named, through an agent carrying the pinned TLS material.
 * Without one, each site sends exactly what it sends today — that is pinned,
 * unedited, in tokenRequestShapes.test.ts.
 */

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
import { pollDeviceTokens } from '../../auth/oidcToken';
import { refusalFrom } from '../../auth/refusal';
import { exchangeSamlAssertion } from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import {
  clientSecretPost,
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
