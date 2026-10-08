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
import { inspect } from 'node:util';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
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
  refreshOidcToken,
} from '../../auth/oidcToken';
import { exchangePasscode } from '../../auth/passcodeAuth';
import { exchangeSamlAssertion } from '../../auth/saml2TokenExchange';
import { refreshJwtToken } from '../../auth/tokenRefresher';
import {
  clientSecretBasic,
  clientSecretPost,
  privateKeyJwt,
  tlsClientCertificate,
} from '../../clientAuthentication';
import { refusedWith, wordsOf } from '../helpers/minted';
import {
  OIDC,
  phrase,
  tokenReply as reply,
  SITES,
} from '../helpers/tokenRequestSites';

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
  return mockedAxios.mock.calls[index]![0] as SentConfig;
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
        // A token request names its own endpoint; the device initiation
        // names only the one it is given.
        ...(site.grantType === 'device_authorization'
          ? {}
          : { tokenEndpoint: site.endpoint }),
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

  it('names the token endpoint in the draft: its own endpoint, or for the device initiation the one it was given', async () => {
    const strategy = returning({});
    await site.run({ strategy, tokenEndpoint: 'https://idp/the-token' });
    expect(strategy.drafts[0]!.tokenEndpoint).toBe(
      site.grantType === 'device_authorization'
        ? 'https://idp/the-token'
        : site.endpoint,
    );
  });

  it('without a token endpoint given, the device initiation names none — never its own endpoint', async () => {
    const strategy = returning({});
    await site.run({ strategy });
    if (site.grantType === 'device_authorization') {
      expect('tokenEndpoint' in strategy.drafts[0]!).toBe(false);
    } else {
      expect(strategy.drafts[0]!.tokenEndpoint).toBe(site.endpoint);
    }
  });

  it('passes the mTLS alias it was given in the draft', async () => {
    const strategy = returning({});
    await site.run({ strategy, mtlsEndpoint: 'https://mtls.idp/token' });
    expect(strategy.drafts[0]!.mtlsEndpoint).toBe('https://mtls.idp/token');
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
      expect(wordsOf(refusedWith(error, 'token-request'))).toEqual({
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
    const refusal = refusedWith(error, 'token-request');
    expect(wordsOf(refusal)).toEqual({
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
    expect(wordsOf(refusedWith(error, 'token-request'))).toEqual({
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
    // `tls` of the site's own operation, not "the token request".
    const failure = readFailure(error, 'unfamiliar-error');
    expect(failure.kind).toBe('tls');
    expect(failure.facts).toEqual({
      operation: site.operation,
      code: 'SELF_SIGNED_CERT_IN_CHAIN',
    });
    const refusal = refusedWith(error, 'token-request');
    expect(wordsOf(refusal)).toEqual({
      ok: false,
      refusal: {
        reason: `${phrase(site.operation)} failed: the server's certificate is not trusted (SELF_SIGNED_CERT_IN_CHAIN)`,
        hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
      },
    });
    expect(JSON.stringify(error)).not.toContain('SECRET-TLS-TEXT');
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
    expect(refusedWith(withMtls, 'token-request')).toEqual(
      refusedWith(today, 'token-request'),
    );
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

/**
 * Secrets a decoding server reads differently from what was sent, each with
 * the form `application/x-www-form-urlencoded` writes it in and the form a
 * server decodes the raw secret to. `&` and `=` are where a form decoder that
 * parses a query string cuts the value; a malformed `%` stays as it is.
 */
const ECHOED_SECRETS = [
  {
    label: '`&` with `+` and `%`',
    secret: 'd&se+cr%41et',
    formSent: 'd%26se%2Bcr%2541et',
    rawDecoded: 'd&se crAet',
  },
  {
    label: '`=` with `+` and `%`',
    secret: 'ab=c+d%42e',
    formSent: 'ab%3Dc%2Bd%2542e',
    rawDecoded: 'ab=c dBe',
  },
  {
    label: 'a malformed `%`',
    secret: 'x+y%zz%4',
    formSent: 'x%2By%25zz%254',
    rawDecoded: 'x y%zz%4',
  },
];

const ECHO_PREFIX = 'bad client secret';

/**
 * A token endpoint's 401 echoing `echoed`: what the thrown error says (every
 * rendering of it) and what the logger was given.
 */
async function echoedOutput(
  echoed: string,
  run: (logger: ILogger) => Promise<unknown>,
): Promise<{ error: string; logs: string; debug: string[] }> {
  const unauthorized = {
    isAxiosError: true,
    message: 'Request failed with status code 401',
    response: {
      status: 401,
      data: {
        error: 'invalid_client',
        error_description: `${ECHO_PREFIX} ${echoed}`,
      },
    },
  };
  // The strategy path calls axios(config); a site's own adapter calls
  // axios.post or axios(config).
  mockedAxios.mockRejectedValue(unauthorized);
  mockedAxios.post.mockRejectedValue(unauthorized);
  const lines: string[] = [];
  const debug: string[] = [];
  const record = (message: string, meta?: unknown) =>
    lines.push(`${message} ${JSON.stringify(meta ?? {})}`);
  const logger = {
    debug: (message: string, meta?: unknown) => {
      record(message, meta);
      debug.push(`${message} ${JSON.stringify(meta ?? {})}`);
    },
    info: record,
    warn: record,
    error: record,
  } as ILogger;
  const error = await failureOf(run(logger));
  return {
    error: [
      messageOf(error),
      String(error),
      JSON.stringify(error),
      JSON.stringify(
        (error as { response?: { data?: unknown } } | null)?.response?.data ??
          null,
      ),
      inspect(error, { depth: null }),
    ].join('\n'),
    logs: lines.join('\n'),
    debug,
  };
}

/**
 * The server's description, and the echoed secret, reach no rendering of
 * the thrown error and no log line. (The redactor these cases also checked
 * is deleted: nothing scans text for secrets.)
 */
function expectNoEcho(
  out: { error: string; logs: string; debug: string[] },
  echoed: string,
  _secrets: string[],
): void {
  expect(out.error).not.toContain(ECHO_PREFIX);
  expect(out.error).not.toContain(echoed);
  expect(out.logs).not.toContain(ECHO_PREFIX);
  expect(out.logs).not.toContain(echoed);
}

describe.each(SITES)(
  '$name: a Basic secret echoed back, as sent or as the server decoded it',
  (site) => {
    describe.each(ECHOED_SECRETS)('$label', (c) => {
      it.each<[string, 'raw' | 'form', keyof typeof c]>([
        ['form: the original secret', 'form', 'secret'],
        ['form: the form-encoded secret that was sent', 'form', 'formSent'],
        ['raw: the secret as sent', 'raw', 'secret'],
        ['raw: the secret as the server decoded it', 'raw', 'rawDecoded'],
      ])(
        '%s is in no rendering of the thrown error nor any log line, and the redactor removes it whole',
        async (_label, encoding, which) => {
          const echoed = c[which];
          const out = await echoedOutput(echoed, (logger) =>
            site.run(
              { strategy: clientSecretBasic(c.secret, { encoding }) },
              logger,
            ),
          );
          // The secret as the strategy's Basic header carried it.
          expectNoEcho(out, echoed, [
            encoding === 'form' ? c.formSent : c.secret,
          ]);
        },
      );
    });
  },
);

describe.each(
  SITES.filter((site) => site.grantType !== 'device_authorization'),
)('$name without a strategy: the client secret echoed back', (site) => {
  describe.each(ECHOED_SECRETS)('$label', (c) => {
    it.each<[string, keyof typeof c]>([
      ['as sent', 'secret'],
      ['form-encoded', 'formSent'],
      ['as a decoding server read it', 'rawDecoded'],
    ])(
      '%s is in no rendering of the thrown error nor any log line, and the redactor removes it whole',
      async (_label, which) => {
        const echoed = c[which];
        const out = await echoedOutput(echoed, (logger) =>
          site.run(undefined, logger, c.secret),
        );
        expectNoEcho(out, echoed, [c.secret]);
      },
    );
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

  it.each(SITES)(
    'no built-in timeout: $name sends no timeout, on either path',
    async (site) => {
      await site.run({ strategy: clientSecretPost('sec') });
      await site.run();
      const configs = [
        ...mockedAxios.mock.calls.map((call) => call[0]),
        ...mockedAxios.post.mock.calls.map((call) => call[2]),
      ] as (Record<string, unknown> | undefined)[];
      expect(configs.length).toBe(2);
      for (const config of configs) {
        expect(config).toBeDefined();
        expect('timeout' in (config ?? {})).toBe(false);
      }
    },
  );

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
    // The configuration case, not 5.4.2's words.
    expect(wordsOf(refusedWith(error, 'token-request'))).toEqual({
      ok: false,
      refusal: {
        reason: 'clientId is required with a client authentication',
        hint: 'check the provider configuration',
      },
    });
  });
});

describe('a TLS failure, by code', () => {
  it.each([
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  ])('%s: fixed words, the hint naming NODE_EXTRA_CA_CERTS', (code) => {
    const refusal = refusedWith(
      Object.assign(new Error('SECRET-TEXT'), { code }),
      'token-request',
    );
    expect(wordsOf(refusal)).toEqual({
      ok: false,
      refusal: {
        reason: `the token request failed: the server's certificate is not trusted (${code})`,
        hint: 'if the server uses a private CA, name its certificate in NODE_EXTRA_CA_CERTS',
      },
    });
  });

  it('CERT_HAS_EXPIRED: the server certificate has expired — no NODE_EXTRA_CA_CERTS', () => {
    expect(
      wordsOf(
        refusedWith(
          Object.assign(new Error('SECRET-TEXT'), { code: 'CERT_HAS_EXPIRED' }),
          'token-request',
        ),
      ),
    ).toEqual({
      ok: false,
      refusal: {
        reason:
          "the token request failed: the server's certificate has expired (CERT_HAS_EXPIRED)",
        hint: "the server must renew its certificate; check also this machine's clock",
      },
    });
  });

  it('ERR_TLS_CERT_ALTNAME_INVALID: the host is not in the server certificate — no NODE_EXTRA_CA_CERTS', () => {
    expect(
      wordsOf(
        refusedWith(
          Object.assign(new Error('SECRET-TEXT'), {
            code: 'ERR_TLS_CERT_ALTNAME_INVALID',
          }),
          'token-request',
        ),
      ),
    ).toEqual({
      ok: false,
      refusal: {
        reason:
          "the token request failed: the host name is not in the server's certificate (ERR_TLS_CERT_ALTNAME_INVALID)",
        hint: "use the host name the server's certificate is issued for",
      },
    });
  });

  // Measured (Node 22, 24 with OpenSSL 3.5; Node 26 with 3.6): a server that
  // requires a client certificate answers CERTIFICATE_REQUIRED (none sent),
  // UNKNOWN_CA (an issuer it does not trust), SSL/TLS_ALERT_CERTIFICATE_EXPIRED.
  // SSLV3_ is older OpenSSL's spelling of the same alerts; the rest follow
  // OpenSSL's reason table (libssl 3.6 strings).
  it.each([
    'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED',
    'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
    'ERR_SSL_SSL/TLS_ALERT_BAD_CERTIFICATE',
    'ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_UNKNOWN',
    'ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED',
    'ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_REVOKED',
    'ERR_SSL_SSL/TLS_ALERT_UNSUPPORTED_CERTIFICATE',
    'ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE',
    'ERR_SSL_SSLV3_ALERT_CERTIFICATE_UNKNOWN',
    'ERR_SSL_SSLV3_ALERT_CERTIFICATE_EXPIRED',
    'ERR_SSL_SSLV3_ALERT_CERTIFICATE_REVOKED',
    'ERR_SSL_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE',
  ])('%s: the server refused the client certificate', (code) => {
    expect(
      wordsOf(
        refusedWith(
          Object.assign(new Error('SECRET-TEXT'), { code }),
          'token-request',
        ),
      ),
    ).toEqual({
      ok: false,
      refusal: {
        reason: `the token request failed: the server refused the client certificate (${code})`,
        hint: "check that the server trusts the certificate's issuer and that the certificate is valid and not revoked",
      },
    });
  });

  it('a handshake failure is not read as a refused certificate: it has other causes', () => {
    expect(
      wordsOf(
        refusedWith(
          Object.assign(new Error('SECRET-TEXT'), {
            code: 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE',
          }),
          'token-request',
        ),
      ),
    ).toEqual({
      ok: false,
      refusal: { reason: 'the token request failed (unknown error)' },
    });
  });

  it('a code off the list stays unknown, and nothing of the message', () => {
    expect(
      wordsOf(
        refusedWith(
          Object.assign(new Error('SECRET-TEXT'), { code: 'SECRET_CODE' }),
          'token-request',
        ),
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
      const refusal = refusedWith(await failureOf(run()), 'token-request');
      expect(refusal.ok === false && refusal.refusal.hint).toContain(
        'NODE_EXTRA_CA_CERTS',
      );
    }
  });
  it('with a strategy, every site that wrapped its errors throws `tls` of its own operation (D2)', async () => {
    mockedAxios.mockRejectedValue(
      Object.assign(new Error('SECRET-TLS'), {
        code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA',
        isAxiosError: true,
      }),
    );
    const auth = { strategy: tlsClientCertificate({ material }), material };
    const runs: [string, () => Promise<unknown>][] = [
      [
        'the client credentials request',
        () =>
          getTokenWithClientCredentials('https://uaa', 'cid', undefined, auth),
      ],
      [
        'the token refresh',
        () => refreshJwtToken('rt', 'https://uaa', 'cid', undefined, auth),
      ],
      [
        'the OIDC password grant',
        () =>
          passwordGrant(
            'https://idp/token',
            'cid',
            undefined,
            'u',
            'p',
            undefined,
            undefined,
            auth,
          ),
      ],
      [
        'the OIDC device authorization',
        () =>
          initiateDeviceAuthorization(
            'https://idp/device',
            'cid',
            undefined,
            undefined,
            auth,
          ),
      ],
    ];
    for (const [subject, run] of runs) {
      expect(
        wordsOf(refusedWith(await failureOf(run()), 'token-request')),
      ).toEqual({
        ok: false,
        refusal: {
          reason: `${subject} failed: the server refused the client certificate (ERR_SSL_TLSV1_ALERT_UNKNOWN_CA)`,
          hint: "check that the server trusts the certificate's issuer and that the certificate is valid and not revoked",
        },
      });
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

/**
 * Every site throws an `AuthProviderFailure` of its own operation:
 * `request-failed` `refused` with the status and the registered code — no
 * config, request, cause or body (the reduced `AxiosError` and
 * `TokenEndpointError` left).
 */
function expectRefusedFailure(thrown: unknown, operation: string): void {
  expect(isAuthProviderFailure(thrown)).toBe(true);
  const failure = readFailure(thrown, 'unfamiliar-error');
  expect(failure.kind).toBe('request-failed');
  expect(failure.facts).toMatchObject({
    operation,
    problem: 'refused',
    status: 400,
    oauthError: 'invalid_client',
  });
  expect(Object.keys(thrown as object).sort()).toEqual(
    ['error', 'message', 'name'].sort(),
  );
  expect((thrown as { cause?: unknown }).cause).toBeUndefined();
}

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
      expectRefusedFailure(thrown, site.operation);
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
    expectRefusedFailure(thrown, site.operation);
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
  /** A logger keeping its debug lines. */
  const debugging = () => {
    const lines: string[] = [];
    const logger = {
      debug: (message: string, meta?: unknown) =>
        lines.push(`${message} ${JSON.stringify(meta ?? {})}`),
      info: () => {},
      warn: () => {},
      error: () => {},
    } as ILogger;
    return { logger, lines };
  };
  /**
   * The failure's words are the operation's and the status alone (the code
   * is not a registered one); the server's words are in no line.
   */
  const expectRefusalNoted = (
    thrown: unknown,
    subject: string,
    lines: string[],
    secrets: string[],
  ) => {
    expect(messageOf(thrown)).toBe(`${subject} failed (HTTP 401)`);
    // One debug line of safe facts: the status; the code is not registered.
    expect(lines).toEqual([
      `${subject}: the token endpoint refused the request {"status":401}`,
    ]);
    for (const secret of secrets) expect(lines[0]).not.toContain(secret);
  };

  it.each([
    ['as today', undefined],
    ['with a strategy', { strategy: clientSecretPost(CLIENT_SECRET) }],
  ])('passcode, %s', async (_label, auth) => {
    mockedAxios.post.mockRejectedValue(echoing([PASSCODE, CLIENT_SECRET]));
    mockedAxios.mockRejectedValue(echoing([PASSCODE, CLIENT_SECRET]));
    const { logger, lines } = debugging();
    const thrown = await failureOf(
      exchangePasscode(
        'https://uaa',
        'cid',
        auth ? undefined : CLIENT_SECRET,
        PASSCODE,
        logger,
        auth,
      ),
    );
    expectRefusalNoted(thrown, 'the passcode exchange', lines, [
      PASSCODE,
      CLIENT_SECRET,
    ]);
  });

  it.each([
    ['as today', undefined],
    ['with a strategy', { strategy: clientSecretPost(CLIENT_SECRET) }],
  ])('password grant, %s', async (_label, auth) => {
    mockedAxios.post.mockRejectedValue(echoing([PASSWORD, CLIENT_SECRET]));
    mockedAxios.mockRejectedValue(echoing([PASSWORD, CLIENT_SECRET]));
    const { logger, lines } = debugging();
    const thrown = await failureOf(
      passwordGrant(
        OIDC,
        'cid',
        auth ? undefined : CLIENT_SECRET,
        'user',
        PASSWORD,
        undefined,
        logger,
        auth,
      ),
    );
    expectRefusalNoted(thrown, 'the OIDC password grant', lines, [
      PASSWORD,
      CLIENT_SECRET,
    ]);
  });

  it("device authorization: the server's words only in the debug line, the strategy's secret redacted", async () => {
    mockedAxios.mockRejectedValue(echoing([CLIENT_SECRET]));
    const { logger, lines } = debugging();
    const thrown = await failureOf(
      initiateDeviceAuthorization(
        'https://idp/device-auth',
        'cid',
        'openid',
        logger,
        {
          strategy: clientSecretPost(CLIENT_SECRET),
        },
      ),
    );
    expectRefusalNoted(thrown, 'the OIDC device authorization', lines, [
      CLIENT_SECRET,
    ]);
  });

  it('device authorization as today, with no logger: the status alone, no line', async () => {
    mockedAxios.post.mockRejectedValue(echoing([]));
    const thrown = await failureOf(
      initiateDeviceAuthorization('https://idp/device-auth', 'cid', 'openid'),
    );
    expect(messageOf(thrown)).toBe(
      'the OIDC device authorization failed (HTTP 401)',
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
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: 'device-authorization',
        code: 'SELF_SIGNED_CERT_IN_CHAIN',
      });
      expect(wordsOf(refusedWith(thrown, 'token-request'))).toEqual({
        ok: false,
        refusal: {
          reason:
            "the OIDC device authorization failed: the server's certificate is not trusted (SELF_SIGNED_CERT_IN_CHAIN)",
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
        error_description: `SERVER-SAYS ${echoed}`,
        error_uri: 'https://docs.example/errors',
        access_token: LEAKED,
        extra: { nested: echoed },
      },
    },
  });
  /**
   * Only the registered code stays, wherever the body is kept: never the
   * server's description or URI, in no rendering of the error.
   */
  const onlyOAuthFields = (thrown: unknown) => {
    const data = (thrown as { response?: { data?: unknown } }).response?.data;
    if (data !== undefined) {
      expect(data).toEqual({ error: 'invalid_grant' });
    }
    const text = `${serialized(thrown)}\n${String(thrown)}\n${inspect(thrown, { depth: null })}`;
    expect(text).not.toContain('SERVER-SAYS');
    expect(text).not.toContain('docs.example');
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

describe('a registered error code is never rewritten by redaction', () => {
  const failing = (data: Record<string, string>) => ({
    isAxiosError: true,
    response: { status: 400, data },
  });

  // `a` is inside `authorization_pending`, `low` inside `slow_down`: redacting
  // them in the code would stop the poll at the first pending answer.
  it.each([
    ['as today, client secret `a`, device code `low`', 'a', 'low', undefined],
    [
      'with a strategy, client secret `a`, device code `low`',
      undefined,
      'low',
      { strategy: clientSecretPost('a') },
    ],
    [
      'with a strategy, client secret `low`, device code `a`',
      undefined,
      'a',
      { strategy: clientSecretPost('low') },
    ],
  ])(
    '%s: the poll continues through authorization_pending and slow_down and gets the token',
    async (_label, secret, deviceCode, auth) => {
      const answers = [
        failing({ error: 'authorization_pending' }),
        failing({ error: 'slow_down' }),
      ];
      for (const target of [mockedAxios, mockedAxios.post]) {
        target
          .mockRejectedValueOnce(answers[0])
          .mockRejectedValueOnce(answers[1])
          .mockResolvedValueOnce(reply);
      }
      // slow_down waits interval + 5 s: run each wait at once.
      const wait = jest.spyOn(global, 'setTimeout').mockImplementation(((
        fn: () => void,
      ) => {
        fn();
        return 0 as unknown as NodeJS.Timeout;
      }) as unknown as typeof setTimeout);
      try {
        const tokens = await pollDeviceTokens(
          OIDC,
          'cid',
          secret,
          deviceCode,
          0,
          undefined,
          auth,
        );
        expect(tokens.accessToken).toBe(reply.data.access_token);
      } finally {
        wait.mockRestore();
      }
      expect(
        mockedAxios.mock.calls.length + mockedAxios.post.mock.calls.length,
      ).toBe(3);
    },
  );

  it.each([
    ['as today', 'S3cr3t-value', undefined],
    [
      'with a strategy',
      undefined,
      { strategy: clientSecretPost('S3cr3t-value') },
    ],
  ])(
    '%s: an unregistered error and the free text stay off the error and the log',
    async (_label, secret, auth) => {
      const body = failing({
        error: 'custom_S3cr3t-value',
        error_description: 'refused S3cr3t-value',
        error_uri: 'https://idp/err?S3cr3t-value',
      });
      mockedAxios.mockRejectedValueOnce(body);
      mockedAxios.post.mockRejectedValueOnce(body);
      const lines: unknown[] = [];
      const logger = {
        debug: (_message: string, meta?: unknown) => lines.push(meta),
        info: () => {},
        warn: () => {},
        error: () => {},
      } as ILogger;
      const thrown = await failureOf(
        pollDeviceTokens(OIDC, 'cid', secret, 'dc', 0, logger, auth),
      );
      // The failure names the status; no unregistered code, no body.
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: 'device-poll',
        problem: 'refused',
        status: 400,
      });
      expect(serialized(thrown)).not.toContain('S3cr3t-value');
      // Safe facts only: the status; the unregistered code is dropped.
      expect(lines).toEqual([{ status: 400 }]);
    },
  );

  it("a registered code is the message's only word from the server", async () => {
    mockedAxios.mockRejectedValueOnce(
      failing({ error: 'invalid_grant', error_description: 'bad a' }),
    );
    const error = await failureOf(
      passwordGrant(OIDC, 'cid', 'a', 'user', 'pw', undefined, undefined, {
        strategy: clientSecretPost('a'),
      }),
    );
    // The operation's words with the status and the registered code.
    expect(messageOf(error)).toBe(
      'the OIDC password grant failed (HTTP 400, invalid_grant)',
    );
  });

  it.each([
    ['as today', 'sec', undefined],
    ['with a strategy', undefined, { strategy: clientSecretPost('sec') }],
  ])(
    '%s: a consumer reading the failure still gets the registered code, and nothing else',
    async (_label, secret, auth) => {
      const body = failing({
        error: 'invalid_grant',
        error_description: 'refresh token expired',
        error_uri: 'https://idp/err',
      });
      mockedAxios.mockRejectedValueOnce(body);
      mockedAxios.post.mockRejectedValueOnce(body);
      const thrown = await failureOf(
        refreshOidcToken(OIDC, 'cid', secret, 'rt', undefined, auth),
      );
      // The code is the failure's `oauthError` fact, not a body.
      expect(readFailure(thrown, 'unfamiliar-error').facts).toEqual({
        operation: 'oidc-token-request',
        problem: 'refused',
        status: 400,
        oauthError: 'invalid_grant',
      });
      const text = serialized(thrown);
      expect(text).not.toContain('refresh token expired');
      expect(text).not.toContain('idp/err');
    },
  );
});
