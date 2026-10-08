/**
 * The producers of the client-authentication, certificate and debug-line
 * refusals: each throws an `AuthProviderFailure` of its kind — the 5.x
 * error classes are gone (the `configuration` cases are in
 * `configurationRows.test.ts`) — with the row's facts and verbatim words; the
 * debug line is the default safe-facts line, or with `authDebug` the
 * `token endpoint said` line.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import {
  isAuthProviderFailure,
  isMinted,
  readFailure,
} from '@mcp-abap-adt/auth-errors';
import type {
  IAuthProviderError,
  ICertificateMaterial,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  assertCertificateMaterial,
  certificateThumbprint,
  checkCertificateMaterial,
} from '../../auth/certificateMaterial';
import {
  prepareTokenRequest,
  sendTokenRequest,
  type TokenRequestSite,
} from '../../auth/tokenRequest';
import { clientSecretBasic } from '../../clientAuthentication/clientSecret';
import { privateKeyJwt } from '../../clientAuthentication/privateKeyJwt';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import { createSignedResponseValidator } from '../../validation/assertionValidator';
import { createInMemoryReplayStore } from '../../validation/inMemoryReplayStore';
import { mintedRefusal } from '../helpers/minted';

const FIXTURES = join(__dirname, '..', 'fixtures', 'certificates');
const read = (name: string) => readFileSync(join(FIXTURES, name));
const MARKER = 'PRODUCER-MARKER';

async function thrownBy(run: () => unknown): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error('expected a throw');
}

/** A failure of this copy, its minted error, and no class of this package. */
function failureError(thrown: unknown): IAuthProviderError {
  expect(isAuthProviderFailure(thrown)).toBe(true);
  expect((thrown as Error).constructor.name).toBe('AuthProviderFailure');
  const error = readFailure(thrown, 'unfamiliar-error');
  expect(isMinted(error)).toBe(true);
  expect(JSON.stringify(error)).not.toContain(MARKER);
  return error;
}

const DRAFT = {
  endpoint: 'https://uaa.example/oauth/token',
  tokenEndpoint: 'https://uaa.example/oauth/token',
  clientId: 'client',
  grantType: 'client_credentials',
};

describe('A3 — the SAML refusal', () => {
  it('A3: a shipped validator throws a minted saml-assertion failure with its rule', async () => {
    const validator = createSignedResponseValidator({
      idpCertificates: [read('client.crt').toString('utf8')],
      replayStore: createInMemoryReplayStore(),
    });
    const payload = Buffer.from(`<!DOCTYPE x><x>${MARKER}</x>`).toString(
      'base64',
    );
    const error = failureError(
      await thrownBy(() =>
        validator.validate(payload, {
          expectedIssuer: 'idp',
          audience: 'sp',
          acsUrl: 'https://sp.example/acs',
        } as never),
      ),
    );
    expect(error).toMatchObject({
      kind: 'saml-assertion',
      facts: { rule: 'doctype', check: 'document' },
      reason:
        'the SAML assertion was refused (document): the SAMLResponse carries a DOCTYPE declaration, which is never accepted',
    });
  });
});

describe('A4 — client-certificate', () => {
  const CERTIFICATE_WORDS = {
    incomplete: {
      reason: 'the client certificate is incomplete',
      hint: 'give a PFX, or a certificate together with its key',
    },
    unusable: {
      reason: 'the client certificate could not be used',
      hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
    },
    expired: {
      reason: 'the client certificate has expired',
      hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
    },
  } as const;

  const cases: ReadonlyArray<
    [keyof typeof CERTIFICATE_WORDS, () => ICertificateMaterial]
  > = [
    ['incomplete', () => ({ cert: read('client.crt') })],
    [
      'unusable',
      () => ({ cert: Buffer.from(MARKER), key: Buffer.from(MARKER) }),
    ],
    ['expired', () => ({ cert: read('expired.crt'), key: read('client.key') })],
  ];

  it.each(cases)(
    'A4: %s — assertCertificateMaterial throws the failure, checkCertificateMaterial answers it',
    async (problem, material) => {
      const thrown = failureError(
        await thrownBy(() => assertCertificateMaterial(material())),
      );
      const expected = {
        kind: 'client-certificate',
        facts: { problem },
        ...CERTIFICATE_WORDS[problem],
      };
      expect(thrown).toMatchObject(expected);
      expect(mintedRefusal(checkCertificateMaterial(material()))).toMatchObject(
        expected,
      );
    },
  );

  it('A4: certificateThumbprint of incomplete material', async () => {
    expect(
      failureError(await thrownBy(() => certificateThumbprint({}))),
    ).toMatchObject({
      kind: 'client-certificate',
      facts: { problem: 'incomplete' },
    });
  });

  it('A4: a strategy whose tlsMaterial() yields nothing — getTokens() throws incomplete', async () => {
    const provider = new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: 'https://uaa.example',
      clientId: 'client',
      clientAuthentication: {
        authenticate: async () => ({}),
        tlsMaterial: async () => undefined as never,
      },
    });
    expect(
      failureError(await thrownBy(() => provider.getTokens())),
    ).toMatchObject({
      kind: 'client-certificate',
      facts: { problem: 'incomplete' },
      ...CERTIFICATE_WORDS.incomplete,
    });
  });
});

describe('A5–A7 — client-authentication', () => {
  it('A5: a strategy result that cannot be sent (a line break in a header)', async () => {
    const error = failureError(
      await thrownBy(() =>
        prepareTokenRequest(
          { ...DRAFT, parameters: new URLSearchParams() },
          {
            strategy: {
              authenticate: async () => ({
                headers: { 'X-Thing': `a\r\n${MARKER}` },
              }),
            },
          },
        ),
      ),
    );
    expect(error).toMatchObject({
      kind: 'client-authentication',
      facts: { problem: 'result-unsendable' },
      reason:
        'the client authentication returned a request that cannot be sent',
      hint: 'check the client authentication strategy',
    });
  });

  it.each([
    ['not a key', () => privateKeyJwt({ key: MARKER, algorithm: 'RS256' })],
    [
      'a key of another algorithm',
      () => privateKeyJwt({ key: read('client.key'), algorithm: 'ES256' }),
    ],
  ])('A6: privateKeyJwt with %s', async (_name, make) => {
    const error = failureError(
      await thrownBy(() => make().authenticate(DRAFT as never)),
    );
    expect(error).toMatchObject({
      kind: 'client-authentication',
      facts: { problem: 'signing-key-unusable' },
      reason: 'the client signing key could not be used',
      hint: 'check the private key and that it matches the algorithm',
    });
  });

  it('A7: raw clientSecretBasic with a client id containing a colon', async () => {
    const error = failureError(
      await thrownBy(() =>
        clientSecretBasic(MARKER, { encoding: 'raw' }).authenticate({
          ...DRAFT,
          clientId: 'a:b',
        } as never),
      ),
    );
    expect(error).toMatchObject({
      kind: 'client-authentication',
      facts: { problem: 'basic-client-id-colon' },
      reason: "the client id contains ':', which raw Basic cannot carry",
      hint: "use encoding: 'form' or clientSecretPost",
    });
  });
});

describe('H10 — the debug line of a refused token request', () => {
  const SECRET = 'abcdefghijklmnop-refresh-token';

  function recording(): { logger: ILogger; lines: unknown[][] } {
    const lines: unknown[][] = [];
    const at =
      (level: string) =>
      (...args: unknown[]) => {
        lines.push([level, ...args]);
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

  const site = (logger: ILogger, authDebug: boolean): TokenRequestSite => ({
    operation: 'token-refresh',
    grant: 'authorization_code',
    authDebug,
    secrets: { refresh_token: SECRET },
    logger,
  });

  const refused = () =>
    Promise.reject({
      isAxiosError: true,
      message: MARKER,
      response: {
        status: 400,
        statusText: MARKER,
        data: {
          error: 'invalid_grant',
          error_description: MARKER,
          error_uri: MARKER,
        },
      },
    });

  it('H10: by default, one debug line of the safe facts', async () => {
    const { logger, lines } = recording();
    const thrown = await thrownBy(() =>
      sendTokenRequest(undefined, refused, site(logger, false)),
    );
    expect(failureError(thrown)).toMatchObject({
      kind: 'request-failed',
      facts: { operation: 'token-refresh', problem: 'refused', status: 400 },
    });
    expect(lines).toEqual([
      [
        'debug',
        'the token refresh: the token endpoint refused the request',
        { status: 400, error: 'invalid_grant' },
      ],
    ]);
    expect(JSON.stringify(lines)).not.toContain(SECRET.slice(4, -4));
  });

  it('H10: with authDebug, the token endpoint said line and the prepared secrets', async () => {
    const { logger, lines } = recording();
    await thrownBy(() =>
      sendTokenRequest(undefined, refused, site(logger, true)),
    );
    expect(lines).toEqual([
      [
        'debug',
        '[token-refresh] token endpoint said',
        {
          status: 400,
          error: 'invalid_grant',
          sent: { refresh_token: 'abcd…oken <redacted, 30 chars>' },
        },
      ],
    ]);
    expect(JSON.stringify(lines)).not.toContain(MARKER);
  });
});
